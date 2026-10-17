use crate::analyze::{self, Analysis};
use crate::code::ArtifactCode;
use crate::compile::{self, Cell};
use crate::report::{CellResult, CheckReport, TestResult, cell_labels};
use crate::source::SourceInfo;
use crate::valgrind::{self, Run, Valgrind};
use crate::xml::{self, ValgrindOutput};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use turboshake::TurboShake128;
use turboshake::digest::{ExtendableOutput, Update};
use wasmcop_job::{Job, Poison, to_hex};
use wasmcop_spec::module::ModuleShape;
use wasmcop_spec::resolve::{Options, Resolved, TestCase, resolve};

pub struct Settings {
    pub valgrind: Valgrind,
    pub runner: PathBuf,
    pub work_dir: PathBuf,
    pub jobs: usize,
}

pub struct Compiled {
    pub path: PathBuf,
    pub code: ArtifactCode,
}

/// A compile error only loses that cell, so it's kept as a reason to skip it.
type Build = Result<Compiled, String>;

struct Module<'a> {
    shape: &'a ModuleShape,
    source: &'a SourceInfo<'a>,
}

struct Work {
    job: Job,
    dir: PathBuf,
}

impl Work {
    fn new(job: &Job, poison: Poison, compiled: &Compiled, dir: PathBuf) -> Work {
        let mut job = job.clone();
        job.poison = poison;
        job.artifact = compiled.path.clone();
        Work { job, dir }
    }
}

/// Runs `work` on every item, several at a time, and returns the results in order.
fn parallel_map<T: Sync, R: Send>(items: &[T], jobs: usize, work: impl Fn(&T) -> Result<R> + Sync) -> Result<Vec<R>> {
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<Result<R>>>> = items.iter().map(|_| Mutex::new(None)).collect();
    thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else { break };
                    *results[index].lock().unwrap() = Some(work(item));
                }
            });
        }
    });
    results.into_iter().map(|result| result.into_inner().unwrap().expect("every item was processed")).collect()
}

fn run_all(work: &[Work], settings: &Settings) -> Result<Vec<Run>> {
    parallel_map(work, settings.jobs, |item| {
        fs::create_dir_all(&item.dir).with_context(|| format!("creating {}", item.dir.display()))?;
        settings.valgrind.run(&settings.runner, item.job.clone(), &item.dir)
    })
}

/// Each cell has its own work directory, so a repeated cell would overwrite itself.
fn unique(cells: &[Cell]) -> Vec<Cell> {
    let mut seen = BTreeSet::new();
    cells.iter().filter(|cell| seen.insert(**cell)).copied().collect()
}

/// Compiled artifacts are kept between runs, since LLVM in particular is slow.
pub fn compile_cell(wasm: &[u8], cell: &Cell) -> Result<Build> {
    if !cell.backend.available() {
        return Ok(Err(format!("this build of wasmcop has no {} backend", cell.backend)));
    }
    let key = artifact_key(wasm, cell, build_fingerprint()?);
    let path = artifact_cache_dir()?.join(format!("{key}.wasmu"));
    if !path.exists() {
        match compile::compile(wasm, cell) {
            Ok(artifact) => write_atomically(&path, &artifact)?,
            Err(reason) => return Ok(Err(reason)),
        }
    }
    let artifact = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let code = ArtifactCode::parse(&artifact).with_context(|| format!("reading {}", path.display()))?;
    Ok(Ok(Compiled { path, code }))
}

fn artifact_cache_dir() -> Result<PathBuf> {
    let dir = valgrind::cache_dir().context("can't tell where the cache directory is")?.join("artifacts");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// A hash of this program.
/// It contains the compilers and their settings, so any change to those invalidates the cache.
fn build_fingerprint() -> Result<&'static [u8; 32]> {
    static FINGERPRINT: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(fingerprint) = FINGERPRINT.get() {
        return Ok(fingerprint);
    }
    let exe = std::env::current_exe().context("locating the wasmcop binary")?;
    let bytes = fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
    Ok(FINGERPRINT.get_or_init(|| {
        let mut fingerprint = [0; 32];
        TurboShake128::digest_xof(&bytes, &mut fingerprint);
        fingerprint
    }))
}

fn artifact_key(wasm: &[u8], cell: &Cell, fingerprint: &[u8; 32]) -> String {
    let mut hash = TurboShake128::default();
    hash.update(fingerprint);
    hash.update(cell.slug().as_bytes());
    hash.update(&[0]);
    hash.update(wasm);
    let mut key = [0; 32];
    hash.finalize_xof_into(&mut key);
    to_hex(&key)
}

/// Parallel runs can compile the same artifact, and a reader must never see half of one.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("artifact path has no directory")?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn read_output(run: &Run) -> Result<ValgrindOutput> {
    xml::parse(&fs::read_to_string(&run.xml).with_context(|| format!("reading {}", run.xml.display()))?)
}

fn analyze_run(run: &Run, compiled: &Compiled, module: &Module) -> Result<Analysis> {
    let code = compiled.code.join(&run.report.functions, module.shape)?;
    Ok(analyze::analyze(&read_output(run)?, &code, &run.report, module.source))
}

/// Runs every test on every cell, and a second time with no secrets to prove the harness itself is quiet.
pub fn check(wasm: &[u8], tests: &[TestCase], options: &Options, cells: &[Cell], settings: &Settings) -> Result<CheckReport> {
    let shape = ModuleShape::parse(wasm)?;
    let source = SourceInfo::new(wasm);
    let module = Module { shape: &shape, source: &source };

    let resolved = tests
        .iter()
        .map(|test| {
            let resolved = resolve(test, &shape, options)?;
            Ok(resolved)
        })
        .collect::<Result<Vec<Resolved>>>()?;

    // Read once here, rather than once per worker.
    build_fingerprint()?;
    let cells = unique(cells);
    let builds = parallel_map(&cells, settings.jobs, |cell| compile_cell(wasm, cell))?;
    let labels = cell_labels(&cells);

    // One queue for everything, so the number of cells doesn't limit how many runs happen at once.
    let mut work = Vec::new();
    for (index, test) in resolved.iter().enumerate() {
        for (cell, build) in cells.iter().zip(&builds) {
            if let Ok(compiled) = build {
                let dir = settings.work_dir.join(format!("test-{index}")).join(cell.slug());
                work.push(Work::new(&test.job, Poison::All, compiled, dir.join("main")));
                work.push(Work::new(&test.job, Poison::None, compiled, dir.join("baseline")));
            }
        }
    }
    let mut runs = run_all(&work, settings)?.into_iter();

    let mut results = Vec::new();
    for (test, resolved) in tests.iter().zip(&resolved) {
        let mut cell_results = Vec::new();
        for (build, label) in builds.iter().zip(&labels) {
            let (skipped, analysis) = match build {
                Err(reason) => (Some(reason.clone()), Analysis::default()),
                Ok(compiled) => {
                    let (main, baseline) = (runs.next().expect("one run per job"), runs.next().expect("one run per job"));
                    let mut analysis = analyze_run(&main, compiled, &module)?;
                    if !resolved.secrets.is_empty() {
                        analyze::warn_if_vacuous(&mut analysis, &main.report);
                    }
                    analysis.failures.extend(analyze::baseline_failures(&read_output(&baseline)?, &baseline.report));
                    (None, analysis)
                }
            };
            cell_results.push(CellResult { cell: label.clone(), skipped, analysis });
        }
        results.push(TestResult { name: test.name.clone(), cells: cell_results });
    }

    Ok(CheckReport { tests: results })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{Backend, CpuProfile, Opt};

    #[test]
    fn cells() {
        let cell = Cell { backend: Backend::Cranelift, opt: Opt::Speed, cpu: CpuProfile::Avx2 };
        let build = [1; 32];
        let key = artifact_key(b"a", &cell, &build);
        assert_eq!(key, artifact_key(b"a", &cell, &build));
        assert_ne!(key, artifact_key(b"b", &cell, &build));
        assert_ne!(key, artifact_key(b"a", &cell, &[2; 32]));
        assert_ne!(key, artifact_key(b"a", &Cell { backend: Backend::Llvm, ..cell }, &build));
        assert_ne!(key, artifact_key(b"a", &Cell { opt: Opt::None, ..cell }, &build));
        assert_ne!(key, artifact_key(b"a", &Cell { cpu: CpuProfile::Sse42, ..cell }, &build));

        let other = Cell { cpu: CpuProfile::Sse42, ..cell };
        assert_eq!(unique(&[cell, other, cell]), [cell, other]);
        assert_eq!(Cell::full(&Backend::ALL, &CpuProfile::ALL).len(), (1 + 3 + 4) * 3);
    }
}
