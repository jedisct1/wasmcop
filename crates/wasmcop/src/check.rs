use crate::analyze::{self, Analysis};
use crate::code::ArtifactCode;
use crate::compile::{self, Cell};
use crate::report::{CellResult, CheckReport, TestResult, cell_labels};
use crate::source::SourceInfo;
use crate::valgrind::{Run, Valgrind};
use crate::xml::{self, ValgrindOutput};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use wasmcop_job::{Job, Poison};
use wasmcop_spec::module::ModuleShape;
use wasmcop_spec::resolve::{Options, Resolved, TestCase, resolve};

pub struct Settings {
    pub valgrind: Valgrind,
    pub runner: PathBuf,
    pub work_dir: PathBuf,
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

fn run_all(work: &[Work], settings: &Settings) -> Result<Vec<Run>> {
    work.iter().map(|item| {
        fs::create_dir_all(&item.dir).with_context(|| format!("creating {}", item.dir.display()))?;
        settings.valgrind.run(&settings.runner, item.job.clone(), &item.dir)
    }).collect()
}

/// Each cell has its own work directory, so a repeated cell would overwrite itself.
fn unique(cells: &[Cell]) -> Vec<Cell> {
    let mut seen = BTreeSet::new();
    cells.iter().filter(|cell| seen.insert(**cell)).copied().collect()
}

pub fn compile_cell(wasm: &[u8], cell: &Cell, work_dir: &Path) -> Result<Build> {
    if !cell.backend.available() {
        return Ok(Err(format!("this build of wasmcop has no {} backend", cell.backend)));
    }
    let artifact = match compile::compile(wasm, cell) {
        Ok(artifact) => artifact,
        Err(reason) => return Ok(Err(reason)),
    };
    let path = work_dir.join(format!("{}.wasmu", cell.slug()));
    fs::write(&path, &artifact).with_context(|| format!("writing {}", path.display()))?;
    let code = ArtifactCode::parse(&artifact).with_context(|| format!("reading {}", path.display()))?;
    Ok(Ok(Compiled { path, code }))
}

fn read_output(run: &Run) -> Result<ValgrindOutput> {
    xml::parse(&fs::read_to_string(&run.xml).with_context(|| format!("reading {}", run.xml.display()))?)
}

fn analyze_run(run: &Run, compiled: &Compiled, module: &Module) -> Result<Analysis> {
    let code = compiled.code.join(&run.report.functions, module.shape)?;
    Ok(analyze::analyze(&read_output(run)?, &code, &run.report, module.source))
}

/// Runs every test on every cell.
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

    let cells = unique(cells);
    let builds = cells.iter().map(|cell| compile_cell(wasm, cell, &settings.work_dir)).collect::<Result<Vec<_>>>()?;
    let labels = cell_labels(&cells);

    let mut work = Vec::new();
    for (index, test) in resolved.iter().enumerate() {
        for (cell, build) in cells.iter().zip(&builds) {
            if let Ok(compiled) = build {
                let dir = settings.work_dir.join(format!("test-{index}")).join(cell.slug());
                work.push(Work::new(&test.job, Poison::All, compiled, dir.join("main")));
            }
        }
    }
    let mut runs = run_all(&work, settings)?.into_iter();

    let mut results = Vec::new();
    for test in tests {
        let mut cell_results = Vec::new();
        for (build, label) in builds.iter().zip(&labels) {
            let (skipped, analysis) = match build {
                Err(reason) => (Some(reason.clone()), Analysis::default()),
                Ok(compiled) => {
                    let main = runs.next().expect("one run per job");
                    let analysis = analyze_run(&main, compiled, &module)?;
                    (None, analysis)
                }
            };
            cell_results.push(CellResult { cell: label.clone(), skipped, analysis });
        }
        results.push(TestResult { name: test.name.clone(), cells: cell_results });
    }

    Ok(CheckReport { tests: results })
}
