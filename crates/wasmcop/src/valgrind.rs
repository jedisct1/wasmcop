use anyhow::{Context, Result, bail};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use wasmcop_job::{Job, Report};

/// Normally empty: noise from the host should fail the run, not get hidden.
const SUPPRESSIONS: &str = include_str!("wasmcop.supp");

#[derive(Debug)]
pub struct Run {
    pub report: Report,
    pub xml: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Valgrind {
    pub path: PathBuf,
    pub version: String,
    /// Has the variable-latency patch.
    pub patched: bool,
}

impl Valgrind {
    /// An explicit path wins, then the build from `scripts/build-valgrind.sh`, then `PATH`.
    pub fn find(explicit: Option<&Path>) -> Result<Valgrind> {
        let cached = cached_valgrind().filter(|path| path.exists());
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None => cached.unwrap_or_else(|| PathBuf::from("valgrind")),
        };
        let output = Command::new(&path)
            .arg("--version")
            .output()
            .with_context(|| format!("running {}", path.display()))?;
        if !output.status.success() {
            bail!("{} --version failed", path.display());
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let help = Command::new(&path)
            .args(["--tool=memcheck", "--help"])
            .output()
            .with_context(|| format!("running {}", path.display()))?;
        let patched = String::from_utf8_lossy(&help.stdout).contains("--variable-latency-errors");
        Ok(Valgrind { path, version, patched })
    }

    pub fn run(&self, runner: &Path, mut job: Job, dir: &Path) -> Result<Run> {
        job.output = dir.join("report.json");
        let job_path = dir.join("job.json");
        let xml = dir.join("errors.xml");
        let suppressions = dir.join("wasmcop.supp");
        fs::write(&job_path, serde_json::to_vec(&job)?)?;
        fs::write(&suppressions, SUPPRESSIONS)?;
        let output = self
            .command(runner, &job_path, &xml, &suppressions)
            .output()
            .with_context(|| format!("running {}", self.path.display()))?;
        if !output.status.success() {
            bail!(
                "the runner failed under Valgrind ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let text = fs::read_to_string(&job.output)
            .with_context(|| format!("reading {}", job.output.display()))?;
        Ok(Run { report: serde_json::from_str(&text)?, xml })
    }

    fn command(&self, runner: &Path, job: &Path, xml: &Path, suppressions: &Path) -> Command {
        let mut command = Command::new(&self.path);
        command.args([
            "--tool=memcheck",
            "--xml=yes",
            "--px-default=allregs-at-each-insn",
            "--px-file-backed=unwindregs-at-mem-access",
            "--smc-check=all-non-file",
            "--expensive-definedness-checks=yes",
            "--partial-loads-ok=no",
            "--leak-check=no",
            "--num-callers=32",
        ]);
        command.arg(format!("--xml-file={}", xml.display()));
        command.arg(format!("--suppressions={}", suppressions.display()));
        if self.patched {
            command.arg("--variable-latency-errors=yes");
        }
        command.arg(runner).arg(job);
        command
    }
}

pub fn cached_valgrind() -> Option<PathBuf> {
    Some(cache_dir()?.join("valgrind/bin/valgrind"))
}

pub fn cache_dir() -> Option<PathBuf> {
    let base = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("wasmcop"))
}

/// The runner lives next to the `wasmcop` binary.
pub fn find_runner() -> Result<PathBuf> {
    let exe = env::current_exe().context("locating the wasmcop binary")?;
    let dir = exe.parent().context("the wasmcop binary has no directory")?;
    // Test binaries are one level down, in target/release/deps.
    for candidate in [dir.join("wasmcop-runner"), dir.join("../wasmcop-runner")] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("wasmcop-runner was not found next to {}. Build it with `make`.", exe.display())
}
