mod imports;
mod run;
mod vg;

use anyhow::{Context, Result, bail};
use std::process::ExitCode;
use wasmcop_job::{Job, Report};

fn load(path: &str) -> Result<Job> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {path}"))
}

fn write_report(job: &Job, report: &Report) -> Result<()> {
    let text = serde_json::to_string(report)?;
    std::fs::write(&job.output, text).with_context(|| format!("writing {}", job.output.display()))
}

fn execute(args: &[String]) -> Result<()> {
    let (native, path) = match args {
        [path] => (false, path),
        [flag, path] if flag == "--native" => (true, path),
        _ => bail!("usage: wasmcop-runner [--native] job.json"),
    };
    let job = load(path)?;
    if !native && !vg::running_on_valgrind() {
        bail!("wasmcop-runner must run under Valgrind (or pass --native to test the harness)");
    }
    let report = run::run(&job).unwrap_or_else(|e| Report {
        error: Some(format!("{e:#}")),
        ..Report::default()
    });
    write_report(&job, &report)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match execute(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wasmcop-runner: {e:#}");
            ExitCode::from(2)
        }
    }
}
