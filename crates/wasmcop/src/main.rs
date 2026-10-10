use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use wasmcop::check::{Settings, check};
use wasmcop::compile::{Backend, Cell};
use wasmcop::valgrind::{Valgrind, find_runner};
use wasmcop_spec::resolve::{Options, TestCase};
use wasmcop_spec::syntax::{Statement, parse_call};

#[derive(Parser)]
#[command(name = "wasmcop", version, about = "Checks whether wasm code handles secrets in constant time")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct CheckArgs {
    /// A .wasm or .wat module
    input: PathBuf,
    /// A function to call, like 'mac(tag: out(32), m: bytes(64), len(m), k: secret bytes(32))'
    #[arg(long = "call")]
    calls: Vec<String>,
    /// Only use these backends [default: all]
    #[arg(long, value_enum, value_delimiter = ',')]
    backend: Vec<Backend>,
}

#[derive(Subcommand)]
enum Command {
    /// Check functions for secret-dependent behavior
    Check(CheckArgs),
}

fn cells(args: &CheckArgs) -> Vec<Cell> {
    let backends: Vec<Backend> = if args.backend.is_empty() {
        Backend::ALL.into_iter().filter(|b| b.available()).collect()
    } else {
        args.backend.clone()
    };
    Cell::defaults(&backends)
}

fn tests_from_calls(calls: &[String]) -> Result<Vec<TestCase>> {
    let mut tests: Vec<TestCase> = Vec::new();
    for text in calls {
        let call = parse_call(text).with_context(|| format!("in --call '{text}'"))?;
        let repeats = tests.iter().filter(|t| t.name == call.function || t.name.starts_with(&format!("{}#", call.function))).count();
        let name = if repeats == 0 { call.function.clone() } else { format!("{}#{}", call.function, repeats + 1) };
        tests.push(TestCase { name, statements: vec![Statement::Call(call)] });
    }
    Ok(tests)
}

fn run_check(args: &CheckArgs) -> Result<ExitCode> {
    if args.calls.is_empty() {
        bail!("say what to call with --call 'function(arguments)'");
    }
    let wasm = wasmcop::read_module(&args.input)?;
    let tests = tests_from_calls(&args.calls)?;
    let options = Options::default();
    let temp = tempfile::tempdir()?;
    let work_dir = temp.path().to_path_buf();
    let settings = Settings { valgrind: Valgrind::find(None)?, runner: find_runner()?, work_dir };
    let report = check(&wasm, &tests, &options, &cells(args), &settings)?;
    print!("{}", report.to_text());
    Ok(ExitCode::from(report.exit_code()))
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Check(args) => run_check(&args),
    };
    result.unwrap_or_else(|e| {
        eprintln!("wasmcop: {e:#}");
        ExitCode::from(2)
    })
}
