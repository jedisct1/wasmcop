use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use wasmcop::check::{Settings, check};
use wasmcop::compile::{Backend, Cell, CpuProfile};
use wasmcop::valgrind::{Valgrind, find_runner};
use wasmcop_spec::module::{ImportItem, ModuleShape};
use wasmcop_spec::file::SpecFile;
use wasmcop_spec::resolve::{Options, TestCase};
use wasmcop_spec::syntax::{Statement, parse_call};

#[derive(Parser)]
#[command(name = "wasmcop", version, about = "Checks whether wasm code handles secrets in constant time")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(clap::Args)]
struct CheckArgs {
    /// A .wasm or .wat module, or a .toml spec file
    input: PathBuf,
    /// A function to call, like 'mac(tag: out(32), m: bytes(64), len(m), k: secret bytes(32))'
    #[arg(long = "call")]
    calls: Vec<String>,
    /// Only use these backends [default: all]
    #[arg(long, value_enum, value_delimiter = ',')]
    backend: Vec<Backend>,
    /// Only use these CPU profiles [default: avx2, or all with --full]
    #[arg(long, value_enum, value_delimiter = ',')]
    cpu: Vec<CpuProfile>,
    /// Try every optimization level and CPU profile
    #[arg(long)]
    full: bool,
    /// How many times to run each test, with different secrets [default: 4]
    #[arg(long)]
    iterations: Option<u32>,
    /// Seed for the test values [default: 1]
    #[arg(long)]
    seed: Option<u64>,
    /// Find out which secrets cause each finding
    #[arg(long)]
    blame: bool,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Use this Valgrind instead of searching for one
    #[arg(long)]
    valgrind: Option<PathBuf>,
    /// How many runs to do at once [default: one per CPU core]
    #[arg(long)]
    jobs: Option<usize>,
    /// Keep job files and Valgrind output here
    #[arg(long)]
    work_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Check functions for secret-dependent behavior
    Check(CheckArgs),
    /// Show a module's functions and what it needs
    List { module: PathBuf },
    /// Check that everything Wasmcop needs is installed
    Doctor {
        #[arg(long)]
        valgrind: Option<PathBuf>,
    },
}

fn list(path: &Path) -> Result<()> {
    let wasm = wasmcop::read_module(path)?;
    let shape = ModuleShape::parse(&wasm).with_context(|| path.display().to_string())?;
    println!("functions:");
    for (name, signature) in &shape.functions {
        println!("  {name}{signature}");
    }
    match shape.memory_binding() {
        Ok(_) => println!("memory: can use buffers"),
        Err(reason) => println!("memory: scalar arguments only, because {reason}"),
    }
    if !shape.imports.is_empty() {
        println!("imports:");
        for import in &shape.imports {
            match &import.item {
                ImportItem::Function(signature) => println!("  {}.{}{signature}", import.module, import.name),
                _ => println!("  {}.{}", import.module, import.name),
            }
        }
    }
    Ok(())
}

fn cells(args: &CheckArgs) -> Vec<Cell> {
    let backends: Vec<Backend> = if args.backend.is_empty() {
        Backend::ALL.into_iter().filter(|b| b.available()).collect()
    } else {
        args.backend.clone()
    };
    let cpus: Vec<CpuProfile> = match (args.cpu.is_empty(), args.full) {
        (false, _) => args.cpu.clone(),
        (true, true) => CpuProfile::ALL.to_vec(),
        (true, false) => vec![CpuProfile::Avx2],
    };
    if args.full {
        Cell::full(&backends, &cpus)
    } else {
        cpus.into_iter().flat_map(|cpu| Cell::defaults_on(&backends, cpu)).collect()
    }
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

/// What to run, from either a spec file or `--call` options.
fn load_tests(args: &CheckArgs) -> Result<(Vec<u8>, Vec<TestCase>, Options)> {
    let (wasm, tests, mut options) = if args.input.extension().is_some_and(|extension| extension == "toml") {
        if !args.calls.is_empty() {
            bail!("--call can't be combined with a spec file. Add the call to the file instead");
        }
        let file = SpecFile::load(&args.input)?;
        (wasmcop::read_module(&file.wasm)?, file.tests, file.options)
    } else {
        if args.calls.is_empty() {
            bail!("say what to call with --call 'function(arguments)', or use a .toml spec file");
        }
        (wasmcop::read_module(&args.input)?, tests_from_calls(&args.calls)?, Options::default())
    };
    options.seed = args.seed.unwrap_or(options.seed);
    options.iterations = args.iterations.unwrap_or(options.iterations);
    Ok((wasm, tests, options))
}

fn run_check(args: &CheckArgs) -> Result<ExitCode> {
    let (wasm, tests, options) = load_tests(args)?;
    if options.iterations == 0 {
        bail!("iterations must be at least 1");
    }
    let temp = tempfile::tempdir()?;
    let work_dir = args.work_dir.clone().unwrap_or_else(|| temp.path().to_path_buf());
    let jobs = args.jobs.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let settings = Settings { valgrind: Valgrind::find(args.valgrind.as_deref())?, runner: find_runner()?, work_dir, jobs, blame: args.blame };
    let report = check(&wasm, &tests, &options, &cells(args), &settings)?;
    match args.format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(ExitCode::from(report.exit_code()))
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Check(args) => run_check(&args),
        Command::List { module } => list(&module).map(|()| ExitCode::SUCCESS),
        Command::Doctor { valgrind } => {
            let (report, usable) = wasmcop::doctor::doctor(valgrind.as_deref());
            print!("{report}");
            Ok(if usable { ExitCode::SUCCESS } else { ExitCode::from(2) })
        }
    };
    result.unwrap_or_else(|e| {
        eprintln!("wasmcop: {e:#}");
        ExitCode::from(2)
    })
}
