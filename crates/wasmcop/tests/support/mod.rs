#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use wasmcop::check::{Settings, check};
use wasmcop::compile::{self, Backend, Cell};
use wasmcop::report::CheckReport;
use wasmcop::valgrind::{Run, Valgrind, find_runner};
use wasmcop_job::{Alloc, Arg, Buffer, Iteration, Job, MemoryBinding, Poison, Scalar, SecretRange, Step, ValType};
use wasmcop_spec::resolve::{Options, TestCase};
use wasmcop_spec::syntax::parse_script;

pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name);
    wat::parse_file(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn scratch() -> TempDir {
    tempfile::tempdir().unwrap()
}

pub fn default_cell(backend: Backend) -> Cell {
    Cell::defaults(&[backend])[0]
}

pub fn options() -> Options {
    Options { iterations: 1, ..Options::default() }
}

pub fn test_case(script: &str) -> TestCase {
    TestCase { name: "t".to_string(), statements: parse_script(script).unwrap() }
}

pub fn default_valgrind() -> Valgrind {
    Valgrind::find(None).unwrap()
}

pub fn settings(dir: &TempDir, valgrind: Valgrind, blame: bool) -> Settings {
    Settings { valgrind, runner: find_runner().unwrap(), work_dir: dir.path().to_path_buf(), jobs: 4, blame }
}

pub fn check_with(wasm: &[u8], script: &str, cells: &[Cell], options: &Options, valgrind: Valgrind, blame: bool) -> CheckReport {
    let dir = scratch();
    check(wasm, &[test_case(script)], options, cells, &settings(&dir, valgrind, blame)).unwrap()
}

fn job(iterations: Vec<Iteration>) -> Job {
    Job {
        artifact: PathBuf::new(),
        output: PathBuf::new(),
        poison: Poison::All,
        memory: MemoryBinding::Exported("memory".to_string()),
        alloc: Alloc::Grow,
        imports: Vec::new(),
        iterations,
    }
}

pub fn secret_buffer(slot: usize, data: Vec<u8>) -> Step {
    let end = data.len() as u32;
    Step::Buffer(Buffer { slot, data, align: 16, at: None, secret: vec![SecretRange { start: 0, end, label: "key".to_string() }], public: false })
}

pub fn secret_i32(value: u32) -> Arg {
    Arg::Value { value: Scalar { ty: ValType::I32, bits: value as u128 }, secret: Some("key".to_string()) }
}

pub fn iteration(steps: Vec<Step>) -> Iteration {
    Iteration { label: "test".to_string(), steps }
}

pub fn call(function: &str, args: Vec<Arg>) -> Step {
    Step::Call { function: function.to_string(), args, results: vec![None] }
}

/// Compiles for `cell` and runs `job` under Valgrind.
pub fn run_job(wasm: &[u8], cell: &Cell, mut job: Job, dir: &TempDir) -> Run {
    let path = dir.path().join("module.wasmu");
    fs::write(&path, compile::compile(wasm, cell).expect("compiles")).unwrap();
    job.artifact = path;
    default_valgrind().run(&find_runner().expect("runner"), job, dir.path()).expect("runs")
}

pub fn execute_with(wasm: &[u8], cell: &Cell, iterations: Vec<Iteration>, dir: &TempDir, adjust: impl FnOnce(&mut Job)) -> Run {
    let mut job = job(iterations);
    adjust(&mut job);
    run_job(wasm, cell, job, dir)
}

pub fn execute(wasm: &[u8], cell: &Cell, iterations: Vec<Iteration>, dir: &TempDir) -> Run {
    let run = execute_with(wasm, cell, iterations, dir, |_| {});
    assert_eq!(run.report.error, None, "harness error");
    run
}
