mod support;

use support::*;
use wasmcop::compile::{Backend, Cell};
use wasmcop_job::{Alloc, Arg, Buffer, Iteration, Outcome, SecretRange, Step};

fn cranelift() -> Cell {
    default_cell(Backend::Cranelift)
}

#[test]
fn reports_functions_and_libcall_symbols() {
    let dir = scratch();
    let steps = vec![secret_buffer(0, vec![0xa5; 32]), call("mem_copy_len", vec![Arg::Address(0)])];
    let run = execute(&fixture("basic.wat"), &cranelift(), vec![iteration(steps)], &dir);
    assert_eq!(run.report.iterations[0].outcome, Outcome::Completed);
    assert!(run.report.iterations[0].errors_per_call[0] > 0);
    assert!(!run.report.functions.is_empty());
    assert!(run.report.functions.iter().all(|f| f.address != 0 && f.length != 0));

    // Findings inside libcalls rely on this symbol being visible.
    let xml = std::fs::read_to_string(&run.xml).unwrap();
    assert!(xml.contains("<fn>wasmer_vm_memory32_copy</fn>"));
}

#[test]
fn traps_come_back_as_outcomes() {
    for backend in Backend::ALL {
        let dir = scratch();
        let trap = |name: &str| iteration(vec![secret_buffer(0, vec![0; 8]), call(name, vec![Arg::Address(0)])]);
        let iterations = vec![trap("trap_unreachable"), trap("trap_oob"), trap("trap_div0")];
        let run = execute(&fixture("basic.wat"), &default_cell(backend), iterations, &dir);
        let expected = [("unreachable", false), ("out of bounds", true), ("divide by zero", false)];
        for (iteration, (text, oob)) in run.report.iterations.iter().zip(expected) {
            assert!(matches!(&iteration.outcome, Outcome::Trap { message, out_of_bounds } if message.contains(text) && *out_of_bounds == oob), "{backend}: {:?}", iteration.outcome);
        }
    }
}

fn buffer(len: usize, align: u32, at: Option<u32>, secret: Vec<SecretRange>) -> Step {
    Step::Buffer(Buffer { slot: 0, data: vec![1; len], align, at, secret, public: true })
}

fn range(start: u32, end: u32) -> SecretRange {
    SecretRange { start, end, label: "key".to_string() }
}

#[test]
fn malformed_jobs_are_refused() {
    let wasm = fixture("basic.wat");
    let bounded = wat::parse_str(r#"(module (memory (export "memory") 1 1))"#).unwrap();
    let cases = [
        (&wasm, buffer(16, 16, None, vec![range(8, 4)]), "outside"),
        (&wasm, buffer(16, 16, None, vec![range(0, 17)]), "outside"),
        (&wasm, buffer(16, 16, Some(u32::MAX), vec![]), "outside"),
        (&wasm, buffer(16, 3, None, vec![]), "power of two"),
        (&wasm, buffer(16, 0, None, vec![]), "power of two"),
        (&bounded, buffer(16, 16, None, vec![]), "growing memory"),
    ];
    for (module, step, text) in cases {
        let dir = scratch();
        let run = execute_with(module, &cranelift(), vec![iteration(vec![step])], &dir, |_| {});
        let error = run.report.error.expect("should be refused");
        assert!(error.contains(text), "{error}");
    }
}

#[test]
fn arena_placement_stays_in_memory() {
    let dir = scratch();
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1)
             (func (export "malloc") (param i32) (result i32) (i32.const -16)))"#,
    )
    .unwrap();
    let iterations = vec![iteration(vec![buffer(64, 16, None, vec![])])];
    let run = execute_with(&wasm, &cranelift(), iterations, &dir, |job| job.alloc = Alloc::Malloc("malloc".to_string()));
    assert!(run.report.error.expect("should be refused").contains("outside"));

    let dir = scratch();
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1)
             (func (export "check") (param i32) (result i32)
               (if (i32.ne (local.get 0) (i32.const 0x80000000)) (then unreachable))
               (i32.const 0)))"#,
    )
    .unwrap();
    let steps = vec![buffer(16, 0x8000_0000, None, vec![]), call("check", vec![Arg::Address(0)])];
    let run = execute(&wasm, &cranelift(), vec![iteration(steps)], &dir);
    assert_eq!(run.report.iterations[0].outcome, Outcome::Completed);
}

#[test]
fn returned_secrets_count_as_output() {
    let one_call = |name: &str, arg: Arg, results: Vec<Option<usize>>| -> Iteration {
        iteration(vec![secret_buffer(0, vec![0xa5; 32]), Step::Call { function: name.to_string(), args: vec![arg], results }])
    };
    let dir = scratch();
    let iterations = vec![
        one_call("arg_ct", secret_i32(5), vec![None]),
        one_call("arg_ct", secret_i32(5), vec![Some(1)]),
        one_call("mem_mul64", Arg::Address(0), vec![None]),
        one_call("arg_ignored", secret_i32(5), vec![None]),
    ];
    let run = execute(&fixture("basic.wat"), &cranelift(), iterations, &dir);
    let tainted: Vec<bool> = run.report.iterations.iter().map(|i| i.output_tainted).collect();
    assert_eq!(tainted, [true, true, true, false]);
    assert!(run.report.iterations.iter().all(|i| i.errors_per_call[0] == 0));
}
