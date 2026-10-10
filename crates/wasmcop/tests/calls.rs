mod support;

use support::*;
use wasmcop::compile::Backend;
use wasmcop_job::{Outcome, Report};
use wasmcop_spec::module::ModuleShape;
use wasmcop_spec::resolve::resolve;

fn run_script(wasm: &[u8], script: &str) -> Report {
    let shape = ModuleShape::parse(wasm).unwrap();
    let resolved = resolve(&test_case(script), &shape, &options()).unwrap();
    let dir = scratch();
    let run = run_job(wasm, &default_cell(Backend::Cranelift), resolved.job, &dir);
    assert_eq!(run.report.error, None);
    assert_eq!(run.report.iterations[0].outcome, Outcome::Completed);
    run.report
}

/// Whether each call in the script produced a Valgrind error.
fn leaks(report: &Report) -> Vec<bool> {
    report.iterations[0].errors_per_call.iter().map(|errors| *errors > 0).collect()
}

#[test]
fn secret_scalars_of_every_type() {
    let script = "
        branch_i32(secret rand)
        branch_i64(secret 5)
        branch_f32(secret 1.5)
        branch_f64(secret rand)
        branch_v128(secret hex(000102030405060708090a0b0c0d0e0f))
        branch_i32(7)
        branch_i64(rand)
        branch_f32(1.5)
        branch_f64(2)
        branch_v128(hex(000102030405060708090a0b0c0d0e0f))
    ";
    let expected = [true, true, true, true, true, false, false, false, false, false];
    assert_eq!(leaks(&run_script(&fixture("args.wat"), script)), expected);
}

#[test]
fn buffers_lengths_and_expect() {
    let script = "
        total = out(4)
        data = hex(01020304)
        sum_into(total, data, len(data))
        expect(total, hex(0a000000))
        expect(total, hex(00000000))

        part = bytes(64, 1, secret=16..48)
        branch_at(part, 8)
        branch_at(part, 20)
        branch_at(part, 60)

        whole = secret bytes(8, ones, align=64)
        branch_at(whole, 0)
        pinned = bytes(4, at=1024)
        branch_at(pinned, 0)
    ";
    let report = run_script(&fixture("args.wat"), script);
    assert_eq!(leaks(&report), [false, false, true, false, true, false]);
    assert_eq!(report.iterations[0].expect_failures.len(), 1);
}

#[test]
fn taint_follows_bound_results_until_declassified() {
    let script = "
        x = identity(secret rand)
        branch_i32(x)
        declassify(x)
        branch_i32(x)
        a, b = pair(secret 5)
        branch_i32(b)
    ";
    assert_eq!(leaks(&run_script(&fixture("args.wat"), script)), [false, true, false, false, true]);
}
