mod support;

use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use support::*;
use wasmcop::compile::{Backend, Cell};
use wasmcop::report::CellResult;
use wasmcop_job::{Outcome, Report, Wasi, to_hex};
use wasmcop_spec::module::ModuleShape;
use wasmcop_spec::resolve::{Options, random_key, resolve};

const CLOCK_START: u64 = 1_700_000_000_000_000_000;

fn run_report(wasm: &[u8], script: &str, options: &Options) -> Report {
    let job = resolve(&test_case(script), &ModuleShape::parse(wasm).unwrap(), options).unwrap().job;
    let dir = scratch();
    let run = run_job(wasm, &default_cell(Backend::Cranelift), job, &dir);
    assert_eq!(run.report.error, None);
    run.report
}

fn cranelift(wasm: &[u8], script: &str) -> CellResult {
    clean_cells(wasm, script, &[Backend::Cranelift]).remove(0)
}

#[test]
fn wasi_follows_the_spec() {
    const OK: &str = "00000000";
    const BADF: &str = "08000000";
    const FAULT: &str = "15000000";
    const INVAL: &str = "1c000000";
    const SPIPE: &str = "46000000";

    let start = to_hex(&CLOCK_START.to_le_bytes());
    let second = to_hex(&(CLOCK_START + 1_000_000).to_le_bytes());
    let script = format!(
        "
        r = out(4)
        a = out(4)
        b = out(4)
        args_sizes(r, a, b)
        expect(r, hex({OK}))
        expect(a, hex(02000000))
        expect(b, hex(05000000))
        ptrs = out(8)
        text = out(5)
        args(r, ptrs, text)
        expect(r, hex({OK}))
        expect(text, hex(6100626300))
        environ_sizes(r, a, b)
        expect(a, hex(01000000))
        expect(b, hex(04000000))
        text2 = out(4)
        environ(r, ptrs, text2)
        expect(text2, hex(4b3d5600))

        t = out(8)
        clock_res(r, 0, t)
        expect(t, hex(40420f0000000000))
        clock_time(r, 0, t)
        expect(t, hex({start}))
        clock_time(r, 1, t)
        expect(t, hex({second}))
        clock_time(r, 9, t)
        expect(r, hex({INVAL}))
        clock_res(r, 9, t)
        expect(r, hex({INVAL}))
        clock_time(r, 0, 0xfffffff0)
        expect(r, hex({FAULT}))

        stat = out(24)
        fdstat(r, 1, stat)
        expect(r, hex({OK}))
        expect(stat, hex(020000000000000040000008000000000000000000000000))
        fdstat(r, 0, stat)
        expect(stat, hex(020000000000000002000008000000000000000000000000))
        fdstat(r, 3, stat)
        expect(r, hex({BADF}))

        prestat(r, 0, t)
        expect(r, hex({BADF}))
        prestat_dir(r, 0, t, 8)
        expect(r, hex({BADF}))

        seek(r, 1, 0, t)
        expect(r, hex({SPIPE}))
        seek(r, 9, 0, t)
        expect(r, hex({BADF}))
        seek(r, 1, 9, t)
        expect(r, hex({INVAL}))

        message = hex(68690a)
        n = out(4)
        write(r, 1, message, len(message), n)
        expect(r, hex({OK}))
        expect(n, hex(03000000))
        write(r, 0, message, len(message), n)
        expect(r, hex({BADF}))
        write(r, 2, 0xfffffff0, 8, n)
        expect(r, hex({FAULT}))
        write(r, 2, message, len(message), 0xfffffff0)
        expect(r, hex({FAULT}))
        write_bad_iovs(r, 2, message, len(message), n)
        expect(r, hex({FAULT}))

        close(r, 2)
        expect(r, hex({OK}))
        write(r, 2, message, len(message), n)
        expect(r, hex({BADF}))
        close(r, 2)
        expect(r, hex({BADF}))
        close(r, 5)
        expect(r, hex({BADF}))

        buf = out(8)
        random(r, buf, 0)
        expect(r, hex({OK}))
        random(r, 0xfffffff0, 32)
        expect(r, hex({FAULT}))
        random(r, 0, 0xffffffff)
        expect(r, hex({FAULT}))
        "
    );

    let wasi = Wasi { args: vec!["a".to_string(), "bc".to_string()], env: vec![("K".to_string(), "V".to_string())] };
    let report = run_report(&fixture("wasi.wat"), &script, &Options { wasi, ..options() });
    assert_eq!(report.iterations[0].outcome, Outcome::Completed);
    assert_eq!(report.iterations[0].expect_failures, Vec::<String>::new());
    assert_eq!(run_report(&fixture("wasi.wat"), "exit(3)", &options()).iterations[0].outcome, Outcome::Exit(3));
}

#[test]
fn output_checks() {
    let print = fixture("print.wat");
    assert_eq!(classes_in(&cranelift(&print, "data = secret bytes(8)\nprint(data, 8)"), "fd_write"), "check");
    assert!(cranelift(&print, "data = bytes(8)\nprint(data, 8)").analysis.findings.is_empty());

    // A bad result pointer has to stop fd_write before it looks at the data.
    let script = "r = out(4)\ndata = secret bytes(8)\nwrite(r, 1, data, 8, 0xfffffff0)\nexpect(r, hex(15000000))";
    assert!(cranelift(&fixture("wasi.wat"), script).analysis.findings.is_empty());
}

#[test]
fn random_get_output_is_secret_unless_told_otherwise() {
    let wasm = fixture("wasi.wat");
    assert_eq!(classes_in(&cranelift(&wasm, "keygen()"), "keygen"), "branch");

    let public = Options { secret_random: false, ..options() };
    let cells = check_with(&wasm, "keygen()", &Cell::defaults(&[Backend::Cranelift]), &public, default_valgrind(), false).tests.remove(0).cells;
    assert!(assert_clean(cells)[0].analysis.findings.is_empty());
}

#[test]
fn the_module_can_mark_and_clear_secrets_itself() {
    let wasm = fixture("annotated.wat");
    assert_eq!(cranelift(&wasm, "declassify_part(secret bytes(16, 1))").analysis.findings.len(), 1);
    assert!(!cranelift(&wasm, "self_poison(bytes(16, 1))").analysis.findings.is_empty());
    assert_eq!(classes_in(&cranelift(&wasm, "check_public(secret bytes(16, 1))"), "assert_public"), "check");
    assert!(cranelift(&wasm, "check_public(bytes(16, 1))").analysis.findings.is_empty());
    assert!(cranelift(&wasm, "scalars(secret bytes(16, 1))").analysis.findings.is_empty());

    let report = run_report(&wasm, "bad_range()", &options());
    assert!(matches!(&report.iterations[0].outcome, Outcome::Trap { message, .. } if message.contains("outside linear memory")), "{:?}", report.iterations[0].outcome);
}

#[test]
fn replays_see_the_same_randomness_and_clock() {
    let wasm = fixture("wasi.wat");
    let backends = [Backend::Cranelift, Backend::Llvm];

    let mut expected = [0u8; 16];
    ChaCha20Rng::from_seed(random_key(1, "t", 0)).fill_bytes(&mut expected);
    let script = format!("r = out(4)\nb = out(16)\nrandom(r, b, 16)\ndeclassify(b)\nexpect(b, hex({}))", to_hex(&expected));
    clean_cells(&wasm, &script, &backends);

    // The branch on the secret is only reached if the clock has the same fixed value in every run.
    for cell in clean_cells(&wasm, "clock_dependent(secret bytes(8, 1))", &backends) {
        assert_eq!(classes_in(&cell, "clock_dependent"), "branch", "{}", cell.cell);
    }
}
