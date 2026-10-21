mod support;

use support::*;
use wasmcop::compile::Backend;
use wasmcop_job::{Outcome, Report, Wasi, to_hex};
use wasmcop_spec::module::ModuleShape;
use wasmcop_spec::resolve::{Options, resolve};

const CLOCK_START: u64 = 1_700_000_000_000_000_000;

fn run_report(wasm: &[u8], script: &str, options: &Options) -> Report {
    let job = resolve(&test_case(script), &ModuleShape::parse(wasm).unwrap(), options).unwrap().job;
    let dir = scratch();
    let run = run_job(wasm, &default_cell(Backend::Cranelift), job, &dir);
    assert_eq!(run.report.error, None);
    run.report
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
