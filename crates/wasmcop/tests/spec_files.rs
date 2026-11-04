mod support;

use std::path::Path;
use std::process::Command;
use support::*;
use wasmcop::compile::{Backend, Cell};
use wasmcop::report::CheckReport;
use wasmcop_job::Job;
use wasmcop_spec::resolve::random_key;

fn run(script: &str, blame: bool) -> CheckReport {
    let report = check_with(&fixture("stream.wat"), script, &Cell::defaults(&[Backend::Cranelift]), &options(), default_valgrind(), blame);
    assert_eq!(report.tests[0].cells[0].analysis.failures, Vec::<String>::new());
    report
}

#[test]
fn taint_survives_between_steps() {
    let steps = "state = out(8)\nkey = secret bytes(8, 1)\ntag = out(8)\ninit(state, key)\nupdate(state)\nfinish(state, tag)\n";
    let report = run(&format!("{steps}branch_on(tag)"), false);
    assert_eq!(report.tests[0].cells[0].analysis.findings.len(), 1);
    let report = run(&format!("{steps}declassify(tag)\nbranch_on(tag)"), false);
    assert!(report.tests[0].cells[0].analysis.findings.is_empty());
}

#[test]
fn a_call_that_ignores_its_secret_gets_a_warning() {
    let report = run("early_exit(secret bytes(16), 16)", false);
    assert!(report.tests[0].cells[0].analysis.warnings[0].contains("no secret reached"));
    let report = run("early_exit(secret bytes(32), 32)", false);
    assert!(report.tests[0].cells[0].analysis.warnings.is_empty());
}

#[test]
fn blame_names_the_secret_or_says_it_cant() {
    let report = run("only_first(a: secret 1, b: secret 1)", true);
    assert_eq!(report.tests[0].cells[0].analysis.findings[0].reached_from, ["a"]);
    assert!(report.to_text().contains("reached from: a"));

    // Each zero hides the other when only one of them is poisoned, whether they're arguments, separate calls or separate poison steps.
    let separately_poisoned = "x = bytes(4, zero)\npoison(x)\nfirst = x\nx = bytes(4, zero)\npoison(x)\nbranch_on_and(first, x)";
    for script in ["both(a: secret 0, b: secret 0)", "put(0, secret 0)\nput(4, secret 0)\nbranch_on_stored_and()", separately_poisoned] {
        let report = run(script, true);
        let findings = &report.tests[0].cells[0].analysis.findings;
        assert_eq!(findings.len(), 1, "{script}: the finding has to stay in the report");
        assert_eq!(findings[0].reached_from, Vec::<String>::new(), "{script}");
        assert!(report.to_text().contains("may take several together"));
    }
}

#[test]
fn spec_files_from_the_command_line() {
    let spec = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/stream.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_wasmcop")).arg("check").arg(&spec).args(["--backend", "cranelift"]).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("streaming") && text.contains("BRANCH in branch_on"), "{text}");
    assert!(text.contains("wrong length") && text.contains("no secret reached"), "{text}");

    let misuse = Command::new(env!("CARGO_BIN_EXE_wasmcop")).arg("check").arg(&spec).args(["--call", "f()"]).output().unwrap();
    assert_eq!(misuse.status.code(), Some(2));

    // The command line wins over the file, which asks for 2 iterations.
    let dir = scratch();
    Command::new(env!("CARGO_BIN_EXE_wasmcop")).arg("check").arg(&spec).args(["--backend", "cranelift", "--iterations", "1", "--seed", "9", "--work-dir"]).arg(dir.path()).output().unwrap();
    let job: Job = serde_json::from_slice(&std::fs::read(dir.path().join("test-0/cranelift-Speed-avx2/main/job.json")).unwrap()).unwrap();
    assert_eq!(job.iterations.len(), 1);
    assert_eq!(job.iterations[0].random_key, random_key(9, "streaming", 0));
}
