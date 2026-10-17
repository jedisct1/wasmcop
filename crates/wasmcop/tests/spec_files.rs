mod support;

use support::*;
use wasmcop::compile::{Backend, Cell};
use wasmcop::report::CheckReport;

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
