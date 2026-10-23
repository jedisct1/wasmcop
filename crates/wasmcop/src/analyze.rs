use crate::classify::{Class, Disposition, classify};
use crate::code::{CodeMap, Owner, format_instruction};
use crate::source::SourceInfo;
use crate::xml::{ValgrindError, ValgrindOutput};
use serde::Serialize;
use std::collections::BTreeMap;
use wasmcop_job::{BUILTINS, Outcome, Report};

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub class: Class,
    pub owner: Owner,
    pub function: String,
    pub native_offset: u64,
    /// The native instruction, unless the problem was inside a runtime function.
    pub instruction: Option<String>,
    pub wasm_offset: Option<u32>,
    pub operator: Option<String>,
    pub source: Option<String>,
    pub runtime_function: Option<String>,
    pub occurrences: u64,
    pub kind: String,
    pub what: String,
    /// With `--blame`, the secrets that cause this finding on their own.
    pub reached_from: Vec<String>,
}

impl Finding {
    fn new(class: Class, owner: Owner, function: String, error: &ValgrindError) -> Finding {
        Finding {
            class,
            owner,
            function,
            native_offset: 0,
            instruction: None,
            wasm_offset: None,
            operator: None,
            source: None,
            runtime_function: None,
            occurrences: 0,
            kind: error.kind.clone(),
            what: error.what.clone(),
            reached_from: Vec::new(),
        }
    }

    /// Whether two findings from different runs of the same code are the same one.
    pub fn same_site(&self, other: &Finding) -> bool {
        self.class == other.class && self.owner == other.owner && self.native_offset == other.native_offset
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    /// Reasons the results can't be trusted, or are incomplete.
    pub failures: Vec<String>,
    /// A `--blame` run failed, so a finding with no secret credited may just be unknown.
    pub blame_failed: bool,
    pub warnings: Vec<String>,
}

fn trapped_out_of_bounds(report: &Report) -> bool {
    report.iterations.iter().any(|i| matches!(i.outcome, Outcome::Trap { out_of_bounds: true, .. }))
}

fn run_failures(report: &Report, failures: &mut Vec<String>) {
    if let Some(error) = &report.error {
        failures.push(format!("the harness failed: {error}"));
    }
    for iteration in &report.iterations {
        match &iteration.outcome {
            Outcome::Completed => {}
            Outcome::Trap { message, .. } => failures.push(format!("iteration {}: trapped {message}", iteration.label)),
            Outcome::Exit(code) => failures.push(format!("iteration {}: the module exited with status {code}", iteration.label)),
        }
        for failure in &iteration.expect_failures {
            failures.push(format!("iteration {}: {failure}", iteration.label));
        }
    }
}

fn describe_host(error: &ValgrindError) -> String {
    let function = error.frames.iter().find_map(|f| f.function.as_deref()).unwrap_or("unknown code");
    format!("{}: {} in {function}", error.kind, error.what)
}

/// Turns Valgrind's errors into findings for one cell.
pub fn analyze(output: &ValgrindOutput, code: &CodeMap, report: &Report, source: &SourceInfo) -> Analysis {
    let mut analysis = Analysis::default();
    run_failures(report, &mut analysis.failures);
    let trapped = trapped_out_of_bounds(report);
    let mut merged: BTreeMap<(Class, Owner, u64), Finding> = BTreeMap::new();

    for error in &output.errors {
        let inner = error.frames.first().and_then(|f| code.locate(f.ip));
        let instruction = inner.and_then(|(function, offset)| function.decode(offset));
        let class = match classify(&error.kind, &error.what, inner.is_none(), instruction.as_ref()) {
            Disposition::GuardPage => {
                if !trapped {
                    analysis.failures.push(format!("unexpected invalid memory access: {}", describe_host(error)));
                }
                continue;
            }
            Disposition::Finding(class) => class,
        };

        // For a problem inside a runtime function, report the generated code that called it.
        let Some((function, offset)) = inner.or_else(|| error.frames.iter().find_map(|f| code.locate(f.ip))) else {
            // Imports run on the host's stack, so Valgrind can't see the wasm code that called them.
            match import_name(error) {
                Some(name) => {
                    let owner = Owner::Import(name.clone());
                    let finding = merged.entry((class, owner.clone(), 0)).or_insert_with(|| Finding { runtime_function: Some(name.clone()), ..Finding::new(class, owner, name, error) });
                    finding.occurrences += error.count;
                }
                None => analysis.failures.push(format!("Valgrind reported something outside the generated code: {}", describe_host(error))),
            }
            continue;
        };

        let owner = Owner::Function(function.wasm_index);
        let finding = merged.entry((class, owner.clone(), offset)).or_insert_with(|| {
            let wasm_offset = function.wasm_offset(offset);
            let operator = wasm_offset.and_then(|o| source.operator(o));
            // Tail calls can hide wasmer's own function, so fall back on whatever is named.
            let runtime_function = inner.is_none().then(|| {
                let mut names = error.frames.iter().filter_map(|f| f.function.as_deref());
                names.clone().find(|n| n.contains("wasmer_vm_")).or_else(|| names.next()).map(str::to_string)
            });
            Finding {
                native_offset: offset,
                instruction: instruction.as_ref().map(format_instruction),
                wasm_offset,
                operator,
                runtime_function: runtime_function.flatten(),
                ..Finding::new(class, owner, function.name.clone(), error)
            }
        });
        finding.occurrences += error.count;
    }

    analysis.findings = merged.into_values().collect();
    analysis.failures.sort();
    analysis.failures.dedup();
    analysis
}

/// Warns about a test that has secrets but never seems to have used them.
pub fn warn_if_vacuous(analysis: &mut Analysis, report: &Report) {
    let quiet = analysis.findings.is_empty() && analysis.failures.is_empty();
    if quiet && !report.iterations.iter().any(|i| i.output_tainted) {
        analysis.warnings.push("no secret reached any output. Check that the call really uses the secret".to_string());
    }
}

/// The name of the import the runner was inside, if any.
fn import_name(error: &ValgrindError) -> Option<String> {
    const MODULE: &str = "wasmcop_runner::wasi::";
    let is_import = |name: &&str| BUILTINS.iter().any(|builtin| builtin.name == *name);
    error.frames.iter().filter_map(|f| f.function.as_deref()).find_map(|text| {
        let matches = text.match_indices(MODULE).map(|(at, _)| &text[at + MODULE.len()..]);
        let names = matches.filter_map(|rest| rest.split(|c: char| !(c.is_alphanumeric() || c == '_')).next());
        names.filter(is_import).last().map(str::to_string)
    })
}

/// The two runs only differ in what's poisoned, so errors here can't come from a secret and mean the harness is noisy.
pub fn baseline_failures(output: &ValgrindOutput, report: &Report) -> Vec<String> {
    let mut failures = Vec::new();
    run_failures(report, &mut failures);
    let trapped = trapped_out_of_bounds(report);
    for error in &output.errors {
        if trapped && classify(&error.kind, &error.what, true, None) == Disposition::GuardPage {
            continue;
        }
        failures.push(format!("the run with no secrets still reported: {}", describe_host(error)));
    }
    failures
}

#[cfg(test)]
impl Finding {
    pub fn sample(class: Class) -> Finding {
        let error = ValgrindError { kind: "UninitCondition".to_string(), what: "x".to_string(), count: 1, frames: Vec::new() };
        Finding { native_offset: 4, instruction: Some("je short 0".to_string()), occurrences: 1, ..Finding::new(class, Owner::Function(0), "f".to_string(), &error) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::CodeFunction;
    use crate::xml::Frame;
    use wasmcop_job::{FunctionExtent, IterationReport};

    const BODY: [u8; 16] = [0x74, 0x05, 0x8b, 0x04, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];

    fn function(wasm_index: u32, address: u64) -> CodeFunction<'static> {
        CodeFunction { wasm_index, name: "f".to_string(), address, length: 16, body: &BODY, wasm_map: &[] }
    }

    fn map() -> CodeMap<'static> {
        CodeMap { functions: vec![function(0, 0x1000), function(1, 0x2000)] }
    }

    fn secret_error(kind: &str, frames: &[(u64, Option<&str>)], count: u64) -> ValgrindError {
        ValgrindError {
            kind: kind.to_string(),
            what: "x".to_string(),
            count,
            frames: frames.iter().map(|(ip, f)| Frame { ip: *ip, function: f.map(str::to_string) }).collect(),
        }
    }

    fn report_with(outcome: Outcome, tainted: bool) -> Report {
        Report {
            functions: vec![FunctionExtent { local_index: 0, address: 0x1000, length: 16 }],
            iterations: vec![IterationReport {
                label: "l".to_string(),
                errors_per_call: Vec::new(),
                outcome,
                output_tainted: tainted,
                expect_failures: Vec::new(),
            }],
            error: None,
        }
    }

    fn out_of_bounds() -> Outcome {
        Outcome::Trap { message: "out of bounds memory access".to_string(), out_of_bounds: true }
    }

    fn run(errors: Vec<ValgrindError>, report: &Report) -> Analysis {
        let wasm = wat::parse_str("(module)").unwrap();
        analyze(&ValgrindOutput { errors }, &map(), report, &SourceInfo::new(&wasm))
    }

    #[test]
    fn libcall_errors_collapse_onto_the_calling_code() {
        let frames = |depth: u64| vec![(0x9000 + depth, Some("memcpy")), (0x8000, Some("wasmer_vm_memory32_copy")), (0x1002, None)];
        let tail_called = vec![(0x9000, Some("memmove")), (0x1002, None)];
        let errors = vec![
            secret_error("UninitCondition", &frames(0), 2),
            secret_error("UninitCondition", &frames(1), 3),
            secret_error("UninitValue", &tail_called, 1),
        ];
        let analysis = run(errors, &report_with(Outcome::Completed, true));
        assert_eq!(analysis.findings.len(), 1);
        let finding = &analysis.findings[0];
        assert_eq!((finding.class, finding.native_offset, finding.occurrences), (Class::Libcall, 2, 6));
        assert_eq!(finding.runtime_function.as_deref(), Some("wasmer_vm_memory32_copy"));
        assert!(analysis.failures.is_empty());
    }

    #[test]
    fn problems_with_the_run_are_failures_not_findings() {
        let completed = report_with(Outcome::Completed, true);
        let outside = secret_error("UninitCondition", &[(0x9000, Some("main"))], 1);
        let guard = secret_error("InvalidRead", &[(0x1002, None)], 1);

        for error in [outside, guard.clone()] {
            let analysis = run(vec![error], &completed);
            assert!(analysis.findings.is_empty() && analysis.failures.len() == 1, "{analysis:?}");
        }

        // A guard page hit is expected when the trap follows, but the trap itself still fails the run.
        let trapped = report_with(out_of_bounds(), false);
        let analysis = run(vec![guard], &trapped);
        assert_eq!(analysis.failures.len(), 1);
        assert!(analysis.failures[0].contains("trapped"));
    }

    #[test]
    fn functions_with_the_same_name_stay_separate() {
        let errors = vec![secret_error("UninitCondition", &[(0x1000, None)], 1), secret_error("UninitCondition", &[(0x2000, None)], 1)];
        let analysis = run(errors, &report_with(Outcome::Completed, true));
        assert_eq!(analysis.findings.iter().map(|f| f.owner.clone()).collect::<Vec<_>>(), [Owner::Function(0), Owner::Function(1)]);
    }

    #[test]
    fn imports_are_named_because_their_callers_are_invisible() {
        let wrapper = |import: &str| format!("on_stack::wrapper::<func_wrapper<wasmcop_runner::wasi::Host, i32, wasmcop_runner::wasi::BadRange, wasmcop_runner::wasi::{import}>>");
        let helper = "wasmcop_runner::wasi::guest_pointer";
        let (write, public) = (wrapper("fd_write"), wrapper("assert_public"));
        let errors = vec![
            secret_error("ClientCheck", &[(0x9000, Some(helper)), (0x9100, Some(&write))], 2),
            secret_error("ClientCheck", &[(0x9000, Some(helper)), (0x9100, Some(&public))], 1),
        ];
        let analysis = run(errors, &report_with(Outcome::Completed, true));
        assert_eq!(analysis.failures, Vec::<String>::new());
        let found: Vec<_> = analysis.findings.iter().map(|f| (f.class, f.function.as_str(), f.occurrences)).collect();
        assert_eq!(found, [(Class::Check, "assert_public", 1), (Class::Check, "fd_write", 2)]);
    }

    #[test]
    fn vacuous_runs_warn() {
        let warnings = |errors, tainted| {
            let report = report_with(Outcome::Completed, tainted);
            let mut analysis = run(errors, &report);
            warn_if_vacuous(&mut analysis, &report);
            analysis.warnings
        };
        assert!(warnings(Vec::new(), false)[0].contains("no secret"));
        assert!(warnings(Vec::new(), true).is_empty());
        assert!(warnings(vec![secret_error("UninitCondition", &[(0x1000, None)], 1)], false).is_empty());
    }

    #[test]
    fn baseline_only_tolerates_guard_pages_when_trapped() {
        let guard = secret_error("InvalidRead", &[(0x1002, None)], 1);
        let completed = report_with(Outcome::Completed, false);
        let output = ValgrindOutput { errors: vec![guard] };
        assert_eq!(baseline_failures(&output, &completed).len(), 1);
        let trapped = report_with(out_of_bounds(), false);
        assert_eq!(baseline_failures(&output, &trapped).len(), 1);
        assert!(baseline_failures(&output, &trapped)[0].contains("trapped"));
    }
}
