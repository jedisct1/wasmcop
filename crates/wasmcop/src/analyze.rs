use crate::classify::{Class, Disposition, classify};
use crate::code::{CodeMap, Owner, format_instruction};
use crate::source::SourceInfo;
use crate::xml::{ValgrindError, ValgrindOutput};
use serde::Serialize;
use std::collections::BTreeMap;
use wasmcop_job::{Outcome, Report};

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
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    /// Reasons the results can't be trusted, or are incomplete.
    pub failures: Vec<String>,
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
            analysis.failures.push(format!("Valgrind reported something outside the generated code: {}", describe_host(error)));
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

    fn report_with(outcome: Outcome, _tainted: bool) -> Report {
        Report {
            functions: vec![FunctionExtent { local_index: 0, address: 0x1000, length: 16 }],
            iterations: vec![IterationReport {
                label: "l".to_string(),
                errors_per_call: Vec::new(),
                outcome,
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
}
