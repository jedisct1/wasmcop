use crate::analyze::{Analysis, Finding};
use crate::classify::Class;
use crate::code::Owner;
use crate::compile::Cell;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, Serialize)]
pub struct CellResult {
    pub cell: String,
    pub skipped: Option<String>,
    pub analysis: Analysis,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub name: String,
    pub cells: Vec<CellResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub tests: Vec<TestResult>,
}

pub const EXIT_CLEAN: u8 = 0;
pub const EXIT_FINDINGS: u8 = 1;
pub const EXIT_FAILED: u8 = 2;

impl CheckReport {
    pub fn exit_code(&self) -> u8 {
        let cells = || self.tests.iter().flat_map(|t| &t.cells);
        let ran_nothing = self.tests.iter().any(|t| t.cells.iter().all(|c| c.skipped.is_some()));
        if ran_nothing || cells().any(|c| !c.analysis.failures.is_empty()) {
            EXIT_FAILED
        } else if cells().any(|c| !c.analysis.findings.is_empty()) {
            EXIT_FINDINGS
        } else {
            EXIT_CLEAN
        }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for test in &self.tests {
            write_test(&mut out, test);
        }
        out
    }
}

/// Short names when every cell is a different backend, otherwise the full cell.
pub fn cell_labels(cells: &[Cell]) -> Vec<String> {
    let mut backends: Vec<_> = cells.iter().map(|c| c.backend).collect();
    backends.sort();
    backends.dedup();
    if backends.len() == cells.len() {
        cells.iter().map(|c| c.backend.to_string()).collect()
    } else {
        cells.iter().map(Cell::to_string).collect()
    }
}

fn write_test(out: &mut String, test: &TestResult) {
    let _ = writeln!(out, "{}", test.name);
    write_table(out, test);

    for cell in &test.cells {
        if let Some(reason) = &cell.skipped {
            let _ = writeln!(out, "  {}: skipped: {reason}", cell.cell);
        }
        for failure in &cell.analysis.failures {
            let _ = writeln!(out, "  {}: FAILED: {failure}", cell.cell);
        }
    }
    write_findings(out, test);
    out.push('\n');
}

fn write_table(out: &mut String, test: &TestResult) {
    let ran: Vec<&CellResult> = test.cells.iter().filter(|c| c.skipped.is_none()).collect();
    let classes: Vec<Class> = Class::ALL
        .into_iter()
        .filter(|class| ran.iter().any(|c| c.analysis.findings.iter().any(|f| f.class == *class)))
        .collect();
    if classes.is_empty() {
        if !ran.is_empty() && ran.iter().all(|c| c.analysis.failures.is_empty()) {
            let _ = writeln!(out, "  no findings");
        }
        return;
    }
    let _ = write!(out, "  {:18}", "");
    for cell in &ran {
        let _ = write!(out, "{:>width$}", cell.cell, width = cell.cell.len().max(5) + 2);
    }
    out.push('\n');
    for class in classes {
        let _ = write!(out, "  {:18}", class.name());
        for cell in &ran {
            let count = cell.analysis.findings.iter().filter(|f| f.class == class).count();
            let _ = write!(out, "{count:>width$}", width = cell.cell.len().max(5) + 2);
        }
        out.push('\n');
    }
    out.push('\n');
}

/// Where a finding happened.
/// Ones that can point at the wasm come first, since they're the most useful.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Place {
    Wasm(u32),
    /// With no wasm offset there is nothing to line findings up on, so they stay per cell.
    Native { cell: String, offset: u64 },
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    class: Class,
    owner: Owner,
    place: Place,
}

fn write_findings(out: &mut String, test: &TestResult) {
    let mut groups: BTreeMap<GroupKey, Vec<(&str, &Finding)>> = BTreeMap::new();
    for cell in &test.cells {
        for finding in &cell.analysis.findings {
            let place = match finding.wasm_offset {
                Some(offset) => Place::Wasm(offset),
                None => Place::Native { cell: cell.cell.clone(), offset: finding.native_offset },
            };
            groups.entry(GroupKey { class: finding.class, owner: finding.owner.clone(), place }).or_default().push((&cell.cell, finding));
        }
    }

    for (key, findings) in groups {
        write_group(out, &key, &findings);
    }
}

fn write_group(out: &mut String, key: &GroupKey, findings: &[(&str, &Finding)]) {
    let first = findings[0].1;
    let _ = write!(out, "  {} in {}", key.class.name().to_uppercase(), first.function);
    match (&key.place, &key.owner) {
        (Place::Wasm(offset), _) => {
            let _ = write!(out, " at wasm {offset:#x}");
        }
        (Place::Native { offset, .. }, Owner::Function(_)) => {
            let _ = write!(out, " +{offset:#x}");
        }
    }
    if let Some(source) = &first.source {
        let _ = write!(out, " ({source})");
    }
    let cells: Vec<&str> = findings.iter().map(|(cell, _)| *cell).collect();
    let _ = writeln!(out, " [{}]", cells.join(", "));
    if let Some(explanation) = key.class.explanation() {
        let _ = writeln!(out, "    {explanation}");
    }
    if key.class == Class::Unclassified {
        let _ = writeln!(out, "    {}: {}", first.kind, first.what);
    }
    for (cell, finding) in findings {
        match (&finding.instruction, &finding.runtime_function) {
            (Some(instruction), _) => {
                let _ = writeln!(out, "    {cell}: {instruction}");
            }
            (None, Some(function)) => {
                let _ = writeln!(out, "    {cell}: in {function}");
            }
            (None, None) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_with(analysis: Analysis, skipped: Option<&str>) -> CheckReport {
        CheckReport {
            tests: vec![TestResult {
                name: "t".to_string(),
                cells: vec![CellResult { cell: "cranelift".to_string(), skipped: skipped.map(str::to_string), analysis }],
            }],
        }
    }

    fn finding(class: Class) -> Finding {
        Finding::sample(class)
    }

    #[test]
    fn text_output() {
        let mut same_name = finding(Class::Branch);
        same_name.owner = Owner::Function(1);
        let text = test_with(Analysis { findings: vec![finding(Class::Branch), same_name], ..Analysis::default() }, None).to_text();
        assert_eq!(text.matches("BRANCH in f").count(), 2, "{text}");

        let mut strange = finding(Class::Unclassified);
        strange.kind = "Overlap".to_string();
        strange.what = "source and destination overlap".to_string();
        let text = test_with(Analysis { findings: vec![strange], ..Analysis::default() }, None).to_text();
        assert!(text.contains("Overlap: source and destination overlap"), "{text}");
    }

    #[test]
    fn exit_codes() {
        let clean = Analysis::default();
        let findings = Analysis { findings: vec![finding(Class::Branch)], ..Analysis::default() };
        let failed = Analysis { failures: vec!["x".to_string()], ..Analysis::default() };
        assert_eq!(test_with(clean.clone(), None).exit_code(), EXIT_CLEAN);
        assert_eq!(test_with(findings.clone(), None).exit_code(), EXIT_FINDINGS);
        assert_eq!(test_with(failed.clone(), None).exit_code(), EXIT_FAILED);
        assert_eq!(test_with(clean, Some("no")).exit_code(), EXIT_FAILED);

        let mut both = test_with(findings, None);
        both.tests[0].cells.push(CellResult { cell: "llvm".to_string(), skipped: None, analysis: failed });
        assert_eq!(both.exit_code(), EXIT_FAILED);
    }
}
