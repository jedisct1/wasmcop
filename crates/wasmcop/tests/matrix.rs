mod support;

use std::collections::BTreeMap;
use support::*;
use wasmcop::classify::Class;
use wasmcop::compile::{Backend, Cell, CpuProfile};
use wasmcop::report::CellResult;

/// A script calling each function in basic.wat on a secret.
fn calls(names: &[&String]) -> String {
    names
        .iter()
        .map(|name| if name.starts_with("arg_") { format!("{name}(secret 0x12345678)\n") } else { format!("{name}(secret bytes(32, 0xa5))\n") })
        .collect()
}

fn check_on(wasm: &[u8], script: &str, cells: &[Cell]) -> Vec<CellResult> {
    check_with(wasm, script, cells, &options(), default_valgrind(), false).tests.remove(0).cells
}

#[test]
fn findings_match_the_expected_table() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/expect.toml")).unwrap();
    let table: BTreeMap<String, BTreeMap<String, [String; 3]>> = toml::from_str(&text).unwrap();
    let wasm = fixture("basic.wat");

    for (profile, rows) in &table {
        let cpu = match profile.as_str() {
            "avx2" => CpuProfile::Avx2,
            "sse42" => CpuProfile::Sse42,
            _ => CpuProfile::Baseline,
        };
        let names: Vec<&String> = rows.keys().collect();
        let results = check_on(&wasm, &calls(&names), &Cell::defaults_on(&Backend::ALL, cpu));
        for (column, result) in results.iter().enumerate() {
            assert_eq!(result.analysis.failures, Vec::<String>::new(), "{}", result.cell);
            for name in &names {
                let got = if result.skipped.is_some() { "skip".to_string() } else { classes_in(result, name) };
                assert_eq!(rows[*name][column], got, "{name} on {} {profile}", result.cell);
            }
        }
    }
}

#[test]
fn findings_point_at_the_right_place() {
    let names: Vec<String> = ["mem_branch_effect", "arg_branch", "mem_fselect", "mem_index", "mem_brtable", "mem_callind", "mem_copy_len"].map(String::from).to_vec();
    let script = calls(&names.iter().collect::<Vec<_>>());
    let results = check_on(&fixture("basic.wat"), &script, &Cell::defaults(&Backend::ALL));

    // Whatever the backend, the instruction at the reported offset has to fit the class.
    for result in &results {
        for finding in &result.analysis.findings {
            let instruction = finding.instruction.as_deref();
            let context = format!("{} {:?} on {}", finding.function, instruction, result.cell);
            match finding.class {
                Class::Branch => assert!(instruction.unwrap().starts_with('j'), "{context}"),
                Class::MemoryAddress => assert!(instruction.unwrap().contains('['), "{context}"),
                Class::JumpTarget => assert!(instruction.unwrap().starts_with("jmp"), "{context}"),
                Class::Libcall => assert!(finding.runtime_function.as_deref().is_some_and(|f| !f.is_empty()), "{context}"),
                other => panic!("unexpected {other:?}: {context}"),
            }
        }
    }

    let operator_of = |column: usize, function: &str, class: Class| {
        let finding = results[column].analysis.findings.iter().find(|f| f.function == function && f.class == class).unwrap();
        (finding.wasm_offset.is_some(), finding.operator.clone(), finding.compiler_introduced)
    };
    let cranelift = |function, class, operator: &str| (1, function, class, Some(operator.to_string()));
    for (column, function, class, operator) in [
        cranelift("mem_branch_effect", Class::Branch, "if"),
        cranelift("arg_branch", Class::Branch, "if"),
        cranelift("mem_fselect", Class::Branch, "select"),
        cranelift("mem_index", Class::MemoryAddress, "i32load8u"),
        cranelift("mem_brtable", Class::MemoryAddress, "brtable"),
        cranelift("mem_callind", Class::Branch, "callindirect"),
        cranelift("mem_copy_len", Class::Libcall, "memorycopy"),
        (0, "mem_index", Class::MemoryAddress, Some("i32load8u".to_string())),
    ] {
        let (mapped, got, _) = operator_of(column, function, class);
        assert!(mapped, "{function}");
        assert_eq!(got, operator, "{function}");
    }
    assert!(operator_of(1, "mem_fselect", Class::Branch).2, "a select isn't a branch in the wasm");
    assert!(!operator_of(1, "arg_branch", Class::Branch).2);

    // Singlepass has no mapping for its branches, and LLVM none at all.
    assert_eq!(operator_of(0, "arg_branch", Class::Branch), (false, None, false));
    assert!(results[2].analysis.findings.iter().all(|f| f.wasm_offset.is_none()));
}

#[test]
fn every_cell_of_the_full_matrix_works() {
    // A secret table lookup, which every backend and level has to report.
    let cells = Cell::full(&Backend::ALL, &CpuProfile::ALL);
    let results = check_on(&fixture("basic.wat"), "mem_index(secret bytes(32))", &cells);
    for (cell, result) in cells.iter().zip(&results) {
        match &result.skipped {
            None => {
                assert_eq!(result.analysis.failures, Vec::<String>::new(), "{cell}");
                assert_eq!(classes_in(result, "mem_index"), "memory-address", "{cell}");
            }
            Some(reason) => assert_eq!((cell.backend, cell.cpu), (Backend::Singlepass, CpuProfile::Baseline), "{reason}"),
        }
    }
}
