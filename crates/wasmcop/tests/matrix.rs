mod support;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use std::collections::BTreeMap;
use std::process::Command;
use support::*;
use wasmcop::check::compile_cell;
use wasmcop::classify::Class;
use wasmcop::compile::{Backend, Cell, CpuProfile};
use wasmcop::report::CellResult;
use wasmcop_spec::module::ModuleShape;

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
fn the_reported_site_is_the_secret_one() {
    let wasm = fixture("sites.wat");
    let shape = ModuleShape::parse(&wasm).unwrap();
    let script = "site_branch(secret bytes(4, 1), 1)\nsite_load(secret bytes(4, 1))";
    let cells = Cell::defaults(&Backend::ALL);

    for (cell, result) in cells.iter().zip(assert_clean(check_on(&wasm, script, &cells))) {
        let compiled = compile_cell(&wasm, cell, 0).unwrap().unwrap();

        // Decoded here without the classifier, so a wrong join can't agree with itself.
        let walk = |name: &str| -> Vec<(u64, Instruction)> {
            let mut decoder = Decoder::with_ip(64, compiled.code.function_body(&shape, name).unwrap(), 0, DecoderOptions::NONE);
            let mut instructions = Vec::new();
            while decoder.can_decode() {
                let offset = decoder.ip();
                instructions.push((offset, decoder.decode()));
            }
            instructions
        };
        let branch = result.analysis.findings.iter().find(|f| f.function == "site_branch").expect("a branch");
        let branches: Vec<u64> = walk("site_branch").iter().filter(|(_, i)| i.flow_control() == FlowControl::ConditionalBranch).map(|(o, _)| *o).collect();
        assert!(branches.len() >= 3, "{}: {branches:?}", result.cell);
        assert_eq!(branch.native_offset, branches[1], "{}: the middle branch is the secret one", result.cell);

        let load = result.analysis.findings.iter().find(|f| f.function == "site_load").expect("a load");
        let instruction = load.instruction.as_deref().unwrap();
        assert!(walk("site_load").iter().any(|(o, _)| *o == load.native_offset), "{}: not an instruction boundary", result.cell);
        assert!(!instruction.contains("0x800") && !instruction.contains("0x808"), "{}: {instruction} is a public load", result.cell);
    }
}

#[test]
fn source_lines_come_from_dwarf() {
    let results = check_on(&fixture("dwarf.wasm"), "leak(secret bytes(8))", &Cell::defaults(&[Backend::Cranelift]));
    let finding = results[0].analysis.findings.iter().find(|f| f.class == Class::Branch).unwrap();
    assert_eq!(finding.function, "leak");
    assert!(finding.source.as_deref().unwrap().ends_with("dwarf.c:2"), "{:?}", finding.source);
}

#[test]
fn a_secret_simd_shift_count_means_the_analysis_is_incomplete() {
    let results = check_on(&fixture("simd.wat"), "shift_by_secret(secret bytes(4, 1))", &Cell::defaults(&Backend::ALL));
    assert!(results[0].skipped.as_deref().is_some_and(|reason| !reason.is_empty()), "singlepass can't compile SIMD, and that must only lose its own cell");
    for result in &results[1..] {
        // Valgrind sometimes keeps tracking the secret past the shift and sometimes doesn't, so only this part is guaranteed.
        assert_eq!(result.skipped, None, "{}", result.cell);
        assert!(classes_in(result, "shift_by_secret").contains("incomplete"), "{}", result.cell);
        assert!(result.analysis.failures.iter().any(|f| f.contains("incomplete")), "{}", result.cell);
    }
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

#[test]
fn exit_codes_from_the_command_line() {
    let module = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/basic.wat");
    let run = |extra: &[&str], call: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_wasmcop")).args(["check", module, "--iterations", "1", "--call", call]).args(extra).output().unwrap();
        (output.status.code(), String::from_utf8_lossy(&output.stdout).into_owned())
    };
    let cranelift = ["--backend", "cranelift"];

    let (code, text) = run(&cranelift, "mem_ct(secret bytes(32))");
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("no findings"));
    let (code, text) = run(&cranelift, "mem_index(secret bytes(32))");
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("MEMORY-ADDRESS in mem_index"));
    let (code, text) = run(&cranelift, "trap_unreachable(secret bytes(32))");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("FAILED"));

    let (code, text) = run(&["--backend", "cranelift,cranelift", "--cpu", "avx2,avx2"], "mem_ct(secret bytes(32))");
    assert_eq!(code, Some(0), "repeated selections: {text}");
}
