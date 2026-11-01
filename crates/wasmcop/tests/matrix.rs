mod support;

use std::collections::BTreeMap;
use support::*;
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
