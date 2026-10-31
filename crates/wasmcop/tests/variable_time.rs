mod support;

use std::collections::BTreeSet;
use support::*;
use wasmcop::classify::Class;
use wasmcop::compile::{Backend, Cell};
use wasmcop::report::CellResult;
use wasmcop::valgrind::Valgrind;

fn run(valgrind: &Valgrind, wasm: &[u8], script: &str, backends: &[Backend]) -> Vec<CellResult> {
    check_with(wasm, script, &Cell::defaults(backends), &options(), valgrind.clone(), false).tests.remove(0).cells
}

fn variable_time_functions(cell: &CellResult) -> BTreeSet<&str> {
    cell.analysis.findings.iter().filter(|f| f.class == Class::VariableTime).map(|f| f.function.as_str()).collect()
}

#[test]
fn division_on_stock_and_patched_valgrind() {
    let script = "mem_div_const(secret bytes(32, 0xa5))\nmem_div_var(secret bytes(32, 0xa5))";
    let wasm = fixture("basic.wat");

    let stock = run(&stock_valgrind(), &wasm, script, &Backend::ALL);
    let has_div = |cell: &CellResult, function: &str| cell.unchecked.iter().any(|s| s.function == function && s.instruction.contains("div"));
    assert!(has_div(&stock[0], "mem_div_const"));
    assert!(!has_div(&stock[1], "mem_div_const"));
    for cell in &stock {
        assert!(variable_time_functions(cell).is_empty(), "{}", cell.cell);
        assert!(has_div(cell, "mem_div_var"), "{}", cell.cell);
    }

    let Some(valgrind) = patched_valgrind() else { return };
    let patched = run(&valgrind, &wasm, script, &Backend::ALL);
    let found: Vec<_> = patched.iter().map(variable_time_functions).collect();
    assert_eq!(found[0], BTreeSet::from(["mem_div_const", "mem_div_var"]), "singlepass always emits div");
    assert_eq!(found[1], BTreeSet::from(["mem_div_var"]), "cranelift turns a constant divisor into a multiply");
    assert_eq!(found[2], BTreeSet::from(["mem_div_var"]), "llvm turns a constant divisor into a multiply");

    // Everything the patched Valgrind reports has to be on the list.
    // Both runs use the same cached artifacts.
    for (patched, stock) in patched.iter().zip(&stock) {
        let listed: BTreeSet<_> = stock.unchecked.iter().map(|s| (s.function.as_str(), s.native_offset)).collect();
        for finding in patched.analysis.findings.iter().filter(|f| f.class == Class::VariableTime) {
            assert!(listed.contains(&(finding.function.as_str(), finding.native_offset)), "{}: {finding:?}", patched.cell);
        }
    }
}
