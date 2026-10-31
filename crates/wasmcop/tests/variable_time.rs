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

#[test]
fn floating_point_division_and_square_root() {
    let Some(valgrind) = patched_valgrind() else { return };
    let scalar = ["f32_div", "f64_div", "f32_sqrt", "f64_sqrt"];
    let vector = ["f32x4_div", "f64x2_div", "f32x4_sqrt", "f64x2_sqrt"];
    let script = |names: &[&str], arg: &str| names.iter().map(|name| format!("{name}({arg})\n")).collect::<String>();
    let secret = "secret bytes(32, 0x40)";
    let public = "bytes(32, 0x40)";

    for (fixture_name, names, backends) in [("float.wat", &scalar, &Backend::ALL[..]), ("simd.wat", &vector, &[Backend::Cranelift, Backend::Llvm][..])] {
        let wasm = fixture(fixture_name);
        for cell in run(&valgrind, &wasm, &script(names, secret), backends) {
            assert_eq!(variable_time_functions(&cell), names.iter().copied().collect(), "{}", cell.cell);
        }
        for cell in run(&valgrind, &wasm, &script(names, public), backends) {
            assert!(cell.analysis.findings.is_empty(), "{}: public operands are fine", cell.cell);
        }
        for cell in run(&stock_valgrind(), &wasm, &script(names, secret), backends) {
            assert!(cell.analysis.findings.is_empty(), "{}: stock Valgrind can't see these", cell.cell);
            for name in names {
                assert!(cell.unchecked.iter().any(|s| s.function == *name), "{}: {name} should be listed", cell.cell);
            }
        }
    }
}

#[test]
fn a_secret_address_and_a_secret_operand_are_both_reported() {
    let Some(valgrind) = patched_valgrind() else { return };
    let cells = run(&valgrind, &fixture("float.wat"), "div_secret_address(secret bytes(32, 0x40))", &Backend::ALL);

    // Needs a backend that folds the load into the division, so that both land on one instruction.
    let both_on_one_instruction = |cell: &CellResult| {
        let findings = &cell.analysis.findings;
        findings.iter().filter(|f| f.class == Class::MemoryAddress).any(|address| findings.iter().any(|f| f.class == Class::VariableTime && f.owner == address.owner && f.native_offset == address.native_offset))
    };
    assert!(cells.iter().any(both_on_one_instruction), "{cells:#?}");
}

#[test]
fn scalar_operations_only_care_about_the_low_lane() {
    let Some(valgrind) = patched_valgrind() else { return };
    let wasm = fixture("simd.wat");
    let backends = [Backend::Cranelift, Backend::Llvm];
    let script = |range: &[(&str, &str)]| -> String { range.iter().map(|(name, secret)| format!("{name}(bytes(16, 0x40, secret={secret}))\n")).collect() };

    let upper_lanes = [("f64_div_lane", "8..16"), ("f32_div_lane", "4..16"), ("f64_sqrt_lane", "8..16"), ("f32_sqrt_lane", "4..16")];
    for cell in run(&valgrind, &wasm, &script(&upper_lanes), &backends) {
        assert!(variable_time_functions(&cell).is_empty(), "{}: {:?}", cell.cell, cell.analysis.findings);
    }

    let low_lane = [("f64_div_lane", "0..8"), ("f32_div_lane", "0..4"), ("f64_sqrt_lane", "0..8"), ("f32_sqrt_lane", "0..4")];
    let names: BTreeSet<&str> = low_lane.iter().map(|(name, _)| *name).collect();
    for cell in run(&valgrind, &wasm, &script(&low_lane), &backends) {
        assert_eq!(variable_time_functions(&cell), names, "{}", cell.cell);
    }
}
