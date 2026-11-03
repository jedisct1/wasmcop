mod support;

use support::*;
use wasmcop::classify::Class;
use wasmcop::compile::{Backend, Cell};
use wasmcop::report::CellResult;
use wasmcop::valgrind::Valgrind;

fn run(valgrind: Valgrind, wasm: &[u8], script: &str) -> Vec<CellResult> {
    assert_clean(check_with(wasm, script, &Cell::defaults(&Backend::ALL), &options(), valgrind, false).tests.remove(0).cells)
}

#[test]
fn table_based_aes_leaks_on_every_backend() {
    let script = "
        c = out(16)
        aes128_encrypt(c, hex(00112233445566778899aabbccddeeff), secret hex(000102030405060708090a0b0c0d0e0f))
        declassify(c)
        expect(c, hex(69c4e0d86a7b0430d8cdb78070b4c55a))
    ";
    let cells = run(stock_valgrind(), &fixture("aes_table.wasm"), script);
    for cell in &cells {
        assert!(cell.analysis.findings.iter().any(|f| f.class == Class::MemoryAddress && f.function == "aes128_encrypt"), "{}", cell.cell);
    }
    let cranelift = cells[1].analysis.findings.iter().find(|f| f.class == Class::MemoryAddress).unwrap();
    assert!(cranelift.source.as_deref().unwrap().contains("aes_table.c:"), "{cranelift:?}");
}

#[test]
fn kyberslash_is_only_visible_where_the_division_survives() {
    let wasm = fixture("poly_tomsg.wat");
    let script = "poly_tomsg(out(32), secret bytes(512, 1))";

    // Stock Valgrind lists every division in the generated code, which shows the instruction is really gone.
    let cells = run(stock_valgrind(), &wasm, script);
    let listed = |cell: &CellResult| cell.unchecked.iter().any(|s| s.function == "poly_tomsg" && s.instruction.contains("div"));
    assert!(listed(&cells[0]), "singlepass keeps the division");
    assert!(!listed(&cells[1]), "cranelift turns it into a multiplication");
    assert!(!listed(&cells[2]), "llvm turns it into a multiplication");

    let Some(valgrind) = patched_valgrind() else { return };
    let cells = run(valgrind, &wasm, script);
    let divides = |cell: &CellResult| cell.analysis.findings.iter().any(|f| f.class == Class::VariableTime);
    assert!(divides(&cells[0]));
    assert!(!divides(&cells[1]) && !divides(&cells[2]));
}
