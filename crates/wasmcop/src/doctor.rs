use crate::compile::Backend;
use crate::valgrind::{Valgrind, find_runner};
use std::fmt::Write;
use std::path::Path;

/// Returns the report and whether the tool is usable.
pub fn doctor(explicit_valgrind: Option<&Path>) -> (String, bool) {
    let mut out = String::new();
    let mut usable = true;
    match Valgrind::find(explicit_valgrind) {
        Ok(valgrind) => {
            let _ = writeln!(out, "valgrind: {} ({})", valgrind.version, valgrind.path.display());
            let _ = writeln!(
                out,
                "variable-time instructions: {}",
                if valgrind.patched {
                    "checked (patched Valgrind)"
                } else {
                    "not checked, run scripts/build-valgrind.sh to enable"
                }
            );
        }
        Err(e) => {
            usable = false;
            let _ = writeln!(out, "valgrind: not usable: {e:#}");
        }
    }
    match find_runner() {
        Ok(runner) => {
            let _ = writeln!(out, "runner: {}", runner.display());
        }
        Err(e) => {
            usable = false;
            let _ = writeln!(out, "runner: {e:#}");
        }
    }
    for backend in Backend::ALL {
        let status = if backend.available() { "available" } else { "not built in" };
        let _ = writeln!(out, "{backend}: {status}");
    }
    (out, usable)
}
