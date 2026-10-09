pub mod analyze;
pub mod classify;
pub mod code;
pub mod compile;
pub mod report;
pub mod source;
pub mod valgrind;
pub mod xml;

use anyhow::{Context, Result};
use std::path::Path;

/// Reads a module from a `.wasm` file or a `.wat` text file.
pub fn read_module(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    wat::parse_bytes(&bytes).map(|wasm| wasm.into_owned()).with_context(|| format!("parsing {}", path.display()))
}
