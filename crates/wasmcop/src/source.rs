use addr2line::Context;
use addr2line::gimli::{self, EndianSlice, LittleEndian};
use std::collections::HashMap;
use wasmparser::{BinaryReader, OperatorsReader, Parser, Payload};

/// Turns a wasm byte offset into the operator there and, if the module has DWARF, a source line.
pub struct SourceInfo<'a> {
    wasm: &'a [u8],
    code_start: usize,
    dwarf: Option<Context<EndianSlice<'a, LittleEndian>>>,
}

impl<'a> SourceInfo<'a> {
    pub fn new(wasm: &'a [u8]) -> SourceInfo<'a> {
        let mut sections: HashMap<&str, &'a [u8]> = HashMap::new();
        let mut code_start = 0;
        for payload in Parser::new(0).parse_all(wasm).flatten() {
            match payload {
                Payload::CodeSectionStart { unchecked_range, .. } => code_start = unchecked_range.start as usize,
                Payload::CustomSection(reader) if reader.name().starts_with(".debug_") => {
                    sections.insert(reader.name(), reader.data());
                }
                _ => {}
            }
        }
        let dwarf = gimli::Dwarf::load(|id| -> Result<_, gimli::Error> {
            let data = sections.get(id.name()).copied().unwrap_or(&[]);
            Ok(EndianSlice::new(data, LittleEndian))
        })
        .ok()
        .filter(|_| !sections.is_empty())
        .and_then(|dwarf| Context::from_dwarf(dwarf).ok());
        SourceInfo { wasm, code_start, dwarf }
    }

    /// The wasm operator's name, in lower case, like `select` or `i32divu`.
    pub fn operator(&self, offset: u32) -> Option<String> {
        let offset = offset as usize;
        let operator = OperatorsReader::new(BinaryReader::new(self.wasm.get(offset..)?, offset as u64)).read().ok()?;
        let text = format!("{operator:?}");
        let name = text.split([' ', '{', '(']).next()?;
        Some(name.to_lowercase())
    }

    pub fn line(&self, offset: u32) -> Option<String> {
        let address = (offset as u64).checked_sub(self.code_start as u64)?;
        let location = self.dwarf.as_ref()?.find_location(address).ok()??;
        Some(format!("{}:{}", location.file?, location.line?))
    }
}

