use wasmparser::{BinaryReader, OperatorsReader};

/// Turns a wasm byte offset into the operator there.
pub struct SourceInfo<'a> {
    wasm: &'a [u8],
}

impl<'a> SourceInfo<'a> {
    pub fn new(wasm: &'a [u8]) -> SourceInfo<'a> {
        SourceInfo { wasm }
    }

    /// The wasm operator's name, in lower case, like `select` or `i32divu`.
    pub fn operator(&self, offset: u32) -> Option<String> {
        let offset = offset as usize;
        let operator = OperatorsReader::new(BinaryReader::new(self.wasm.get(offset..)?, offset as u64)).read().ok()?;
        let text = format!("{operator:?}");
        let name = text.split([' ', '{', '(']).next()?;
        Some(name.to_lowercase())
    }
}
