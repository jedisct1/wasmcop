use crate::classify::is_variable_time;
use anyhow::{Context, Result, anyhow, bail};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use serde::Serialize;
use wasmcop_job::FunctionExtent;
use wasmcop_spec::module::ModuleShape;
use wasmer_compiler::ArtifactBuild;
use wasmer_compiler::serialize::{SerializableCompilation, SerializableModule};
use wasmer_types::MetadataHeader;

/// What a finding belongs to.
/// Imports aren't wasm functions, so they go by name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Function(u32),
    Import(String),
}

/// A variable-time instruction that nobody checked.
#[derive(Debug, Clone, Serialize)]
pub struct UncheckedSite {
    pub owner: Owner,
    pub function: String,
    pub native_offset: u64,
    pub instruction: String,
}

/// Native offset, length, and offset in the wasm file.
type WasmRange = (u32, u32, u32);

struct ArtifactFunction {
    body: Vec<u8>,
    wasm_map: Vec<WasmRange>,
}

/// The compiled code in an artifact, which stays the same across runs.
pub struct ArtifactCode {
    functions: Vec<ArtifactFunction>,
}

/// One compiled function, and where this run loaded it.
#[derive(Debug, Clone)]
pub struct CodeFunction<'a> {
    pub wasm_index: u32,
    pub name: String,
    pub address: u64,
    pub length: u64,
    pub body: &'a [u8],
    pub wasm_map: &'a [WasmRange],
}

impl CodeFunction<'_> {
    pub fn wasm_offset(&self, native_offset: u64) -> Option<u32> {
        let offset = u32::try_from(native_offset).ok()?;
        self.wasm_map.iter().find(|(start, len, _)| offset >= *start && offset - *start < *len).map(|(_, _, wasm)| *wasm)
    }

    pub fn decode(&self, native_offset: u64) -> Option<Instruction> {
        let bytes = self.body.get(native_offset as usize..)?;
        let mut decoder = Decoder::with_ip(64, bytes, native_offset, DecoderOptions::NONE);
        let instruction = decoder.decode();
        (!instruction.is_invalid()).then_some(instruction)
    }
}

pub fn format_instruction(instruction: &Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_hex(false);
    options.set_branch_leading_zeros(false);
    options.set_space_after_operand_separator(true);
    let mut text = String::new();
    formatter.format(instruction, &mut text);
    text
}

fn function_name(shape: &ModuleShape, wasm_index: u32) -> String {
    shape.function_names.get(&wasm_index).cloned().unwrap_or_else(|| format!("function[{wasm_index}]"))
}

impl ArtifactCode {
    /// `offset_shift` turns offsets in the compiled module into offsets in the original file.
    pub fn parse(artifact: &[u8], offset_shift: i64) -> Result<ArtifactCode> {
        // The format needs 16-byte alignment, which a plain Vec<u8> doesn't promise.
        let mut aligned = vec![0u128; artifact.len().div_ceil(16)];
        let bytes = &mut as_bytes(&mut aligned)[..artifact.len()];
        bytes.copy_from_slice(artifact);
        let bytes = &bytes[..];

        let after_magic = bytes.get(ArtifactBuild::MAGIC_HEADER.len()..).context("artifact too short")?;
        let length = MetadataHeader::parse(after_magic).map_err(|e| anyhow!("{e}"))?;
        let metadata = after_magic.get(MetadataHeader::LEN..MetadataHeader::LEN + length).context("artifact too short")?;
        let archived = SerializableModule::archive_from_slice_checked(metadata).map_err(|e| anyhow!("{e}"))?;
        let module = SerializableModule::deserialize_from_archive(archived).map_err(|e| anyhow!("{e}"))?;
        let SerializableCompilation::Rkyv(compilation) = module.compilation else {
            bail!("wasmer stored this artifact in a format Wasmcop can't read");
        };

        let functions = compilation
            .function_bodies
            .values()
            .zip(compilation.function_frame_info.values())
            .map(|(body, info)| ArtifactFunction {
                body: body.body.clone(),
                wasm_map: info
                    .address_map
                    .instructions
                    .iter()
                    .filter(|entry| !entry.srcloc.is_default())
                    .map(|entry| (entry.code_offset as u32, entry.code_len as u32, (i64::from(entry.srcloc.bits()) + offset_shift) as u32))
                    .collect(),
            })
            .collect();
        Ok(ArtifactCode { functions })
    }

    /// Lines the code up with where one run loaded it.
    pub fn join(&self, extents: &[FunctionExtent], shape: &ModuleShape) -> Result<CodeMap<'_>> {
        let mut functions = Vec::new();
        for extent in extents {
            let function = self.functions.get(extent.local_index as usize).context("unknown function in the artifact")?;
            let wasm_index = extent.local_index + shape.imported_functions;
            functions.push(CodeFunction {
                wasm_index,
                name: function_name(shape, wasm_index),
                address: extent.address,
                length: extent.length,
                body: &function.body,
                wasm_map: &function.wasm_map,
            });
        }
        Ok(CodeMap { functions })
    }

    /// Every instruction whose speed can depend on its operands.
    pub fn variable_time_sites(&self, shape: &ModuleShape) -> Vec<UncheckedSite> {
        let mut sites = Vec::new();
        for (index, function) in self.functions.iter().enumerate() {
            let wasm_index = index as u32 + shape.imported_functions;
            let mut decoder = Decoder::with_ip(64, &function.body, 0, DecoderOptions::NONE);
            while decoder.can_decode() {
                let native_offset = decoder.ip();
                let instruction = decoder.decode();
                if is_variable_time(instruction.mnemonic()) {
                    sites.push(UncheckedSite { owner: Owner::Function(wasm_index), function: function_name(shape, wasm_index), native_offset, instruction: format_instruction(&instruction) });
                }
            }
        }
        sites
    }
}

#[derive(Debug, Clone, Default)]
pub struct CodeMap<'a> {
    pub functions: Vec<CodeFunction<'a>>,
}

impl<'a> CodeMap<'a> {
    /// The function containing this address, and the offset inside it.
    pub fn locate(&self, address: u64) -> Option<(&CodeFunction<'a>, u64)> {
        self.functions.iter().find(|f| address >= f.address && address - f.address < f.length).map(|f| (f, address - f.address))
    }
}

fn as_bytes(words: &mut [u128]) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, words.len() * 16) }
}
