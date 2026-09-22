use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fmt;
use wasmcop_job::{MemoryBinding, ValType};
use wasmparser::{CompositeInnerType, ExternalKind, Parser, Payload, TypeRef};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Val(ValType),
    Ref(String),
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Val(ValType::I32) => f.write_str("i32"),
            Type::Val(ValType::I64) => f.write_str("i64"),
            Type::Val(ValType::F32) => f.write_str("f32"),
            Type::Val(ValType::F64) => f.write_str("f64"),
            Type::Val(ValType::V128) => f.write_str("v128"),
            Type::Ref(name) => f.write_str(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Signature {
    pub params: Vec<Type>,
    pub results: Vec<Type>,
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |types: &[Type]| types.iter().map(Type::to_string).collect::<Vec<_>>().join(", ");
        write!(f, "({})", list(&self.params))?;
        match self.results.len() {
            0 => Ok(()),
            1 => write!(f, " -> {}", self.results[0]),
            _ => write!(f, " -> ({})", list(&self.results)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInfo {
    pub initial: u32,
    pub maximum: Option<u32>,
    pub shared: bool,
    pub import: Option<(String, String)>,
    pub exports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportItem {
    Function(Signature),
    Memory,
    Table,
    Global { ty: Type, mutable: bool },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportShape {
    pub module: String,
    pub name: String,
    pub item: ImportItem,
}

#[derive(Debug, Clone, Default)]
pub struct ModuleShape {
    pub functions: BTreeMap<String, Signature>,
    pub memories: Vec<MemoryInfo>,
    pub imports: Vec<ImportShape>,
    pub imported_functions: u32,
}

fn val_type(ty: wasmparser::ValType) -> Type {
    match ty {
        wasmparser::ValType::I32 => Type::Val(ValType::I32),
        wasmparser::ValType::I64 => Type::Val(ValType::I64),
        wasmparser::ValType::F32 => Type::Val(ValType::F32),
        wasmparser::ValType::F64 => Type::Val(ValType::F64),
        wasmparser::ValType::V128 => Type::Val(ValType::V128),
        wasmparser::ValType::Ref(reference) => Type::Ref(reference.to_string()),
    }
}

fn pages(value: u64) -> Result<u32> {
    u32::try_from(value).context("memory limit does not fit in 32 bits")
}

fn memory_info(ty: &wasmparser::MemoryType, import: Option<(String, String)>) -> Result<MemoryInfo> {
    if ty.memory64 {
        bail!("this module uses memory64, which wasmer 7.5.0 cannot compile");
    }
    Ok(MemoryInfo {
        initial: pages(ty.initial)?,
        maximum: ty.maximum.map(pages).transpose()?,
        shared: ty.shared,
        import,
        exports: Vec::new(),
    })
}

impl ModuleShape {
    pub fn parse(wasm: &[u8]) -> Result<ModuleShape> {
        let mut shape = ModuleShape::default();
        let mut types: Vec<Option<Signature>> = Vec::new();
        let mut functions: Vec<Signature> = Vec::new();
        let signature = |types: &[Option<Signature>], index: u32| -> Result<Signature> {
            types
                .get(index as usize)
                .cloned()
                .flatten()
                .with_context(|| format!("type {index} is not a function type"))
        };

        for payload in Parser::new(0).parse_all(wasm) {
            match payload.context("this file is not a valid wasm module")? {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        for ty in group?.into_types() {
                            types.push(match ty.composite_type.inner {
                                CompositeInnerType::Func(func) => Some(Signature {
                                    params: func.params().iter().copied().map(val_type).collect(),
                                    results: func.results().iter().copied().map(val_type).collect(),
                                }),
                                _ => None,
                            });
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader.into_imports() {
                        let import = import?;
                        let qualified = (import.module.to_string(), import.name.to_string());
                        let item = match import.ty {
                            TypeRef::Func(index) => {
                                let sig = signature(&types, index)?;
                                functions.push(sig.clone());
                                shape.imported_functions += 1;
                                ImportItem::Function(sig)
                            }
                            TypeRef::Memory(ty) => {
                                shape.memories.push(memory_info(&ty, Some(qualified.clone()))?);
                                ImportItem::Memory
                            }
                            TypeRef::Table(_) => ImportItem::Table,
                            TypeRef::Global(ty) => ImportItem::Global {
                                ty: val_type(ty.content_type),
                                mutable: ty.mutable,
                            },
                            _ => ImportItem::Other,
                        };
                        shape.imports.push(ImportShape {
                            module: qualified.0,
                            name: qualified.1,
                            item,
                        });
                    }
                }
                Payload::FunctionSection(reader) => {
                    for index in reader {
                        functions.push(signature(&types, index?)?);
                    }
                }
                Payload::MemorySection(reader) => {
                    for ty in reader {
                        shape.memories.push(memory_info(&ty?, None)?);
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export?;
                        match export.kind {
                            ExternalKind::Func => {
                                let sig = functions
                                    .get(export.index as usize)
                                    .context("export of an unknown function")?;
                                shape.functions.insert(export.name.to_string(), sig.clone());
                            }
                            ExternalKind::Memory => {
                                shape
                                    .memories
                                    .get_mut(export.index as usize)
                                    .context("export of an unknown memory")?
                                    .exports
                                    .push(export.name.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(shape)
    }

    /// The memory buffers go in, or the reason there isn't one.
    pub fn memory_binding(&self) -> Result<MemoryBinding, String> {
        let memory = match self.memories.as_slice() {
            [] => return Err("the module has no memory".to_string()),
            [memory] => memory,
            more => return Err(format!("the module has {} memories, and Wasmcop needs exactly one", more.len())),
        };
        if memory.shared {
            return Err("the module's memory is shared".to_string());
        }
        if let Some((module, name)) = &memory.import {
            return Ok(MemoryBinding::Imported { module: module.clone(), name: name.clone() });
        }
        match memory.exports.first() {
            Some(name) => Ok(MemoryBinding::Exported(name.clone())),
            None => Err("the module does not export its memory, so Wasmcop can't reach it".to_string()),
        }
    }
}
