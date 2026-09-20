use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fmt;
use wasmcop_job::ValType;
use wasmparser::{CompositeInnerType, ExternalKind, Parser, Payload};

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

#[derive(Debug, Clone, Default)]
pub struct ModuleShape {
    pub functions: BTreeMap<String, Signature>,
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
                Payload::FunctionSection(reader) => {
                    for index in reader {
                        functions.push(signature(&types, index?)?);
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
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(shape)
    }
}
