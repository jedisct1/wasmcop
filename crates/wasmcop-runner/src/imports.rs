use crate::run::to_value;
use crate::wasi::{self, Host};
use anyhow::{Result, bail};
use wasmcop_job::{ImportKind, Iteration, Job, MemoryBinding, ValType};
use wasmer::{Function, FunctionEnv, FunctionType, Global, Imports, Memory, MemoryType, RuntimeError, Store, Type, Value};

pub struct Provided {
    pub imports: Imports,
    /// The memory buffers go in, when the module imports it.
    pub memory: Option<Memory>,
    pub host: FunctionEnv<Host>,
}

fn wasmer_type(ty: ValType) -> Type {
    match ty {
        ValType::I32 => Type::I32,
        ValType::I64 => Type::I64,
        ValType::F32 => Type::F32,
        ValType::F64 => Type::F64,
        ValType::V128 => Type::V128,
    }
}

fn function_type(params: &[ValType], results: &[ValType]) -> FunctionType {
    FunctionType::new(
        params.iter().copied().map(wasmer_type).collect::<Vec<_>>(),
        results.iter().copied().map(wasmer_type).collect::<Vec<_>>(),
    )
}

pub fn provide(job: &Job, iteration: &Iteration, store: &mut Store) -> Result<Provided> {
    let mut imports = Imports::new();
    let mut memory = None;
    let host = FunctionEnv::new(store, Host::new(job, iteration)?);
    for import in &job.imports {
        let (module, name) = (import.module.as_str(), import.name.as_str());
        match &import.kind {
            ImportKind::Builtin => match wasi::builtin(store, &host, module, name) {
                Some(function) => imports.define(module, name, function),
                None => bail!("{module}.{name} isn't implemented"),
            },
            ImportKind::Trap { params, results } => {
                let message = format!("{module}.{name} was called");
                let function = Function::new(store, function_type(params, results), move |_| {
                    Err(RuntimeError::new(message.clone()))
                });
                imports.define(module, name, function);
            }
            ImportKind::Constant { params, results } => {
                let types: Vec<ValType> = results.iter().map(|r| r.ty).collect();
                let values: Vec<Value> = results.iter().map(|r| to_value(*r, false)).collect();
                let function = Function::new(store, function_type(params, &types), move |_| Ok(values.clone()));
                imports.define(module, name, function);
            }
            ImportKind::Global { value, mutable } => {
                let value = to_value(*value, false);
                let global = if *mutable { Global::new_mut(store, value) } else { Global::new(store, value) };
                imports.define(module, name, global);
            }
            ImportKind::Memory { minimum, maximum, shared } => {
                let created = Memory::new(store, MemoryType::new(*minimum, *maximum, *shared))?;
                if matches!(&job.memory, MemoryBinding::Imported { module: m, name: n } if m == module && n == name) {
                    memory = Some(created.clone());
                }
                imports.define(module, name, created);
            }
        }
    }
    Ok(Provided { imports, memory, host })
}
