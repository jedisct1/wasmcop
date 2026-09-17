use anyhow::{Context, Result, anyhow};
use wasmcop_job::{FunctionExtent, Job, Report};
use wasmer::sys::EngineBuilder;
use wasmer::{Engine, Module, Store};
use wasmer_types::entity::EntityRef;

pub fn run(job: &Job) -> Result<Report> {
    let engine: Engine = EngineBuilder::headless().into();
    let store = Store::new(engine.clone());
    let module = unsafe { Module::deserialize_from_file(&store, &job.artifact) }
        .with_context(|| format!("loading {}", job.artifact.display()))?;
    let report = Report { functions: function_extents(&module)?, ..Report::default() };

    Ok(report)
}

fn function_extents(module: &Module) -> Result<Vec<FunctionExtent>> {
    let artifact = module.sys_artifact().ok_or_else(|| anyhow!("not a native artifact"))?;
    let extents = artifact
        .finished_function_extents()
        .ok_or_else(|| anyhow!("artifact has no allocated functions"))?;
    Ok(extents
        .into_iter()
        .map(|(index, extent)| FunctionExtent {
            local_index: index.index() as u32,
            address: extent.ptr.0 as u64,
            length: extent.length as u64,
        })
        .collect())
}
