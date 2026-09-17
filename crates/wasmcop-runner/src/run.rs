use crate::vg;
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use wasmcop_job::{Arg, FunctionExtent, Iteration, IterationReport, Job, Outcome, Report, Scalar, Step, ValType};
use wasmer::sys::EngineBuilder;
use wasmer::{Engine, Instance, Module, RuntimeError, Store, Value};
use wasmer_types::TrapCode;
use wasmer_types::entity::EntityRef;

#[derive(Clone)]
enum Slot {
    Value(Value),
}

pub fn run(job: &Job) -> Result<Report> {
    let engine: Engine = EngineBuilder::headless().into();
    let store = Store::new(engine.clone());
    let module = unsafe { Module::deserialize_from_file(&store, &job.artifact) }
        .with_context(|| format!("loading {}", job.artifact.display()))?;
    let mut report = Report { functions: function_extents(&module)?, ..Report::default() };
    drop(store);

    for iteration in &job.iterations {
        // Each memory reserves a lot of address space and Valgrind's is limited, so don't keep them around.
        let mut store = Store::new(engine.clone());
        report.iterations.push(run_iteration(job, &module, &mut store, iteration)?);
    }
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

fn run_iteration(
    job: &Job,
    module: &Module,
    store: &mut Store,
    iteration: &Iteration,
) -> Result<IterationReport> {
    let instance = Instance::new(store, module, &wasmer::Imports::new()).context("instantiating")?;
    let mut state = IterationState {
        job,
        instance: &instance,
        slots: HashMap::new(),
    };
    let mut report = IterationReport {
        label: iteration.label.clone(),
        errors_per_call: Vec::new(),
        outcome: Outcome::Completed,
    };

    for step in &iteration.steps {
        if let Some(outcome) = state.step(store, step, &mut report)? {
            report.outcome = outcome;
            break;
        }
    }
    Ok(report)
}

struct IterationState<'a> {
    job: &'a Job,
    instance: &'a Instance,
    slots: HashMap<usize, Slot>,
}

impl IterationState<'_> {
    fn step(
        &mut self,
        store: &mut Store,
        step: &Step,
        report: &mut IterationReport,
    ) -> Result<Option<Outcome>> {
        match step {
            Step::Call { function, args, results } => {
                return self.call(store, function, args, results, report);
            }
        }
    }

    fn argument(&self, arg: &Arg) -> Result<Value> {
        Ok(match arg {
            Arg::Value { value, secret } => {
                let tainted = secret.as_ref().is_some_and(|label| self.job.poison.covers(label));
                to_value(*value, tainted)
            }
            Arg::Slot(slot) => match self.slots.get(slot) {
                Some(Slot::Value(value)) => value.clone(),
                _ => bail!("slot {slot} is not a value"),
            },
        })
    }

    fn call(
        &mut self,
        store: &mut Store,
        name: &str,
        args: &[Arg],
        results: &[Option<usize>],
        report: &mut IterationReport,
    ) -> Result<Option<Outcome>> {
        let function = self
            .instance
            .exports
            .get_function(name)
            .with_context(|| format!("function export {name}"))?;
        let values = args.iter().map(|a| self.argument(a)).collect::<Result<Vec<_>>>()?;
        let before = vg::count_errors();
        let returned = function.call(store, &values);
        report.errors_per_call.push(vg::count_errors() - before);
        match returned {
            Ok(values) => {
                for (slot, value) in results.iter().zip(values.iter()) {
                    if let Some(slot) = slot {
                        self.slots.insert(*slot, Slot::Value(value.clone()));
                    }
                }
                Ok(None)
            }
            Err(trap) => Ok(Some(failure_outcome(name, trap))),
        }
    }
}

fn failure_outcome(function: &str, trap: RuntimeError) -> Outcome {
    let message = format!("in {function}: {trap}");
    let out_of_bounds = matches!(trap.to_trap(), Some(TrapCode::HeapAccessOutOfBounds | TrapCode::TableAccessOutOfBounds));
    Outcome::Trap { message, out_of_bounds }
}

pub fn to_value(scalar: Scalar, tainted: bool) -> Value {
    fn mark<T: Copy>(value: T, tainted: bool) -> T {
        if tainted { vg::undefined_value(value) } else { value }
    }
    match scalar.ty {
        ValType::I32 => Value::I32(mark(scalar.bits as u32 as i32, tainted)),
        ValType::I64 => Value::I64(mark(scalar.bits as u64 as i64, tainted)),
        ValType::F32 => Value::F32(mark(f32::from_bits(scalar.bits as u32), tainted)),
        ValType::F64 => Value::F64(mark(f64::from_bits(scalar.bits as u64), tainted)),
        ValType::V128 => Value::V128(mark(scalar.bits, tainted)),
    }
}
