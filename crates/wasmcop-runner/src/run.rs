use crate::{imports, vg, wasi};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use wasmcop_job::{
    Alloc, Arg, Buffer, FunctionExtent, Iteration, IterationReport, Job, MemoryBinding, Outcome, Region, Report, Scalar, Step, ValType, to_hex,
};
use wasmer::sys::EngineBuilder;
use wasmer::{Engine, Instance, Memory, Module, RuntimeError, Store, Value, WASM_PAGE_SIZE};
use wasmer_types::TrapCode;
use wasmer_types::entity::EntityRef;

/// Stops a small over-read from picking up the next buffer's secret.
const BUFFER_GAP: u32 = 64;

#[derive(Clone)]
enum Slot {
    Buffer { address: u32, length: u32, public: bool },
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

fn exported_memory(job: &Job, instance: &Instance) -> Result<Option<Memory>> {
    Ok(match &job.memory {
        MemoryBinding::Exported(name) => Some(instance.exports.get_memory(name).with_context(|| format!("memory export {name}"))?.clone()),
        MemoryBinding::Unavailable | MemoryBinding::Imported { .. } => None,
    })
}

fn run_iteration(
    job: &Job,
    module: &Module,
    store: &mut Store,
    iteration: &Iteration,
) -> Result<IterationReport> {
    let provided = imports::provide(job, iteration, store)?;
    let instance = Instance::new(store, module, &provided.imports).context("instantiating")?;
    let memory = provided.memory.or(exported_memory(job, &instance)?);
    provided.host.as_mut(store).memory = memory.clone();
    let mut state = IterationState {
        job,
        instance: &instance,
        memory,
        slots: HashMap::new(),
        arena: None,
        result_tainted: false,
    };
    let mut report = IterationReport {
        label: iteration.label.clone(),
        errors_per_call: Vec::new(),
        outcome: Outcome::Completed,
        output_tainted: false,
        expect_failures: Vec::new(),
    };
    state.prepare_arena(store, iteration)?;

    for step in &iteration.steps {
        if let Some(outcome) = state.step(store, step, &mut report)? {
            report.outcome = outcome;
            break;
        }
    }
    report.output_tainted = state.output_tainted(store);
    Ok(report)
}

struct IterationState<'a> {
    job: &'a Job,
    instance: &'a Instance,
    memory: Option<Memory>,
    slots: HashMap<usize, Slot>,
    arena: Option<Arena>,
    result_tainted: bool,
}

struct Arena {
    next: u64,
    end: u64,
}

impl IterationState<'_> {
    fn memory(&self) -> Result<&Memory> {
        self.memory.as_ref().ok_or_else(|| anyhow!("this module has no memory the runner can use"))
    }

    /// Makes room for every buffer without a fixed address.
    /// Sizes are u64 so a 4 GiB memory can't overflow.
    fn prepare_arena(&mut self, store: &mut Store, iteration: &Iteration) -> Result<()> {
        let mut size: u64 = 0;
        for step in &iteration.steps {
            if let Step::Buffer(buffer) = step
                && buffer.at.is_none()
            {
                size += buffer.data.len() as u64 + u64::from(buffer.align) + u64::from(BUFFER_GAP);
            }
        }
        if size == 0 {
            return Ok(());
        }
        let request = u32::try_from(size).context("buffers do not fit in linear memory")?;
        let base = match &self.job.alloc {
            Alloc::Malloc(name) => {
                let function = self.instance.exports.get_function(name)?;
                let result = function
                    .call(store, &[Value::I32(request as i32)])
                    .map_err(|e| anyhow!("{name} trapped: {e}"))?;
                let base = match result.first() {
                    Some(Value::I32(base)) => *base as u32,
                    _ => bail!("{name} did not return an i32"),
                };
                if base == 0 {
                    bail!("{name}({size}) failed");
                }
                u64::from(base)
            }
            Alloc::Grow => {
                let pages = request.div_ceil(WASM_PAGE_SIZE as u32);
                let memory = self.memory()?.clone();
                let previous = memory
                    .grow(store, pages)
                    .map_err(|e| anyhow!("growing memory by {pages} pages: {e}"))?;
                u64::from(previous.0) * WASM_PAGE_SIZE as u64
            }
        };
        let end = base + size;
        if end > self.memory()?.view(store).data_size() {
            bail!("arena {base:#x}+{size} is outside linear memory");
        }
        self.arena = Some(Arena { next: base, end });
        Ok(())
    }

    fn step(
        &mut self,
        store: &mut Store,
        step: &Step,
        report: &mut IterationReport,
    ) -> Result<Option<Outcome>> {
        match step {
            Step::Buffer(buffer) => self.buffer(store, buffer)?,
            Step::Call { function, args, results } => {
                return self.call(store, function, args, results, report);
            }
            Step::Poison { region, label } => {
                if self.job.poison.covers(label) {
                    let (pointer, length) = self.region_ptr(store, region)?;
                    vg::make_undefined(pointer, length);
                }
            }
            Step::Declassify { region } => self.declassify(store, region)?,
            Step::Expect { region, bytes } => {
                let (pointer, length) = self.region_ptr(store, region)?;
                let actual = vg::defined_copy(pointer, length);
                if actual != *bytes {
                    report.expect_failures.push(format!("expected {}, got {}", to_hex(bytes), to_hex(&actual)));
                }
            }
        }
        Ok(None)
    }

    fn declassify(&mut self, store: &Store, region: &Region) -> Result<()> {
        if let Region::Slot(slot) = region
            && let Some(Slot::Value(value)) = self.slots.get_mut(slot)
        {
            *value = declassified(value);
            return Ok(());
        }
        let (pointer, length) = self.region_ptr(store, region)?;
        vg::make_defined(pointer, length);
        Ok(())
    }

    fn buffer(&mut self, store: &mut Store, buffer: &Buffer) -> Result<()> {
        let length = u32::try_from(buffer.data.len()).context("buffer larger than 4 GiB")?;
        if !buffer.align.is_power_of_two() {
            bail!("alignment {} is not a power of two", buffer.align);
        }
        for range in &buffer.secret {
            if range.start > range.end || range.end > length {
                bail!("secret range {}..{} is outside a {length}-byte buffer", range.start, range.end);
            }
        }
        let address = match buffer.at {
            Some(address) => u64::from(address),
            None => {
                let arena = self.arena.as_mut().ok_or_else(|| anyhow!("no arena"))?;
                let address = arena.next.next_multiple_of(u64::from(buffer.align));
                arena.next = address + u64::from(length) + u64::from(BUFFER_GAP);
                if arena.next > arena.end {
                    bail!("arena exhausted");
                }
                address
            }
        };
        let view = self.memory()?.view(store);
        if address + u64::from(length) > view.data_size() {
            bail!("buffer {address:#x}+{length} is outside linear memory");
        }
        // Write first, because writing clears the secret marking.
        view.write(address, &buffer.data)
            .with_context(|| format!("writing {length} bytes at {address:#x}"))?;
        for range in &buffer.secret {
            if self.job.poison.covers(&range.label) {
                let offset = (address + u64::from(range.start)) as usize;
                let pointer = unsafe { view.data_ptr().add(offset) };
                vg::make_undefined(pointer, (range.end - range.start) as usize);
            }
        }
        let address = u32::try_from(address).context("buffer address does not fit in an i32")?;
        self.slots.insert(buffer.slot, Slot::Buffer { address, length, public: buffer.public });
        Ok(())
    }

    fn argument(&self, arg: &Arg) -> Result<Value> {
        Ok(match arg {
            Arg::Value { value, secret } => {
                let tainted = secret.as_ref().is_some_and(|label| self.job.poison.covers(label));
                to_value(*value, tainted)
            }
            Arg::Address(slot) => match self.slots.get(slot) {
                Some(Slot::Buffer { address, .. }) => Value::I32(*address as i32),
                _ => bail!("slot {slot} is not a buffer"),
            },
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
                // Unbound results count too, so check before dropping them.
                self.result_tainted |= values.iter().any(value_tainted);
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

    fn region_ptr(&self, store: &Store, region: &Region) -> Result<(*const u8, usize)> {
        let (address, length) = match region {
            Region::Slot(slot) => match self.slots.get(slot) {
                Some(Slot::Buffer { address, length, .. }) => (*address, *length),
                _ => bail!("slot {slot} is not a buffer"),
            },
            Region::Absolute { address, length } => (*address, *length),
        };
        let view = self.memory()?.view(store);
        let pointer = wasi::guest_pointer(&view, address, length).ok_or_else(|| anyhow!("region {address:#x}+{length} is outside linear memory"))?;
        Ok((pointer, length as usize))
    }

    fn output_tainted(&self, store: &Store) -> bool {
        self.result_tainted
            || self.slots.values().any(|slot| match slot {
                Slot::Buffer { address, length, public: true } => {
                    self.memory.as_ref().is_some_and(|memory| {
                        let view = memory.view(store);
                        let pointer = unsafe { view.data_ptr().add(*address as usize) as *const u8 };
                        vg::is_undefined(pointer, *length as usize)
                    })
                }
                _ => false,
            })
    }
}

fn failure_outcome(function: &str, trap: RuntimeError) -> Outcome {
    if let Some(exit) = trap.downcast_ref::<wasi::Exit>() {
        return Outcome::Exit(exit.0);
    }
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

fn declassified(value: &Value) -> Value {
    match value {
        Value::I32(v) => Value::I32(vg::defined_value(*v)),
        Value::I64(v) => Value::I64(vg::defined_value(*v)),
        Value::F32(v) => Value::F32(vg::defined_value(*v)),
        Value::F64(v) => Value::F64(vg::defined_value(*v)),
        Value::V128(v) => Value::V128(vg::defined_value(*v)),
        other => other.clone(),
    }
}

fn value_tainted(value: &Value) -> bool {
    match value {
        Value::I32(v) => vg::value_is_undefined(*v),
        Value::I64(v) => vg::value_is_undefined(*v),
        Value::F32(v) => vg::value_is_undefined(*v),
        Value::F64(v) => vg::value_is_undefined(*v),
        Value::V128(v) => vg::value_is_undefined(*v),
        _ => false,
    }
}
