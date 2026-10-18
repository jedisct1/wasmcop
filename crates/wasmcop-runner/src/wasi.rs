//! WASI preview 1 and the `wasmcop` imports.
//! Everything a module can observe comes from the job, so repeated runs behave the same.

use crate::vg;
use anyhow::{Context, Result};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use wasmcop_job::{Iteration, Job, Poison, RANDOM_LABEL, WASI_MODULE};
use wasmer::{Function, FunctionEnv, FunctionEnvMut, Memory, MemoryView, Store};

const SUCCESS: i32 = 0;
const FAULT: i32 = 21;

pub struct Host {
    pub memory: Option<Memory>,
    random: ChaCha20Rng,
    args: Vec<Vec<u8>>,
    environ: Vec<Vec<u8>>,
    poison: Poison,
    secret_random: bool,
}

impl Host {
    pub fn new(job: &Job, iteration: &Iteration) -> Result<Host> {
        let key: [u8; 32] = iteration.random_key.as_slice().try_into().context("the random key must be 32 bytes")?;
        let terminated = |text: String| {
            let mut bytes = text.into_bytes();
            bytes.push(0);
            bytes
        };
        Ok(Host {
            memory: None,
            random: ChaCha20Rng::from_seed(key),
            args: job.wasi.args.iter().cloned().map(terminated).collect(),
            environ: job.wasi.env.iter().map(|(k, v)| terminated(format!("{k}={v}"))).collect(),
            poison: job.poison.clone(),
            secret_random: job.secret_random,
        })
    }
}

fn view<'a>(memory: &'a Option<Memory>, store: &'a impl wasmer::AsStoreRef) -> Option<MemoryView<'a>> {
    memory.as_ref().map(|memory| memory.view(store))
}

fn write_all(view: &MemoryView, address: i32, bytes: &[u8]) -> Result<(), i32> {
    view.write(address as u32 as u64, bytes).map_err(|_| FAULT)
}

fn write_u32(view: &MemoryView, address: i32, value: u32) -> Result<(), i32> {
    write_all(view, address, &value.to_le_bytes())
}

/// `None` if any of the range is outside linear memory.
pub fn guest_pointer(view: &MemoryView, address: u32, length: u32) -> Option<*const u8> {
    if u64::from(address) + u64::from(length) > view.data_size() {
        return None;
    }
    Some(unsafe { view.data_ptr().add(address as usize) as *const u8 })
}

fn errno(result: Result<(), i32>) -> i32 {
    result.err().unwrap_or(SUCCESS)
}

fn sizes_get(env: &mut FunctionEnvMut<Host>, list: fn(&Host) -> &Vec<Vec<u8>>, count_out: i32, size_out: i32) -> i32 {
    let (host, store) = env.data_and_store_mut();
    let items = list(host);
    let count = items.len() as u32;
    let size: usize = items.iter().map(Vec::len).sum();
    let Some(view) = view(&host.memory, &store) else { return FAULT };
    errno(write_u32(&view, count_out, count).and_then(|()| write_u32(&view, size_out, size as u32)))
}

fn strings_get(env: &mut FunctionEnvMut<Host>, list: fn(&Host) -> &Vec<Vec<u8>>, pointers: i32, buffer: i32) -> i32 {
    let (host, store) = env.data_and_store_mut();
    let Some(view) = view(&host.memory, &store) else { return FAULT };
    let mut next = buffer as u32;
    for (index, item) in list(host).iter().enumerate() {
        let slot = pointers.wrapping_add((index * 4) as i32);
        if let Err(error) = write_u32(&view, slot, next).and_then(|()| write_all(&view, next as i32, item)) {
            return error;
        }
        next = next.wrapping_add(item.len() as u32);
    }
    SUCCESS
}

fn args_sizes_get(mut env: FunctionEnvMut<Host>, count_out: i32, size_out: i32) -> i32 {
    sizes_get(&mut env, |host| &host.args, count_out, size_out)
}

fn args_get(mut env: FunctionEnvMut<Host>, pointers: i32, buffer: i32) -> i32 {
    strings_get(&mut env, |host| &host.args, pointers, buffer)
}

fn environ_sizes_get(mut env: FunctionEnvMut<Host>, count_out: i32, size_out: i32) -> i32 {
    sizes_get(&mut env, |host| &host.environ, count_out, size_out)
}

fn environ_get(mut env: FunctionEnvMut<Host>, pointers: i32, buffer: i32) -> i32 {
    strings_get(&mut env, |host| &host.environ, pointers, buffer)
}

fn random_get(mut env: FunctionEnvMut<Host>, buffer: i32, length: i32) -> i32 {
    let (host, store) = env.data_and_store_mut();
    let Some(view) = view(&host.memory, &store) else { return FAULT };
    let Some(pointer) = guest_pointer(&view, buffer as u32, length as u32) else { return FAULT };

    let mut scratch = [0u8; 4096];
    let start = u64::from(buffer as u32);
    let total = u64::from(length as u32);
    let mut done = 0;
    while done < total {
        let size = (total - done).min(scratch.len() as u64) as usize;
        host.random.fill_bytes(&mut scratch[..size]);
        if view.write(start + done, &scratch[..size]).is_err() {
            return FAULT;
        }
        done += size as u64;
    }
    if host.secret_random && host.poison.covers(RANDOM_LABEL) {
        vg::make_undefined(pointer, total as usize);
    }
    SUCCESS
}

pub fn builtin(store: &mut Store, env: &FunctionEnv<Host>, module: &str, name: &str) -> Option<Function> {
    macro_rules! typed {
        ($function:ident) => {
            Some(Function::new_typed_with_env(store, env, $function))
        };
    }
    match module {
        WASI_MODULE => match name {
            "args_get" => typed!(args_get),
            "args_sizes_get" => typed!(args_sizes_get),
            "environ_get" => typed!(environ_get),
            "environ_sizes_get" => typed!(environ_sizes_get),
            "random_get" => typed!(random_get),
            _ => None,
        },
        _ => None,
    }
}
