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
    poison: Poison,
    secret_random: bool,
}

impl Host {
    pub fn new(job: &Job, iteration: &Iteration) -> Result<Host> {
        let key: [u8; 32] = iteration.random_key.as_slice().try_into().context("the random key must be 32 bytes")?;
        Ok(Host {
            memory: None,
            random: ChaCha20Rng::from_seed(key),
            poison: job.poison.clone(),
            secret_random: job.secret_random,
        })
    }
}

fn view<'a>(memory: &'a Option<Memory>, store: &'a impl wasmer::AsStoreRef) -> Option<MemoryView<'a>> {
    memory.as_ref().map(|memory| memory.view(store))
}

/// `None` if any of the range is outside linear memory.
pub fn guest_pointer(view: &MemoryView, address: u32, length: u32) -> Option<*const u8> {
    if u64::from(address) + u64::from(length) > view.data_size() {
        return None;
    }
    Some(unsafe { view.data_ptr().add(address as usize) as *const u8 })
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
            "random_get" => typed!(random_get),
            _ => None,
        },
        _ => None,
    }
}
