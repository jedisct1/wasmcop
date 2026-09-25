//! Turns parsed tests into concrete steps for the runner, checking them against the module.

use crate::module::{ModuleShape, Signature, Type};
use crate::syntax::{Arg, Call, Statement, Value};
use anyhow::{Context, Result, anyhow, bail};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use turboshake::TurboShake128;
use turboshake::digest::{ExtendableOutput, Update};
use wasmcop_job::{self as job, Alloc, Iteration, Job, MemoryBinding, Poison, Scalar, Step, ValType};

#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub seed: u64,
    pub iterations: u32,
}

impl Default for Options {
    fn default() -> Options {
        Options { seed: 1, iterations: 4 }
    }
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub job: Job,
    /// Every secret's label, for blame and for spotting tests with no secrets.
    pub secrets: BTreeSet<String>,
}

pub fn resolve(test: &TestCase, shape: &ModuleShape, options: &Options) -> Result<Resolved> {
    let mut secrets = BTreeSet::new();
    let mut iterations = Vec::new();
    for iteration in 0..options.iterations {
        let mut walker = Walker {
            test,
            shape,
            options,
            iteration,
            bindings: HashMap::new(),
            steps: Vec::new(),
            next_item: 0,
            label_uses: HashMap::new(),
            secrets: &mut secrets,
        };
        for statement in &test.statements {
            walker.statement(statement).with_context(|| format!("in test `{}`", test.name))?;
        }
        iterations.push(Iteration {
            label: pattern(iteration).label(iteration),
            steps: walker.steps,
        });
    }

    let job = Job {
        artifact: PathBuf::new(),
        output: PathBuf::new(),
        poison: Poison::All,
        memory: shape.memory_binding().unwrap_or(MemoryBinding::Unavailable),
        alloc: default_alloc(shape),
        iterations,
    };
    Ok(Resolved { job, secrets })
}

fn default_alloc(shape: &ModuleShape) -> Alloc {
    let malloc = Signature { params: vec![Type::Val(ValType::I32)], results: vec![Type::Val(ValType::I32)] };
    if shape.functions.get("malloc") == Some(&malloc) {
        Alloc::Malloc("malloc".to_string())
    } else {
        Alloc::Grow
    }
}

fn plain_signature(signature: &Signature, name: &str) -> Result<(Vec<ValType>, Vec<ValType>)> {
    let plain = |types: &[Type]| -> Result<Vec<ValType>> {
        types
            .iter()
            .map(|ty| match ty {
                Type::Val(ty) => Ok(*ty),
                Type::Ref(reference) => bail!("{name} uses {reference}, and reference types are not supported"),
            })
            .collect()
    };
    Ok((plain(&signature.params)?, plain(&signature.results)?))
}

#[derive(Clone, Copy)]
enum Pattern {
    Random,
    Zeros,
    Ones,
}

impl Pattern {
    fn label(self, iteration: u32) -> String {
        match self {
            Pattern::Random => format!("random-{iteration}"),
            Pattern::Zeros => "zeros".to_string(),
            Pattern::Ones => "ones".to_string(),
        }
    }
}

fn pattern(iteration: u32) -> Pattern {
    match iteration {
        1 => Pattern::Zeros,
        2 => Pattern::Ones,
        _ => Pattern::Random,
    }
}

pub fn random_key(seed: u64, test: &str, iteration: u32) -> [u8; 32] {
    derive(seed, test, iteration, u32::MAX)
}

/// Public values stay the same across iterations, so they share this scope.
const PUBLIC_SCOPE: u32 = u32::MAX - 1;

fn derive(seed: u64, test: &str, scope: u32, item: u32) -> [u8; 32] {
    let mut hash = TurboShake128::default();
    hash.update(b"wasmcop-values\0");
    hash.update(&seed.to_le_bytes());
    hash.update(&(test.len() as u64).to_le_bytes());
    hash.update(test.as_bytes());
    hash.update(&scope.to_le_bytes());
    hash.update(&item.to_le_bytes());
    let mut output = [0; 32];
    hash.finalize_xof_into(&mut output);
    output
}

#[derive(Clone)]
enum Binding {
    Scalar { literal: Literal, secret: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Literal {
    Int(i128),
    Float(f64),
    Bits(u128),
}

struct Walker<'a> {
    test: &'a TestCase,
    shape: &'a ModuleShape,
    options: &'a Options,
    iteration: u32,
    bindings: HashMap<String, Binding>,
    steps: Vec<Step>,
    next_item: u32,
    label_uses: HashMap<String, u32>,
    secrets: &'a mut BTreeSet<String>,
}

impl Walker<'_> {
    fn statement(&mut self, statement: &Statement) -> Result<()> {
        match statement {
            Statement::Call(call) => self.call(call),
        }
    }

    fn item(&mut self) -> u32 {
        self.next_item += 1;
        self.next_item
    }

    fn rng(&self, scope: u32, item: u32) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(derive(self.options.seed, &self.test.name, scope, item))
    }

    /// Creates what an argument needs before the call.
    /// `label` names it if it's secret.
    fn declare(&mut self, arg: &Arg, label: &str) -> Result<Binding> {
        match &arg.value {
            Value::Int(value) => Ok(self.scalar(Literal::Int(*value), arg.secret, label)),
            Value::Float(value) => Ok(self.scalar(Literal::Float(*value), arg.secret, label)),
            Value::Rand => {
                let literal = self.random_scalar(arg.secret);
                Ok(self.scalar(literal, arg.secret, label))
            }
        }
    }

    /// Separately declared secrets need separate labels, or blame would poison them together.
    fn fresh_label(&mut self, label: &str) -> String {
        let uses = self.label_uses.entry(label.to_string()).or_insert(0);
        *uses += 1;
        let label = if *uses == 1 { label.to_string() } else { format!("{label}#{uses}") };
        self.secrets.insert(label.clone());
        label
    }

    fn scalar(&mut self, literal: Literal, secret: bool, label: &str) -> Binding {
        let secret = secret.then(|| self.fresh_label(label));
        Binding::Scalar { literal, secret }
    }

    fn random_scalar(&mut self, secret: bool) -> Literal {
        let item = self.item();
        if secret {
            match pattern(self.iteration) {
                Pattern::Zeros => return Literal::Bits(0),
                Pattern::Ones => return Literal::Bits(u128::MAX),
                Pattern::Random => {}
            }
        }
        let scope = if secret { self.iteration } else { PUBLIC_SCOPE };
        let mut bytes = [0u8; 16];
        self.rng(scope, item).fill_bytes(&mut bytes);
        Literal::Bits(u128::from_le_bytes(bytes))
    }

    fn call(&mut self, call: &Call) -> Result<()> {
        let signature = self.shape.functions.get(&call.function).ok_or_else(|| {
            anyhow!("the module has no exported function `{}`. `wasmcop list` shows what it exports", call.function)
        })?;
        if call.args.len() != signature.params.len() {
            bail!(
                "{} takes {} arguments {}, but the call has {}",
                call.function,
                signature.params.len(),
                signature,
                call.args.len()
            );
        }
        let (params, results) = plain_signature(signature, &call.function)?;

        let mut args = Vec::new();
        for (index, arg) in call.args.iter().enumerate() {
            let label = argument_label(arg, &call.function, index);
            let binding = self.declare(arg, &label)?;
            if let Some(name) = &arg.name {
                self.bindings.insert(name.clone(), binding.clone());
            }
            args.push(self.argument(binding, params[index], &call.function, index)?);
        }

        let slots = vec![None; results.len()];
        self.steps.push(Step::Call { function: call.function.clone(), args, results: slots });
        Ok(())
    }

    fn argument(&self, binding: Binding, ty: ValType, function: &str, index: usize) -> Result<job::Arg> {
        let context = || format!("argument {index} of {function}");
        match binding {
            Binding::Scalar { literal, secret } => {
                let value = typed(literal, ty).with_context(context)?;
                Ok(job::Arg::Value { value, secret })
            }
        }
    }
}

fn argument_label(arg: &Arg, function: &str, index: usize) -> String {
    arg.name.clone().unwrap_or_else(|| format!("{function}:arg{index}"))
}

fn typed(literal: Literal, ty: ValType) -> Result<Scalar> {
    let bits = match (literal, ty) {
        (Literal::Bits(bits), ValType::I32 | ValType::F32) => bits & 0xffff_ffff,
        (Literal::Bits(bits), ValType::I64 | ValType::F64) => bits & 0xffff_ffff_ffff_ffff,
        (Literal::Bits(bits), ValType::V128) => bits,
        (Literal::Int(value), ValType::I32) => {
            if !(i32::MIN as i128..=u32::MAX as i128).contains(&value) {
                bail!("{value} doesn't fit in an i32");
            }
            value as u32 as u128
        }
        (Literal::Int(value), ValType::I64) => {
            if !(i64::MIN as i128..=u64::MAX as i128).contains(&value) {
                bail!("{value} doesn't fit in an i64");
            }
            value as u64 as u128
        }
        (Literal::Int(value), ValType::F32) => (value as f32).to_bits() as u128,
        (Literal::Int(value), ValType::F64) => (value as f64).to_bits() as u128,
        (Literal::Int(value), ValType::V128) => {
            u128::try_from(value).map_err(|_| anyhow!("{value} doesn't fit in a v128"))?
        }
        (Literal::Float(value), ValType::F32) => (value as f32).to_bits() as u128,
        (Literal::Float(value), ValType::F64) => value.to_bits() as u128,
        (Literal::Float(value), _) => bail!("{value} is a float, but this parameter is {}", Type::Val(ty)),
    };
    Ok(Scalar { ty, bits })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::parse_call;

    fn options(iterations: u32) -> Options {
        Options { seed: 7, iterations, ..Options::default() }
    }

    fn resolve_with(module: &str, script: &str, options: &Options) -> Result<Resolved> {
        let shape = ModuleShape::parse(&wat::parse_str(module)?)?;
        let test = TestCase { name: "t".to_string(), statements: vec![Statement::Call(parse_call(script)?)] };
        resolve(&test, &shape, options)
    }

    fn try_resolve(module: &str, script: &str, iterations: u32) -> Result<Resolved> {
        resolve_with(module, script, &options(iterations))
    }

    #[test]
    fn calls_are_checked_against_the_signature() {
        let module = r#"(module (memory (export "m") 1)
            (func (export "f") (param i32) (result i32) (i32.const 0))
            (func (export "wide") (param i64) (result i32) (i32.const 0))
            (func (export "two") (result i32 i32) (i32.const 0) (i32.const 1))
            (func (export "fr") (param funcref))
            (func (export "er") (result externref) (ref.null extern)))"#;
        for (script, reason) in [
            ("g(1)", "no exported function"),
            ("f(1, 2)", "takes 1 arguments"),
            ("fr(1)", "reference types"),
            ("er()", "reference types"),
            ("f(0x1ffffffff)", "doesn't fit"),
            ("f(1.5)", "float"),
        ] {
            let error = format!("{:#}", try_resolve(module, script, 1).unwrap_err());
            assert!(error.contains(reason), "{script}: {error}");
        }
    }
}
