//! What the driver asks the runner to do, and what the runner reports back.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub artifact: PathBuf,
    /// Where the runner writes its report.
    pub output: PathBuf,
    pub poison: Poison,
    pub iterations: Vec<Iteration>,
}

/// Baseline runs use `None`, blame runs use `Only`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Poison {
    All,
    None,
    Only(String),
}

impl Poison {
    pub fn covers(&self, label: &str) -> bool {
        match self {
            Poison::All => true,
            Poison::None => false,
            Poison::Only(only) => only == label,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
}

/// A wasm value as raw bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar {
    pub ty: ValType,
    #[serde(with = "hex_u128")]
    pub bits: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iteration {
    pub label: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Step {
    Call {
        function: String,
        args: Vec<Arg>,
        /// `None` means the result isn't kept.
        results: Vec<Option<usize>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Arg {
    Value {
        value: Scalar,
        /// Label of the secret, if it is one.
        secret: Option<String>,
    },
    Slot(usize),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub functions: Vec<FunctionExtent>,
    pub iterations: Vec<IterationReport>,
    /// Set when the harness itself failed.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionExtent {
    pub local_index: u32,
    pub address: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationReport {
    pub label: String,
    /// How many Valgrind errors each call caused.
    pub errors_per_call: Vec<u64>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Completed,
    Trap { message: String, out_of_bounds: bool },
    Exit(i32),
}

mod hex_u128 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{value:x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        u128::from_str_radix(&String::deserialize(d)?, 16).map_err(D::Error::custom)
    }
}
