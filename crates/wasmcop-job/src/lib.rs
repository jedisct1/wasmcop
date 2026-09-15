//! What the driver asks the runner to do, and what the runner reports back.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub artifact: PathBuf,
    /// Where the runner writes its report.
    pub output: PathBuf,
    pub iterations: Vec<Iteration>,
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

mod hex_u128 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{value:x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        u128::from_str_radix(&String::deserialize(d)?, 16).map_err(D::Error::custom)
    }
}
