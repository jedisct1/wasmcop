//! What the driver asks the runner to do, and what the runner reports back.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `None` if the text isn't an even number of hex digits.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let digit = |b: u8| char::from(b).to_digit(16);
    text.as_bytes().chunks_exact(2).map(|pair| Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub artifact: PathBuf,
    /// Where the runner writes its report.
    pub output: PathBuf,
    pub poison: Poison,
    pub memory: MemoryBinding,
    pub alloc: Alloc,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryBinding {
    Unavailable,
    Exported(String),
    /// Matches an entry in `Job::imports`.
    Imported { module: String, name: String },
}

/// Where buffers without a fixed address go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Alloc {
    /// An exported `(i32) -> i32` allocator, called once.
    Malloc(String),
    Grow,
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
    Buffer(Buffer),
    Call {
        function: String,
        args: Vec<Arg>,
        /// `None` means the result isn't kept.
        results: Vec<Option<usize>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buffer {
    pub slot: usize,
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
    pub align: u32,
    pub at: Option<u32>,
    pub secret: Vec<SecretRange>,
}

/// `end` is exclusive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRange {
    pub start: u32,
    pub end: u32,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Arg {
    Value {
        value: Scalar,
        /// Label of the secret, if it is one.
        secret: Option<String>,
    },
    Address(usize),
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

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::to_hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::from_hex(&String::deserialize(d)?).ok_or_else(|| D::Error::custom("invalid hex string"))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(text: &str) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "hex_bytes")] Vec<u8>);
        serde_json::from_str::<Wrapper>(&format!("{text:?}")).map(|w| w.0)
    }

    #[test]
    fn hex() {
        assert_eq!(decode("00ffA5").unwrap(), [0x00, 0xff, 0xa5]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        for bad in ["abc", "zz", "+1", "\u{e9}", "\u{20ac}a"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }
}
