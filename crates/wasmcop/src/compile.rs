use clap::ValueEnum;
use enumset::EnumSet;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::str::FromStr;
use wasmer::sys::{CpuFeature, Cranelift, CraneliftOptLevel, EngineBuilder, Singlepass, Target, Triple};
use wasmer::{Engine, Module, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ValueEnum)]
pub enum Backend {
    Singlepass,
    Cranelift,
    Llvm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Opt {
    /// Singlepass has no levels.
    Fixed,
    None,
    Less,
    Default,
    Speed,
    SpeedAndSize,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ValueEnum)]
pub enum CpuProfile {
    Avx2,
    Sse42,
    Baseline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cell {
    pub backend: Backend,
    pub opt: Opt,
    pub cpu: CpuProfile,
}

impl Cell {
    pub fn defaults(backends: &[Backend]) -> Vec<Cell> {
        Cell::defaults_on(backends, CpuProfile::Avx2)
    }

    pub fn defaults_on(backends: &[Backend], cpu: CpuProfile) -> Vec<Cell> {
        backends.iter().map(|&backend| Cell { backend, opt: backend.default_opt(), cpu }).collect()
    }

    pub fn full(backends: &[Backend], cpus: &[CpuProfile]) -> Vec<Cell> {
        let mut cells = Vec::new();
        for &backend in backends {
            for &opt in backend.opt_levels() {
                for &cpu in cpus {
                    cells.push(Cell { backend, opt, cpu });
                }
            }
        }
        cells
    }

    /// A name that's safe to use in a path.
    pub fn slug(&self) -> String {
        format!("{}-{:?}-{}", self.backend, self.opt, self.cpu)
    }
}

impl Backend {
    pub fn default_opt(self) -> Opt {
        match self {
            Backend::Singlepass => Opt::Fixed,
            Backend::Cranelift => Opt::Speed,
            Backend::Llvm => Opt::Aggressive,
        }
    }

    pub fn opt_levels(self) -> &'static [Opt] {
        match self {
            Backend::Singlepass => &[Opt::Fixed],
            Backend::Cranelift => &[Opt::None, Opt::Speed, Opt::SpeedAndSize],
            Backend::Llvm => &[Opt::None, Opt::Less, Opt::Default, Opt::Aggressive],
        }
    }

    /// Whether this build includes the backend.
    pub fn available(self) -> bool {
        match self {
            Backend::Singlepass | Backend::Cranelift => true,
            Backend::Llvm => cfg!(feature = "llvm"),
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::Singlepass => "singlepass",
            Backend::Cranelift => "cranelift",
            Backend::Llvm => "llvm",
        })
    }
}

impl fmt::Display for Opt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Opt::Fixed => "-",
            Opt::None => "none",
            Opt::Less => "less",
            Opt::Default => "default",
            Opt::Speed => "speed",
            Opt::SpeedAndSize => "speed_and_size",
            Opt::Aggressive => "aggressive",
        })
    }
}

impl fmt::Display for CpuProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CpuProfile::Avx2 => "avx2",
            CpuProfile::Sse42 => "sse42",
            CpuProfile::Baseline => "baseline",
        })
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.backend, self.opt, self.cpu)
    }
}

impl Backend {
    pub const ALL: [Backend; 3] = [Backend::Singlepass, Backend::Cranelift, Backend::Llvm];
}

impl CpuProfile {
    pub const ALL: [CpuProfile; 3] = [CpuProfile::Avx2, CpuProfile::Sse42, CpuProfile::Baseline];

    fn features(self) -> EnumSet<CpuFeature> {
        use CpuFeature::*;
        match self {
            CpuProfile::Baseline => SSE2.into(),
            CpuProfile::Sse42 => SSE2 | SSE3 | SSSE3 | SSE41 | SSE42 | POPCNT,
            CpuProfile::Avx2 => {
                SSE2 | SSE3 | SSSE3 | SSE41 | SSE42 | POPCNT | AVX | AVX2 | BMI1 | BMI2 | LZCNT
            }
        }
    }

    fn target(self) -> Target {
        let triple = Triple::from_str("x86_64-unknown-linux-gnu").expect("valid triple");
        Target::new(triple, self.features())
    }
}

fn engine(cell: &Cell) -> Result<Engine, String> {
    let builder = match cell.backend {
        Backend::Singlepass => EngineBuilder::new(Singlepass::default()),
        Backend::Cranelift => {
            let mut config = Cranelift::default();
            config.opt_level(match cell.opt {
                Opt::None => CraneliftOptLevel::None,
                Opt::SpeedAndSize => CraneliftOptLevel::SpeedAndSize,
                _ => CraneliftOptLevel::Speed,
            });
            EngineBuilder::new(config)
        }
        #[cfg(feature = "llvm")]
        Backend::Llvm => {
            use wasmer::sys::{LLVM, LLVMOptLevel};
            let mut config = LLVM::default();
            config.opt_level(match cell.opt {
                Opt::None => LLVMOptLevel::None,
                Opt::Less => LLVMOptLevel::Less,
                Opt::Default => LLVMOptLevel::Default,
                _ => LLVMOptLevel::Aggressive,
            });
            EngineBuilder::new(config)
        }
        #[cfg(not(feature = "llvm"))]
        Backend::Llvm => return Err("this build of wasmcop has no LLVM backend".to_string()),
    };
    Ok(builder.set_target(Some(cell.cpu.target())).into())
}

/// Checks that a module is valid wasm, under the same rules the compilers use.
pub fn validate(wasm: &[u8]) -> Result<(), String> {
    let engine: Engine = EngineBuilder::new(Cranelift::default()).into();
    Module::validate(&engine, wasm).map_err(|e| e.to_string())
}

/// Never targets the host CPU, because Valgrind refuses code that needs features it can't emulate, like AVX-512.
///
/// Wasmer panics on some things it doesn't implement, so a panic counts as a normal compile failure.
pub fn compile(wasm: &[u8], cell: &Cell) -> Result<Vec<u8>, String> {
    let engine = engine(cell)?;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let store = Store::new(engine);
        let module = Module::new(&store, wasm).map_err(|e| e.to_string())?;
        module.serialize().map(|bytes| bytes.to_vec()).map_err(|e| e.to_string())
    }));
    match outcome {
        Ok(result) => result,
        Err(panic) => Err(panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .map_or_else(|| "the compiler panicked".to_string(), |m| format!("the compiler panicked: {m}"))),
    }
}
