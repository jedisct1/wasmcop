//! TOML spec files, for tests with several steps.

use crate::resolve::{Options, TestCase};
use crate::syntax::{Statement, parse_call, parse_script};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    wasm: PathBuf,
    iterations: Option<u32>,
    seed: Option<u64>,
    #[serde(default)]
    test: Vec<RawTest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTest {
    name: String,
    call: Option<String>,
    steps: Option<String>,
}

#[derive(Debug)]
pub struct SpecFile {
    /// Resolved against the directory of the spec file.
    pub wasm: PathBuf,
    pub options: Options,
    pub tests: Vec<TestCase>,
}

impl SpecFile {
    pub fn load(path: &Path) -> Result<SpecFile> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        SpecFile::parse(&text, dir).with_context(|| format!("in {}", path.display()))
    }

    fn parse(text: &str, dir: &Path) -> Result<SpecFile> {
        let raw: RawFile = toml::from_str(text)?;
        if raw.test.is_empty() {
            bail!("there are no [[test]] entries");
        }
        let mut tests = Vec::new();
        for test in raw.test {
            if tests.iter().any(|t: &TestCase| t.name == test.name) {
                bail!("two tests are named `{}`", test.name);
            }
            let statements = match (&test.call, &test.steps) {
                (Some(call), None) => vec![Statement::Call(parse_call(call).with_context(|| format!("in test `{}`", test.name))?)],
                (None, Some(steps)) => parse_script(steps).with_context(|| format!("in test `{}`", test.name))?,
                _ => bail!("test `{}` needs either `call` or `steps`", test.name),
            };
            tests.push(TestCase { name: test.name, statements });
        }
        let defaults = Options::default();
        let options = Options {
            seed: raw.seed.unwrap_or(defaults.seed),
            iterations: raw.iterations.unwrap_or(defaults.iterations),
            ..defaults
        };
        Ok(SpecFile { wasm: dir.join(raw.wasm), options, tests })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_file() {
        let minimal = SpecFile::parse("wasm = \"m.wasm\"\n[[test]]\nname = \"t\"\ncall = \"f()\"", Path::new(".")).unwrap();
        assert_eq!((minimal.options.seed, minimal.options.iterations, minimal.options.secret_random), (1, 4, true));
    }

    #[test]
    fn mistakes_are_reported() {
        for (text, reason) in [
            ("wasm = \"m\"", "no [[test]]"),
            ("wasm = \"m\"\ntypo = 1\n[[test]]\nname = \"t\"\ncall = \"f()\"", "typo"),
            ("wasm = \"m\"\n[[test]]\nname = \"t\"", "needs either"),
            ("wasm = \"m\"\n[[test]]\nname = \"t\"\ncall = \"f()\"\nsteps = \"f()\"", "needs either"),
            ("wasm = \"m\"\n[[test]]\nname = \"t\"\ncall = \"f(\"", "in test `t`"),
            ("wasm = \"m\"\n[[test]]\nname = \"t\"\ncall = \"f()\"\n[[test]]\nname = \"t\"\ncall = \"f()\"", "two tests"),
        ] {
            let error = format!("{:#}", SpecFile::parse(text, Path::new(".")).unwrap_err());
            assert!(error.contains(reason), "{text}: {error}");
        }
    }
}
