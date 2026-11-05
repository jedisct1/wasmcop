//! TOML spec files, for tests with several steps.

use crate::resolve::{ImportOverride, Literal, Options, TestCase};
use crate::syntax::{Statement, parse_call, parse_script};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wasmcop_job::{Alloc, Wasi};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    wasm: PathBuf,
    iterations: Option<u32>,
    seed: Option<u64>,
    random: Option<String>,
    alloc: Option<String>,
    #[serde(default)]
    wasi: RawWasi,
    #[serde(default)]
    imports: BTreeMap<String, RawImport>,
    #[serde(default)]
    test: Vec<RawTest>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWasi {
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawImport {
    Integer(i64),
    Float(f64),
    Text(String),
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
        let secret_random = match raw.random.as_deref() {
            None | Some("secret") => true,
            Some("public") => false,
            Some(other) => bail!("random must be \"secret\" or \"public\", not `{other}`"),
        };
        let alloc = match raw.alloc.as_deref() {
            None => None,
            Some("grow") => Some(Alloc::Grow),
            Some(other) => match other.strip_prefix("export:") {
                Some(name) if !name.is_empty() => Some(Alloc::Malloc(name.to_string())),
                _ => bail!("alloc must be \"grow\" or \"export:name\", not `{other}`"),
            },
        };
        let imports = raw
            .imports
            .into_iter()
            .map(|(name, value)| {
                let action = match value {
                    RawImport::Text(text) if text == "trap" => ImportOverride::Trap,
                    RawImport::Text(text) => return Err(anyhow!("import {name}: expected \"trap\" or a number, not `{text}`")),
                    RawImport::Integer(value) => ImportOverride::Constant(Literal::Int(value.into())),
                    RawImport::Float(value) => ImportOverride::Constant(Literal::Float(value)),
                };
                Ok((name, action))
            })
            .collect::<Result<_>>()?;
        let defaults = Options::default();
        let options = Options {
            seed: raw.seed.unwrap_or(defaults.seed),
            iterations: raw.iterations.unwrap_or(defaults.iterations),
            secret_random,
            alloc,
            wasi: Wasi { args: raw.wasi.args, env: raw.wasi.env.into_iter().collect() },
            imports,
        };
        Ok(SpecFile { wasm: dir.join(raw.wasm), options, tests })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
        wasm = "m.wasm"
        iterations = 8
        seed = 42
        random = "public"
        alloc = "export:my_alloc"

        [wasi]
        args = ["a"]
        env = { K = "V" }

        [imports]
        "env.abort" = "trap"
        "env.pid" = 7
        "env.scale" = 1.5

        [[test]]
        name = "one"
        call = "f(1)"

        [[test]]
        name = "two"
        steps = """
        x = out(4)
        f(x)
        """
    "#;

    #[test]
    fn a_complete_file() {
        let file = SpecFile::parse(FULL, Path::new("/dir")).unwrap();
        assert_eq!(file.wasm, Path::new("/dir/m.wasm"));
        assert_eq!(file.tests.len(), 2);
        assert_eq!(file.tests[1].statements.len(), 2);
        let options = file.options;
        assert_eq!(options.imports["env.abort"], ImportOverride::Trap);
        assert_eq!(options.imports["env.pid"], ImportOverride::Constant(Literal::Int(7)));
        assert_eq!(options.imports["env.scale"], ImportOverride::Constant(Literal::Float(1.5)));
        assert_eq!(options.wasi.env, [("K".to_string(), "V".to_string())]);
        assert_eq!((options.seed, options.iterations, options.secret_random), (42, 8, false));
        assert!(matches!(options.alloc, Some(Alloc::Malloc(ref name)) if name == "my_alloc"));

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
            ("wasm = \"m\"\nrandom = \"maybe\"\n[[test]]\nname = \"t\"\ncall = \"f()\"", "random must be"),
            ("wasm = \"m\"\nalloc = \"x\"\n[[test]]\nname = \"t\"\ncall = \"f()\"", "alloc must be"),
            ("wasm = \"m\"\n[imports]\n\"e.f\" = \"go\"\n[[test]]\nname = \"t\"\ncall = \"f()\"", "expected \"trap\""),
            ("wasm = \"m\"\n[[test]]\nname = \"t\"\ncall = \"f()\"\n[[test]]\nname = \"t\"\ncall = \"f()\"", "two tests"),
        ] {
            let error = format!("{:#}", SpecFile::parse(text, Path::new(".")).unwrap_err());
            assert!(error.contains(reason), "{text}: {error}");
        }
    }
}
