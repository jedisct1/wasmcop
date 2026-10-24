use anyhow::{Context, Result};
use wasmparser::BinaryReader;

const SECTION_EXPORT: u8 = 7;
const SECTION_START: u8 = 8;
const EXPORT_NAME: &str = "__wasmcop_start";

/// A module ready to compile, and how its offsets differ from the original file.
pub struct Prepared {
    pub wasm: Vec<u8>,
    /// The export to call right after instantiation, if the module has a start function.
    pub start_export: Option<String>,
    /// Add this to an offset in `wasm` to get the offset in the original file.
    pub offset_shift: i64,
}

struct Section {
    id: u8,
    /// Where the section begins, including its header.
    start: usize,
    body: std::ops::Range<usize>,
}

fn read_u32(bytes: &[u8], position: &mut usize) -> Result<u32> {
    let mut reader = BinaryReader::new(bytes.get(*position..).context("truncated wasm module")?, 0);
    let value = reader.read_var_u32().context("malformed wasm module")?;
    *position += reader.current_position();
    Ok(value)
}

fn write_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn sections(wasm: &[u8]) -> Result<Vec<Section>> {
    let mut sections = Vec::new();
    let mut position = 8;
    while position < wasm.len() {
        let start = position;
        let id = wasm[position];
        position += 1;
        let size = read_u32(wasm, &mut position)? as usize;
        let end = position.checked_add(size).filter(|end| *end <= wasm.len()).context("truncated wasm module")?;
        sections.push(Section { id, start, body: position..end });
        position = end;
    }
    Ok(sections)
}

fn write_section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    write_u32(out, body.len() as u32);
    out.extend_from_slice(body);
}

/// An export name the module isn't already using.
fn free_name(wasm: &[u8]) -> String {
    let mut name = EXPORT_NAME.to_string();
    while wasm.windows(name.len()).any(|window| window == name.as_bytes()) {
        name.push('_');
    }
    name
}

/// Turns the start section into an export that the runner calls after instantiation, since imports called from a start function need the module's memory, and wasmer only hands that over afterwards.
///
/// Function bodies aren't touched, so the generated code stays the same.
pub fn defer_start(wasm: &[u8]) -> Result<Prepared> {
    let sections = sections(wasm)?;
    let Some(start) = sections.iter().find(|s| s.id == SECTION_START) else {
        return Ok(Prepared { wasm: wasm.to_vec(), start_export: None, offset_shift: 0 });
    };
    let mut position = start.body.start;
    let function = read_u32(wasm, &mut position)?;

    let name = free_name(wasm);
    let mut entry = Vec::new();
    write_u32(&mut entry, name.len() as u32);
    entry.extend_from_slice(name.as_bytes());
    entry.push(0);
    write_u32(&mut entry, function);

    let exports = sections.iter().find(|s| s.id == SECTION_EXPORT);
    let new_exports = match exports {
        Some(section) => {
            let mut position = section.body.start;
            let count = read_u32(wasm, &mut position)?;
            let mut body = Vec::new();
            write_u32(&mut body, count + 1);
            body.extend_from_slice(&wasm[position..section.body.end]);
            body.extend_from_slice(&entry);
            body
        }
        None => {
            let mut body = Vec::new();
            write_u32(&mut body, 1);
            body.extend_from_slice(&entry);
            body
        }
    };

    let mut out = wasm[..8].to_vec();
    for section in &sections {
        let original = &wasm[section.start..section.body.end];
        match section.id {
            SECTION_EXPORT => write_section(&mut out, SECTION_EXPORT, &new_exports),
            // With no export section, this is where one has to go.
            SECTION_START if exports.is_none() => write_section(&mut out, SECTION_EXPORT, &new_exports),
            SECTION_START => {}
            _ => out.extend_from_slice(original),
        }
    }
    let offset_shift = wasm.len() as i64 - out.len() as i64;
    Ok(Prepared { wasm: out, start_export: Some(name), offset_shift })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;
    use wasmparser::{Parser, Payload};

    fn parts(wasm: &[u8]) -> (bool, Vec<String>, usize) {
        let (mut has_start, mut exports, mut code_start) = (false, Vec::new(), 0);
        for payload in Parser::new(0).parse_all(wasm) {
            match payload.unwrap() {
                Payload::StartSection { .. } => has_start = true,
                Payload::ExportSection(reader) => exports.extend(reader.into_iter().map(|e| e.unwrap().name.to_string())),
                Payload::CodeSectionStart { unchecked_range, .. } => code_start = unchecked_range.start as usize,
                _ => {}
            }
        }
        (has_start, exports, code_start)
    }

    #[test]
    fn start_becomes_an_export_with_or_without_an_export_section() {
        for (module, exports) in [
            (r#"(module (func $s) (start $s))"#, vec![EXPORT_NAME]),
            (r#"(module (func $s) (func (export "f")) (start $s))"#, vec!["f", EXPORT_NAME]),
        ] {
            let wasm = wat::parse_str(module).unwrap();
            let prepared = defer_start(&wasm).unwrap();
            wasmparser::validate(&prepared.wasm).unwrap();
            let (has_start, names, code) = parts(&prepared.wasm);
            assert!(!has_start);
            assert_eq!(names, exports);
            assert_eq!(prepared.start_export.as_deref(), Some(EXPORT_NAME));
            assert_eq!(code as i64 + prepared.offset_shift, parts(&wasm).2 as i64);
        }
    }

    #[test]
    fn modules_without_a_start_are_left_alone() {
        let wasm = wat::parse_str(r#"(module (func (export "f")))"#).unwrap();
        let prepared = defer_start(&wasm).unwrap();
        assert_eq!(prepared.wasm, wasm);
        assert_eq!((prepared.start_export, prepared.offset_shift), (None, 0));
    }

    #[test]
    fn invalid_start_sections_are_refused_before_rewriting() {
        let returns_a_value = wat::parse_str(r#"(module (func $s (result i32) (i32.const 1)) (func (export "f")) (start $s))"#).unwrap();
        assert!(compile::validate(&returns_a_value).is_err());

        let valid = wat::parse_str(r#"(module (func $s) (start $s))"#).unwrap();
        compile::validate(&valid).unwrap();
        let all = sections(&valid).unwrap();
        let start = all.iter().find(|s| s.id == SECTION_START).unwrap();
        let bytes = &valid[start.start..start.body.end];

        let mut duplicated = valid.clone();
        duplicated.splice(start.body.end..start.body.end, bytes.iter().copied());
        assert!(compile::validate(&duplicated).is_err());

        let mut out_of_order = valid.clone();
        out_of_order.drain(start.start..start.body.end);
        out_of_order.extend_from_slice(bytes);
        assert!(compile::validate(&out_of_order).is_err());
    }

    #[test]
    fn the_export_name_never_collides() {
        let wasm = wat::parse_str(format!(r#"(module (func $s) (func (export "{EXPORT_NAME}")) (start $s))"#)).unwrap();
        let prepared = defer_start(&wasm).unwrap();
        wasmparser::validate(&prepared.wasm).unwrap();
        assert_eq!(prepared.start_export.unwrap(), format!("{EXPORT_NAME}_"));
    }
}
