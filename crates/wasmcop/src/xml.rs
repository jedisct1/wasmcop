use anyhow::{Context, Result};
use quick_xml::Reader;
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::Event;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ValgrindOutput {
    pub errors: Vec<ValgrindError>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValgrindError {
    pub kind: String,
    pub what: String,
    /// How many times this error happened.
    /// Valgrind folds duplicates together.
    pub count: u64,
    pub frames: Vec<Frame>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Frame {
    pub ip: u64,
    pub function: Option<String>,
}

#[derive(Default)]
struct Element {
    name: String,
    text: String,
    children: Vec<Element>,
}

impl Element {
    fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

fn parse_tree(text: &str) -> Result<Element> {
    let mut reader = Reader::from_str(text);
    let mut stack = vec![Element::default()];
    loop {
        match reader.read_event().context("malformed Valgrind XML")? {
            Event::Start(start) => {
                let name = start.name().as_ref().to_string();
                stack.push(Element { name, ..Element::default() });
            }
            Event::End(_) => {
                let element = stack.pop().context("unbalanced Valgrind XML")?;
                stack.last_mut().context("unbalanced Valgrind XML")?.children.push(element);
            }
            Event::Text(text) => {
                stack.last_mut().context("text outside an element")?.text.push_str(&text);
            }
            Event::GeneralRef(reference) => {
                let replacement = resolve_xml_entity(&reference).with_context(|| format!("unknown XML entity {}", &*reference))?;
                stack.last_mut().context("text outside an element")?.text.push_str(replacement);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let [root] = <[Element; 1]>::try_from(stack).map_err(|_| anyhow::anyhow!("truncated Valgrind XML"))?;
    Ok(root)
}

pub fn parse(text: &str) -> Result<ValgrindOutput> {
    let root = parse_tree(text)?;
    let output = root.child("valgrindoutput").context("this is not Valgrind XML")?;

    let mut counts = HashMap::new();
    if let Some(error_counts) = output.child("errorcounts") {
        for pair in error_counts.children_named("pair") {
            if let (Some(unique), Some(count)) = (pair.text_of("unique"), pair.text_of("count")) {
                counts.insert(unique.to_string(), count.parse::<u64>().context("bad error count")?);
            }
        }
    }

    let mut errors = Vec::new();
    for element in output.children_named("error") {
        let unique = element.text_of("unique").context("error without an id")?;
        let mut frames = Vec::new();
        for frame in element.child("stack").context("error without a stack")?.children_named("frame") {
            let ip = frame.text_of("ip").context("frame without an address")?;
            let digits = ip.strip_prefix("0x").context("frame address is not hex")?;
            frames.push(Frame {
                ip: u64::from_str_radix(digits, 16).context("bad frame address")?,
                function: frame.text_of("fn").map(str::to_string),
            });
        }
        errors.push(ValgrindError {
            kind: element.text_of("kind").context("error without a kind")?.to_string(),
            what: element.text_of("what").unwrap_or_default().to_string(),
            count: counts.get(unique).copied().unwrap_or(1),
            frames,
        });
    }
    Ok(ValgrindOutput { errors })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_counts_and_escapes() {
        let xml = r#"<?xml version="1.0"?>
<valgrindoutput>
  <protocolversion>6</protocolversion>
  <error>
    <unique>0x1</unique>
    <kind>UninitCondition</kind>
    <what>Conditional jump</what>
    <stack>
      <frame><ip>0x4A95012</ip></frame>
      <frame><ip>0x10</ip><fn>foo&lt;T&gt;::bar</fn></frame>
    </stack>
  </error>
  <errorcounts><pair><count>5</count><unique>0x1</unique></pair></errorcounts>
</valgrindoutput>"#;
        let output = parse(xml).unwrap();
        let error = &output.errors[0];
        assert_eq!(error.kind, "UninitCondition");
        assert_eq!(error.count, 5);
        assert_eq!(error.frames[0], Frame { ip: 0x4A95012, function: None });
        assert_eq!(error.frames[1].function.as_deref(), Some("foo<T>::bar"));
    }

    #[test]
    fn truncated_xml_is_an_error() {
        assert!(parse("<valgrindoutput><error>").is_err());
        assert!(parse("<other></other>").is_err());
    }
}
