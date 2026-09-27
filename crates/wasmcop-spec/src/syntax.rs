//! Parses calls like `mac(tag: out(32), m: bytes(64), len(m), k: secret bytes(32))` and multi-step scripts.

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Bind { names: Vec<String>, value: Bound },
    Call(Call),
    Declassify(Target),
    Poison(Target),
    Expect { target: String, bytes: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Bound {
    Arg(Arg),
    Call(Call),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub function: String,
    pub args: Vec<Arg>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Arg {
    pub name: Option<String>,
    pub secret: bool,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i128),
    Float(f64),
    Rand,
    Bytes { len: u32, fill: Fill, options: BufferOptions },
    Hex { bytes: Vec<u8>, options: BufferOptions },
    Out { len: u32, options: BufferOptions },
    Len(String),
    Ref(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fill {
    Random,
    Zero,
    Ones,
    Byte(u8),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BufferOptions {
    pub align: Option<u32>,
    pub at: Option<u32>,
    pub secret: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Name(String),
    Range { address: u32, length: u32 },
}

pub fn parse_call(input: &str) -> Result<Call> {
    let mut parser = Parser::new(input);
    let call = parser.call_at_start()?;
    parser.skip_space();
    if !parser.at_end() {
        return parser.error("unexpected text after the call");
    }
    Ok(call)
}

/// One statement per line.
/// `;` also separates statements and `#` starts a comment.
pub fn parse_script(input: &str) -> Result<Vec<Statement>> {
    let mut parser = Parser::new(input);
    let mut statements = Vec::new();
    loop {
        parser.skip_blank_lines();
        if parser.at_end() {
            return Ok(statements);
        }
        statements.push(parser.statement()?);
        parser.skip_space();
        if !parser.at_end() && !parser.at_statement_end() {
            return parser.error("expected the end of the statement");
        }
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    /// Inside parentheses a newline is just whitespace.
    depth: u32,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Parser { input, pos: 0, depth: 0 }
    }

    fn error<T>(&self, message: &str) -> Result<T> {
        let line_start = self.input[..self.pos].rfind('\n').map_or(0, |i| i + 1);
        let line_end = self.input[self.pos..].find('\n').map_or(self.input.len(), |i| self.pos + i);
        let column = self.input[line_start..self.pos].chars().count();
        bail!(
            "{message}\n  {}\n  {}^",
            &self.input[line_start..line_end],
            " ".repeat(column)
        )
    }

    fn rest(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn at_statement_end(&self) -> bool {
        matches!(self.peek(), Some('\n' | ';' | '#'))
    }

    fn skip_space(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' || (c == '\n' && self.depth > 0) {
                self.pos += c.len_utf8();
            } else if c == '#' && self.depth > 0 {
                self.skip_comment();
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) {
        self.pos += self.rest().find('\n').unwrap_or(self.rest().len());
    }

    fn skip_blank_lines(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' => self.pos += 1,
                '#' => self.skip_comment(),
                _ => break,
            }
        }
    }

    fn eat(&mut self, expected: char) -> bool {
        self.skip_space();
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<()> {
        if self.eat(expected) {
            Ok(())
        } else {
            self.error(&format!("expected `{expected}`"))
        }
    }

    fn open(&mut self) -> Result<()> {
        self.expect('(')?;
        self.depth += 1;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.expect(')')?;
        self.depth -= 1;
        Ok(())
    }

    /// Export names can hold almost anything, but these are the characters compilers actually use.
    fn identifier(&mut self) -> Option<String> {
        self.skip_space();
        let rest = self.rest();
        let first = rest.chars().next()?;
        if !(first.is_alphabetic() || first == '_' || first == '$') {
            return None;
        }
        let end = rest
            .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '$' | '.')))
            .unwrap_or(rest.len());
        self.pos += end;
        Some(rest[..end].to_string())
    }

    fn peek_identifier(&mut self) -> Option<String> {
        let saved = self.pos;
        let identifier = self.identifier();
        self.pos = saved;
        identifier
    }

    fn require_identifier(&mut self, what: &str) -> Result<String> {
        match self.identifier() {
            Some(identifier) => Ok(identifier),
            None => self.error(&format!("expected {what}")),
        }
    }

    fn number_text(&mut self) -> Option<&'a str> {
        self.skip_space();
        let rest = self.rest();
        let mut end = usize::from(rest.starts_with('-'));
        if rest[end..].starts_with("0x") || rest[end..].starts_with("0X") {
            end += 2;
            end += rest[end..].find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len() - end);
        } else {
            let digits = rest[end..].find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len() - end);
            if digits == 0 {
                return None;
            }
            end += digits;
            // Needs a digit after the point so `16..48` stays a range.
            if rest[end..].starts_with('.') && rest[end + 1..].starts_with(|c: char| c.is_ascii_digit()) {
                end += 1;
                end += rest[end..].find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len() - end);
            }
            if rest[end..].starts_with(['e', 'E']) {
                let mut exponent = end + 1;
                if rest[exponent..].starts_with(['+', '-']) {
                    exponent += 1;
                }
                let digits = rest[exponent..].find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len() - exponent);
                if digits > 0 {
                    end = exponent + digits;
                }
            }
        }
        self.pos += end;
        Some(&rest[..end])
    }

    fn integer(&mut self, what: &str) -> Result<i128> {
        let start = self.pos;
        let Some(text) = self.number_text() else {
            return self.error(&format!("expected {what}"));
        };
        match parse_integer(text) {
            Some(value) => Ok(value),
            None => {
                self.pos = start;
                self.error(&format!("expected {what}"))
            }
        }
    }

    fn u32_value(&mut self, what: &str) -> Result<u32> {
        let start = self.pos;
        let value = self.integer(what)?;
        match u32::try_from(value) {
            Ok(value) => Ok(value),
            Err(_) => {
                self.pos = start;
                self.error(&format!("{what} must fit in 32 bits"))
            }
        }
    }

    fn statement(&mut self) -> Result<Statement> {
        let name = self.require_identifier("a statement")?;
        if self.peek_is('(') {
            return self.builtin_or_call(name);
        }
        let mut names = vec![name];
        while self.eat(',') {
            names.push(self.require_identifier("a name")?);
        }
        self.expect('=')?;
        let value = self.bound()?;
        Ok(Statement::Bind { names, value })
    }

    fn peek_is(&mut self, expected: char) -> bool {
        self.skip_space();
        self.peek() == Some(expected)
    }

    fn builtin_or_call(&mut self, name: String) -> Result<Statement> {
        match name.as_str() {
            "declassify" => Ok(Statement::Declassify(self.target()?)),
            "poison" => Ok(Statement::Poison(self.target()?)),
            "expect" => {
                self.open()?;
                let target = self.require_identifier("the name of a buffer")?;
                self.expect(',')?;
                let keyword = self.require_identifier("hex(...)")?;
                if keyword != "hex" {
                    return self.error("expect compares against hex(...)");
                }
                let bytes = self.hex_body()?;
                self.close()?;
                Ok(Statement::Expect { target, bytes })
            }
            _ => Ok(Statement::Call(self.call_args(name)?)),
        }
    }

    fn target(&mut self) -> Result<Target> {
        self.open()?;
        let target = if let Some(name) = self.identifier() {
            Target::Name(name)
        } else {
            let address = self.u32_value("an address or a name")?;
            self.expect(',')?;
            let length = self.u32_value("a length")?;
            Target::Range { address, length }
        };
        self.close()?;
        Ok(target)
    }

    fn call_at_start(&mut self) -> Result<Call> {
        let name = self.require_identifier("a function name")?;
        self.call_args(name)
    }

    fn call_args(&mut self, function: String) -> Result<Call> {
        self.open()?;
        let mut args = Vec::new();
        if !self.peek_is(')') {
            loop {
                args.push(self.arg()?);
                if !self.eat(',') {
                    break;
                }
            }
        }
        self.close()?;
        Ok(Call { function, args })
    }

    fn bound(&mut self) -> Result<Bound> {
        let saved = self.pos;
        if let Some(name) = self.identifier()
            && !is_value_keyword(&name)
            && self.peek_is('(')
        {
            return Ok(Bound::Call(self.call_args(name)?));
        }
        self.pos = saved;
        let arg = self.arg()?;
        if arg.name.is_some() {
            return self.error("a binding is already named");
        }
        Ok(Bound::Arg(arg))
    }

    fn arg(&mut self) -> Result<Arg> {
        let mut name = None;
        let saved = self.pos;
        if let Some(identifier) = self.identifier() {
            if self.eat(':') {
                name = Some(identifier);
            } else {
                self.pos = saved;
            }
        }
        let secret = self.peek_identifier().as_deref() == Some("secret");
        if secret {
            self.identifier();
        }
        let value = self.value()?;
        Ok(Arg { name, secret, value })
    }

    fn value(&mut self) -> Result<Value> {
        self.skip_space();
        if let Some(identifier) = self.identifier() {
            return match identifier.as_str() {
                "rand" => Ok(Value::Rand),
                "bytes" => self.bytes(),
                "hex" => self.hex(),
                "out" => self.out(),
                "len" => {
                    self.open()?;
                    let name = self.require_identifier("the name of a buffer")?;
                    self.close()?;
                    Ok(Value::Len(name))
                }
                _ => Ok(Value::Ref(identifier)),
            };
        }
        let start = self.pos;
        let Some(text) = self.number_text() else {
            return self.error("expected an argument");
        };
        if let Some(value) = parse_integer(text) {
            return Ok(Value::Int(value));
        }
        match text.parse::<f64>() {
            Ok(value) => Ok(Value::Float(value)),
            Err(_) => {
                self.pos = start;
                self.error("expected a number")
            }
        }
    }

    fn bytes(&mut self) -> Result<Value> {
        self.open()?;
        let len = self.u32_value("a byte count")?;
        let mut fill = Fill::Random;
        let mut options = BufferOptions::default();
        while self.eat(',') {
            match self.peek_identifier().as_deref() {
                Some("zero") => {
                    self.identifier();
                    fill = Fill::Zero;
                }
                Some("ones") => {
                    self.identifier();
                    fill = Fill::Ones;
                }
                Some(_) => self.option(&mut options)?,
                None => {
                    let start = self.pos;
                    let value = self.integer("a fill byte")?;
                    match u8::try_from(value) {
                        Ok(byte) => fill = Fill::Byte(byte),
                        Err(_) => {
                            self.pos = start;
                            return self.error("a fill byte must be between 0 and 255");
                        }
                    }
                }
            }
        }
        self.close()?;
        Ok(Value::Bytes { len, fill, options })
    }

    fn hex(&mut self) -> Result<Value> {
        let bytes = self.hex_body_open()?;
        let mut options = BufferOptions::default();
        while self.eat(',') {
            self.option(&mut options)?;
        }
        self.close()?;
        Ok(Value::Hex { bytes, options })
    }

    fn hex_body(&mut self) -> Result<Vec<u8>> {
        let bytes = self.hex_body_open()?;
        self.close()?;
        Ok(bytes)
    }

    fn hex_body_open(&mut self) -> Result<Vec<u8>> {
        self.open()?;
        self.skip_space();
        let rest = self.rest();
        let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
        let Some(bytes) = wasmcop_job::from_hex(&rest[..end]) else {
            return self.error("hex needs an even number of digits");
        };
        self.pos += end;
        Ok(bytes)
    }

    fn out(&mut self) -> Result<Value> {
        self.open()?;
        let len = self.u32_value("a byte count")?;
        let mut options = BufferOptions::default();
        while self.eat(',') {
            self.option(&mut options)?;
        }
        self.close()?;
        if options.secret.is_some() {
            return self.error("output buffers start out public");
        }
        Ok(Value::Out { len, options })
    }

    fn option(&mut self, options: &mut BufferOptions) -> Result<()> {
        let name = self.require_identifier("an option")?;
        self.expect('=')?;
        match name.as_str() {
            "align" => options.align = Some(self.u32_value("an alignment")?),
            "at" => options.at = Some(self.u32_value("an address")?),
            "secret" => {
                let start = self.u32_value("the start of a range")?;
                if !self.rest().starts_with("..") {
                    return self.error("expected `..`");
                }
                self.pos += 2;
                options.secret = Some((start, self.u32_value("the end of a range")?));
            }
            _ => return self.error(&format!("unknown option `{name}`")),
        }
        Ok(())
    }
}

fn is_value_keyword(name: &str) -> bool {
    matches!(name, "bytes" | "hex" | "out" | "len")
}

fn parse_integer(text: &str) -> Option<i128> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text),
    };
    let magnitude = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<i128>().ok()?,
    };
    Some(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg_of(text: &str) -> Arg {
        parse_call(&format!("f({text})")).unwrap().args.remove(0)
    }

    #[test]
    fn arguments() {
        let call = parse_call("mac(tag: out(32), m: bytes(64), len(m), k: secret bytes(32))").unwrap();
        assert_eq!(call.function, "mac");
        assert_eq!(call.args[0].name.as_deref(), Some("tag"));
        assert_eq!(call.args[2].value, Value::Len("m".to_string()));
        assert!(call.args[3].secret && !call.args[1].secret);

        assert_eq!(arg_of("42").value, Value::Int(42));
        assert_eq!(arg_of("0x2a").value, Value::Int(42));
        assert_eq!(arg_of("-1").value, Value::Int(-1));
        assert_eq!(arg_of("1.5").value, Value::Float(1.5));
        assert_eq!(arg_of("1e3").value, Value::Float(1000.0));
        assert_eq!(arg_of("rand").value, Value::Rand);
        let secret = arg_of("secret rand");
        assert!(secret.secret);
        assert_eq!(secret.value, Value::Rand);

        let plain = BufferOptions::default();
        assert_eq!(arg_of("bytes(16)").value, Value::Bytes { len: 16, fill: Fill::Random, options: plain.clone() });
        assert_eq!(arg_of("bytes(16, zero)").value, Value::Bytes { len: 16, fill: Fill::Zero, options: plain.clone() });
        assert_eq!(arg_of("bytes(16, ones)").value, Value::Bytes { len: 16, fill: Fill::Ones, options: plain.clone() });
        assert_eq!(arg_of("bytes(16, 0xa5)").value, Value::Bytes { len: 16, fill: Fill::Byte(0xa5), options: plain.clone() });
        assert_eq!(arg_of("hex(00ffA5)").value, Value::Hex { bytes: vec![0, 255, 165], options: plain.clone() });
        assert_eq!(arg_of("out(64)").value, Value::Out { len: 64, options: plain });
        let options = BufferOptions { align: Some(64), at: Some(4096), secret: Some((16, 48)) };
        assert_eq!(
            arg_of("bytes(64, secret=16..48, align=64, at=4096)").value,
            Value::Bytes { len: 64, fill: Fill::Random, options }
        );
    }

    #[test]
    fn script_with_every_statement_kind() {
        let script = "
            # state lives across calls
            st  = out(256)
            key = secret bytes(32); msg = bytes(1024)
            hmac_init(st, key, len(key))
            a, b = split(msg,
                         len(msg))    # newlines are fine inside parentheses
            declassify(st)
            declassify(0x1000, 16)
            poison(key)
            expect(st, hex(00ff))
        ";
        let statements = parse_script(script).unwrap();
        assert_eq!(statements.len(), 9);
        assert!(matches!(&statements[4], Statement::Bind { names, value: Bound::Call(_) } if names.len() == 2));
        assert_eq!(statements[5], Statement::Declassify(Target::Name("st".to_string())));
        assert_eq!(statements[6], Statement::Declassify(Target::Range { address: 0x1000, length: 16 }));
        assert_eq!(statements[8], Statement::Expect { target: "st".to_string(), bytes: vec![0, 255] });

        let statements = parse_script("x = bytes(4)\ny = f(x)").unwrap();
        assert!(matches!(&statements[0], Statement::Bind { value: Bound::Arg(_), .. }));
        assert!(matches!(&statements[1], Statement::Bind { value: Bound::Call(_), .. }));
    }

    #[test]
    fn bad_input_is_an_error() {
        let error = parse_call("f(bytes(16, secret=4))").unwrap_err().to_string();
        assert!(error.contains("expected `..`"), "{error}");
        assert!(error.contains('^'), "{error}");
        assert!(parse_call("f(hex(abc))").unwrap_err().to_string().contains("even number"));
        assert!(parse_call("f(1) g").is_err());
        assert!(parse_call("f(bytes(1, 256))").is_err());
        assert!(parse_call("f(out(1, secret=0..1))").is_err());
        assert!(parse_script("f(1) g(2)").is_err());
        assert!(parse_call("f(bytes(99999999999))").is_err());
        assert!(parse_call("f(\u{20ac})").is_err());
        assert!(parse_script("x = bytes(4) \u{20ac}").is_err());
    }
}
