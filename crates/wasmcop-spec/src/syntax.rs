use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
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

    fn skip_space(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' || (c == '\n' && self.depth > 0) {
                self.pos += c.len_utf8();
            } else {
                break;
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

    fn peek_is(&mut self, expected: char) -> bool {
        self.skip_space();
        self.peek() == Some(expected)
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
                _ => self.error(&format!("unknown value `{identifier}`")),
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
        assert_eq!(arg_of("42").value, Value::Int(42));
        assert_eq!(arg_of("0x2a").value, Value::Int(42));
        assert_eq!(arg_of("-1").value, Value::Int(-1));
        assert_eq!(arg_of("1.5").value, Value::Float(1.5));
        assert_eq!(arg_of("1e3").value, Value::Float(1000.0));
        assert_eq!(arg_of("rand").value, Value::Rand);
        let secret = arg_of("secret rand");
        assert!(secret.secret);
        assert_eq!(secret.value, Value::Rand);
    }

    #[test]
    fn bad_input_is_an_error() {
        assert!(parse_call("f(1) g").is_err());
        assert!(parse_call("f(\u{20ac})").is_err());
    }
}
