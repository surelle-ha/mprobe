use std::collections::HashSet;

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Literal(String),
    Variable(String),
}

#[derive(Debug, Clone)]
pub struct Template {
    segments: Vec<Segment>,
    variables: Vec<String>,
}

impl Template {
    pub fn parse(input: &str, available: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut available: Vec<String> = available.into_iter().collect();
        available.push("domain".to_owned());
        available.sort_by_key(|name| std::cmp::Reverse(name.len()));
        available.dedup();

        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut variables = Vec::new();
        let mut seen = HashSet::new();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '\\' && i + 1 < chars.len() {
                literal.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if chars[i] != '$' {
                literal.push(chars[i]);
                i += 1;
                continue;
            }

            if !literal.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut literal)));
            }

            let (name, consumed) = if chars.get(i + 1) == Some(&'{') {
                let Some(relative_end) = chars[i + 2..].iter().position(|ch| *ch == '}') else {
                    bail!("unclosed variable in combination template");
                };
                let end = i + 2 + relative_end;
                let name: String = chars[i + 2..end].iter().collect();
                if !available.iter().any(|candidate| candidate == &name) {
                    bail!("unknown template variable '${{{name}}}'");
                }
                (name, end - i + 1)
            } else {
                let remainder: String = chars[i + 1..].iter().collect();
                let Some(name) = available
                    .iter()
                    .find(|candidate| remainder.starts_with(candidate.as_str()))
                else {
                    let attempted: String = chars[i + 1..]
                        .iter()
                        .take_while(|ch| ch.is_ascii_alphanumeric() || **ch == '_')
                        .collect();
                    if attempted.is_empty() {
                        bail!("a '$' in a combination must be followed by a variable name");
                    }
                    bail!("unknown template variable '${attempted}'");
                };
                (name.clone(), name.chars().count() + 1)
            };

            if seen.insert(name.clone()) {
                variables.push(name.clone());
            }
            segments.push(Segment::Variable(name));
            i += consumed;
        }

        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        if variables.iter().all(|name| name == "domain") {
            bail!("combination must contain at least one wordlist variable");
        }

        Ok(Self {
            segments,
            variables,
        })
    }

    pub fn variables(&self) -> impl Iterator<Item = &str> {
        self.variables.iter().map(String::as_str)
    }

    pub fn list_variables(&self) -> impl Iterator<Item = &str> {
        self.variables().filter(|name| *name != "domain")
    }

    pub fn renders_full_address(&self) -> bool {
        self.variables.iter().any(|name| name == "domain")
            || self
                .segments
                .iter()
                .any(|segment| matches!(segment, Segment::Literal(value) if value.contains('@')))
    }

    pub fn render<'a>(
        &self,
        domain: &str,
        values: impl Fn(&str) -> Option<&'a str>,
    ) -> Result<String> {
        let mut output = String::new();
        for segment in &self.segments {
            match segment {
                Segment::Literal(value) => output.push_str(value),
                Segment::Variable(name) if name == "domain" => output.push_str(domain),
                Segment::Variable(name) => {
                    let Some(value) = values(name) else {
                        bail!("no value supplied for '${name}'");
                    };
                    output.push_str(value);
                }
            }
        }
        if !self.renders_full_address() {
            output.push('@');
            output.push_str(domain);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        vec!["fname".into(), "lname".into(), "petname".into()]
    }

    #[test]
    fn parses_underscores_without_braces() {
        let template = Template::parse("$fname_$lname", names()).unwrap();
        assert_eq!(
            template
                .render("example.com", |name| match name {
                    "fname" => Some("john"),
                    "lname" => Some("doe"),
                    _ => None,
                })
                .unwrap(),
            "john_doe@example.com"
        );
    }

    #[test]
    fn supports_braces_domain_and_escaped_punctuation() {
        let template = Template::parse("${fname}\\.${lname}@$domain", names()).unwrap();
        assert_eq!(
            template
                .render("example.com", |name| match name {
                    "fname" => Some("jane"),
                    "lname" => Some("doe"),
                    _ => None,
                })
                .unwrap(),
            "jane.doe@example.com"
        );
    }

    #[test]
    fn rejects_unknown_variable() {
        let error = Template::parse("$first.$lname", names()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unknown template variable '$first'")
        );
    }
}
