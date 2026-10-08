use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::template::Template;

pub fn candidate_count(template: &Template, lists: &HashMap<String, Vec<String>>) -> Result<u128> {
    template.list_variables().try_fold(1_u128, |total, name| {
        let Some(list) = lists.get(name) else {
            bail!("wordlist '${name}' is not loaded");
        };
        Ok(total.saturating_mul(list.len() as u128))
    })
}

pub struct CandidateIter<'a> {
    template: &'a Template,
    domain: &'a str,
    variable_names: Vec<&'a str>,
    lists: Vec<&'a [String]>,
    indices: Vec<usize>,
    done: bool,
}

impl<'a> CandidateIter<'a> {
    pub fn new(
        template: &'a Template,
        domain: &'a str,
        wordlists: &'a HashMap<String, Vec<String>>,
    ) -> Result<Self> {
        let variable_names: Vec<_> = template.list_variables().collect();
        let mut lists = Vec::with_capacity(variable_names.len());
        for name in &variable_names {
            let Some(list) = wordlists.get(*name) else {
                bail!("wordlist '${name}' is not loaded");
            };
            lists.push(list.as_slice());
        }
        let done = lists.is_empty() || lists.iter().any(|list| list.is_empty());
        let indices = vec![0; lists.len()];
        Ok(Self {
            template,
            domain,
            variable_names,
            lists,
            indices,
            done,
        })
    }

    fn advance(&mut self) {
        for position in (0..self.indices.len()).rev() {
            self.indices[position] += 1;
            if self.indices[position] < self.lists[position].len() {
                return;
            }
            self.indices[position] = 0;
        }
        self.done = true;
    }
}

impl Iterator for CandidateIter<'_> {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut values = HashMap::with_capacity(self.variable_names.len());
        for (position, name) in self.variable_names.iter().enumerate() {
            values.insert(*name, self.lists[position][self.indices[position]].as_str());
        }
        let candidate = self
            .template
            .render(self.domain, |name| values.get(name).copied());
        self.advance();
        Some(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cartesian_product_has_stable_order() {
        let mut lists = HashMap::new();
        lists.insert("fname".into(), vec!["amy".into(), "bob".into()]);
        lists.insert("lname".into(), vec!["lee".into(), "fox".into()]);
        let template = Template::parse("$fname.$lname", lists.keys().cloned()).unwrap();
        let values: Vec<_> = CandidateIter::new(&template, "example.com", &lists)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(
            values,
            [
                "amy.lee@example.com",
                "amy.fox@example.com",
                "bob.lee@example.com",
                "bob.fox@example.com",
            ]
        );
    }
}
