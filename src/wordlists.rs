use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

pub const BUILTINS: &[(&str, &str, &str)] = &[
    (
        "fname",
        "wordlists/fname.txt",
        include_str!("../wordlists/fname.txt"),
    ),
    (
        "lname",
        "wordlists/lname.txt",
        include_str!("../wordlists/lname.txt"),
    ),
    (
        "petname",
        "wordlists/petname.txt",
        include_str!("../wordlists/petname.txt"),
    ),
    (
        "role",
        "wordlists/role.txt",
        include_str!("../wordlists/role.txt"),
    ),
];

pub fn builtin_names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|(name, _, _)| *name)
}

pub fn builtin_metadata() -> impl Iterator<Item = (&'static str, &'static str, usize)> {
    BUILTINS
        .iter()
        .map(|(name, path, content)| (*name, *path, parse_lines(content).len()))
}

pub fn load(
    named: &[(String, PathBuf)],
    positional: &[PathBuf],
    template_order: &[String],
) -> Result<HashMap<String, Vec<String>>> {
    let mut lists: HashMap<String, Vec<String>> = BUILTINS
        .iter()
        .map(|(name, _, content)| ((*name).to_owned(), parse_lines(content)))
        .collect();

    if positional.len() > template_order.len() {
        bail!(
            "received {} positional wordlists, but the combination has only {} variables",
            positional.len(),
            template_order.len()
        );
    }
    for (path, name) in positional.iter().zip(template_order) {
        lists.insert(name.clone(), read_file(path)?);
    }
    for (name, path) in named {
        lists.insert(name.clone(), read_file(path)?);
    }
    Ok(lists)
}

pub fn parse_named(value: &str) -> Result<(String, PathBuf)> {
    let Some((name, path)) = value.split_once('=') else {
        bail!("wordlist override must use NAME=FILE (for example: fname=staff.txt)");
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        bail!("invalid wordlist variable name '{name}'");
    }
    if path.is_empty() {
        bail!("wordlist path cannot be empty");
    }
    Ok((name.to_owned(), PathBuf::from(path)))
}

fn read_file(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("could not read wordlist {}", path.display()))?;
    let values = parse_lines(&content);
    if values.is_empty() {
        bail!("wordlist {} contains no usable entries", path.display());
    }
    Ok(values)
}

fn parse_lines(content: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let normalized = normalize_local_part(line);
            (!normalized.is_empty() && seen.insert(normalized.clone())).then_some(normalized)
        })
        .collect()
}

fn normalize_local_part(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-'))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn normalizes_comments_and_duplicates() {
        assert_eq!(
            parse_lines("# note\n Jane \njane\nO'Brien\n\n"),
            ["jane", "obrien"]
        );
    }

    #[test]
    fn positional_files_follow_template_order() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "Custom").unwrap();
        let lists = load(
            &[],
            &[file.path().to_owned()],
            &["fname".into(), "lname".into()],
        )
        .unwrap();
        assert_eq!(lists["fname"], ["custom"]);
        assert!(lists["lname"].len() > 10);
    }
}
