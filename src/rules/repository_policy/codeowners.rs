use std::collections::BTreeMap;
use std::path::Path;

use crate::findings::Finding;

use super::finding;

const MISSING_PATH: &str = "codeowners-path-missing";

pub(super) fn analyze(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in auxiliary.iter().filter(|(path, _)| is_codeowners(path)) {
        for entry in entries(source) {
            if auxiliary
                .get(&marker(entry.line, entry.pattern))
                .is_some_and(|exists| exists == "false")
            {
                findings.push(finding(
                    MISSING_PATH,
                    path,
                    entry.line,
                    format!("CODEOWNERS literal path `{}` does not exist", entry.pattern),
                    vec![normalized_target(entry.pattern).to_owned()],
                ));
            }
        }
    }
    findings
}

pub(super) fn existence_markers(
    root: &Path,
    auxiliary: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut existence = BTreeMap::new();
    let mut markers = Vec::new();
    for (_, source) in auxiliary.iter().filter(|(path, _)| is_codeowners(path)) {
        for entry in entries(source) {
            let target = normalized_target(entry.pattern);
            let exists = *existence
                .entry(target)
                .or_insert_with(|| literal_path_exists(root, target));
            markers.push((marker(entry.line, entry.pattern), exists.to_string()));
        }
    }
    markers
}

fn literal_path_exists(root: &Path, target: &str) -> bool {
    if root.join(target).exists() {
        return true;
    }
    if target.contains('/') {
        return false;
    }
    let mut directories = vec![root.to_owned()];
    while let Some(directory) = directories.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_name() == target {
                return true;
            }
            let path = entry.path();
            if path.is_dir() && !ignored_directory(&entry.file_name()) {
                directories.push(path);
            }
        }
    }
    false
}

fn ignored_directory(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(".git" | "node_modules" | "target" | ".dart_tool")
    )
}

struct Entry<'a> {
    line: usize,
    pattern: &'a str,
}

fn entries(source: &str) -> impl Iterator<Item = Entry<'_>> {
    source.lines().enumerate().filter_map(|(index, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.contains('\\') {
            return None;
        }
        let mut fields = line.split_ascii_whitespace();
        let pattern = fields.next()?;
        if fields.next().is_none() || !literal_pattern(pattern) {
            return None;
        }
        Some(Entry {
            line: index + 1,
            pattern,
        })
    })
}

fn literal_pattern(pattern: &str) -> bool {
    let target = normalized_target(pattern);
    !pattern.starts_with('!')
        && !pattern.contains(['*', '?', '[', ']'])
        && !target.is_empty()
        && target != "."
        && !Path::new(target)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn normalized_target(pattern: &str) -> &str {
    pattern.trim_start_matches('/').trim_end_matches('/')
}

fn marker(line: usize, pattern: &str) -> String {
    format!("@codeowners-exists/{line}:{pattern}")
}

fn is_codeowners(path: &str) -> bool {
    matches!(
        path,
        "CODEOWNERS" | ".github/CODEOWNERS" | "docs/CODEOWNERS"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reports_only_missing_literal_paths() {
        let root = tempdir().expect("temporary repository");
        std::fs::create_dir(root.path().join("src")).expect("source directory");
        std::fs::create_dir(root.path().join(".github")).expect("metadata directory");
        let source = "/src/ @team\n/docs/guide.md @docs\nCODEOWNERS @security\n*.rs @rust\nescaped\\ path @team\n";
        std::fs::write(root.path().join(".github/CODEOWNERS"), source).expect("CODEOWNERS fixture");
        let mut files = BTreeMap::from([(".github/CODEOWNERS".to_owned(), source.to_owned())]);
        files.extend(existence_markers(root.path(), &files));
        let findings = analyze(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].related_files, ["docs/guide.md"]);
    }

    #[test]
    fn ignores_comments_negation_and_globs() {
        let source = "# comment\n!src/generated @team\nsrc/** @team\n";
        assert_eq!(entries(source).count(), 0);
    }
}
