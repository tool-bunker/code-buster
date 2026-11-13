use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::findings::Finding;

use super::{finding, line_containing};

const UNSAFE_COMPILER_OPTION: &str = "ts-unsafe-compiler-option";
const CI_MISSING_TYPECHECK: &str = "ts-ci-missing-typecheck";

static COMPILER_OPTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\"compilerOptions\"\s*:\s*\{"#).expect("compilerOptions regex must compile")
});
static UNSAFE_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\"(strict|noImplicitAny|strictNullChecks)\"\s*:\s*false\b"#)
        .expect("unsafe TypeScript option regex must compile")
});
static CI_JAVASCRIPT_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:build|test|lint|check)\b")
        .expect("JavaScript CI command regex must compile")
});

pub(super) fn analyze(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = unsafe_compiler_options(auxiliary);
    findings.extend(missing_ci_typecheck(auxiliary));
    findings
}

fn unsafe_compiler_options(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in auxiliary.iter().filter(|(path, _)| is_tsconfig(path)) {
        let sanitized = strip_jsonc_comments(source);
        let Some(options) = COMPILER_OPTIONS.find(&sanitized) else {
            continue;
        };
        let open = options.end() - 1;
        let Some(close) = matching_brace(&sanitized, open) else {
            continue;
        };
        for matched in UNSAFE_OPTION.captures_iter(&sanitized[open + 1..close]) {
            let whole = matched.get(0).expect("unsafe option match must exist");
            let option = matched
                .get(1)
                .expect("unsafe option name must exist")
                .as_str();
            let offset = open + 1 + whole.start();
            findings.push(finding(
                UNSAFE_COMPILER_OPTION,
                path,
                1 + sanitized[..offset]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
                format!("TypeScript compiler option {option} is explicitly disabled"),
                Vec::new(),
            ));
        }
    }
    findings
}

fn missing_ci_typecheck(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let Some(source) = auxiliary.get("package.json") else {
        return Vec::new();
    };
    let Ok(package) = serde_json::from_str::<Value>(source) else {
        return Vec::new();
    };
    let Some(scripts) = package.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let typecheck_scripts = scripts
        .iter()
        .filter(|(name, command)| is_typecheck_script(name, command.as_str().unwrap_or_default()))
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    if typecheck_scripts.is_empty() {
        return Vec::new();
    }
    let ci_sources = auxiliary
        .iter()
        .filter(|(path, _)| is_ci_path(path))
        .map(|(_, source)| source.as_str())
        .collect::<Vec<_>>();
    if ci_sources.is_empty()
        || !ci_sources
            .iter()
            .any(|source| CI_JAVASCRIPT_COMMAND.is_match(source))
        || ci_runs_typecheck(&ci_sources, scripts, &typecheck_scripts)
    {
        return Vec::new();
    }
    let Some(script) = typecheck_scripts.first().copied() else {
        return Vec::new();
    };
    vec![finding(
        CI_MISSING_TYPECHECK,
        "package.json",
        line_containing(source, &format!("\"{script}\"")),
        format!("checked-in CI does not invoke declared `{script}` type checking"),
        ci_paths(auxiliary),
    )]
}

fn ci_runs_typecheck(
    ci_sources: &[&str],
    scripts: &serde_json::Map<String, Value>,
    typecheck_scripts: &BTreeSet<&str>,
) -> bool {
    ci_sources.iter().any(|source| {
        contains_typecheck_command(source)
            || typecheck_scripts
                .iter()
                .any(|name| invokes_script(source, name))
            || scripts.iter().any(|(name, command)| {
                invokes_script(source, name)
                    && command.as_str().is_some_and(|command| {
                        contains_typecheck_command(command)
                            || typecheck_scripts
                                .iter()
                                .any(|typecheck| invokes_script(command, typecheck))
                    })
            })
    })
}

fn contains_typecheck_command(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    let compact = lower.replace([' ', '\t'], "");
    compact.contains("tsc--noemit")
        || compact.contains("tsc-b")
        || compact.contains("vue-tsc")
        || compact.contains("svelte-check")
        || lower
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':'))
            })
            .any(is_typecheck_marker)
}

fn is_typecheck_marker(token: &str) -> bool {
    ["typecheck", "type-check", "type_check", "type:check"]
        .iter()
        .any(|prefix| token.starts_with(prefix))
        || matches!(
            token,
            "checktypes"
                | "check-types"
                | "check_types"
                | "check:types"
                | "tscheck"
                | "ts-check"
                | "ts_check"
                | "ts:check"
        )
}

fn invokes_script(source: &str, name: &str) -> bool {
    let source = source.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    [
        format!("npm run {name}"),
        format!("pnpm run {name}"),
        format!("pnpm {name}"),
        format!("yarn run {name}"),
        format!("yarn {name}"),
        format!("bun run {name}"),
    ]
    .iter()
    .any(|command| source.contains(command))
        || (source
            .split_ascii_whitespace()
            .map(clean_shell_token)
            .any(|token| matches!(token, "run-p" | "run-s" | "npm-run-all"))
            && source
                .split_ascii_whitespace()
                .map(clean_shell_token)
                .any(|token| token == name))
}

fn clean_shell_token(token: &str) -> &str {
    token.trim_matches(['\'', '"', '(', ')', ';', '&'])
}

fn is_typecheck_script(name: &str, command: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace(['-', '_', ':'], "");
    normalized.contains("typecheck")
        || normalized == "checktypes"
        || contains_typecheck_command(command)
}

fn is_tsconfig(path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "tsconfig.json" || (name.starts_with("tsconfig.") && name.ends_with(".json"))
}

fn is_ci_path(path: &str) -> bool {
    path == ".gitlab-ci.yml"
        || path == "azure-pipelines.yml"
        || path == "Jenkinsfile"
        || (path.starts_with(".github/workflows/")
            && (path.ends_with(".yml") || path.ends_with(".yaml")))
}

fn ci_paths(auxiliary: &BTreeMap<String, String>) -> Vec<String> {
    auxiliary
        .keys()
        .filter(|path| is_ci_path(path))
        .cloned()
        .collect()
}

pub(super) fn strip_jsonc_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = Vec::with_capacity(source.len());
    let mut index = 0;
    let mut quote = JsoncQuote::default();
    while index < bytes.len() {
        if quote.consume(bytes[index]) {
            output.push(bytes[index]);
            index += 1;
        } else if let Some(width) = jsonc_comment_width(&bytes[index..]) {
            output.extend(
                bytes[index..index + width]
                    .iter()
                    .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' }),
            );
            index += width;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).expect("masked JSONC must preserve UTF-8")
}

fn jsonc_comment_width(remaining: &[u8]) -> Option<usize> {
    if remaining.starts_with(b"//") {
        Some(
            remaining
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(remaining.len()),
        )
    } else if remaining.starts_with(b"/*") {
        Some(
            remaining[2..]
                .windows(2)
                .position(|pair| pair == b"*/")
                .map_or(remaining.len(), |end| end + 4),
        )
    } else {
        None
    }
}

#[derive(Default)]
struct JsoncQuote {
    active: Option<u8>,
    escaped: bool,
}

impl JsoncQuote {
    fn consume(&mut self, byte: u8) -> bool {
        if let Some(active) = self.active {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == active {
                self.active = None;
            }
            true
        } else if matches!(byte, b'\'' | b'"') {
            self.active = Some(byte);
            true
        } else {
            false
        }
    }
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0;
    let mut quote = JsoncQuote::default();
    let mut index = open;
    while index < bytes.len() {
        let byte = bytes[index];
        if quote.consume(byte) {
            index += 1;
            continue;
        }
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_jsonc_strings_unicode_crlf_and_unterminated_comments() {
        for (source, expected) in [
            (
                "{\"url\":\"é // /* \\\"\",'label':'# --'}//é\r\n",
                "{\"url\":\"é // /* \\\"\",'label':'# --'}     \n",
            ),
            ("é/*é\r\n*/x", "é     \n  x"),
            ("é/*é", "é    "),
            ("\"unterminated //é\\", "\"unterminated //é\\"),
        ] {
            assert_eq!(strip_jsonc_comments(source), expected);
            assert_eq!(strip_jsonc_comments(source).len(), source.len());
        }
    }

    #[test]
    fn matches_jsonc_braces_outside_escaped_strings() {
        let source = r#"{"é":"}\"{",'other':'{'}tail"#;
        assert_eq!(
            matching_brace(source, 0),
            Some(source.find("tail").unwrap() - 1)
        );
        assert_eq!(matching_brace(r#"{"nested":{"é":"}"}}"#, 0), Some(20));
        assert_eq!(matching_brace("{'unterminated }\\", 0), None);
        assert_eq!(matching_brace("{/* masked first */", 0), None);
    }

    #[test]
    fn reports_explicitly_disabled_safety_options_inside_compiler_options() {
        let files = BTreeMap::from([
            ("tsconfig.json".to_owned(), "{\n  // policy\n  \"compilerOptions\": {\n    \"strict\": false,\n    \"strictNullChecks\": false\n  },\n  \"strict\": false\n}".to_owned()),
            ("tsconfig.safe.json".to_owned(), "{\"compilerOptions\":{\"strict\":true,\"noImplicitAny\":true}}".to_owned()),
        ]);
        let findings = unsafe_compiler_options(&files);
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            [(UNSAFE_COMPILER_OPTION, 4), (UNSAFE_COMPILER_OPTION, 5)]
        );
    }

    #[test]
    fn reports_declared_typecheck_omitted_by_direct_ci_but_accepts_script_indirection() {
        let mut files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"scripts":{"typecheck":"tsc --noEmit","test":"vitest"}}"#.to_owned(),
            ),
            (
                ".github/workflows/ci.yml".to_owned(),
                "run: npm test".to_owned(),
            ),
        ]);
        assert_eq!(missing_ci_typecheck(&files).len(), 1);
        files.insert(
            ".github/workflows/ci.yml".to_owned(),
            "run: npm run typecheck\nrun: npm test".to_owned(),
        );
        assert!(missing_ci_typecheck(&files).is_empty());
        files.insert(
            "package.json".to_owned(),
            r#"{"scripts":{"typecheck":"tsc --noEmit","verify":"npm run typecheck && vitest"}}"#
                .to_owned(),
        );
        files.insert(
            ".github/workflows/ci.yml".to_owned(),
            "run: npm run verify".to_owned(),
        );
        assert!(missing_ci_typecheck(&files).is_empty());

        files.insert(
            "package.json".to_owned(),
            r#"{"scripts":{"typecheck-all":"tsgo --build","ci:compile":"pn typecheck-all"}}"#
                .to_owned(),
        );
        files.insert(
            ".github/workflows/ci.yml".to_owned(),
            "run: pn pipeline ts-check --include-workspace-root".to_owned(),
        );
        assert!(missing_ci_typecheck(&files).is_empty());

        files.insert(
            "package.json".to_owned(),
            r#"{"scripts":{"typescript":"tsc --noEmit","check-fixtures":"tsc --noEmit","types-and-precompiled":"run-p typescript check-fixtures"}}"#
                .to_owned(),
        );
        files.insert(
            ".github/workflows/ci.yml".to_owned(),
            "run: pnpm types-and-precompiled".to_owned(),
        );
        assert!(missing_ci_typecheck(&files).is_empty());
    }

    #[test]
    fn abstains_without_direct_checked_in_javascript_ci() {
        let files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"scripts":{"typecheck":"tsc --noEmit"}}"#.to_owned(),
            ),
            (
                ".github/workflows/ci.yml".to_owned(),
                "jobs:\n  call:\n    uses: org/shared/.github/workflows/ci.yml@main".to_owned(),
            ),
        ]);
        assert!(missing_ci_typecheck(&files).is_empty());
    }
}
