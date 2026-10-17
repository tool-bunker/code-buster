use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;

const PRETTIER_FILES: &[&str] = &[
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.js",
    "prettier.config.js",
];

pub fn analyze(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(tab_indentation(sources, config));
    findings.extend(trailing_whitespace(sources, config));
    findings.extend(long_lines(sources, config));
    findings
}

fn tab_indentation(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    let root = policy_root(config);
    let mut policies = HashMap::new();
    let mut findings = Vec::new();
    for (path, source) in sources {
        if findings.len() >= 50 {
            break;
        }
        let dart = path.ends_with(".dart");
        if !should_check_tab_indentation(path, &root, &mut policies) {
            continue;
        }
        let lines = source.split('\n').collect::<Vec<_>>();
        let matches = if dart {
            dart_tab_indent_lines(&lines)
        } else {
            tab_indent_lines(&lines, path)
        };
        if matches.is_empty() {
            continue;
        }
        let message = if matches.len() == 1 {
            "tab character used for indentation/alignment".to_owned()
        } else {
            format!("tab characters used on {} lines", matches.len())
        };
        findings.push(layout_finding(
            "tab-indent",
            path,
            matches[0],
            message,
            "Tabs render differently across editors and many project styles forbid tab indentation.",
            "Use spaces for indentation.",
            matches
                .iter()
                .skip(1)
                .map(|line| format!("{path}:{line}"))
                .collect(),
        ));
    }
    findings
}

fn trailing_whitespace(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    let root = policy_root(config);
    let mut policies = HashMap::new();
    let mut findings = Vec::new();
    for (path, source) in sources {
        if findings.len() >= 50 {
            break;
        }
        let dart = path.ends_with(".dart");
        if !should_check_trailing_whitespace(path, &root, &mut policies) {
            continue;
        }
        let lines = source.split('\n').collect::<Vec<_>>();
        let matches = if dart {
            dart_trailing_whitespace_lines(&lines)
        } else {
            lines
                .iter()
                .enumerate()
                .filter_map(|(index, line)| {
                    (!line.is_empty() && matches!(line.as_bytes().last(), Some(b' ' | b'\t')))
                        .then_some(index + 1)
                })
                .collect::<Vec<_>>()
        };
        if matches.is_empty() {
            continue;
        }
        let message = if matches.len() == 1 {
            "line has trailing whitespace".to_owned()
        } else {
            format!("{} lines have trailing whitespace", matches.len())
        };
        findings.push(layout_finding(
            "trailing-whitespace",
            path,
            matches[0],
            message,
            "Trailing whitespace creates noisy diffs.",
            "Trim trailing spaces before committing.",
            matches
                .iter()
                .skip(1)
                .map(|line| format!("{path}:{line}"))
                .collect(),
        ));
    }
    findings
}

fn long_lines(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    let root = policy_root(config);
    let mut policies = HashMap::new();
    let mut findings = Vec::new();
    for (path, source) in sources {
        if path.ends_with(".dart") {
            continue;
        }
        let line_limit = cached_policy(&mut policies, path, || generic_line_limit(path, &root));
        let template_language = TEMPLATE_LANGUAGE.is_match(path);
        let mut in_template = false;
        for (index, raw) in source.split('\n').enumerate() {
            let template_content =
                template_content_on_line(raw, template_language, &mut in_template);
            let length = raw.encode_utf16().count();
            if should_report_long_line(raw, length, line_limit, template_content) {
                findings.push(long_line_finding(path, index + 1, length, line_limit));
            }
        }
    }
    findings
}

fn template_content_on_line(line: &str, template_language: bool, in_template: &mut bool) -> bool {
    let started_in_template = *in_template;
    if template_language && unescaped_backtick_count(line) % 2 == 1 {
        *in_template = !*in_template;
    }
    started_in_template || *in_template
}

fn should_report_long_line(
    line: &str,
    length: usize,
    line_limit: usize,
    template_content: bool,
) -> bool {
    line_limit > 0
        && length > line_limit
        && !template_content
        && !is_unwrappable_line(line.trim_start())
}

fn is_unwrappable_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#')
        || trimmed.starts_with("import ")
        || trimmed.starts_with("export ")
        || trimmed.contains('\'')
        || trimmed.contains('"')
        || trimmed.contains('`')
}

fn long_line_finding(path: &str, line: usize, length: usize, line_limit: usize) -> Finding {
    layout_finding(
        "long-line",
        path,
        line,
        format!("line length {length} > {line_limit}"),
        "Shorter lines are easier to scan and review.",
        "Wrap the expression/call using normal language indentation conventions.",
        Vec::new(),
    )
}

fn tab_indent_lines(lines: &[&str], source_path: &str) -> Vec<usize> {
    let mut context = TabIndentContext::new(source_path);
    let mut matches = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !context.excludes_line() && starts_with_indentation_tab(line) {
            matches.push(index + 1);
        }
        context.advance(line);
    }
    matches
}

struct TabIndentContext {
    template_language: bool,
    lua: bool,
    in_template: bool,
    in_block_comment: bool,
    lua_long_string: Option<String>,
}

impl TabIndentContext {
    fn new(source_path: &str) -> Self {
        Self {
            template_language: TEMPLATE_LANGUAGE.is_match(source_path),
            lua: LUA_LANGUAGE.is_match(source_path),
            in_template: false,
            in_block_comment: false,
            lua_long_string: None,
        }
    }

    fn excludes_line(&self) -> bool {
        self.in_template || self.in_block_comment || self.lua_long_string.is_some()
    }

    fn advance(&mut self, line: &str) {
        if self.template_language && unescaped_backtick_count(line) % 2 == 1 {
            self.in_template = !self.in_template;
        }
        self.advance_lua_long_string(line);
        self.advance_block_comment(line);
    }

    fn advance_lua_long_string(&mut self, line: &str) {
        if !self.lua {
            return;
        }
        if let Some(equals) = self.lua_long_string.as_deref() {
            if line.contains(&format!("]{equals}]")) {
                self.lua_long_string = None;
            }
        } else if let Some(opening) = LUA_LONG_STRING.captures(line) {
            let complete = opening.get(0).unwrap();
            let equals = opening.name("equals").unwrap().as_str();
            if !line[complete.end()..].contains(&format!("]{equals}]")) {
                self.lua_long_string = Some(equals.to_owned());
            }
        }
    }

    fn advance_block_comment(&mut self, line: &str) {
        if self.in_block_comment {
            if line.contains("*/") {
                self.in_block_comment = false;
            }
        } else if let Some(opening) = line.find("/*")
            && !line[opening + 2..].contains("*/")
        {
            self.in_block_comment = true;
        }
    }
}

fn starts_with_indentation_tab(line: &str) -> bool {
    line.as_bytes()
        .iter()
        .find(|byte| **byte != b' ')
        .is_some_and(|byte| *byte == b'\t')
}

fn dart_tab_indent_lines(lines: &[&str]) -> Vec<usize> {
    let mut matches = Vec::new();
    let mut triple_quote: Option<&str> = None;
    for (index, line) in lines.iter().enumerate() {
        let inside_triple_string = triple_quote.is_some();
        triple_quote = next_dart_triple_quote(line, triple_quote);
        let trimmed = line.trim_start();
        let comment_line =
            trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*');
        let indentation_end = line.len() - trimmed.len();
        if !inside_triple_string
            && triple_quote.is_none()
            && !comment_line
            && line[..indentation_end].contains('\t')
        {
            matches.push(index + 1);
        }
    }
    matches
}

fn dart_trailing_whitespace_lines(lines: &[&str]) -> Vec<usize> {
    let mut matches = Vec::new();
    let mut triple_quote: Option<&str> = None;
    for (index, line) in lines.iter().enumerate() {
        let inside_triple_string = triple_quote.is_some();
        triple_quote = next_dart_triple_quote(line, triple_quote);
        if !inside_triple_string
            && triple_quote.is_none()
            && !line.is_empty()
            && matches!(line.as_bytes().last(), Some(b' ' | b'\t'))
        {
            matches.push(index + 1);
        }
    }
    matches
}

fn next_dart_triple_quote<'a>(line: &str, mut quote: Option<&'a str>) -> Option<&'a str> {
    for delimiter in ["'''", "\"\"\""] {
        if line.matches(delimiter).count() % 2 == 1 {
            quote = if quote.is_none() {
                Some(delimiter)
            } else {
                None
            };
        }
    }
    quote
}

fn unescaped_backtick_count(line: &str) -> usize {
    line.match_indices('`')
        .filter(|(index, _)| *index == 0 || line.as_bytes()[index - 1] != b'\\')
        .count()
}

fn generic_line_limit(source_path: &str, root: &Path) -> usize {
    biome_line_limit(source_path, root)
        .or_else(|| prettier_line_limit(source_path, root))
        .or_else(|| editor_config_line_limit(source_path, root))
        .unwrap_or(0)
}

fn prettier_line_limit(source_path: &str, root: &Path) -> Option<usize> {
    for directory in policy_directories(source_path, root) {
        for name in PRETTIER_FILES {
            let path = directory.join(name);
            if !path.is_file() {
                continue;
            }
            let Ok(source) = fs::read_to_string(path) else {
                continue;
            };
            if let Some(width) = PRETTIER_WIDTH.captures(&source) {
                return width.name("width").unwrap().as_str().parse().ok();
            }
        }
    }
    None
}

fn editor_config_line_limit(source_path: &str, root: &Path) -> Option<usize> {
    editor_config_value(source_path, root, "max_line_length").and_then(|value| {
        if value.eq_ignore_ascii_case("off") {
            Some(0)
        } else {
            value.parse().ok()
        }
    })
}

fn biome_line_limit(source_path: &str, root: &Path) -> Option<usize> {
    for directory in policy_directories(source_path, root) {
        let path = directory.join("biome.json");
        if !path.is_file() {
            continue;
        }
        let source = fs::read_to_string(path).ok()?;
        let decoded = match serde_json::from_str::<Value>(&source) {
            Ok(decoded) => decoded,
            Err(_) => return None,
        };
        let Some(formatter) = decoded.get("formatter").and_then(Value::as_object) else {
            continue;
        };
        if formatter.get("enabled") == Some(&Value::Bool(false)) {
            return Some(0);
        }
        if let Some(width) = formatter.get("lineWidth").and_then(Value::as_u64)
            && width > 0
        {
            return usize::try_from(width).ok();
        }
    }
    None
}

fn trailing_whitespace_forbidden(source_path: &str, root: &Path) -> bool {
    for directory in policy_directories(source_path, root) {
        if PRETTIER_FILES
            .iter()
            .any(|name| directory.join(name).is_file())
        {
            return true;
        }
        if let Some(value) =
            editor_config_value_in_directory(source_path, &directory, "trim_trailing_whitespace")
        {
            return value.eq_ignore_ascii_case("true");
        }
    }
    false
}

fn tabs_forbidden(source_path: &str, root: &Path) -> bool {
    if source_path.to_ascii_lowercase().ends_with(".go") {
        return false;
    }
    for directory in policy_directories(source_path, root) {
        for name in PRETTIER_FILES {
            let path = directory.join(name);
            if !path.is_file() {
                continue;
            }
            let Ok(source) = fs::read_to_string(path) else {
                continue;
            };
            match serde_json::from_str::<Value>(&source) {
                Ok(Value::Object(object)) => {
                    return object.get("useTabs") != Some(&Value::Bool(true));
                }
                Ok(_) => {}
                Err(_) => {
                    return PRETTIER_USE_TABS
                        .captures(&source)
                        .and_then(|captures| captures.name("value"))
                        .is_none_or(|value| value.as_str() != "true");
                }
            }
        }
        if let Some(value) =
            editor_config_value_in_directory(source_path, &directory, "indent_style")
        {
            return value.eq_ignore_ascii_case("space");
        }
    }
    false
}

fn editor_config_value(source_path: &str, root: &Path, key: &str) -> Option<String> {
    for directory in policy_directories(source_path, root) {
        if let Some(value) = editor_config_value_in_directory(source_path, &directory, key) {
            return Some(value);
        }
    }
    None
}

fn editor_config_value_in_directory(
    source_path: &str,
    directory: &Path,
    key: &str,
) -> Option<String> {
    let path = directory.join(".editorconfig");
    let source = fs::read_to_string(path).ok()?;
    let extension = Path::new(source_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut applies = true;
    let mut selected = None;
    for raw in source.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            applies = editor_config_pattern_applies(&line[1..line.len() - 1], &extension);
            continue;
        }
        let Some((candidate_key, value)) = line.split_once('=') else {
            continue;
        };
        if applies && candidate_key.trim().eq_ignore_ascii_case(key) {
            selected = Some(value.trim().to_owned());
        }
    }
    selected
}

fn editor_config_pattern_applies(pattern: &str, extension: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    if matches!(pattern.as_str(), "*" | "*.*") || pattern == format!("*.{extension}") {
        return true;
    }
    pattern
        .strip_prefix("*.{")
        .and_then(|value| value.strip_suffix('}'))
        .is_some_and(|extensions| extensions.split(',').any(|value| value == extension))
}

fn policy_root(config: &Config) -> PathBuf {
    fs::canonicalize(&config.root).unwrap_or_else(|_| absolute_path(&config.root))
}

fn should_check_tab_indentation(
    source_path: &str,
    root: &Path,
    policies: &mut HashMap<PolicyCacheKey, bool>,
) -> bool {
    source_path.ends_with(".dart")
        || cached_policy(policies, source_path, || tabs_forbidden(source_path, root))
}

fn should_check_trailing_whitespace(
    source_path: &str,
    root: &Path,
    policies: &mut HashMap<PolicyCacheKey, bool>,
) -> bool {
    source_path.ends_with(".dart")
        || cached_policy(policies, source_path, || {
            trailing_whitespace_forbidden(source_path, root)
        })
}

type PolicyCacheKey = (PathBuf, String);

fn cached_policy<T: Copy>(
    policies: &mut HashMap<PolicyCacheKey, T>,
    source_path: &str,
    resolve: impl FnOnce() -> T,
) -> T {
    *policies
        .entry(policy_cache_key(source_path))
        .or_insert_with(resolve)
}

fn policy_cache_key(source_path: &str) -> PolicyCacheKey {
    let path = Path::new(source_path);
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    (parent, extension)
}

fn policy_directories(source_path: &str, root: &Path) -> Vec<PathBuf> {
    let mut directory = root
        .join(source_path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.to_path_buf());
    let mut directories = Vec::new();
    while directory == root || directory.starts_with(root) {
        directories.push(directory.clone());
        if directory == root || !directory.pop() {
            break;
        }
    }
    directories
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn layout_finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    why: &str,
    suggestion: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("layout rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("layout rule severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message,
        confidence: "high".to_owned(),
        why: why.to_owned(),
        suggestion: suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static TEMPLATE_LANGUAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(?:js|jsx|mjs|cjs|ts|tsx)$").unwrap());
static LUA_LANGUAGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(?:lua|luau)$").unwrap());
static LUA_LONG_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[(?P<equals>=*)\[").unwrap());
static PRETTIER_WIDTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:[\"']?printWidth[\"']?\s*[:=]\s*)(?P<width>\d+)"#).unwrap());
static PRETTIER_USE_TABS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"useTabs\s*[:=]\s*(?P<value>true|false)").unwrap());

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn reports_layout_rules_in_repository_order_with_exact_contracts() {
        let root = TempRoot::new();
        root.write(".prettierrc", r#"{"useTabs": false, "printWidth": 20}"#);
        let config = Config::defaults(root.path().to_path_buf());
        let findings = analyze(
            &sources(&[
                ("source.dart", "\tvalue;  "),
                ("src/main.js", "constResultValue = computeResultValue();"),
            ]),
            &config,
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.severity.as_str(),
                    finding.path.as_str(),
                    finding.line,
                    finding.end_line,
                    finding.message.as_str(),
                    finding.confidence.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "tab-indent",
                    "warn",
                    "source.dart",
                    1,
                    1,
                    "tab character used for indentation/alignment",
                    "high",
                ),
                (
                    "trailing-whitespace",
                    "info",
                    "source.dart",
                    1,
                    1,
                    "line has trailing whitespace",
                    "high",
                ),
                (
                    "long-line",
                    "info",
                    "src/main.js",
                    1,
                    1,
                    "line length 40 > 20",
                    "high",
                ),
            ]
        );
    }

    #[test]
    fn honors_nested_prettier_and_editorconfig_overrides() {
        let root = TempRoot::new();
        root.write(".editorconfig", "[*]\nindent_style = space\n");
        root.write("docs/.prettierrc", r#"{"useTabs": true}"#);
        root.write(
            "src/.editorconfig",
            "[*]\nindent_style = space\n[*.cs]\nindent_style = tab\n",
        );
        let config = Config::defaults(root.path().to_path_buf());
        let findings = tab_indentation(
            &sources(&[
                ("docs/style.css", "\t.selector {}"),
                ("src/main.cs", "\tvar value = 1;"),
                ("src/main.ts", "\tconst value = 1;"),
                ("src/main.go", "\tvalue := 1"),
            ]),
            &config,
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("src/main.ts", 1)]
        );
    }

    #[test]
    fn ignores_tabs_inside_templates_long_strings_comments_and_dart_strings() {
        let root = TempRoot::new();
        root.write(".editorconfig", "[*]\nindent_style = space\n");
        let config = Config::defaults(root.path().to_path_buf());
        let findings = tab_indentation(
            &sources(&[
                (
                    "fixture.ts",
                    "const fixture = `\n\tgenerated\n`;\n  \tconst actual = 1;",
                ),
                (
                    "help.lua",
                    "local text = [[\n\tgenerated help\n]]\n  \tlocal value = 1",
                ),
                (
                    "source.dart",
                    "final text = '''\n\tgenerated\n''';\n//\tcomment\n  \tfinal value = 1;",
                ),
            ]),
            &config,
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| {
                    (
                        finding.path.as_str(),
                        finding.line,
                        finding.related_files.clone(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                ("fixture.ts", 4, Vec::<String>::new()),
                ("help.lua", 4, Vec::<String>::new()),
                ("source.dart", 5, Vec::<String>::new()),
            ]
        );
    }

    #[test]
    fn requires_formatter_evidence_and_honors_trailing_overrides() {
        let root = TempRoot::new();
        let mut config = Config::defaults(root.path().to_path_buf());
        let source = sources(&[("src/main.cs", "class Main { }  ")]);
        assert!(trailing_whitespace(&source, &config).is_empty());

        root.write(
            ".editorconfig",
            "[*]\ntrim_trailing_whitespace = true\n[*.cs]\ntrim_trailing_whitespace = false\n",
        );
        assert!(trailing_whitespace(&source, &config).is_empty());

        root.write(
            "src/.editorconfig",
            "[*.cs]\ntrim_trailing_whitespace = true\n",
        );
        config.root = root.path().to_path_buf();
        let findings = trailing_whitespace(&source, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].message, "line has trailing whitespace");
    }

    #[test]
    fn applies_biome_prettier_and_editorconfig_line_policies() {
        let root = TempRoot::new();
        root.write("plain/.prettierrc", r#"{"printWidth": 10}"#);
        root.write(
            "disabled/biome.json",
            r#"{"formatter": {"enabled": false}}"#,
        );
        root.write("editor/.editorconfig", "[*.ts]\nmax_line_length = 12\n");
        let config = Config::defaults(root.path().to_path_buf());
        let findings = long_lines(
            &sources(&[
                ("disabled/main.ts", "abcdefghijklmnopqrst"),
                ("editor/main.ts", "abcdefghijklm"),
                ("plain/main.py", "abcdefghijklmnopqrst"),
                ("plain/main.ts", "abcdefghijklmnopqrst"),
            ]),
            &config,
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.message.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("editor/main.ts", "line length 13 > 12"),
                ("plain/main.py", "line length 20 > 10"),
                ("plain/main.ts", "line length 20 > 10"),
            ]
        );
    }

    #[test]
    fn ignores_unwrappable_and_template_lines_but_reports_wrappable_code() {
        let root = TempRoot::new();
        root.write(".editorconfig", "[*.ts]\nmax_line_length = 10\n");
        let config = Config::defaults(root.path().to_path_buf());
        let findings = long_lines(
            &sources(&[(
                "main.ts",
                "// this comment is long\n\
                 import something from 'somewhere';\n\
                 const text = `\n\
                 template content is long\n\
                 `;\n\
                 abcdefghijk",
            )]),
            &config,
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![6]
        );
    }

    #[test]
    fn ignores_dart_trailing_whitespace_inside_triple_strings() {
        let config = Config::defaults(".".into());
        let findings = trailing_whitespace(
            &sources(&[(
                "source.dart",
                "final text = '''  \ninside text  \n''';  \nfinal value = 1;  ",
            )]),
            &config,
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.line, finding.message.as_str()))
                .collect::<Vec<_>>(),
            vec![(4, "line has trailing whitespace")]
        );
    }

    #[test]
    fn aggregates_lines_and_caps_file_findings_deterministically() {
        let config = Config::defaults(".".into());
        let mut many_sources = BTreeMap::new();
        for index in 0..51 {
            many_sources.insert(
                format!("file-{index:02}.dart"),
                "\tfirst\n\tsecond  ".to_owned(),
            );
        }
        let tab_findings = tab_indentation(&many_sources, &config);
        let trailing_findings = trailing_whitespace(&many_sources, &config);

        assert_eq!(tab_findings.len(), 50);
        assert_eq!(trailing_findings.len(), 50);
        assert_eq!(tab_findings[0].message, "tab characters used on 2 lines");
        assert_eq!(
            tab_findings[0].related_files,
            vec!["file-00.dart:2".to_owned()]
        );
        assert_eq!(tab_findings[49].path, "file-49.dart");
        assert_eq!(trailing_findings[49].path, "file-49.dart");
    }

    struct TempRoot(TempDir);

    impl TempRoot {
        fn new() -> Self {
            Self(tempfile::tempdir().expect("temporary repository must be created"))
        }

        fn path(&self) -> &Path {
            self.0.path()
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
    }

    fn sources(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
            .collect()
    }
}
