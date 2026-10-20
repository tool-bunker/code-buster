use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::languages::rust::rules::function_lexical_facts;
use crate::rule_catalog;

const RULE_ORDER: &[&str] = &[
    "todo-comment",
    "fixme-comment",
    "operation-on-same-value",
    "suspicious-command-arg-space",
    "large-number-ungrouped",
    "large-inline-list",
    "needless-bool-branch",
];

pub fn analyze(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    if !config.rule_groups.contains("suspicious")
        && !RULE_ORDER
            .iter()
            .any(|code| config.severity_overrides.contains_key(*code))
    {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let todo_enabled = enabled(config, "todo-comment");
    let fixme_enabled = enabled(config, "fixme-comment");
    if todo_enabled || fixme_enabled {
        let (todo_findings, fixme_findings) = comment_markers(sources, todo_enabled, fixme_enabled);
        findings.extend(todo_findings);
        findings.extend(fixme_findings);
    }
    if enabled(config, "operation-on-same-value") {
        findings.extend(operation_on_same_value(sources));
    }
    if enabled(config, "suspicious-command-arg-space") {
        findings.extend(suspicious_command_arguments(sources));
    }
    if enabled(config, "large-number-ungrouped") {
        findings.extend(large_numbers(sources));
    }
    if enabled(config, "large-inline-list") {
        findings.extend(large_inline_lists(sources));
    }
    if enabled(config, "needless-bool-branch") {
        findings.extend(needless_bool_branches(sources));
    }
    findings
}

fn enabled(config: &Config, code: &str) -> bool {
    config.rule_groups.contains("suspicious") || config.severity_overrides.contains_key(code)
}

fn large_numbers(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        if excludes_large_number_file(path) {
            continue;
        }
        append_large_numbers(&mut findings, path, source);
    }
    findings
}

fn append_large_numbers(findings: &mut Vec<Finding>, path: &str, source: &str) {
    let raw_lines = source.split('\n').collect::<Vec<_>>();
    let preprocessed = mask_inactive_preprocessor_branches(&raw_lines);
    let masked = mask_generic_rule_strings(&preprocessed, path);
    let mut in_block_comment = false;
    let mut language = LargeNumberLanguageExclusions::new(path);

    for (index, line) in masked.iter().enumerate() {
        if language.excludes_line(line) {
            continue;
        }
        let code = strip_comments(line, &mut in_block_comment);
        if large_number_candidates(&code).any(|candidate| {
            !excludes_large_number_candidate(&language, raw_lines[index], &code, candidate)
        }) {
            findings.push(large_number_finding(path, index + 1));
        }
    }
}

#[derive(Clone, Copy)]
struct LargeNumberCandidate<'a> {
    literal: &'a str,
    start: usize,
    end: usize,
}

fn large_number_candidates(code: &str) -> impl Iterator<Item = LargeNumberCandidate<'_>> {
    LARGE_NUMBER
        .find_iter(code)
        .filter_map(move |number| parse_large_number_candidate(code, number))
}

fn parse_large_number_candidate<'a>(
    code: &'a str,
    number: regex::Match<'a>,
) -> Option<LargeNumberCandidate<'a>> {
    let literal = number.as_str();
    let previous = number
        .start()
        .checked_sub(1)
        .and_then(|offset| code.as_bytes().get(offset))
        .copied();
    let next = code.as_bytes().get(number.end()).copied();
    if matches!(previous, Some(b'0'..=b'9' | b'.'))
        || matches!(next, Some(b'0'..=b'9' | b'.'))
        || is_legacy_octal(literal)
        || has_non_decimal_base_prefix(code, number.start())
    {
        return None;
    }
    Some(LargeNumberCandidate {
        literal,
        start: number.start(),
        end: number.end(),
    })
}

fn has_non_decimal_base_prefix(code: &str, number_start: usize) -> bool {
    let bytes = code.as_bytes();
    let mut token_start = number_start;
    while token_start > 0
        && matches!(
            bytes[token_start - 1],
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'x' | b'X' | b'_'
        )
    {
        token_start -= 1;
    }
    bytes.get(token_start).copied() == Some(b'0')
        && matches!(
            bytes.get(token_start + 1).copied(),
            Some(b'x' | b'X' | b'b' | b'B')
        )
}

fn excludes_large_number_candidate(
    language: &LargeNumberLanguageExclusions<'_>,
    raw_line: &str,
    code: &str,
    candidate: LargeNumberCandidate<'_>,
) -> bool {
    inside_url(raw_line, candidate.start, candidate.end)
        || is_commit_hash_link_label(raw_line, candidate.literal)
        || language.excludes_candidate(code, candidate.literal)
}

fn excludes_large_number_file(path: &str) -> bool {
    is_dependency_metadata(path)
        || uses_unavailable_digit_grouping(path)
        || uses_html_text_syntax(path)
}

struct LargeNumberLanguageExclusions<'a> {
    path: &'a str,
    python: bool,
    python_docstring: Option<&'static str>,
}

impl<'a> LargeNumberLanguageExclusions<'a> {
    fn new(path: &'a str) -> Self {
        Self {
            path,
            python: path.ends_with(".py"),
            python_docstring: None,
        }
    }

    fn excludes_line(&mut self, line: &str) -> bool {
        if !self.python {
            return false;
        }
        let trimmed = line.trim_start();
        if let Some(delimiter) = self.python_docstring {
            if trimmed.contains(delimiter) {
                self.python_docstring = None;
            }
            return true;
        }
        let delimiter = if trimmed.starts_with("\"\"\"") {
            Some("\"\"\"")
        } else if trimmed.starts_with("'''") {
            Some("'''")
        } else {
            None
        };
        if let Some(delimiter) = delimiter {
            if trimmed.matches(delimiter).count() % 2 == 1 {
                self.python_docstring = Some(delimiter);
            }
            return true;
        }
        false
    }

    fn excludes_candidate(&self, code: &str, literal: &str) -> bool {
        is_java_serial_version_uid(self.path, code, literal)
    }
}

fn large_number_finding(path: &str, line: usize) -> Finding {
    finding(
        "large-number-ungrouped",
        path,
        line,
        "large numeric literal is not digit-grouped",
        "high",
    )
}

#[derive(Clone, Copy)]
enum PreprocessorDirective<'a> {
    Begin(Option<&'a str>),
    Next(Option<&'a str>),
    End,
}

fn classify_preprocessor_directive(line: &str) -> Option<PreprocessorDirective<'_>> {
    let captures = PREPROCESSOR_DIRECTIVE.captures(line)?;
    let name = captures.name("name")?.as_str();
    let expression = captures.name("expression")?.as_str();
    match name {
        "if" => Some(PreprocessorDirective::Begin(Some(expression))),
        "ifdef" | "ifndef" => Some(PreprocessorDirective::Begin(None)),
        "elif" => Some(PreprocessorDirective::Next(Some(expression))),
        "else" => Some(PreprocessorDirective::Next(None)),
        "endif" => Some(PreprocessorDirective::End),
        _ => None,
    }
}

fn false_preprocessor_expression(expression: Option<&str>) -> bool {
    expression.is_some_and(|value| FALSE_PREPROCESSOR_EXPRESSION.is_match(value))
}

#[derive(Default)]
struct PreprocessorBranchState {
    parents: Vec<bool>,
    disabled: bool,
}

impl PreprocessorBranchState {
    fn transition(&mut self, directive: PreprocessorDirective<'_>) {
        match directive {
            PreprocessorDirective::Begin(expression) => {
                self.parents.push(self.disabled);
                self.disabled = self.disabled || false_preprocessor_expression(expression);
            }
            PreprocessorDirective::Next(expression) => {
                if let Some(parent) = self.parents.last() {
                    self.disabled = *parent || false_preprocessor_expression(expression);
                }
            }
            PreprocessorDirective::End => {
                if let Some(parent) = self.parents.pop() {
                    self.disabled = parent;
                }
            }
        }
    }

    fn mask_line(&self, line: &str) -> String {
        if self.disabled {
            String::new()
        } else {
            line.to_owned()
        }
    }
}

pub(crate) fn mask_inactive_preprocessor_branches(lines: &[&str]) -> Vec<String> {
    let mut result = Vec::with_capacity(lines.len());
    let mut state = PreprocessorBranchState::default();
    for line in lines {
        let Some(directive) = classify_preprocessor_directive(line) else {
            result.push(state.mask_line(line));
            continue;
        };
        state.transition(directive);
        result.push(String::new());
    }
    result
}

pub(crate) fn mask_generic_rule_strings(lines: &[String], path: &str) -> Vec<String> {
    if path.ends_with(".rs") {
        return mask_rust_strings(lines);
    }
    if !path.ends_with(".dart") && !path.ends_with(".py") {
        return lines
            .iter()
            .map(|line| strip_generic_strings(line).into_owned())
            .collect();
    }
    let mut masker = MultilineStringMasker::default();
    lines.iter().map(|line| masker.mask_line(line)).collect()
}

#[derive(Default)]
struct MultilineStringMasker {
    quote: Option<&'static str>,
    raw: bool,
    block_comment_depth: usize,
}

impl MultilineStringMasker {
    fn mask_line(&mut self, line: &str) -> String {
        let bytes = line.as_bytes();
        let mut masked = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if self.quote.is_some() {
                self.consume_quoted(line, &mut index, &mut masked);
            } else if self.block_comment_depth > 0 {
                self.consume_block_comment(bytes, &mut index, &mut masked);
            } else if self.consume_code(line, &mut index, &mut masked) {
                break;
            }
        }
        if self.quote.is_some_and(|delimiter| delimiter.len() == 1) {
            self.quote = None;
            self.raw = false;
        }
        String::from_utf8(masked).expect("masked source must remain UTF-8")
    }

    fn consume_quoted(&mut self, line: &str, index: &mut usize, masked: &mut Vec<u8>) {
        let Some(delimiter) = self.quote else {
            return;
        };
        let bytes = line.as_bytes();
        if !self.raw && bytes[*index] == b'\\' {
            Self::mask_width(masked, index, 1);
            if *index < bytes.len() {
                Self::mask_width(masked, index, character_width(line, *index));
            }
            return;
        }
        if line[*index..].starts_with(delimiter) {
            Self::mask_width(masked, index, delimiter.len());
            self.quote = None;
            self.raw = false;
            return;
        }
        Self::mask_width(masked, index, character_width(line, *index));
    }

    fn consume_block_comment(&mut self, bytes: &[u8], index: &mut usize, masked: &mut Vec<u8>) {
        if bytes[*index..].starts_with(b"/*") {
            self.block_comment_depth += 1;
            masked.extend_from_slice(b"/*");
            *index += 2;
        } else if bytes[*index..].starts_with(b"*/") {
            self.block_comment_depth -= 1;
            masked.extend_from_slice(b"*/");
            *index += 2;
        } else {
            masked.push(bytes[*index]);
            *index += 1;
        }
    }

    fn consume_code(&mut self, line: &str, index: &mut usize, masked: &mut Vec<u8>) -> bool {
        let bytes = line.as_bytes();
        if bytes[*index..].starts_with(b"//") {
            masked.extend_from_slice(&bytes[*index..]);
            *index = bytes.len();
            return true;
        }
        if bytes[*index..].starts_with(b"/*") {
            self.block_comment_depth = 1;
            masked.extend_from_slice(b"/*");
            *index += 2;
            return false;
        }
        if matches!(bytes[*index], b'\'' | b'\"') {
            self.open_quote(bytes, *index);
            let width = self.quote.map_or(1, str::len);
            Self::mask_width(masked, index, width);
            return false;
        }
        let width = character_width(line, *index);
        masked.extend_from_slice(&bytes[*index..*index + width]);
        *index += width;
        false
    }

    fn open_quote(&mut self, bytes: &[u8], index: usize) {
        let quote = bytes[index];
        let triple = bytes.get(index + 1) == Some(&quote) && bytes.get(index + 2) == Some(&quote);
        self.quote = Some(match (quote, triple) {
            (b'\'', true) => "'''",
            (b'"', true) => "\"\"\"",
            (b'\'', false) => "'",
            _ => "\"",
        });
        self.raw = index > 0
            && matches!(bytes[index - 1], b'r' | b'R')
            && (index == 1 || !is_identifier_byte(bytes[index - 2]));
    }

    fn mask_width(masked: &mut Vec<u8>, index: &mut usize, width: usize) {
        masked.extend(std::iter::repeat_n(b' ', width));
        *index += width;
    }
}

fn character_width(line: &str, index: usize) -> usize {
    line[index..].chars().next().map_or(1, char::len_utf8)
}

fn mask_rust_strings(lines: &[String]) -> Vec<String> {
    let mut result = Vec::with_capacity(lines.len());
    let mut raw_terminator: Option<String> = None;
    for line in lines {
        let mut masked = line.as_bytes().to_vec();
        let mut index = 0;
        while index < line.len() {
            if let Some(terminator) = &raw_terminator {
                if let Some(relative_end) = line[index..].find(terminator) {
                    let end = index + relative_end + terminator.len();
                    masked[index..end].fill(b' ');
                    index = end;
                    raw_terminator = None;
                } else {
                    masked[index..].fill(b' ');
                    index = line.len();
                }
                continue;
            }
            if let Some(start) = RUST_RAW_STRING_START.find_at(line, index)
                && start.start() == index
            {
                let hashes = start.as_str().bytes().filter(|byte| *byte == b'#').count();
                raw_terminator = Some(format!("\"{}", "#".repeat(hashes)));
                masked[start.start()..start.end()].fill(b' ');
                index = start.end();
                continue;
            }
            if matches!(line.as_bytes()[index], b'\"' | b'\'') {
                let delimiter = line.as_bytes()[index];
                let mut end = index + 1;
                let mut escaped = false;
                while end < line.len() {
                    let byte = line.as_bytes()[end];
                    end += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == delimiter {
                        break;
                    }
                }
                if end <= line.len() && line.as_bytes()[end - 1] == delimiter {
                    masked[index..end].fill(b' ');
                    index = end;
                    continue;
                }
            }
            index += line[index..].chars().next().unwrap().len_utf8();
        }
        result.push(String::from_utf8(masked).expect("masked Rust source must remain UTF-8"));
    }
    result
}

fn inside_url(line: &str, start: usize, end: usize) -> bool {
    URL.find_iter(line)
        .any(|url| start >= url.start() && end <= url.end())
}

fn is_commit_hash_link_label(line: &str, literal: &str) -> bool {
    let Ok(pattern) = COMMIT_LINK.as_ref() else {
        return false;
    };
    pattern.captures_iter(line).any(|link| {
        let Some(hash) = link.name("hash").map(|value| value.as_str()) else {
            return false;
        };
        let Some(label) = link.name("label").map(|value| value.as_str()) else {
            return false;
        };
        literal.eq_ignore_ascii_case(label)
            && hash
                .get(..label.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(label))
    })
}

fn is_java_serial_version_uid(path: &str, code: &str, literal: &str) -> bool {
    if !path.ends_with(".java") {
        return false;
    }
    let Ok(pattern) = JAVA_SERIAL_VERSION_UID.as_ref() else {
        return false;
    };
    pattern.captures_iter(code).any(|assignment| {
        assignment
            .name("literal")
            .is_some_and(|value| value.as_str() == literal)
    })
}

fn is_legacy_octal(literal: &str) -> bool {
    literal.len() >= 2
        && literal.starts_with('0')
        && literal.as_bytes()[1..]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'7'))
}

fn is_dependency_metadata(path: &str) -> bool {
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    DEPENDENCY_METADATA.contains(basename)
}

fn uses_unavailable_digit_grouping(path: &str) -> bool {
    let Some(extension) = Path::new(path).extension().and_then(|value| value.to_str()) else {
        return false;
    };
    let extension_with_dot = format!(".{extension}");
    extension_with_dot != ".C"
        && matches!(
            extension_with_dot.to_ascii_lowercase().as_str(),
            ".c" | ".css" | ".h" | ".lua" | ".sql" | ".m"
        )
}

fn uses_html_text_syntax(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| matches!(extension.to_ascii_lowercase().as_str(), "htm" | "html"))
}

fn large_inline_lists(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let lines = source.split('\n').collect::<Vec<_>>();
        if lines
            .iter()
            .take(10)
            .any(|line| GENERATED_HEADER.is_match(line))
        {
            continue;
        }
        let rust_test_lines = if path.ends_with(".rs") {
            function_lexical_facts(source).1
        } else {
            BTreeSet::new()
        };
        let mut in_block_comment = false;
        for (index, line) in lines.iter().enumerate() {
            if rust_test_lines.contains(&index) {
                continue;
            }
            let stripped = strip_generic_strings(line);
            let code = strip_comments(&stripped, &mut in_block_comment);
            let Some(collection) = COLLECTION.captures(&code) else {
                continue;
            };
            if collection
                .name("contents")
                .unwrap()
                .as_str()
                .matches(',')
                .count()
                >= 12
            {
                findings.push(finding(
                    "large-inline-list",
                    path,
                    index + 1,
                    "large inline collection literal",
                    "medium",
                ));
            }
        }
    }
    findings
}

pub(crate) fn mask_rust_test_regions(path: &str, source: &str) -> String {
    if !path.ends_with(".rs") {
        return source.to_owned();
    }
    let lines = source.split('\n').collect::<Vec<_>>();
    let test_lines = function_lexical_facts(source).1;
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            if test_lines.contains(&index) {
                " ".repeat(line.len())
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn needless_bool_branches(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let lines = source.split('\n').collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            if !TRUE_BRANCH.is_match(&strip_generic_strings(line)) {
                continue;
            }
            let mut matching_false = false;
            for next in lines.iter().skip(index + 1).take(4) {
                let raw = next.trim();
                if raw.is_empty() {
                    continue;
                }
                if CONDITIONAL_BOOLEAN_RETURN.is_match(raw) {
                    break;
                }
                matching_false = FALSE_RETURN.is_match(&strip_generic_strings(raw));
                break;
            }
            if matching_false {
                findings.push(finding(
                    "needless-bool-branch",
                    path,
                    index + 1,
                    "boolean branch can return its condition directly",
                    "medium",
                ));
            }
        }
    }
    findings
}

fn strip_generic_strings(line: &str) -> Cow<'_, str> {
    QUOTED_LITERAL.replace_all(line, "")
}

fn strip_comments(line: &str, in_block_comment: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut code = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if *in_block_comment {
            if bytes[index..].starts_with(b"*/") {
                *in_block_comment = false;
                code.push(b' ');
                index += 2;
            } else {
                code.push(b' ');
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            *in_block_comment = true;
            code.push(b' ');
            index += 2;
        } else if bytes[index..].starts_with(b"//") {
            break;
        } else {
            code.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(code).expect("stripped source must remain UTF-8")
}

fn strip_command_comments(line: &str, in_block_comment: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut code = Vec::with_capacity(bytes.len());
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if *in_block_comment {
            if bytes[index..].starts_with(b"*/") {
                *in_block_comment = false;
                code.push(b' ');
                index += 2;
            } else {
                code.push(b' ');
                index += 1;
            }
        } else if let Some(delimiter) = quote {
            code.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            index += 1;
        } else if matches!(byte, b'\'' | b'\"') {
            quote = Some(byte);
            code.push(byte);
            index += 1;
        } else if bytes[index..].starts_with(b"/*") {
            *in_block_comment = true;
            code.push(b' ');
            index += 2;
        } else if bytes[index..].starts_with(b"//") || byte == b'#' {
            break;
        } else {
            code.push(byte);
            index += 1;
        }
    }
    String::from_utf8(code).expect("stripped command source must remain UTF-8")
}

#[derive(Clone, Copy, Default)]
struct CommentSyntax {
    slash_line: bool,
    slash_block: bool,
    hash_line: bool,
    dash_line: bool,
    semicolon_line: bool,
    percent_line: bool,
}

impl CommentSyntax {
    fn for_path(path: &str) -> Self {
        let lower = path.to_ascii_lowercase();
        let extension = Path::new(&lower)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{value}"))
            .unwrap_or_default();
        let basename = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
        let slash_line = matches!(
            extension.as_str(),
            ".c" | ".cc"
                | ".cpp"
                | ".cs"
                | ".cxx"
                | ".dart"
                | ".go"
                | ".groovy"
                | ".h"
                | ".hh"
                | ".hpp"
                | ".java"
                | ".js"
                | ".jsx"
                | ".kt"
                | ".kts"
                | ".m"
                | ".mjs"
                | ".mm"
                | ".mojo"
                | ".php"
                | ".rs"
                | ".scala"
                | ".scss"
                | ".swift"
                | ".ts"
                | ".tsx"
                | ".vue"
                | ".wren"
        );
        let slash_block = slash_line || matches!(extension.as_str(), ".css" | ".less" | ".sql");
        let hash_line = matches!(
            extension.as_str(),
            ".bash"
                | ".fish"
                | ".jl"
                | ".nim"
                | ".pl"
                | ".pm"
                | ".ps1"
                | ".py"
                | ".pyi"
                | ".r"
                | ".rb"
                | ".sh"
                | ".toml"
                | ".yaml"
                | ".yml"
                | ".zsh"
        ) || matches!(basename, "dockerfile" | "gemfile" | "makefile");
        Self {
            slash_line,
            slash_block,
            hash_line,
            dash_line: matches!(extension.as_str(), ".hs" | ".lua" | ".luau" | ".sql"),
            semicolon_line: matches!(
                extension.as_str(),
                ".clj" | ".cljc" | ".cljs" | ".el" | ".lisp"
            ),
            percent_line: matches!(extension.as_str(), ".erl" | ".hrl" | ".tex"),
        }
    }
}

#[derive(Default)]
struct CommentState {
    in_block_comment: bool,
    multiline_string: Option<String>,
}

fn extract_comments(line: &str, syntax: CommentSyntax, state: &mut CommentState) -> String {
    let mut comments = String::new();
    let mut index = 0;
    while index < line.len() {
        if let Some(delimiter) = state.multiline_string.as_deref() {
            if let Some(end) = line[index..].find(delimiter) {
                index += end + delimiter.len();
                state.multiline_string = None;
                continue;
            }
            break;
        }
        if state.in_block_comment {
            if let Some(end) = line[index..].find("*/") {
                append_comment(&mut comments, &line[index..index + end]);
                state.in_block_comment = false;
                index += end + 2;
                continue;
            }
            append_comment(&mut comments, &line[index..]);
            break;
        }

        let delimiter = if line[index..].starts_with("\"\"\"") {
            Some("\"\"\"")
        } else if line[index..].starts_with("'''") {
            Some("'''")
        } else if line[index..].starts_with('`') {
            Some("`")
        } else {
            None
        };
        if let Some(delimiter) = delimiter {
            let after = index + delimiter.len();
            if let Some(end) = line[after..].find(delimiter) {
                index = after + end + delimiter.len();
            } else {
                state.multiline_string = Some(delimiter.to_owned());
                break;
            }
            continue;
        }

        let byte = line.as_bytes()[index];
        if matches!(byte, b'\'' | b'\"') {
            let quote = byte;
            index += 1;
            let mut escaped = false;
            while index < line.len() {
                let current = line.as_bytes()[index];
                index += 1;
                if escaped {
                    escaped = false;
                } else if current == b'\\' {
                    escaped = true;
                } else if current == quote {
                    break;
                }
            }
            continue;
        }
        let remaining = &line.as_bytes()[index..];
        if syntax.slash_block && remaining.starts_with(b"/*") {
            state.in_block_comment = true;
            index += 2;
        } else if syntax.slash_line && remaining.starts_with(b"//") {
            append_comment(&mut comments, &line[index + 2..]);
            break;
        } else if syntax.hash_line && byte == b'#' {
            append_comment(&mut comments, &line[index + 1..]);
            break;
        } else if syntax.dash_line && remaining.starts_with(b"--") {
            append_comment(&mut comments, &line[index + 2..]);
            break;
        } else if (syntax.semicolon_line && byte == b';') || (syntax.percent_line && byte == b'%') {
            append_comment(&mut comments, &line[index + 1..]);
            break;
        } else {
            index += line[index..].chars().next().unwrap().len_utf8();
        }
    }
    comments
}

fn append_comment(comments: &mut String, comment: &str) {
    if !comments.is_empty() {
        comments.push('\n');
    }
    comments.push_str(comment);
}

fn finding(code: &str, path: &str, line: usize, message: &str, confidence: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("generic rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("generic rule severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

static TODO_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*\*?\s*todo(?:$|[\s:(])").unwrap());
static FIXME_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*\*?\s*fixme(?:$|[\s:(])").unwrap());
static QUOTED_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"#).unwrap()
});
static COMPARISON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?P<left>[A-Za-z_]\w*)\s+(?P<operator>==|!=|<=|>=|<|>)\s+(?P<right>[A-Za-z_]\w*)\b",
    )
    .unwrap()
});
static LEADING_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\(\s*(?:(?:const|volatile|signed|unsigned|struct)\s+)*[A-Za-z_]\w*(?:\s*[*&]\s*)*\)\s*)+$").unwrap()
});
static NAN_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:isnan|nan)\b").unwrap());
static FOLLOWING_NAN_GUARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:unexpected\s+nan|nan\s+cannot\s+equal)\b").unwrap());
static NO_SELF_COMPARE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bno-self-compare\b").unwrap());
static CLOSING_BRACE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*}\s*$").unwrap());
static COMMAND_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:Process\.(?:run|start)|subprocess\.(?:run|Popen))\s*\(").unwrap()
});
static ARGUMENT_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\[(,])\s*[rRuUbBfF]{0,2}(?:\"(?P<double>(?:\\.|[^\"\\])*)\"|'(?P<single>(?:\\.|[^'\\])*)')"#).unwrap()
});
static LARGE_NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d{7,}").unwrap());
static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>\"']+"#).unwrap());
static COMMIT_LINK: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)<a\b[^>]*\bhref\s*=\s*[\"'][^\"']*/commit/(?P<hash>[0-9a-f]{7,40})(?:[/?#][^\"']*)?[\"'][^>]*>\s*(?P<label>[0-9a-f]{7,40})\s*</a>"#,
    )
});
static JAVA_SERIAL_VERSION_UID: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"\bserialVersionUID\s*=\s*[+-]?(?P<literal>\d+)[Ll]?\b"));
static PREPROCESSOR_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*#\s*(?P<name>if|ifdef|ifndef|elif|else|endif)\b(?P<expression>.*)$").unwrap()
});
static FALSE_PREPROCESSOR_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:\(\s*)*0+[uUlL]*(?:\s*\))*\s*(?:(?://.*)|(?:/\*.*\*/\s*))?$").unwrap()
});
static RUST_RAW_STRING_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r##"(?:br|r)(#*)\""##).unwrap());
static GENERATED_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bcode generated\b.*\bdo not edit\b").unwrap());
static COLLECTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\[{](?P<contents>[^\]}]+)[\]}]").unwrap());
static TRUE_BRANCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*if\s*\([^)]*\)\s*(?:return\s+true|\{\s*return\s+true)").unwrap()
});
static FALSE_RETURN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:}\s*)*(?:else\s+)?return\s+false\b").unwrap());
static CONDITIONAL_BOOLEAN_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:}\s*)*(?:else\s+)?if\b.*\breturn\s+(?:true|false)\b").unwrap()
});

static DEPENDENCY_METADATA: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    [
        "Cargo.lock",
        "Cargo.toml",
        "Gemfile",
        "Gemfile.lock",
        "Package.resolved",
        "Package.swift",
        "Pipfile",
        "Pipfile.lock",
        "Podfile",
        "Podfile.lock",
        "composer.json",
        "composer.lock",
        "go.mod",
        "go.sum",
        "gradle.lockfile",
        "gradle.properties",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "package.json",
        "packages.lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pubspec.lock",
        "pubspec.yaml",
        "pyproject.toml",
        "uv.lock",
        "yarn.lock",
    ]
    .into_iter()
    .collect()
});

include!("generic/suspicious.rs");
include!("generic/tests.rs");
