use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        analyze_file(path, source, &mut findings);
    }
    findings
}

fn analyze_file(path: &str, source: &str, findings: &mut Vec<Finding>) {
    let mut seen_patterns = BTreeMap::<String, usize>::new();
    let lower_path = path.to_ascii_lowercase();
    let supports_slash_literals = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|extension| lower_path.ends_with(extension));
    let hash_comments = path.ends_with(".py") || path.ends_with(".nim");
    let dash_comments = path.ends_with(".lua") || path.ends_with(".luau") || path.ends_with(".sql");
    let mut in_block_comment = false;

    for (index, line) in source.split('\n').enumerate() {
        let scan = without_comments(line, in_block_comment, hash_comments, dash_comments);
        in_block_comment = scan.in_block_comment;
        for site in patterns(&scan.code, supports_slash_literals) {
            analyze_pattern(
                path,
                &lower_path,
                index + 1,
                &scan.code,
                site,
                &mut seen_patterns,
                findings,
            );
        }
    }
}

fn analyze_pattern(
    path: &str,
    lower_path: &str,
    line_number: usize,
    line: &str,
    site: PatternSite,
    seen_patterns: &mut BTreeMap<String, usize>,
    findings: &mut Vec<Finding>,
) {
    let pattern = site.pattern.as_str();
    if has_runtime_interpolation(pattern) {
        return;
    }
    if lower_path.ends_with(".dart") && site.raw && !is_valid_dart_pattern(pattern) {
        findings.push(finding(
            "regex-invalid",
            path,
            line_number,
            "invalid regular expression",
            "high",
        ));
        return;
    }
    report_single_literal(path, line_number, pattern, findings);
    report_repeated_compile(path, line_number, &site, seen_patterns, findings);
    report_unanchored_validation(path, line_number, line, &site, findings);
    report_backtracking_risk(path, line_number, pattern, findings);
    report_leading_wildcard(path, line_number, pattern, findings);
    report_empty_alternative(path, line_number, pattern, findings);
    report_ascii_range(path, line_number, pattern, findings);
}

fn report_single_literal(
    path: &str,
    line_number: usize,
    pattern: &str,
    findings: &mut Vec<Finding>,
) {
    if pattern.len() == 1 && pattern.as_bytes()[0].is_ascii_alphanumeric() {
        findings.push(finding(
            "regex-single-literal",
            path,
            line_number,
            "single-literal regular expression",
            "medium",
        ));
    }
}

fn report_repeated_compile(
    path: &str,
    line_number: usize,
    site: &PatternSite,
    seen_patterns: &mut BTreeMap<String, usize>,
    findings: &mut Vec<Finding>,
) {
    if site.constructor && seen_patterns.get(&site.pattern).copied().unwrap_or(0) > 0 {
        findings.push(finding(
            "regex-repeated-compile",
            path,
            line_number,
            "regular expression compiled repeatedly",
            "medium",
        ));
    }
    if site.constructor {
        *seen_patterns.entry(site.pattern.clone()).or_default() += 1;
    }
}

fn report_unanchored_validation(
    path: &str,
    line_number: usize,
    line: &str,
    site: &PatternSite,
    findings: &mut Vec<Finding>,
) {
    if looks_validation(line, site)
        && !site.pattern.starts_with('^')
        && !site.pattern.starts_with(r"\A")
    {
        findings.push(finding(
            "regex-unanchored-validation",
            path,
            line_number,
            "validation regular expression is not anchored",
            "medium",
        ));
    }
}

fn report_backtracking_risk(
    path: &str,
    line_number: usize,
    pattern: &str,
    findings: &mut Vec<Finding>,
) {
    if has_ambiguous_nested_repetition(pattern) {
        findings.push(finding(
            "regex-catastrophic-backtracking-risk",
            path,
            line_number,
            "nested repetition may cause catastrophic backtracking",
            "medium",
        ));
    }
}

fn report_leading_wildcard(
    path: &str,
    line_number: usize,
    pattern: &str,
    findings: &mut Vec<Finding>,
) {
    let suffix = pattern
        .strip_prefix(".*")
        .or_else(|| pattern.strip_prefix(".+"));
    if suffix.is_some_and(|suffix| !matches!(suffix, "" | "$" | r"\z" | r"\Z")) {
        findings.push(finding(
            "regex-leading-dot-star",
            path,
            line_number,
            "regular expression starts with broad wildcard",
            "medium",
        ));
    }
}

fn report_empty_alternative(
    path: &str,
    line_number: usize,
    pattern: &str,
    findings: &mut Vec<Finding>,
) {
    if has_empty_alternative(pattern) {
        findings.push(finding(
            "regex-empty-alternative",
            path,
            line_number,
            "regular expression contains an empty alternative",
            "medium",
        ));
    }
}

fn report_ascii_range(path: &str, line_number: usize, pattern: &str, findings: &mut Vec<Finding>) {
    if pattern.contains("[A-z]") {
        findings.push(finding(
            "regex-a-z-range",
            path,
            line_number,
            "[A-z] includes punctuation between Z and a",
            "medium",
        ));
    }
}

#[derive(Clone)]
struct PatternSite {
    pattern: String,
    constructor: bool,
    raw: bool,
    start: usize,
    end: usize,
}

fn patterns(line: &str, supports_slash_literals: bool) -> Vec<PatternSite> {
    let mut result = Vec::new();
    for capture in CONSTRUCTOR_PATTERN.captures_iter(line) {
        let Some(whole) = capture.get(0) else {
            continue;
        };
        let Some(pattern) = capture.get(2).or_else(|| capture.get(3)) else {
            continue;
        };
        result.push(PatternSite {
            pattern: pattern.as_str().to_owned(),
            constructor: true,
            raw: capture.get(1).is_some(),
            start: whole.start(),
            end: whole.end(),
        });
    }
    if supports_slash_literals {
        let code = mask_quoted_strings_and_comments(line);
        result.extend(slash_literal_patterns(&code));
    }
    result.sort_by_key(|site| site.start);
    result
}

fn slash_literal_patterns(line: &str) -> Vec<PatternSite> {
    let bytes = line.as_bytes();
    let mut result = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !is_slash_literal_candidate(bytes, index) {
            index += 1;
            continue;
        }
        let start = index;
        let Some(body) = scan_slash_literal_body(bytes, start) else {
            index += 1;
            continue;
        };
        let (end, pattern) = finish_slash_literal(line, start, body);
        if let Some(pattern) = pattern {
            result.push(pattern);
        }
        index = end;
    }
    result
}

fn is_slash_literal_candidate(bytes: &[u8], index: usize) -> bool {
    bytes[index] == b'/'
        && (index == 0 || bytes[index - 1] != b'/')
        && !matches!(bytes.get(index + 1), Some(b'/') | Some(b'*') | None)
}

#[derive(Clone, Copy)]
struct SlashLiteralBody {
    closing: usize,
    units: usize,
}

#[derive(Clone, Copy)]
enum SlashLiteralBodyTransition {
    EscapedPair,
    Closing,
    Unit,
}

fn slash_literal_body_transition(bytes: &[u8], cursor: usize) -> SlashLiteralBodyTransition {
    if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
        SlashLiteralBodyTransition::EscapedPair
    } else if bytes[cursor] == b'/' {
        SlashLiteralBodyTransition::Closing
    } else {
        SlashLiteralBodyTransition::Unit
    }
}

fn scan_slash_literal_body(bytes: &[u8], start: usize) -> Option<SlashLiteralBody> {
    let mut cursor = start + 1;
    let mut units = 0usize;
    while cursor < bytes.len() {
        match slash_literal_body_transition(bytes, cursor) {
            SlashLiteralBodyTransition::EscapedPair => {
                units += 1;
                cursor += 2;
            }
            SlashLiteralBodyTransition::Closing => {
                return Some(SlashLiteralBody {
                    closing: cursor,
                    units,
                });
            }
            SlashLiteralBodyTransition::Unit => {
                units += 1;
                cursor += 1;
            }
        }
    }
    None
}

fn finish_slash_literal(
    line: &str,
    start: usize,
    body: SlashLiteralBody,
) -> (usize, Option<PatternSite>) {
    let bytes = line.as_bytes();
    let mut end = body.closing + 1;
    while end < bytes.len() && b"gimsuy".contains(&bytes[end]) {
        end += 1;
    }
    let pattern = (body.units >= 2 && can_start_slash_literal(line, start)).then(|| PatternSite {
        pattern: line[start + 1..body.closing].to_owned(),
        constructor: false,
        raw: true,
        start,
        end,
    });
    (end, pattern)
}

fn can_start_slash_literal(line: &str, offset: usize) -> bool {
    let prefix = line[..offset].trim_end();
    if prefix.is_empty() {
        return true;
    }
    if matches!(
        prefix.as_bytes().last(),
        Some(b'=')
            | Some(b'(')
            | Some(b'[')
            | Some(b'{')
            | Some(b',')
            | Some(b':')
            | Some(b';')
            | Some(b'!')
            | Some(b'?')
    ) {
        return true;
    }
    ["return", "case", "throw", "yield", "=>"]
        .iter()
        .any(|keyword| prefix.ends_with(keyword))
}

struct CommentScan {
    code: String,
    in_block_comment: bool,
}

#[derive(Clone, Copy)]
enum CommentScanState {
    Code,
    Quoted { delimiter: u8, escaped: bool },
    BlockComment,
}

fn without_comments(
    line: &str,
    in_block_comment: bool,
    hash_comments: bool,
    dash_comments: bool,
) -> CommentScan {
    let bytes = line.as_bytes();
    let mut code = String::with_capacity(bytes.len());
    let mut state = match in_block_comment {
        true => CommentScanState::BlockComment,
        false => CommentScanState::Code,
    };
    let mut copy_start = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            CommentScanState::BlockComment => match (byte, next) {
                (b'*', Some(b'/')) => {
                    code.push(' ');
                    index += 2;
                    copy_start = index;
                    state = CommentScanState::Code;
                }
                _ => {
                    code.push(' ');
                    index += 1;
                    copy_start = index;
                }
            },
            CommentScanState::Quoted { delimiter, escaped } => {
                state = match (escaped, byte) {
                    (true, _) => CommentScanState::Quoted {
                        delimiter,
                        escaped: false,
                    },
                    (false, b'\\') => CommentScanState::Quoted {
                        delimiter,
                        escaped: true,
                    },
                    (false, current) => match current == delimiter {
                        true => CommentScanState::Code,
                        false => CommentScanState::Quoted {
                            delimiter,
                            escaped: false,
                        },
                    },
                };
                index += 1;
            }
            CommentScanState::Code => match (byte, next, hash_comments, dash_comments) {
                (b'"' | b'\'' | b'`', _, _, _) => {
                    state = CommentScanState::Quoted {
                        delimiter: byte,
                        escaped: false,
                    };
                    index += 1;
                }
                (b'/', Some(b'*'), _, _) => {
                    code.push_str(&line[copy_start..index]);
                    code.push(' ');
                    index += 2;
                    copy_start = index;
                    state = CommentScanState::BlockComment;
                }
                (b'/', Some(b'/'), _, _) | (b'#', _, true, _) | (b'-', Some(b'-'), _, true) => {
                    code.push_str(&line[copy_start..index]);
                    copy_start = bytes.len();
                    break;
                }
                _ => index += 1,
            },
        }
    }
    code.push_str(&line[copy_start..]);
    CommentScan {
        code,
        in_block_comment: matches!(state, CommentScanState::BlockComment),
    }
}

#[derive(Clone, Copy)]
enum QuoteMaskState {
    Code,
    Quoted { delimiter: u8, escaped: bool },
}

enum QuoteMaskTransition {
    Preserve,
    Mask,
    MaskRemainder,
}

impl QuoteMaskState {
    fn transition(&mut self, byte: u8, next: Option<u8>) -> QuoteMaskTransition {
        match *self {
            Self::Quoted { delimiter, escaped } => {
                let next_escaped = !escaped && byte == b'\\';
                if !escaped && byte == delimiter {
                    *self = Self::Code;
                } else {
                    *self = Self::Quoted {
                        delimiter,
                        escaped: next_escaped,
                    };
                }
                QuoteMaskTransition::Mask
            }
            Self::Code if matches!(byte, b'"' | b'\'' | b'`') => {
                *self = Self::Quoted {
                    delimiter: byte,
                    escaped: false,
                };
                QuoteMaskTransition::Mask
            }
            Self::Code if byte == b'/' && next == Some(b'/') => QuoteMaskTransition::MaskRemainder,
            Self::Code => QuoteMaskTransition::Preserve,
        }
    }
}

fn mask_quoted_strings_and_comments(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut result = bytes.to_vec();
    let mut state = QuoteMaskState::Code;
    let mut index = 0usize;
    while index < bytes.len() {
        match state.transition(bytes[index], bytes.get(index + 1).copied()) {
            QuoteMaskTransition::Preserve => {}
            QuoteMaskTransition::Mask => result[index] = b' ',
            QuoteMaskTransition::MaskRemainder => {
                result[index..].fill(b' ');
                break;
            }
        }
        index += 1;
    }
    String::from_utf8(result).expect("quoted-string mask must remain UTF-8")
}

fn has_runtime_interpolation(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    (0..bytes.len()).any(|index| {
        bytes[index] == b'$'
            && (index == 0 || bytes[index - 1] != b'\\')
            && bytes
                .get(index + 1)
                .is_some_and(|next| *next == b'{' || next.is_ascii_alphabetic() || *next == b'_')
    })
}

fn is_valid_dart_pattern(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut parentheses = 0usize;
    let mut in_class = false;
    let mut escaped = false;
    for byte in bytes {
        if escaped {
            escaped = false;
            continue;
        }
        if *byte == b'\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if *byte == b']' {
                in_class = false;
            }
            continue;
        }
        match byte {
            b'[' => in_class = true,
            b'(' => parentheses += 1,
            b')' if parentheses == 0 => return false,
            b')' => parentheses -= 1,
            _ => {}
        }
    }
    !escaped && !in_class && parentheses == 0
}

fn looks_validation(line: &str, site: &PatternSite) -> bool {
    let mut without_pattern = line.as_bytes().to_vec();
    let Some(pattern_bytes) = without_pattern.get_mut(site.start..site.end) else {
        return false;
    };
    pattern_bytes.fill(b' ');
    let Ok(without_pattern) = std::str::from_utf8(&without_pattern) else {
        return false;
    };
    let code = mask_quoted_strings_and_comments(without_pattern);
    if TO_MATCH.is_match(&code) {
        return false;
    }
    if !VALIDATION_NAME.is_match(&code) {
        return false;
    }
    MATCH_METHOD.is_match(&code) || VALIDATION_ASSIGNMENT.is_match(&code)
}

fn has_ambiguous_nested_repetition(pattern: &str) -> bool {
    if REPEATED_WILDCARD.is_match(pattern) {
        return true;
    }
    for (inner, quantifier) in quantified_groups(pattern) {
        if FIXED_QUANTIFIER.is_match(quantifier) || quantifier == "{0,1}" {
            continue;
        }
        let inner = inner.strip_prefix("?:").unwrap_or(inner);
        if ESCAPED_LITERAL_DELIMITER.is_match(inner) {
            continue;
        }
        if inner.contains(".*") || inner.contains(".+") || is_repeated_single_atom(inner) {
            return true;
        }
    }
    false
}

#[derive(Default)]
struct QuantifiedGroupScanner {
    starts: Vec<usize>,
    escaped: bool,
    in_class: bool,
}

impl QuantifiedGroupScanner {
    fn close_group(&mut self, index: usize, byte: u8) -> Option<usize> {
        if self.escaped {
            self.escaped = false;
            return None;
        }
        match byte {
            b'\\' => self.escaped = true,
            b'[' if !self.in_class => self.in_class = true,
            b']' if self.in_class => self.in_class = false,
            b'(' if !self.in_class => self.starts.push(index),
            b')' if !self.in_class => return self.starts.pop(),
            _ => {}
        }
        None
    }
}

fn quantified_groups(pattern: &str) -> Vec<(&str, &str)> {
    let mut scanner = QuantifiedGroupScanner::default();
    let mut result = Vec::new();
    for (index, byte) in pattern.bytes().enumerate() {
        let Some(start) = scanner.close_group(index, byte) else {
            continue;
        };
        if let Some(group) = finish_quantified_group(pattern, start, index) {
            result.push(group);
        }
    }
    result
}

fn finish_quantified_group(pattern: &str, start: usize, closing: usize) -> Option<(&str, &str)> {
    let quantifier_start = closing + 1;
    match pattern.as_bytes().get(quantifier_start) {
        Some(b'+' | b'*') => Some((
            &pattern[start + 1..closing],
            &pattern[quantifier_start..quantifier_start + 1],
        )),
        Some(b'{') => {
            let relative_end = pattern[quantifier_start + 1..].find('}')?;
            let quantifier_end = quantifier_start + 1 + relative_end;
            let quantifier = &pattern[quantifier_start..=quantifier_end];
            BRACED_QUANTIFIER
                .is_match(quantifier)
                .then_some((&pattern[start + 1..closing], quantifier))
        }
        _ => None,
    }
}

fn is_repeated_single_atom(inner: &str) -> bool {
    let bytes = inner.as_bytes();
    if bytes.len() < 2 || !matches!(bytes[bytes.len() - 1], b'+' | b'*') {
        return false;
    }
    let atom = &inner[..inner.len() - 1];
    atom.len() == 1 && atom.as_bytes()[0] != b'\\'
        || atom.len() == 2 && atom.starts_with('\\')
        || atom.starts_with('[') && atom.ends_with(']') && !atom[1..atom.len() - 1].contains(']')
}

#[derive(Default)]
enum EmptyAlternativeLexicalState {
    #[default]
    Expression,
    EscapedExpression,
    CharacterClass,
    EscapedCharacterClass,
}

#[derive(Default)]
enum EmptyAlternativeGroupState {
    #[default]
    Start,
    Occupied,
    AfterAlternative,
}

#[derive(Default)]
struct EmptyAlternativeScanner {
    lexical: EmptyAlternativeLexicalState,
    group: EmptyAlternativeGroupState,
}

impl EmptyAlternativeScanner {
    fn consume(&mut self, byte: u8) -> bool {
        match self.lexical {
            EmptyAlternativeLexicalState::Expression => self.consume_expression(byte),
            EmptyAlternativeLexicalState::EscapedExpression => {
                self.lexical = EmptyAlternativeLexicalState::Expression;
                false
            }
            EmptyAlternativeLexicalState::CharacterClass => {
                self.consume_character_class(byte);
                false
            }
            EmptyAlternativeLexicalState::EscapedCharacterClass => {
                self.lexical = EmptyAlternativeLexicalState::CharacterClass;
                false
            }
        }
    }

    fn consume_expression(&mut self, byte: u8) -> bool {
        match byte {
            b'\\' => {
                self.lexical = EmptyAlternativeLexicalState::EscapedExpression;
                self.group = EmptyAlternativeGroupState::Occupied;
                false
            }
            b'[' => {
                self.lexical = EmptyAlternativeLexicalState::CharacterClass;
                self.group = EmptyAlternativeGroupState::Occupied;
                false
            }
            b'|' => self.consume_alternative(),
            _ => {
                self.group = EmptyAlternativeGroupState::Occupied;
                false
            }
        }
    }

    fn consume_character_class(&mut self, byte: u8) {
        match byte {
            b'\\' => self.lexical = EmptyAlternativeLexicalState::EscapedCharacterClass,
            b']' => self.lexical = EmptyAlternativeLexicalState::Expression,
            _ => {}
        }
    }

    fn consume_alternative(&mut self) -> bool {
        match self.group {
            EmptyAlternativeGroupState::Start | EmptyAlternativeGroupState::AfterAlternative => {
                true
            }
            EmptyAlternativeGroupState::Occupied => {
                self.group = EmptyAlternativeGroupState::AfterAlternative;
                false
            }
        }
    }

    fn ends_with_alternative(&self) -> bool {
        matches!(self.group, EmptyAlternativeGroupState::AfterAlternative)
    }
}

fn has_empty_alternative(pattern: &str) -> bool {
    let mut scanner = EmptyAlternativeScanner::default();
    pattern.bytes().any(|byte| scanner.consume(byte)) || scanner.ends_with_alternative()
}

fn finding(code: &str, path: &str, line: usize, message: &str, confidence: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("regex rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
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

static CONSTRUCTOR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:RegExp|re\.compile|Pattern\.compile)\s*\(\s*(r)?(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)')(?:\s*,\s*["'][gimsuy]*["'])?\s*\)"#,
    )
    .unwrap()
});
static VALIDATION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:validation|validator|validate|isValid)\w*").unwrap());
static TO_MATCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.toMatch\s*\(").unwrap());
static MATCH_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.(?:test|hasMatch|firstMatch|allMatches|matches|match)\s*\(").unwrap()
});
static VALIDATION_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:validation|validator|validate|isValid)\w*\s*=").unwrap()
});
static REPEATED_WILDCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\*){2,}|(?:\.\+){2,}").unwrap());
static FIXED_QUANTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\{\d+\}$").unwrap());
static BRACED_QUANTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\{\d*,?\d*\}$").unwrap());
static ESCAPED_LITERAL_DELIMITER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\[^A-Za-z0-9]$").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn reports_complete_regex_rule_family() {
        let source = r#"final invalid = RegExp(r'[');
final literal = RegExp('x');
final first = RegExp('[A-z]+');
final second = RegExp('[A-z]+');
if (RegExp('ordinary').hasMatch(input)) {}
final RegExpMatch? ordinaryMatch = RegExp('ordinary').firstMatch(input);
final validationEmail = RegExp('.*(a+)+|');"#;
        let codes = analyze(&BTreeMap::from([(
            "patterns.dart".to_owned(),
            source.to_owned(),
        )]))
        .into_iter()
        .map(|finding| finding.code)
        .collect::<BTreeSet<_>>();
        assert_eq!(
            codes,
            BTreeSet::from([
                "regex-a-z-range".to_owned(),
                "regex-catastrophic-backtracking-risk".to_owned(),
                "regex-empty-alternative".to_owned(),
                "regex-invalid".to_owned(),
                "regex-leading-dot-star".to_owned(),
                "regex-repeated-compile".to_owned(),
                "regex-single-literal".to_owned(),
                "regex-unanchored-validation".to_owned(),
            ])
        );
    }

    #[test]
    fn ignores_regexes_that_only_match_an_unrestricted_value() {
        let mut findings = Vec::new();
        report_leading_wildcard("patterns.py", 1, ".*", &mut findings);
        report_leading_wildcard("patterns.py", 2, ".+$", &mut findings);
        report_leading_wildcard("patterns.py", 3, ".*required", &mut findings);

        assert_eq!(
            findings
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn distinguishes_escaped_pipes_and_javascript_division() {
        let source = r#"const shell = /\bcommand\s+-v\b|&&|\|\||>\/dev\/null|2>&1/;
const classPipe = /[|]/;
const ratio = total / count;
const leading = /|value/;
const trailing = /value|/;
const adjacent = /value||other/;"#;
        let lines = analyze(&BTreeMap::from([(
            "patterns.js".to_owned(),
            source.to_owned(),
        )]))
        .into_iter()
        .filter(|finding| finding.code == "regex-empty-alternative")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
        assert_eq!(lines, vec![4, 5, 6]);
    }

    #[test]
    fn ignores_comments_interpolation_and_safe_repetition() {
        let sources = BTreeMap::from([
            (
                "patterns.dart".to_owned(),
                r"final dynamic = RegExp('^$typeName\\(');\n// RegExp(r'[');".to_owned(),
            ),
            (
                "patterns.js".to_owned(),
                "const path = /(?:[\\w@.+-]+\\/)+[\\w@.+-]+\\.[A-Za-z]\\w*/g;\n/* RegExp(r'['); */"
                    .to_owned(),
            ),
        ]);
        assert!(analyze(&sources).into_iter().all(|finding| {
            finding.code != "regex-invalid"
                && finding.code != "regex-catastrophic-backtracking-risk"
        }));
    }

    #[test]
    fn malformed_constructor_patterns_do_not_abort_analysis() {
        let source = r#"final openClass = RegExp(r'[abc');
final openGroup = RegExp(r'(abc');
final extraClose = RegExp(r'abc)');
final unicodeOpenGroup = RegExp(r"(é");
final literal = RegExp('x');"#;
        let findings = analyze(&BTreeMap::from([(
            "malformed.dart".to_owned(),
            source.to_owned(),
        )]))
        .into_iter()
        .map(|finding| (finding.code, finding.line))
        .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("regex-invalid".to_owned(), 1),
                ("regex-invalid".to_owned(), 2),
                ("regex-invalid".to_owned(), 3),
                ("regex-invalid".to_owned(), 4),
                ("regex-single-literal".to_owned(), 5),
            ]
        );
    }

    #[test]
    fn malformed_slash_literals_do_not_abort_analysis() {
        let source = "const closeOnly = /)+/;\n\
            const unicodeOpenGroup = /(é/;\n\
            const openGroup = /(abc/;\n\
            const nestedOpenGroup = /((a+)+/;\n\
            const unterminated = /abc\\\n\
            const range = /[A-z]/;";
        let findings = analyze(&BTreeMap::from([(
            "malformed.js".to_owned(),
            source.to_owned(),
        )]))
        .into_iter()
        .map(|finding| (finding.code, finding.line))
        .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("regex-catastrophic-backtracking-risk".to_owned(), 4),
                ("regex-a-z-range".to_owned(), 6),
            ]
        );
    }
}
