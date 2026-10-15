use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::dart_null_assertion::dart_source_with_interpolations;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{index::DartSourceIndex, quote_aware_matching_delimiter};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        let source = index.source(path);
        let original_lines = source.split('\n').collect::<Vec<_>>();
        let masked = dart_source_with_interpolations(source, &index.masked_lines(path).join("\n"));
        let masked_lines =
            mask_comments(&masked.split('\n').map(str::to_owned).collect::<Vec<_>>());
        let masked_source = masked_lines.join("\n");
        findings.extend(line_rules(path, &original_lines, &masked_lines));
        findings.extend(blocking_async_operations(path, source));
        findings.extend(process_shell_invocations(path, source, &masked_lines));
        findings.extend(broad_catches(path, &masked_source));
        findings.extend(unreachable_statements(path, &masked_lines));
    }
    findings
}

pub(crate) fn mask_comments(lines: &[String]) -> Vec<String> {
    let mut masker = LineCommentMasker::default();
    let mut result = Vec::with_capacity(lines.len());
    for line in lines {
        result.push(masker.mask_line(line));
    }
    result
}

#[derive(Default)]
struct LineCommentMasker {
    block_depth: usize,
}

enum CommentTransition {
    OpenBlock,
    CloseBlock,
    LineComment,
    MaskByte,
    Advance,
}

impl LineCommentMasker {
    fn mask_line(&mut self, line: &str) -> String {
        let bytes = line.as_bytes();
        let mut masked = bytes.to_vec();
        let mut index = 0usize;
        while index < bytes.len() {
            match self.transition(&bytes[index..]) {
                CommentTransition::OpenBlock => {
                    self.block_depth += 1;
                    masked[index..index + 2].fill(b' ');
                    index += 2;
                }
                CommentTransition::CloseBlock => {
                    self.block_depth -= 1;
                    masked[index..index + 2].fill(b' ');
                    index += 2;
                }
                CommentTransition::LineComment => {
                    masked[index..].fill(b' ');
                    break;
                }
                CommentTransition::MaskByte => {
                    masked[index] = b' ';
                    index += 1;
                }
                CommentTransition::Advance => index += 1,
            }
        }
        String::from_utf8(masked).expect("ASCII comment masking preserves UTF-8")
    }

    fn transition(&self, remaining: &[u8]) -> CommentTransition {
        if self.block_depth > 0 {
            if remaining.starts_with(b"/*") {
                CommentTransition::OpenBlock
            } else if remaining.starts_with(b"*/") {
                CommentTransition::CloseBlock
            } else {
                CommentTransition::MaskByte
            }
        } else if remaining.starts_with(b"//") {
            CommentTransition::LineComment
        } else if remaining.starts_with(b"/*") {
            CommentTransition::OpenBlock
        } else {
            CommentTransition::Advance
        }
    }
}

pub(crate) fn mask_comments_preserving_strings(source: &str) -> String {
    DartCommentMasker::new(source).mask()
}

struct DartCommentMasker<'a> {
    bytes: &'a [u8],
    masked: Vec<u8>,
    block_depth: usize,
    quote: Option<u8>,
    triple: bool,
    raw: bool,
    index: usize,
}

impl<'a> DartCommentMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            masked: source.as_bytes().to_vec(),
            block_depth: 0,
            quote: None,
            triple: false,
            raw: false,
            index: 0,
        }
    }

    fn mask(mut self) -> String {
        while self.index < self.bytes.len() {
            if self.block_depth > 0 {
                self.consume_block_comment();
            } else if self.quote.is_some() {
                self.consume_quoted_byte();
            } else {
                self.consume_code_byte();
            }
        }
        String::from_utf8(self.masked).expect("ASCII comment masking preserves UTF-8")
    }

    fn consume_block_comment(&mut self) {
        if self.bytes[self.index..].starts_with(b"/*") {
            self.block_depth += 1;
            self.masked[self.index..self.index + 2].fill(b' ');
            self.index += 2;
        } else if self.bytes[self.index..].starts_with(b"*/") {
            self.block_depth -= 1;
            self.masked[self.index..self.index + 2].fill(b' ');
            self.index += 2;
        } else {
            if self.bytes[self.index] != b'\n' {
                self.masked[self.index] = b' ';
            }
            self.index += 1;
        }
    }

    fn consume_quoted_byte(&mut self) {
        let current_quote = self.quote.unwrap_or_default();
        if self.triple && self.bytes[self.index..].starts_with(&[current_quote; 3]) {
            self.close_quote(3);
        } else if !self.triple
            && !self.raw
            && self.bytes[self.index] == b'\\'
            && self.index + 1 < self.bytes.len()
        {
            self.index += 2;
        } else if !self.triple && self.bytes[self.index] == current_quote {
            self.close_quote(1);
        } else {
            self.index += 1;
        }
    }

    fn close_quote(&mut self, width: usize) {
        self.quote = None;
        self.raw = false;
        self.index += width;
    }

    fn consume_code_byte(&mut self) {
        if self.bytes[self.index..].starts_with(b"//") {
            self.consume_line_comment();
        } else if self.bytes[self.index..].starts_with(b"/*") {
            self.block_depth = 1;
            self.masked[self.index..self.index + 2].fill(b' ');
            self.index += 2;
        } else if matches!(self.bytes[self.index], b'\'' | b'"') {
            self.open_quote();
        } else {
            self.index += 1;
        }
    }

    fn consume_line_comment(&mut self) {
        while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
            self.masked[self.index] = b' ';
            self.index += 1;
        }
    }

    fn open_quote(&mut self) {
        let current_quote = self.bytes[self.index];
        self.raw = self.index > 0
            && matches!(self.bytes[self.index - 1], b'r' | b'R')
            && (self.index == 1
                || !(self.bytes[self.index - 2].is_ascii_alphanumeric()
                    || self.bytes[self.index - 2] == b'_'));
        self.triple = self.bytes[self.index..].starts_with(&[current_quote; 3]);
        self.quote = Some(current_quote);
        self.index += if self.triple { 3 } else { 1 };
    }
}

fn line_rules(path: &str, original_lines: &[&str], masked_lines: &[String]) -> Vec<Finding> {
    let masked_source = masked_lines.join("\n");
    let cli_main_lines = command_line_main_lines(path, &masked_source);
    let mut findings = Vec::new();
    emit_late_declaration_findings(path, &masked_source, &mut findings);
    emit_per_line_findings(path, original_lines, masked_lines, &mut findings);
    emit_print_findings(path, &masked_source, &cli_main_lines, &mut findings);
    findings
}

fn emit_late_declaration_findings(path: &str, source: &str, findings: &mut Vec<Finding>) {
    for declaration in LATE_DECLARATION.captures_iter(source) {
        let tail = declaration.get(1).unwrap().as_str().trim_start();
        if is_final_declaration(tail) {
            continue;
        }
        let declaration_match = declaration.get(0).unwrap();
        let line = line_at(source, declaration_match.start());
        let mut issue = finding(
            "dart-late-mutable",
            path,
            line,
            "mutable late variable used",
            "medium",
        );
        let statement_end = source[declaration_match.start()..]
            .find(';')
            .map(|offset| declaration_match.start() + offset)
            .unwrap_or_else(|| declaration_match.end().saturating_sub(1));
        issue.end_line = line_at(source, statement_end);
        findings.push(issue);
    }
}

fn is_final_declaration(tail: &str) -> bool {
    tail.strip_prefix("final")
        .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

fn emit_per_line_findings(
    path: &str,
    original_lines: &[&str],
    masked_lines: &[String],
    findings: &mut Vec<Finding>,
) {
    for (index, (original, masked)) in original_lines.iter().zip(masked_lines).enumerate() {
        emit_qualified_line_findings(path, index + 1, original, masked, findings);
    }
}

fn emit_qualified_line_findings(
    path: &str,
    line: usize,
    original: &str,
    masked: &str,
    findings: &mut Vec<Finding>,
) {
    if is_analyzer_suppression(original) {
        findings.push(finding(
            "dart-analyzer-ignore",
            path,
            line,
            "Dart analyzer diagnostic suppressed",
            "medium",
        ));
    }
    for _ in DYNAMIC.find_iter(masked) {
        findings.push(finding(
            "dart-dynamic",
            path,
            line,
            "dynamic disables static type checking at this boundary",
            "high",
        ));
    }
    findings.extend(secret_findings(path, line, original, masked));
    emit_sensitive_random_finding(path, line, masked, findings);
}

fn is_analyzer_suppression(source: &str) -> bool {
    let trimmed = source.trim();
    trimmed.starts_with("// ignore:") || trimmed.starts_with("// ignore_for_file:")
}

fn emit_sensitive_random_finding(
    path: &str,
    line: usize,
    masked: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(declaration) = SENSITIVE_RANDOM.captures(masked) else {
        return;
    };
    let name = declaration.get(1).unwrap().as_str();
    if SENSITIVE_NAME.is_match(name) {
        findings.push(finding(
            "dart-insecure-random",
            path,
            line,
            "non-cryptographic Random used for security-sensitive value",
            "high",
        ));
    }
}

fn emit_print_findings(
    path: &str,
    source: &str,
    cli_main_lines: &BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    for invocation in DIRECT_PRINT.find_iter(source) {
        emit_qualified_print_finding(path, source, invocation, cli_main_lines, findings);
    }
}

fn emit_qualified_print_finding(
    path: &str,
    source: &str,
    invocation: regex::Match<'_>,
    cli_main_lines: &BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    let line = line_at(source, invocation.start());
    if cli_main_lines.contains(&line) {
        return;
    }
    let open = invocation.end() - 1;
    let Some(close) = quote_aware_matching_delimiter(source, open, b'(', b')') else {
        return;
    };
    let mut result = finding(
        "dart-print",
        path,
        line,
        "print call left in application code",
        "medium",
    );
    result.end_line = line_at(source, close);
    findings.push(result);
}

fn secret_findings(path: &str, line: usize, source: &str, masked: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for declaration in STRING_DECLARATION.captures_iter(source) {
        let name_capture = declaration.name("name").unwrap();
        let name = name_capture.as_str();
        if masked.get(name_capture.range()) != Some(name) || !SENSITIVE_NAME.is_match(name) {
            continue;
        }
        let value = declaration.name("value").unwrap().as_str();
        if looks_like_secret(value)
            && !is_public_protocol_identifier(name, value)
            && !GRAPHQL_OPERATION.is_match(value.trim_start())
            && !is_deterministic_test_fixture_secret(path, value)
        {
            findings.push(finding(
                "dart-hardcoded-secret",
                path,
                line,
                &format!("possible hardcoded secret assigned to `{name}`"),
                "high",
            ));
        }
    }
    findings
}

fn looks_like_secret(value: &str) -> bool {
    let normalized = value.trim();
    let lower = normalized.to_ascii_lowercase();
    if normalized.contains("-----BEGIN ") && normalized.contains("PRIVATE KEY-----") {
        return true;
    }
    if normalized.len() < 12
        || [
            "password",
            "changeme",
            "your-secret",
            "your_api_key",
            "placeholder",
            "example",
        ]
        .contains(&lower.as_str())
    {
        return false;
    }
    if normalized
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
        && !normalized
            .chars()
            .any(|character| character.is_ascii_digit())
    {
        return false;
    }
    let has_lower = normalized
        .chars()
        .any(|character| character.is_ascii_lowercase());
    let has_upper = normalized
        .chars()
        .any(|character| character.is_ascii_uppercase());
    let has_digit = normalized
        .chars()
        .any(|character| character.is_ascii_digit());
    has_lower && (has_upper || has_digit)
}

fn is_public_protocol_identifier(name: &str, value: &str) -> bool {
    URI_SCHEME.is_match(value)
        || name.to_ascii_lowercase().contains("useragent")
        || name.to_ascii_lowercase().contains("user_agent")
}

fn is_deterministic_test_fixture_secret(path: &str, value: &str) -> bool {
    TEST_PATH.is_match(path) && NUMBERED_FIXTURE_CREDENTIAL.is_match(value.trim())
}

fn command_line_main_lines(path: &str, source: &str) -> BTreeSet<usize> {
    if !path.starts_with("bin/") && !path.starts_with("tool/") {
        return BTreeSet::new();
    }
    let mut lines = BTreeSet::new();
    for declaration in MAIN_FUNCTION.find_iter(source) {
        let open = declaration.end() - 1;
        let Some(close) = quote_aware_matching_delimiter(source, open, b'{', b'}') else {
            continue;
        };
        let start_line = line_at(source, declaration.start());
        let end_line = line_at(source, close);
        lines.extend(start_line..=end_line);
    }
    lines
}

fn blocking_async_operations(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut async_depth = 0isize;
    for (index, raw) in source.split('\n').enumerate() {
        let line = raw.trim();
        if line.contains(" async") || line.starts_with("async ") {
            async_depth = 1;
        }
        if async_depth > 0 {
            async_depth += raw.bytes().filter(|byte| *byte == b'{').count() as isize;
            async_depth -= raw.bytes().filter(|byte| *byte == b'}').count() as isize;
        }
        if async_depth > 0 && BLOCKING_OPERATION.is_match(line) {
            findings.push(finding(
                "dart-blocking-in-async",
                path,
                index + 1,
                "blocking operation used in async code",
                "medium",
            ));
        }
        if async_depth > 0 && line.starts_with('}') {
            async_depth = 0;
        }
    }
    findings
}

fn process_shell_invocations(path: &str, source: &str, masked_lines: &[String]) -> Vec<Finding> {
    let masked = masked_lines.join("\n");
    let mut findings = Vec::new();
    for invocation in PROCESS_INVOCATION.find_iter(&masked) {
        let open = invocation.end() - 1;
        let Some(close) = quote_aware_matching_delimiter(&masked, open, b'(', b')') else {
            continue;
        };
        if RUN_IN_SHELL.is_match(&masked[open + 1..close]) {
            findings.push(finding(
                "dart-process-shell",
                path,
                line_at(source, invocation.start()),
                "process launched through a shell",
                "high",
            ));
        }
    }
    findings
}

fn broad_catches(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for clause in CATCH_CLAUSE.captures_iter(source) {
        let whole = clause.get(0).unwrap();
        let prefix_start = whole.start().saturating_sub(2_000);
        let prefix = &source[prefix_start..whole.start()];
        if TYPED_CATCH_PREFIX.is_match(prefix) {
            continue;
        }
        let open = whole.end() - 1;
        let Some(close) = quote_aware_matching_delimiter(source, open, b'{', b'}') else {
            continue;
        };
        let body = &source[open + 1..close];
        let parameters = clause.get(1).unwrap().as_str();
        let names = parameters
            .split(',')
            .map(str::trim)
            .filter(|name| IDENTIFIER.is_match(name))
            .collect::<Vec<_>>();
        let forwards = RETHROW.is_match(body)
            || (names.len() >= 2
                && Regex::new(&format!(
                    r"\bcompleteError\s*\(\s*{}\s*,\s*{}\s*\)",
                    regex::escape(names[0]),
                    regex::escape(names[1])
                ))
                .unwrap()
                .is_match(body));
        if !forwards {
            let line = line_at(source, whole.start());
            let mut result = finding(
                "dart-broad-catch",
                path,
                line,
                "catch clause catches every exception type",
                "high",
            );
            result.end_line = line_at(source, close);
            findings.push(result);
        }
    }
    findings
}

fn unreachable_statements(path: &str, masked_lines: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in masked_lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !UNCONDITIONAL_FLOW.is_match(trimmed) {
            continue;
        }
        let indentation = line.len() - trimmed.len();
        for (next_index, next) in masked_lines.iter().enumerate().skip(index + 1) {
            let next_trimmed = next.trim_start();
            if next_trimmed.is_empty() {
                continue;
            }
            let next_indentation = next.len() - next_trimmed.len();
            if next_trimmed.starts_with('}') || next_indentation < indentation {
                break;
            }
            findings.push(finding(
                "dart-unreachable-statement",
                path,
                next_index + 1,
                "statement is unreachable after unconditional control flow",
                "high",
            ));
            break;
        }
    }
    findings
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding(code: &str, path: &str, line: usize, message: &str, confidence: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart core rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart core rule severity must be valid"),
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

static DYNAMIC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdynamic\b").unwrap());
static LATE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?ms)^[ \t]*(?:(?:static|external|covariant)[ \t]+)*late[ \t]+(.+?)(?:;|=)")
        .unwrap()
});
static DIRECT_PRINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^.\w])print\s*\(").unwrap());
static STRING_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:(?:const|final|var|late(?:\s+final)?)\s+(?:[A-Za-z_]\w*(?:<[^;=]+>)?\s+)?|[A-Za-z_]\w*(?:<[^;=]+>)?\s+)(?P<name>[A-Za-z_]\w*)\s*=\s*r?[\"'](?P<value>[^\"'\r\n]*)[\"']"#).unwrap()
});
static SENSITIVE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)password|secret|api_?key|access_?token|auth_?token|token|nonce|private_?key")
        .unwrap()
});
static SENSITIVE_RANDOM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:const|final|var|late|[A-Za-z_]\w*)\s+(?:[A-Za-z_]\w*\s+)?([A-Za-z_]\w*)\s*=.*\bRandom\s*\(").unwrap()
});
static URI_SCHEME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://").unwrap());
static GRAPHQL_OPERATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:query|mutation|subscription|fragment)\b").unwrap());
static TEST_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|/)(?:test|tests)(?:/|$)|_test\.dart$").unwrap());
static NUMBERED_FIXTURE_CREDENTIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[a-z]+(?:[-_][a-z]+)+[-_]\d{1,6}$").unwrap());
static MAIN_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:void|Future(?:<[^>]+>)?)\s+main\s*\([^)]*\)\s*(?:async\s*)?\{").unwrap()
});
static BLOCKING_OPERATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sleep|readAsStringSync|writeAsStringSync|readAsBytesSync)\s*\(").unwrap()
});
static PROCESS_INVOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bProcess\.(?:run|start)\s*\(").unwrap());
static RUN_IN_SHELL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\brunInShell\s*:\s*true\b").unwrap());
static CATCH_CLAUSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcatch\s*\(([^)]*)\)\s*\{").unwrap());
static TYPED_CATCH_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bon\s+[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:<[^>]+>)?\s*$").unwrap()
});
static RETHROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\brethrow\b").unwrap());
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());
static UNCONDITIONAL_FLOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:return\b[^;]*;|throw\b[^;]*;|rethrow\s*;|break(?:\s+\w+)?\s*;|continue(?:\s+\w+)?\s*;)\s*$").unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn finds_core_style_security_and_idiomatic_risks() {
        let fixture = Fixture::new([(
            "lib/risky.dart",
            "void run(dynamic input, String command) async {\n\tprint(input);  \n  late String value;\n  final token = Random();\n  try {\n    Process.run(command, const [], runInShell: true);\n  } catch (_) {}\n}",
        )]);
        let codes = analyze(&fixture.context())
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();

        assert!(codes.contains("dart-dynamic"));
        assert!(codes.contains("dart-print"));
        assert!(codes.contains("dart-late-mutable"));
        assert!(codes.contains("dart-insecure-random"));
        assert!(codes.contains("dart-process-shell"));
        assert!(codes.contains("dart-broad-catch"));
    }

    #[test]
    fn reports_analyzer_suppression_and_blocking_async_operations() {
        let fixture = Fixture::new([(
            "lib/io.dart",
            "// ignore_for_file: avoid_print\nFuture<String> load(File file) async {\n  return file.readAsStringSync();\n}",
        )]);
        let findings = analyze(&fixture.context());

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("dart-analyzer-ignore", 1), ("dart-blocking-in-async", 3),]
        );
    }

    #[test]
    fn reports_only_mutable_late_declarations() {
        let fixture = Fixture::new([(
            "lib/declarations.dart",
            "void declarations() {\n  var template = 'late String inside a string';\n  final chocolate = 'Chocolate tree';\n  // late String insideAComment;\n  late final String immutable;\n  late String mutable;\n  late Map<String?, Object?> Function(Map<String?, Object?> value)\n    multilineMutable;\n  builder..late = true;\n}",
        )]);
        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "dart-late-mutable")
            .collect::<Vec<_>>();

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.line, finding.end_line))
                .collect::<Vec<_>>(),
            [(6, 6), (7, 8)]
        );
    }

    #[test]
    fn allows_print_only_in_command_line_main() {
        let fixture = Fixture::new([
            (
                "tool/report.dart",
                "void main() {\n  print('machine-readable report');\n}\nvoid debug() {\n  print('temporary diagnostic');\n}",
            ),
            (
                "lib/application.dart",
                "void main() {\n  print('application diagnostic');\n}",
            ),
        ]);
        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "dart-print")
            .collect::<Vec<_>>();

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("lib/application.dart", 2), ("tool/report.dart", 5)]
        );
    }

    #[test]
    fn requires_credential_entropy_and_excludes_public_or_fixture_values() {
        let fixture = Fixture::new([
            (
                "lib/secrets.dart",
                "const tokenGroup = 'md.comp.assist-chip';\nconst tokenPath = '/path/to/token';\nconst passwordTextFieldKeyValue = 'passwordField';\nconst accessToken = '0123456789abcdef';\nconst privateKey = '-----BEGIN PRIVATE KEY-----data-----END PRIVATE KEY-----';\nconst nonceUrl = 'https://api.example.com/v1/secure/nonce';\nconst allowlistedUserAgentToken = 'Product-v3.5.9';",
            ),
            (
                "test/show_instance_test.dart",
                "const showToken = 'show-token-3165';\nconst accessToken = '0123456789abcdef';",
            ),
        ]);
        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "dart-hardcoded-secret")
            .collect::<Vec<_>>();

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("lib/secrets.dart", 4),
                ("lib/secrets.dart", 5),
                ("test/show_instance_test.dart", 2),
            ]
        );
    }

    #[test]
    fn ignores_secret_shaped_assignments_inside_multiline_string_fixtures() {
        let fixture = Fixture::new([(
            "test/rules_test.dart",
            "const fixture = '''\nconst nonce = \"4AEemGb0xJptoIGFP3Nd\";\n''';\nconst nonce = '4AEemGb0xJptoIGFP3Nd';",
        )]);

        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "dart-hardcoded-secret")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn reports_unreachable_statements_and_accepts_typed_safe_process_code() {
        let fixture = Fixture::new([
            (
                "lib/storage.dart",
                "String? read(String key) {\n  return null;\n  print('disabled implementation');\n}",
            ),
            (
                "lib/safe.dart",
                "void run(String input) {\n  try {\n    Process.run('git', <String>['status']);\n  } on ProcessException catch (error) {\n    printError(error);\n  }\n}",
            ),
        ]);
        let findings = analyze(&fixture.context());

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "dart-unreachable-statement")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert!(!findings.iter().any(|finding| {
            finding.path == "lib/safe.dart"
                && matches!(
                    finding.code.as_str(),
                    "dart-process-shell" | "dart-broad-catch"
                )
        }));
    }

    #[test]
    fn masks_comments_after_raw_strings_without_masking_urls() {
        let source = "final slash = r'\\'; // remove me\nfinal url = 'https://example.test/path';";
        let masked = mask_comments_preserving_strings(source);

        assert!(masked.contains("r'\\'"));
        assert!(masked.contains("https://example.test/path"));
        assert!(!masked.contains("remove me"));
    }

    #[test]
    fn masks_nested_comments_while_preserving_multiline_literals() {
        let source = "final fixture = '''// kept\n/* kept */'''; /* outer /* nested */ removed */\n\
final raw = r'// kept raw'; // gone";
        let masked = mask_comments_preserving_strings(source);

        assert_eq!(masked.len(), source.len());
        assert_eq!(masked.matches('\n').count(), source.matches('\n').count());
        assert!(masked.contains("// kept\n/* kept */"));
        assert!(masked.contains("r'// kept raw'"));
        assert!(!masked.contains("removed"));
        assert!(!masked.contains("gone"));
    }

    struct Fixture {
        sources: BTreeMap<String, String>,
    }

    impl Fixture {
        fn new<const N: usize>(sources: [(&str, &str); N]) -> Self {
            Self {
                sources: sources
                    .into_iter()
                    .map(|(path, source)| (path.to_owned(), source.to_owned()))
                    .collect(),
            }
        }

        fn context(&self) -> SourceAnalysisContext<'_> {
            SourceAnalysisContext::unchanged(&self.sources)
        }
    }
}
