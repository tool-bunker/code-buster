use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

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
        let comments_masked = index.comments_masked(path);
        let code = mask_string_literals(comments_masked);
        let scopes = function_scopes(&code);
        let loops = loops(&code);
        findings.extend(loop_findings(path, source, &code, &scopes, &loops));
        findings.extend(regexp_findings(path, source, &code, &loops));
        findings.extend(repeated_traversal_findings(path, source, &code, &scopes));
    }
    findings
}

#[derive(Debug)]
struct FunctionScope {
    start: usize,
    body_start: usize,
    end: usize,
    parameters: String,
    is_class_method: bool,
}

fn function_scopes(code: &str) -> Vec<FunctionScope> {
    let classes = class_ranges(code);
    NAMED_FUNCTION
        .captures_iter(code)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            let marker = captures.name("marker")?;
            let (body_start, end) = if marker.as_str() == "{" {
                (
                    marker.end(),
                    quote_aware_matching_delimiter(code, marker.start(), b'{', b'}')? + 1,
                )
            } else {
                (marker.end(), expression_end(code, marker.end()))
            };
            let class = classes
                .iter()
                .find(|range| range.body_start <= whole.start() && end <= range.end);
            let is_class_method =
                class.is_some_and(|range| brace_depth(code, range.body_start, whole.start()) == 0);
            Some(FunctionScope {
                start: whole.start(),
                body_start,
                end,
                parameters: captures.name("parameters")?.as_str().to_owned(),
                is_class_method,
            })
        })
        .collect()
}

struct ClassRange {
    body_start: usize,
    end: usize,
}

fn class_ranges(code: &str) -> Vec<ClassRange> {
    CLASS_START
        .find_iter(code)
        .filter_map(|matched| {
            let open = matched.end() - 1;
            Some(ClassRange {
                body_start: open + 1,
                end: quote_aware_matching_delimiter(code, open, b'{', b'}')? + 1,
            })
        })
        .collect()
}

fn brace_depth(code: &str, start: usize, end: usize) -> usize {
    let mut depth = 0usize;
    for byte in &code.as_bytes()[start..end] {
        if *byte == b'{' {
            depth += 1;
        } else if *byte == b'}' {
            depth = depth.saturating_sub(1);
        }
    }
    depth
}

#[derive(Debug)]
struct Loop {
    start: usize,
    end: usize,
    repeated_ranges: Vec<(usize, usize)>,
}

fn loops(code: &str) -> Vec<Loop> {
    let mut result = Vec::new();
    let mut do_while_offsets = BTreeSet::new();

    for matched in DO_KEYWORD.find_iter(code) {
        let Some((body_start, body_end)) = statement_range(code, matched.end()) else {
            continue;
        };
        let mut cursor = skip_whitespace(code, body_end);
        if !code[cursor..].starts_with("while") {
            continue;
        }
        let while_start = cursor;
        cursor = skip_whitespace(code, cursor + "while".len());
        if code.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        let Some(condition_end) = quote_aware_matching_delimiter(code, cursor, b'(', b')') else {
            continue;
        };
        do_while_offsets.insert(while_start);
        result.push(Loop {
            start: matched.start(),
            end: expression_end(code, condition_end + 1),
            repeated_ranges: vec![(body_start, body_end), (cursor + 1, condition_end)],
        });
    }

    for captures in LOOP_START.captures_iter(code) {
        let whole = captures.get(0).unwrap();
        let kind = captures.get(1).unwrap().as_str();
        if kind == "while" && do_while_offsets.contains(&whole.start()) {
            continue;
        }
        let open = whole.end() - 1;
        let Some(close) = quote_aware_matching_delimiter(code, open, b'(', b')') else {
            continue;
        };
        let Some((body_start, body_end)) = statement_range(code, close + 1) else {
            continue;
        };
        let mut repeated_ranges = vec![(body_start, body_end)];
        if kind == "while" {
            repeated_ranges.push((open + 1, close));
        } else if let Some(first_semicolon) = top_level_separator(&code[open + 1..close], b';') {
            repeated_ranges.push((open + 1 + first_semicolon + 1, close));
        }
        result.push(Loop {
            start: whole.start(),
            end: body_end,
            repeated_ranges,
        });
    }

    result.sort_by_key(|item| item.start);
    result
}

fn loop_findings(
    path: &str,
    source: &str,
    code: &str,
    scopes: &[FunctionScope],
    loops: &[Loop],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for current in loops.iter().filter(|current| {
        !loops
            .iter()
            .any(|candidate| candidate.start < current.start && current.end <= candidate.end)
    }) {
        let Some(scope) = enclosing_scope(scopes, current.start) else {
            continue;
        };
        let function_text = &code[scope.start..scope.end];
        let loop_text = &code[current.start..current.end];
        let strings = STRING_DECLARATION
            .captures_iter(function_text)
            .filter_map(|captures| captures.get(1).map(|matched| matched.as_str()));
        if strings.into_iter().any(|name| {
            Regex::new(&format!(r"\b{}\s*\+=", regex::escape(name)))
                .unwrap()
                .is_match(loop_text)
        }) {
            findings.push(finding(
                "dart-string-concat-in-loop",
                path,
                line_at(source, current.start),
                line_at(source, current.end.saturating_sub(1)),
                "String concatenation occurs during each loop iteration",
            ));
        }

        let mut has_list_membership = false;
        let mut has_front_removal = false;
        for name in LIST_DECLARATION
            .captures_iter(function_text)
            .filter_map(|captures| captures.get(1).map(|matched| matched.as_str()))
        {
            has_list_membership |=
                Regex::new(&format!(r"\b{}\s*\.\s*contains\s*\(", regex::escape(name)))
                    .unwrap()
                    .is_match(loop_text);
            has_front_removal |= Regex::new(&format!(
                r"\b{}\s*\.\s*removeAt\s*\(\s*0\s*\)",
                regex::escape(name)
            ))
            .unwrap()
            .is_match(loop_text);
        }
        if has_list_membership {
            findings.push(finding(
                "dart-quadratic-list-membership",
                path,
                line_at(source, current.start),
                line_at(source, current.end.saturating_sub(1)),
                "List.contains performs a linear membership scan inside a loop",
            ));
        }
        if has_front_removal {
            findings.push(finding(
                "dart-list-front-removal-in-loop",
                path,
                line_at(source, current.start),
                line_at(source, current.end.saturating_sub(1)),
                "List.removeAt(0) shifts the remaining elements during each loop iteration",
            ));
        }
    }
    findings
}

struct ClosureRange {
    start: usize,
    end: usize,
}

fn arrow_closure_ranges(code: &str) -> Vec<ClosureRange> {
    ARROW_CLOSURE
        .find_iter(code)
        .map(|matched| ClosureRange {
            start: matched.start(),
            end: expression_end(code, matched.end()),
        })
        .collect()
}

fn regexp_findings(path: &str, source: &str, code: &str, loops: &[Loop]) -> Vec<Finding> {
    let closures = arrow_closure_ranges(code);
    let mut reported = BTreeSet::new();
    let mut findings = Vec::new();
    for matched in CONSTANT_REGEXP
        .find_iter(source)
        .filter(|matched| code.as_bytes()[matched.start()] != b' ')
    {
        let selected = loops
            .iter()
            .enumerate()
            .filter(|(_, current)| {
                current
                    .repeated_ranges
                    .iter()
                    .any(|(start, end)| *start <= matched.start() && matched.end() <= *end)
                    && !closures.iter().any(|closure| {
                        closure.start <= matched.start()
                            && matched.end() <= closure.end
                            && current.start < closure.start
                    })
            })
            .min_by_key(|(_, current)| current.end - current.start);
        let Some((index, _)) = selected else {
            continue;
        };
        if reported.insert(index) {
            findings.push(finding(
                "dart-regexp-created-in-loop",
                path,
                line_at(source, matched.start()),
                line_at(source, matched.end().saturating_sub(1)),
                "constant RegExp is compiled during each loop iteration",
            ));
        }
    }
    findings
}

fn repeated_traversal_findings(
    path: &str,
    source: &str,
    code: &str,
    scopes: &[FunctionScope],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for scope in scopes.iter().filter(|scope| scope.is_class_method) {
        let text = &code[scope.start..scope.end];
        let mut names = COLLECTION_DECLARATION
            .captures_iter(&scope.parameters)
            .filter_map(|captures| captures.get(1).map(|matched| matched.as_str().to_owned()))
            .collect::<BTreeSet<_>>();
        names.extend(
            COLLECTION_DECLARATION
                .captures_iter(text)
                .filter_map(|captures| captures.get(1).map(|matched| matched.as_str().to_owned())),
        );
        let mut counts = BTreeMap::new();
        for name in names {
            let traversal = Regex::new(&format!(
                r"\b{}\s*\.\s*(?:where|firstWhere|any|contains)\s*\(",
                regex::escape(&name)
            ))
            .unwrap();
            let count = traversal.find_iter(text).count();
            if count >= 3 {
                counts.insert(name, count);
            }
        }
        for (name, count) in counts {
            findings.push(finding(
                "dart-repeated-iterable-traversal",
                path,
                line_at(source, scope.start),
                line_at(source, scope.end.saturating_sub(1)),
                &format!("`{name}` is traversed {count} times in one method"),
            ));
        }
    }
    findings
}

fn enclosing_scope(scopes: &[FunctionScope], offset: usize) -> Option<&FunctionScope> {
    scopes
        .iter()
        .filter(|scope| scope.body_start <= offset && offset < scope.end)
        .min_by_key(|scope| scope.end - scope.start)
}

fn statement_range(source: &str, mut start: usize) -> Option<(usize, usize)> {
    start = skip_whitespace(source, start);
    if source.as_bytes().get(start) == Some(&b'{') {
        return Some((
            start + 1,
            quote_aware_matching_delimiter(source, start, b'{', b'}')? + 1,
        ));
    }
    Some((start, expression_end(source, start)))
}

fn skip_whitespace(source: &str, mut offset: usize) -> usize {
    while offset < source.len() && source.as_bytes()[offset].is_ascii_whitespace() {
        offset += 1;
    }
    offset
}

enum SeparatorScanTransition {
    Advance(usize),
    Found,
}

#[derive(Default)]
struct SeparatorScanState {
    depths: [usize; 3],
    quote: Option<u8>,
}

impl SeparatorScanState {
    fn transition(&mut self, byte: u8, has_next: bool, separator: u8) -> SeparatorScanTransition {
        if let Some(quote) = self.quote {
            return self.quoted_transition(byte, quote, has_next);
        }
        self.code_transition(byte, separator)
    }

    fn quoted_transition(
        &mut self,
        byte: u8,
        quote: u8,
        has_next: bool,
    ) -> SeparatorScanTransition {
        if byte == b'\\' && has_next {
            return SeparatorScanTransition::Advance(2);
        }
        if byte == quote {
            self.quote = None;
        }
        SeparatorScanTransition::Advance(1)
    }

    fn code_transition(&mut self, byte: u8, separator: u8) -> SeparatorScanTransition {
        match byte {
            b'\'' | b'"' => self.quote = Some(byte),
            b'(' => self.depths[0] += 1,
            b')' => self.depths[0] = self.depths[0].saturating_sub(1),
            b'[' => self.depths[1] += 1,
            b']' => self.depths[1] = self.depths[1].saturating_sub(1),
            b'{' => self.depths[2] += 1,
            b'}' => self.depths[2] = self.depths[2].saturating_sub(1),
            value if value == separator && self.depths == [0, 0, 0] => {
                return SeparatorScanTransition::Found;
            }
            _ => {}
        }
        SeparatorScanTransition::Advance(1)
    }
}

fn top_level_separator(source: &str, separator: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut state = SeparatorScanState::default();
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        match state.transition(byte, index + 1 < bytes.len(), separator) {
            SeparatorScanTransition::Advance(width) => index += width,
            SeparatorScanTransition::Found => return Some(index),
        }
    }
    None
}

#[derive(Default)]
struct ExpressionScanState {
    depths: [usize; 3],
    quote: Option<u8>,
}

enum ExpressionScanTransition {
    Advance(usize),
    Complete,
}

impl ExpressionScanState {
    fn transition(&mut self, byte: u8, has_next: bool) -> ExpressionScanTransition {
        if let Some(quote) = self.quote {
            return self.quoted_transition(byte, quote, has_next);
        }
        self.code_transition(byte)
    }

    fn quoted_transition(
        &mut self,
        byte: u8,
        quote: u8,
        has_next: bool,
    ) -> ExpressionScanTransition {
        if byte == b'\\' && has_next {
            return ExpressionScanTransition::Advance(2);
        }
        if byte == quote {
            self.quote = None;
        }
        ExpressionScanTransition::Advance(1)
    }

    fn code_transition(&mut self, byte: u8) -> ExpressionScanTransition {
        if self.is_terminal(byte) {
            return ExpressionScanTransition::Complete;
        }
        match byte {
            b'\'' | b'"' => self.quote = Some(byte),
            b'(' => self.depths[0] += 1,
            b')' if self.depths[0] > 0 => self.depths[0] -= 1,
            b'[' => self.depths[1] += 1,
            b']' if self.depths[1] > 0 => self.depths[1] -= 1,
            b'{' => self.depths[2] += 1,
            b'}' if self.depths[2] > 0 => self.depths[2] -= 1,
            _ => {}
        }
        ExpressionScanTransition::Advance(1)
    }

    fn is_terminal(&self, byte: u8) -> bool {
        byte == b';' && self.depths == [0, 0, 0]
    }
}

fn expression_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut state = ExpressionScanState::default();
    let mut index = start;
    while let Some(&byte) = bytes.get(index) {
        match state.transition(byte, index + 1 < bytes.len()) {
            ExpressionScanTransition::Advance(width) => index += width,
            ExpressionScanTransition::Complete => return index + 1,
        }
    }
    source.len()
}

#[derive(Clone, Copy)]
enum StringMaskState {
    Code,
    Literal { quote: u8, triple: bool, raw: bool },
}

struct StringMasker<'a> {
    bytes: &'a [u8],
    masked: Vec<u8>,
    state: StringMaskState,
    index: usize,
}

impl<'a> StringMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            masked: source.as_bytes().to_vec(),
            state: StringMaskState::Code,
            index: 0,
        }
    }

    fn mask(mut self) -> String {
        while self.index < self.bytes.len() {
            match self.state {
                StringMaskState::Code => self.advance_code(),
                StringMaskState::Literal { quote, triple, raw } => {
                    self.advance_literal(quote, triple, raw);
                }
            }
        }
        String::from_utf8(self.masked).expect("ASCII string masking preserves UTF-8")
    }

    fn advance_code(&mut self) {
        let quote = self.bytes[self.index];
        if !matches!(quote, b'\'' | b'"') {
            self.index += 1;
            return;
        }

        let raw = self.index > 0
            && matches!(self.bytes[self.index - 1], b'r' | b'R')
            && (self.index == 1
                || !(self.bytes[self.index - 2].is_ascii_alphanumeric()
                    || self.bytes[self.index - 2] == b'_'));
        let triple = self.bytes[self.index..].starts_with(&[quote; 3]);
        let width = if triple { 3 } else { 1 };
        self.masked[self.index..self.index + width].fill(b' ');
        self.state = StringMaskState::Literal { quote, triple, raw };
        self.index += width;
    }

    fn advance_literal(&mut self, quote: u8, triple: bool, raw: bool) {
        if triple && self.bytes[self.index..].starts_with(&[quote; 3]) {
            self.masked[self.index..self.index + 3].fill(b' ');
            self.state = StringMaskState::Code;
            self.index += 3;
            return;
        }

        if !triple && !raw && self.bytes[self.index] == b'\\' && self.index + 1 < self.bytes.len() {
            self.masked[self.index..self.index + 2].fill(b' ');
            self.index += 2;
            return;
        }

        if !triple && self.bytes[self.index] == quote {
            self.masked[self.index] = b' ';
            self.state = StringMaskState::Code;
            self.index += 1;
            return;
        }

        if self.bytes[self.index] != b'\n' {
            self.masked[self.index] = b' ';
        }
        self.index += 1;
    }
}

fn mask_string_literals(source: &str) -> String {
    StringMasker::new(source).mask()
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding(code: &str, path: &str, line: usize, end_line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart performance metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart performance severity must be valid"),
        path: path.to_owned(),
        line,
        end_line,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+[A-Za-z_]\w*[^\{;]*\{").unwrap());
static NAMED_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<return>[A-Za-z_]\w*(?:<[^>{}]+>)?\??)\s+[A-Za-z_]\w*\s*\((?P<parameters>[^;()]*)\)\s*(?:async\s*)?(?P<marker>\{|=>)").unwrap()
});
static LOOP_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(for|while)\s*\(").unwrap());
static ARROW_CLOSURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\([^(){};]*\)|\b[A-Za-z_]\w*)\s*(?:async\s*)?=>").unwrap());
static DO_KEYWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdo\b").unwrap());
static STRING_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bString\s+([A-Za-z_]\w*)").unwrap());
static LIST_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bList(?:\s*<[^>]+>)?\s+([A-Za-z_]\w*)").unwrap());
static COLLECTION_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:Iterable|Queue)(?:\s*<[^>]+>)?\s+([A-Za-z_]\w*)").unwrap());
static CONSTANT_REGEXP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\bRegExp\s*\(\s*(?:(?:r|R)(?:'[^']*'|"[^"]*")|'(?:\\.|[^'\\$])*'|"(?:\\.|[^"\\$])*")\s*(?:,|\))"#,
    )
    .unwrap()
});
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn finds_loop_allocation_concatenation_and_repeated_traversal() {
        let fixture = Fixture::new([(
            "lib/risks.dart",
            "class Risks {\n  String scan(Iterable<String> items) {\n    String output = '';\n    for (final item in items) {\n      final matcher = RegExp('item');\n      output += item;\n    }\n    items.any(valid);\n    items.firstWhere(valid);\n    items.contains('done');\n    return output;\n  }\n}",
        )]);

        assert_eq!(
            code_ranges(&fixture),
            vec![
                ("dart-regexp-created-in-loop".to_owned(), 5, 5),
                ("dart-repeated-iterable-traversal".to_owned(), 2, 12),
                ("dart-string-concat-in-loop".to_owned(), 4, 7),
            ]
        );
    }

    #[test]
    fn accepts_stable_regexps_buffers_and_list_traversals() {
        let fixture = Fixture::new([(
            "lib/safe.dart",
            "class Safe {\n  final RegExp matcher = RegExp('item');\n  String scan(List<String> items) {\n    final buffer = StringBuffer();\n    for (final item in items) {\n      if (matcher.hasMatch(item)) buffer.write(item);\n    }\n    items.any(valid);\n    items.firstWhere(valid);\n    items.contains('done');\n    return buffer.toString();\n  }\n  bool matchesAny(List<String> patterns, String value) {\n    for (final pattern in patterns) {\n      if (RegExp(pattern).hasMatch(value)) return true;\n    }\n    return false;\n  }\n}",
        )]);

        assert!(code_ranges(&fixture).is_empty());
    }

    #[test]
    fn limits_regexp_findings_to_repeated_loop_regions() {
        let fixture = Fixture::new([(
            "lib/regex.dart",
            "void scan(String raw, List<String> values) {\n  for (final part in raw.split(RegExp(r'[;,]'))) {\n    consume(part);\n  }\n  for (final value in values) {\n    if (RegExp(r'^\\w+$').hasMatch(value)) consume(value);\n  }\n}",
        )]);

        assert_eq!(
            code_ranges(&fixture),
            vec![("dart-regexp-created-in-loop".to_owned(), 6, 6)]
        );
    }

    #[test]
    fn distinguishes_list_membership_from_set_membership() {
        let fixture = Fixture::new([(
            "lib/membership.dart",
            "void retain(List<String> blocked, Set<String> allowed, List<String> values) {\n  for (final value in values) {\n    if (blocked.contains(value)) continue;\n    if (allowed.contains(value)) consume(value);\n  }\n}",
        )]);

        assert_eq!(
            code_ranges(&fixture),
            vec![("dart-quadratic-list-membership".to_owned(), 2, 5)]
        );
    }

    #[test]
    fn reports_list_front_removal_inside_loops() {
        let fixture = Fixture::new([(
            "lib/queue.dart",
            "void drain(List<String> queue) {\n  while (queue.isNotEmpty) {\n    consume(queue.removeAt(0));\n  }\n}\n\nvoid once(List<String> queue) {\n  consume(queue.removeAt(0));\n}",
        )]);

        assert_eq!(
            code_ranges(&fixture),
            vec![("dart-list-front-removal-in-loop".to_owned(), 2, 4)]
        );
    }

    #[test]
    fn checks_only_the_outer_loop_for_loop_wide_patterns() {
        let fixture = Fixture::new([(
            "lib/nested.dart",
            "void render(List<String> blocked, List<String> values) {\n  String output = '';\n  for (final value in values) {\n    while (ready()) {\n      output += value;\n      if (blocked.contains(value)) break;\n    }\n  }\n}",
        )]);

        assert_eq!(
            code_ranges(&fixture),
            vec![
                ("dart-quadratic-list-membership".to_owned(), 3, 8),
                ("dart-string-concat-in-loop".to_owned(), 3, 8),
            ]
        );
    }

    #[test]
    fn tracks_local_iterables_and_skips_for_initializers() {
        let fixture = Fixture::new([(
            "lib/work.dart",
            "class Work {\n  void inspect() {\n    Iterable<int> values = load();\n    values.where(valid);\n    values.any(valid);\n    values.contains(3);\n  }\n  void scan(String value) {\n    for (\n      final initial = RegExp('initial');\n      RegExp('condition').hasMatch(value);\n      consume(RegExp('update'))\n    ) {\n      consume(RegExp('body'));\n    }\n  }\n}",
        )]);

        assert_eq!(
            code_ranges(&fixture),
            vec![
                ("dart-regexp-created-in-loop".to_owned(), 11, 11),
                ("dart-repeated-iterable-traversal".to_owned(), 2, 7),
            ]
        );
    }

    #[test]
    fn ignores_performance_patterns_inside_string_literals() {
        let fixture = Fixture::new([(
            "lib/generated.dart",
            "void render(List<String> values) {\n  for (final value in values) {\n    print(\"RegExp('fake') values.contains(value) output += value\");\n  }\n}",
        )]);

        assert!(code_ranges(&fixture).is_empty());
    }

    #[test]
    fn ignores_regexp_creation_inside_nested_callbacks() {
        let fixture = Fixture::new([(
            "lib/callback.dart",
            "void scan(List<String> values) {\n  for (final value in values) {\n    values.where((String candidate) => RegExp('value').hasMatch(candidate));\n  }\n}",
        )]);

        assert!(code_ranges(&fixture).is_empty());
    }

    fn code_ranges(fixture: &Fixture) -> Vec<(String, usize, usize)> {
        let mut findings = analyze(&fixture.context())
            .into_iter()
            .map(|finding| (finding.code, finding.line, finding.end_line))
            .collect::<Vec<_>>();
        findings.sort();
        findings
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
