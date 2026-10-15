use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let facts = context
        .sources()
        .iter()
        .map(|(path, source)| (path.clone(), scan_lines(path, source)))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    findings.extend(excessive_comment_density(context, &facts));
    findings.extend(narrating_implementation_comments(context, &facts));
    findings.extend(trivial_comment_restatements(context, &facts));
    findings.extend(single_method_delegating_classes(context));
    findings.extend(parallel_schema_definitions(context));
    findings
}

#[derive(Clone)]
struct LineFacts {
    code: String,
    comment: String,
    documentation: bool,
}

#[derive(Clone, Copy)]
struct CommentSyntax {
    hash: bool,
    dash: bool,
    triple_quotes: bool,
}

#[derive(Default)]
struct CommentScanState {
    in_block: bool,
    in_documentation_block: bool,
    multiline_quote: Option<&'static str>,
}

enum CommentStart {
    None,
    Continue,
    Break,
}

fn scan_lines(path: &str, source: &str) -> Vec<LineFacts> {
    let lower_path = path.to_ascii_lowercase();
    let syntax = CommentSyntax {
        hash: HASH_COMMENT_PATH.is_match(&lower_path),
        dash: DASH_COMMENT_PATH.is_match(&lower_path),
        triple_quotes: lower_path.ends_with(".dart") || lower_path.ends_with(".py"),
    };
    let mut state = CommentScanState::default();
    let mut result = source
        .split('\n')
        .map(|line| scan_line(line, syntax, &mut state))
        .collect::<Vec<_>>();
    if lower_path.ends_with(".go") {
        mark_go_documentation_comments(&mut result);
    }
    result
}

fn scan_line(line: &str, syntax: CommentSyntax, state: &mut CommentScanState) -> LineFacts {
    let mut code = String::new();
    let mut comment = String::new();
    let mut documentation = false;
    let mut index = 0usize;
    while index < line.len() {
        if consume_multiline_quote(line, &mut index, state) {
            continue;
        }
        if consume_block_comment(line, &mut index, &mut comment, &mut documentation, state) {
            continue;
        }
        match consume_comment_start(
            line,
            &mut index,
            &mut comment,
            &mut documentation,
            syntax,
            state,
        ) {
            CommentStart::Continue => continue,
            CommentStart::Break => break,
            CommentStart::None => {}
        }
        let Some(character) = line[index..].chars().next() else {
            break;
        };
        if matches!(character, '"' | '\'' | '`') {
            index = mask_comment_scanner_quote(line, index, character, syntax, state, &mut code);
        } else {
            code.push(character);
            index += character.len_utf8();
        }
    }
    LineFacts {
        code,
        comment,
        documentation,
    }
}

fn consume_multiline_quote(line: &str, index: &mut usize, state: &mut CommentScanState) -> bool {
    let Some(quote) = state.multiline_quote else {
        return false;
    };
    if let Some(relative) = line[*index..].find(quote) {
        *index += relative + quote.len();
        state.multiline_quote = None;
    } else {
        *index = line.len();
    }
    true
}

fn consume_block_comment(
    line: &str,
    index: &mut usize,
    comment: &mut String,
    documentation: &mut bool,
    state: &mut CommentScanState,
) -> bool {
    if !state.in_block {
        return false;
    }
    *documentation = state.in_documentation_block;
    if let Some(relative) = line[*index..].find("*/") {
        comment.push_str(&line[*index..*index + relative]);
        *index += relative + 2;
        state.in_documentation_block = false;
        state.in_block = false;
    } else {
        comment.push_str(&line[*index..]);
        *index = line.len();
    }
    true
}

fn consume_comment_start(
    line: &str,
    index: &mut usize,
    comment: &mut String,
    documentation: &mut bool,
    syntax: CommentSyntax,
    state: &mut CommentScanState,
) -> CommentStart {
    let tail = &line[*index..];
    if let Some(start) = consume_slash_comment_start(tail, index, comment, documentation, state) {
        return start;
    }
    if consume_language_comment(line, tail, *index, comment, syntax) {
        return CommentStart::Break;
    }
    CommentStart::None
}

fn consume_slash_comment_start(
    tail: &str,
    index: &mut usize,
    comment: &mut String,
    documentation: &mut bool,
    state: &mut CommentScanState,
) -> Option<CommentStart> {
    if tail.starts_with("///") || tail.starts_with("//!") {
        *documentation = true;
        comment.push_str(&tail[3..]);
        return Some(CommentStart::Break);
    }
    if tail.starts_with("/**") || tail.starts_with("/*!") {
        *documentation = true;
        state.in_block = true;
        state.in_documentation_block = true;
        *index += 3;
        return Some(CommentStart::Continue);
    }
    if let Some(rest) = tail.strip_prefix("//") {
        comment.push_str(rest);
        return Some(CommentStart::Break);
    }
    if tail.starts_with("/*") {
        state.in_block = true;
        *index += 2;
        return Some(CommentStart::Continue);
    }
    None
}

fn consume_language_comment(
    line: &str,
    tail: &str,
    index: usize,
    comment: &mut String,
    syntax: CommentSyntax,
) -> bool {
    if syntax.hash
        && let Some(rest) = tail.strip_prefix('#')
    {
        if index != 0 || !line.starts_with("#!") {
            comment.push_str(rest);
        }
        return true;
    }
    if syntax.dash
        && let Some(rest) = tail.strip_prefix("--")
    {
        comment.push_str(rest);
        return true;
    }
    false
}

fn mask_comment_scanner_quote(
    line: &str,
    mut index: usize,
    character: char,
    syntax: CommentSyntax,
    state: &mut CommentScanState,
    code: &mut String,
) -> usize {
    let triple = match character {
        '"' => "\"\"\"",
        '\'' => "'''",
        '`' => "```",
        _ => unreachable!(),
    };
    if syntax.triple_quotes && line[index..].starts_with(triple) {
        index += triple.len();
        if let Some(relative) = line[index..].find(triple) {
            return index + relative + triple.len();
        }
        state.multiline_quote = Some(triple);
        return line.len();
    }
    code.push(' ');
    index += character.len_utf8();
    let mut escaped = false;
    while index < line.len() {
        let Some(current) = line[index..].chars().next() else {
            break;
        };
        code.push(' ');
        index += current.len_utf8();
        if escaped {
            escaped = false;
        } else if current == '\\' {
            escaped = true;
        } else if current == character {
            break;
        }
    }
    index
}

#[derive(Default)]
struct GoDeclarationState {
    brace_depth: isize,
    declaration_block_depth: Option<isize>,
}

impl GoDeclarationState {
    fn advance(&mut self, code: &str) -> bool {
        let documents_preceding_comments =
            GO_DECLARATION.is_match(code) || self.declaration_block_depth.is_some();
        let opening_braces = code.bytes().filter(|byte| *byte == b'{').count() as isize;
        let closing_braces = code.bytes().filter(|byte| *byte == b'}').count() as isize;
        if GO_DECLARATION_BLOCK.is_match(code) {
            self.declaration_block_depth = Some(self.brace_depth + opening_braces - closing_braces);
        }
        self.brace_depth += opening_braces - closing_braces;
        if self
            .declaration_block_depth
            .is_some_and(|depth| self.brace_depth < depth)
        {
            self.declaration_block_depth = None;
        }
        documents_preceding_comments
    }
}

fn mark_go_documentation_comments(facts: &mut [LineFacts]) {
    let mut state = GoDeclarationState::default();
    for index in 0..facts.len() {
        if state.advance(&facts[index].code) {
            mark_preceding_go_comments(facts, index);
        }
    }
}

fn mark_preceding_go_comments(facts: &mut [LineFacts], index: usize) {
    for fact in facts[..index].iter_mut().rev() {
        if !fact.code.trim().is_empty() || fact.comment.trim().is_empty() {
            break;
        }
        fact.documentation = true;
    }
}

struct CommentFile<'a> {
    path: &'a str,
    code: usize,
    comments: usize,
    baseline_comments: usize,
    first: usize,
}

fn excessive_comment_density(
    context: &SourceAnalysisContext<'_>,
    facts_by_path: &BTreeMap<String, Vec<LineFacts>>,
) -> Vec<Finding> {
    let files = collect_comment_files(context, facts_by_path);
    if files.len() < 5 {
        return Vec::new();
    }
    let median = median_comment_ratio(&files);
    files
        .iter()
        .filter_map(|file| {
            qualify_density_outlier(file, median)
                .map(|ratio| emit_density_finding(file, ratio, median))
        })
        .collect()
}

fn collect_comment_files<'a>(
    context: &'a SourceAnalysisContext<'_>,
    facts_by_path: &BTreeMap<String, Vec<LineFacts>>,
) -> Vec<CommentFile<'a>> {
    context
        .sources()
        .keys()
        .filter(|path| !excluded_comment_density_path(path))
        .filter_map(|path| summarize_comment_file(path, &facts_by_path[path]))
        .collect()
}

fn summarize_comment_file<'a>(path: &'a str, facts: &[LineFacts]) -> Option<CommentFile<'a>> {
    let mut file = CommentFile {
        path,
        code: 0,
        comments: 0,
        baseline_comments: 0,
        first: 0,
    };
    for (index, fact) in facts.iter().enumerate().skip(leading_license_end(facts)) {
        if !fact.code.trim().is_empty() {
            file.code += 1;
        }
        if fact.comment.trim().is_empty() {
            continue;
        }
        file.baseline_comments += 1;
        if !fact.documentation {
            file.comments += 1;
            if file.first == 0 {
                file.first = index + 1;
            }
        }
    }
    (file.code + file.baseline_comments >= 20).then_some(file)
}

fn median_comment_ratio(files: &[CommentFile<'_>]) -> f64 {
    let mut ratios = files
        .iter()
        .map(|file| file.baseline_comments as f64 / (file.code + file.baseline_comments) as f64)
        .collect::<Vec<_>>();
    ratios.sort_by(f64::total_cmp);
    ratios[ratios.len() / 2]
}

fn qualify_density_outlier(file: &CommentFile<'_>, median: f64) -> Option<f64> {
    if file.comments < 8 || file.code < 5 {
        return None;
    }
    let ratio = file.comments as f64 / (file.code + file.comments) as f64;
    let baseline = median.max(0.04);
    (ratio >= 0.10 && ratio >= baseline * 2.5).then_some(ratio)
}

fn emit_density_finding(file: &CommentFile<'_>, ratio: f64, median: f64) -> Finding {
    finding(
        "excessive-comment-density",
        file.path,
        file.first,
        format!(
            "{} comment lines for {} code lines ({}%; repository median {}%)",
            file.comments,
            file.code,
            (ratio * 100.0).round() as usize,
            (median * 100.0).round() as usize
        ),
        "medium",
        Vec::new(),
    )
}

fn leading_license_end(facts: &[LineFacts]) -> usize {
    let mut header = String::new();
    let mut end = 0usize;
    for (index, fact) in facts.iter().take(40).enumerate() {
        if !fact.code.trim().is_empty() {
            break;
        }
        let comment = fact.comment.trim();
        if !comment.is_empty() {
            header.push_str(comment);
            header.push('\n');
            end = index + 1;
        }
    }
    let text = header.to_ascii_lowercase();
    if text.contains("copyright")
        && (text.contains("licensed under") || text.contains("permission is hereby granted"))
    {
        end
    } else {
        0
    }
}

fn narrating_implementation_comments(
    context: &SourceAnalysisContext<'_>,
    facts_by_path: &BTreeMap<String, Vec<LineFacts>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in context.sources().keys() {
        if excluded_comment_path(path) {
            continue;
        }
        for (index, fact) in facts_by_path[path].iter().enumerate() {
            if !fact.documentation && NARRATION.is_match(&fact.comment) {
                findings.push(finding(
                    "narrating-implementation-comment",
                    path,
                    index + 1,
                    "comment narrates the implementation sequence".to_owned(),
                    "high",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

struct CommentRestatement<'a> {
    path: &'a str,
    line: usize,
    code: &'a str,
}

fn trivial_comment_restatements<'a>(
    context: &'a SourceAnalysisContext<'_>,
    facts_by_path: &'a BTreeMap<String, Vec<LineFacts>>,
) -> Vec<Finding> {
    context
        .sources()
        .keys()
        .filter(|path| !excluded_comment_path(path))
        .flat_map(|path| qualified_restatements(path, &facts_by_path[path]))
        .map(emit_restatement_finding)
        .collect()
}

fn qualified_restatements<'a>(
    path: &'a str,
    facts: &'a [LineFacts],
) -> impl Iterator<Item = CommentRestatement<'a>> + 'a {
    (0..facts.len().saturating_sub(1))
        .filter_map(move |index| qualify_restatement(path, facts, index))
}

fn qualify_restatement<'a>(
    path: &'a str,
    facts: &'a [LineFacts],
    index: usize,
) -> Option<CommentRestatement<'a>> {
    let fact = &facts[index];
    if fact.documentation || !fact.code.trim().is_empty() {
        return None;
    }
    let captures = COMMENT_SHAPE.captures(&fact.comment)?;
    let (Some(verb), Some(name)) = (captures.get(1), captures.get(2)) else {
        return None;
    };
    let code = code_after_comment(facts, index + 1)?;
    restates(&verb.as_str().to_ascii_lowercase(), name.as_str(), code).then_some(
        CommentRestatement {
            path,
            line: index + 1,
            code,
        },
    )
}

fn code_after_comment(facts: &[LineFacts], mut index: usize) -> Option<&str> {
    while index < facts.len() && facts[index].code.trim().is_empty() {
        if !facts[index].comment.trim().is_empty() {
            return None;
        }
        index += 1;
    }
    facts.get(index).map(|fact| fact.code.trim())
}

fn emit_restatement_finding(restatement: CommentRestatement<'_>) -> Finding {
    let displayed = if restatement.code.chars().count() > 80 {
        format!(
            "{}...",
            restatement.code.chars().take(77).collect::<String>()
        )
    } else {
        restatement.code.to_owned()
    };
    finding(
        "trivial-comment-restatement",
        restatement.path,
        restatement.line,
        format!("comment restates `{displayed}`"),
        "high",
        Vec::new(),
    )
}

fn restates(verb: &str, name: &str, code: &str) -> bool {
    let escaped = regex::escape(name);
    let pattern = if verb.starts_with("return") {
        format!(r"^return\s+{escaped}\s*[;)]?")
    } else if verb.starts_with("increment") {
        format!(r"^(?:\+\+{escaped}|{escaped}\+\+)\s*;?$")
    } else if verb.starts_with("decrement") {
        format!(r"^(?:--{escaped}|{escaped}--)\s*;?$")
    } else if verb.starts_with("set") || verb.starts_with("assign") {
        format!(r"^(?:[A-Za-z_]+\.)?{escaped}\s*=")
    } else {
        format!(r"^(?:await\s+)?(?:[A-Za-z_]+\.)?{escaped}\s*\(")
    };
    Regex::new(&pattern).is_ok_and(|pattern| pattern.is_match(code))
}

struct DelegatingClassCandidate<'a> {
    path: &'a str,
    source: &'a str,
    start: usize,
    class_name: &'a str,
    field: &'a str,
    constructor: &'a str,
    constructor_field: &'a str,
    method: &'a str,
    receiver: &'a str,
    forwarded_method: &'a str,
    parameters: &'a str,
    arguments: &'a str,
}

struct QualifiedDelegation<'a> {
    path: &'a str,
    line: usize,
    class_name: &'a str,
    field: &'a str,
    method: &'a str,
}

fn single_method_delegating_classes(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".dart") && !excluded_comment_path(path))
        .flat_map(|(path, source)| delegating_class_candidates(path, source))
        .filter_map(qualify_delegating_class)
        .map(emit_delegating_class_finding)
        .collect()
}

fn delegating_class_candidates<'a>(
    path: &'a str,
    source: &'a str,
) -> impl Iterator<Item = DelegatingClassCandidate<'a>> + 'a {
    DELEGATING_CLASS
        .captures_iter(source)
        .filter_map(move |captures| {
            Some(DelegatingClassCandidate {
                path,
                source,
                start: captures.get(0)?.start(),
                class_name: captures.name("class")?.as_str(),
                field: captures.name("field")?.as_str(),
                constructor: captures.name("constructor")?.as_str(),
                constructor_field: captures.name("constructor_field")?.as_str(),
                method: captures.name("method")?.as_str(),
                receiver: captures.name("receiver")?.as_str(),
                forwarded_method: captures.name("forwarded_method")?.as_str(),
                parameters: captures.name("parameters")?.as_str(),
                arguments: captures.name("arguments")?.as_str(),
            })
        })
}

fn qualify_delegating_class(
    candidate: DelegatingClassCandidate<'_>,
) -> Option<QualifiedDelegation<'_>> {
    if candidate.class_name != candidate.constructor
        || candidate.field != candidate.constructor_field
        || candidate.field != candidate.receiver
        || candidate.method != candidate.forwarded_method
    {
        return None;
    }
    let parameters = parameter_names(candidate.parameters);
    let arguments = arguments(candidate.arguments);
    if parameters.is_empty() || parameters != arguments {
        return None;
    }
    let line = candidate.source[..candidate.start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    Some(QualifiedDelegation {
        path: candidate.path,
        line,
        class_name: candidate.class_name,
        field: candidate.field,
        method: candidate.method,
    })
}

fn emit_delegating_class_finding(delegation: QualifiedDelegation<'_>) -> Finding {
    finding(
        "single-method-delegating-class",
        delegation.path,
        delegation.line,
        format!(
            "`{}` only forwards `{}` to `{}` with unchanged arguments",
            delegation.class_name, delegation.method, delegation.field
        ),
        "high",
        Vec::new(),
    )
}

fn parameter_names(source: &str) -> Vec<String> {
    source
        .split(',')
        .filter_map(|parameter| parameter.split_whitespace().last())
        .filter(|name| IDENTIFIER.is_match(name))
        .map(str::to_owned)
        .collect()
}

fn arguments(source: &str) -> Vec<String> {
    source
        .split(',')
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .map(str::to_owned)
        .collect()
}

struct SchemaLiteral {
    path: String,
    line: usize,
    key_count: usize,
}

fn parallel_schema_definitions(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut by_signature = BTreeMap::<String, Vec<SchemaLiteral>>::new();
    for (path, source) in context.sources() {
        if excluded_schema_path(path) {
            continue;
        }
        for literal in SCHEMA_LITERAL.captures_iter(source) {
            let Some(body) = literal.get(1).map(|capture| capture.as_str()) else {
                continue;
            };
            let mut keys = SCHEMA_KEY
                .captures_iter(body)
                .filter_map(|capture| capture.get(1).map(|key| key.as_str().to_owned()))
                .collect::<Vec<_>>();
            keys.sort();
            keys.dedup();
            if keys.len() < 5 {
                continue;
            }
            let Some(start) = literal.get(0).map(|capture| capture.start()) else {
                continue;
            };
            let line = source[..start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            let signature = keys.join("\0");
            by_signature
                .entry(signature)
                .or_default()
                .push(SchemaLiteral {
                    path: path.clone(),
                    line,
                    key_count: keys.len(),
                });
        }
    }
    let mut findings = Vec::new();
    for matches in by_signature.into_values() {
        let mut by_path = BTreeMap::new();
        for item in matches {
            by_path.insert(item.path.clone(), item);
        }
        if by_path.len() < 2 {
            continue;
        }
        let distinct = by_path.into_values().collect::<Vec<_>>();
        let primary = &distinct[0];
        findings.push(finding(
            "parallel-schema-definition",
            &primary.path,
            primary.line,
            format!(
                "{}-key contract is repeated in {} files",
                primary.key_count,
                distinct.len()
            ),
            "medium",
            distinct
                .iter()
                .skip(1)
                .map(|item| format!("{}:{}", item.path, item.line))
                .collect(),
        ));
    }
    findings
}

fn excluded_comment_path(path: &str) -> bool {
    TEST_PATH.is_match(path) || GENERATED_PATH.is_match(path) || DOCUMENTATION_PATH.is_match(path)
}

fn excluded_comment_density_path(path: &str) -> bool {
    excluded_comment_path(path) || COMMENT_DENSITY_MANIFEST_PATH.is_match(path)
}

fn excluded_schema_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    TEST_PATH.is_match(&lower)
        || GENERATED_PATH.is_match(&lower)
        || SCHEMA_ASSET_PATH.is_match(&lower)
        || SCHEMA_MANIFEST_PATH.is_match(&lower)
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("generated-code risk metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("generated-code risk severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static TEST_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(?:test|tests|spec|specs|__tests__|fixture|fixtures)(?:/|$)|(?:_test|\.test|\.spec)\.").unwrap()
});
static GENERATED_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(?:generated|gen)(?:/|$)|\.(?:g|freezed|gr)\.[^.]+$").unwrap()
});
static DOCUMENTATION_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(?:doc|docs|documentation)(?:/|$)|\.(?:md|mdx|rst|txt)$").unwrap()
});
static COMMENT_DENSITY_MANIFEST_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(?:go\.mod|package(?:-lock)?\.json|pubspec\.ya?ml|cargo\.toml)$").unwrap()
});
static HASH_COMMENT_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(?:py|pyi|rb|sh|bash|zsh|fish|pl|pm|r|jl|nim|toml|ya?ml)$").unwrap()
});
static DASH_COMMENT_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(?:lua|luau|sql|hs)$").unwrap());
static GO_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:package\s+\w+|(?:type|var|const)\s+(?:\w+|\()|func\s+(?:\([^)]*\)\s*)?\w+)")
        .unwrap()
});
static GO_DECLARATION_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*type\s+\w+\s+(?:interface|struct)\s*\{").unwrap());
static NARRATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:(?:first|next|now|then|finally),?\s+(?:we|i)(?:\s+will|\s+need\s+to|\s+can|\s+should)?|(?:we|i)\s+(?:will|need\s+to|are\s+going\s+to)\s+(?:first|next|now|then))\b").unwrap()
});
static COMMENT_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(return|returns|increment|increments|decrement|decrements|set|sets|assign|assigns|call|calls|invoke|invokes)\s+(?:the\s+)?([A-Za-z_]\w*)[.!]?\s*$").unwrap()
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());
static DELEGATING_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?ms)class\s+(?P<class>[A-Za-z_]\w*)\s*\{\s*(?:final\s+)?[A-Za-z_]\w*(?:<[^;{}]+>)?\s+(?P<field>[A-Za-z_]\w*)\s*;\s*(?P<constructor>[A-Za-z_]\w*)\s*\(\s*this\.(?P<constructor_field>[A-Za-z_]\w*)\s*\)\s*;\s*(?:Future(?:<[^>{}]+>)?|[A-Za-z_]\w*(?:<[^>{}]+>)?|void)\s+(?P<method>[A-Za-z_]\w*)\s*\((?P<parameters>[^{};]*)\)\s*(?:async\s*)?=>\s*(?:await\s+)?(?P<receiver>[A-Za-z_]\w*)\.(?P<forwarded_method>[A-Za-z_]\w*)\s*\((?P<arguments>[^{};]*)\)\s*;\s*\}").unwrap()
});
static SCHEMA_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\{([^{}]{0,4000})\}").unwrap());
static SCHEMA_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[\"']([A-Za-z_][A-Za-z0-9_-]*)[\"']\s*:"#).unwrap());
static SCHEMA_ASSET_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|/)(?:assets|i18n|l10n|locale|locales)(?:/|$)").unwrap());
static SCHEMA_MANIFEST_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|/)(?:package(?:-lock)?|pubspec|composer|cargo)\.(?:json|yaml|yml|toml)$")
        .unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comment_scanning_distinguishes_literals_docs_and_language_comments() {
        let python = scan_lines(
            "tool.py",
            "#!/usr/bin/env python\n\"\"\"\n# literal content\n\"\"\"\nvalue = 1 # explanation",
        );
        assert!(python[0].comment.is_empty());
        assert!(python[2].comment.is_empty());
        assert_eq!(python[4].comment.trim(), "explanation");

        let lua = scan_lines("tool.lua", "local text = \"-- literal\"\n-- actual comment");
        assert!(lua[0].comment.is_empty());
        assert_eq!(lua[1].comment.trim(), "actual comment");

        let dart = scan_lines("lib/api.dart", "/** API documentation */\nfinal value = 1;");
        assert!(dart[0].documentation);
        assert_eq!(dart[0].comment.trim(), "API documentation");
    }

    #[test]
    fn reports_only_repository_relative_comment_density_outliers() {
        let mut sources = ordinary_sources("dart");
        sources.insert(
            "lib/narrated.dart".to_owned(),
            (0..16)
                .map(|line| format!("// explanation number {line}"))
                .chain((0..8).map(|line| format!("final value{line} = {line};")))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);

        let finding = findings
            .iter()
            .find(|finding| finding.code == "excessive-comment-density")
            .unwrap();
        assert_eq!(finding.path, "lib/narrated.dart");
        assert!(finding.message.contains("repository median 0%"));
    }

    #[test]
    fn excludes_documentation_license_and_manifest_comments_from_density() {
        let mut documented_sources = ordinary_sources("dart");
        documented_sources.insert(
            "lib/documented.dart".to_owned(),
            (0..8)
                .map(|line| format!("/// API field {line}"))
                .chain((0..56).map(|line| format!("final value{line} = {line};")))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&documented_sources);
        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());

        let mut go_sources = ordinary_sources("go");
        go_sources.insert(
            "documented.go".to_owned(),
            ["package api".to_owned(), "type API interface {".to_owned()]
                .into_iter()
                .chain((0..8).flat_map(|method| {
                    [
                        format!("  // Method{method} performs an API operation."),
                        format!("  Method{method}() error"),
                    ]
                }))
                .chain(["}".to_owned()])
                .chain((0..10).flat_map(|declaration| {
                    [
                        format!("// Value{declaration} describes the exported value."),
                        format!("var Value{declaration} = {declaration}"),
                    ]
                }))
                .chain((0..10).map(|line| format!("var private{line} = {line}")))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&go_sources);
        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());

        let mut licensed_sources = ordinary_sources("go");
        licensed_sources.insert(
            "licensed.go".to_owned(),
            format!(
                "// Copyright 2026 The Authors\n// Licensed under the Apache License, Version 2.0\npackage licensed\n{}",
                (0..18)
                    .map(|line| format!("var value{line} = {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        );
        licensed_sources.insert(
            "go.mod".to_owned(),
            (0..24)
                .map(|line| format!("require example.com/dependency{line} v1.0.0 // indirect"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&licensed_sources);
        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());
    }

    #[test]
    fn reports_first_person_narration_but_not_rationale_or_documentation() {
        let sources = BTreeMap::from([
            (
                "lib/source.dart".to_owned(),
                "// First, we load the cache.\nloadCache();\n// Keep this order because the server signs canonical bytes.\nsignPayload();\n/// Next, we describe the public API.\nvoid api() {}".to_owned(),
            ),
            (
                "test/source_test.dart".to_owned(),
                "// Now we invoke the subject.\ninvoke();".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = narrating_implementation_comments(&context, &facts(&context));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn reports_only_adjacent_lexical_restatements() {
        let sources = BTreeMap::from([(
            "lib/source.dart".to_owned(),
            "// Return result.\nreturn result;\n// Increment count\ncount++;\n// Set timeout\nthis.timeout = timeout;\n// Retry because the endpoint is eventually consistent.\nretry();\n/// Returns the public result.\nObject result() => value;".to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = trivial_comment_restatements(&context, &facts(&context));

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
    }

    #[test]
    fn reports_only_unchanged_single_method_dart_delegation() {
        let sources = BTreeMap::from([
            (
                "lib/pass_through.dart".to_owned(),
                "class UserService {\n  final UserRepository repository;\n  UserService(this.repository);\n  Future<User> getUser(String id) => repository.getUser(id);\n}".to_owned(),
            ),
            (
                "lib/policy.dart".to_owned(),
                "class UserPolicy {\n  final UserRepository repository;\n  UserPolicy(this.repository);\n  Future<User> getUser(String id) => repository.getUser(validate(id));\n}".to_owned(),
            ),
            (
                "lib/multi.dart".to_owned(),
                "class UserCache {\n  final UserRepository repository;\n  UserCache(this.repository);\n  Future<User> getUser(String id) => repository.getUser(id);\n  void clear() => repository.clear();\n}".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = single_method_delegating_classes(&context);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/pass_through.dart");
        assert!(findings[0].message.contains("UserService"));
    }

    #[test]
    fn reports_only_identical_substantial_cross_file_schemas() {
        let sources = BTreeMap::from([
            (
                "lib/request.dart".to_owned(),
                "final request = {\n  'id': id,\n  'name': name,\n  'email': email,\n  'role': role,\n  'active': active,\n};".to_owned(),
            ),
            (
                "lib/response.dart".to_owned(),
                "final response = {\n  \"active\": value.active,\n  \"role\": value.role,\n  \"email\": value.email,\n  \"name\": value.name,\n  \"id\": value.id,\n};".to_owned(),
            ),
            (
                "test/request_test.dart".to_owned(),
                "final fixture = {'id': 1, 'name': 'a', 'email': 'a@b.c', 'role': 'user', 'active': true};".to_owned(),
            ),
            (
                "lib/different.dart".to_owned(),
                "{'id': 1, 'name': 2, 'email': 3, 'role': 4, 'created': 5}".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = parallel_schema_definitions(&context);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/request.dart");
        assert_eq!(findings[0].related_files, vec!["lib/response.dart:1"]);
    }

    fn ordinary_sources(extension: &str) -> BTreeMap<String, String> {
        (0..4)
            .map(|file| {
                (
                    format!("lib/ordinary_{file}.{extension}"),
                    (0..24)
                        .map(|line| format!("final value{line} = {line};"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            })
            .collect()
    }

    fn facts(context: &SourceAnalysisContext<'_>) -> BTreeMap<String, Vec<LineFacts>> {
        context
            .sources()
            .iter()
            .map(|(path, source)| (path.clone(), scan_lines(path, source)))
            .collect()
    }
}
