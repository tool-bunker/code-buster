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
pub(super) struct LineFacts {
    code: String,
    pub(super) comment: String,
    pub(super) documentation: bool,
    commented: bool,
}

#[derive(Clone, Copy)]
struct CommentSyntax {
    hash: bool,
    dash: bool,
    shell: bool,
    triple_quotes: bool,
    rust: bool,
    multiline_strings: bool,
}

#[derive(Default)]
struct CommentScanState {
    in_block: bool,
    in_documentation_block: bool,
    multiline_quote: Option<String>,
    multiline_escapes: bool,
}

enum CommentStart {
    None,
    Continue,
    Break,
}

pub(super) fn scan_lines(path: &str, source: &str) -> Vec<LineFacts> {
    let lower_path = path.to_ascii_lowercase();
    let shell = crate::languages::shell::is_shell_source(path, source);
    let syntax = CommentSyntax {
        hash: HASH_COMMENT_PATH.is_match(&lower_path),
        dash: DASH_COMMENT_PATH.is_match(&lower_path),
        triple_quotes: lower_path.ends_with(".dart") || lower_path.ends_with(".py"),
        shell,
        rust: lower_path.ends_with(".rs"),
        multiline_strings: matches!(
            lower_path.rsplit('.').next(),
            Some("rs" | "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx")
        ),
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
    let mut commented = state.in_block;
    let mut index = 0usize;
    while index < line.len() {
        if consume_multiline_quote(line, &mut index, state) {
            continue;
        }
        if consume_block_comment(line, &mut index, &mut comment, &mut documentation, state) {
            continue;
        }
        if syntax.rust && consume_rust_raw_string(line, &mut index, state) {
            code.push(' ');
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
            CommentStart::Continue => {
                commented = true;
                continue;
            }
            CommentStart::Break => {
                commented = true;
                break;
            }
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
        commented,
    }
}

fn consume_multiline_quote(line: &str, index: &mut usize, state: &mut CommentScanState) -> bool {
    let Some(quote) = state.multiline_quote.as_deref() else {
        return false;
    };
    let closing = line[*index..].match_indices(quote).find(|(relative, _)| {
        !state.multiline_escapes
            || line.as_bytes()[*index..*index + *relative]
                .iter()
                .rev()
                .take_while(|byte| **byte == b'\\')
                .count()
                % 2
                == 0
    });
    if let Some((relative, _)) = closing {
        *index += relative + quote.len();
        state.multiline_quote = None;
    } else {
        *index = line.len();
    }
    true
}

fn consume_rust_raw_string(line: &str, index: &mut usize, state: &mut CommentScanState) -> bool {
    if !matches!(line.as_bytes()[*index], b'r' | b'b' | b'c')
        || (*index > 0 && line.as_bytes()[*index - 1].is_ascii_alphanumeric())
    {
        return false;
    }
    let Some(captures) = RUST_RAW_QUOTE.captures(&line[*index..]) else {
        return false;
    };
    let opening = captures.get(0).unwrap();
    let hashes = captures.name("hashes").unwrap().as_str();
    state.multiline_quote = Some(format!("\"{hashes}"));
    state.multiline_escapes = false;
    *index += opening.end();
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
    if !syntax.shell
        && let Some(start) = consume_slash_comment_start(tail, index, comment, documentation, state)
    {
        return start;
    }
    if consume_language_comment(line, tail, *index, comment, documentation, syntax) {
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
    documentation: &mut bool,
    syntax: CommentSyntax,
) -> bool {
    consume_hash_comment(line, tail, index, comment, documentation, syntax)
        || consume_dash_comment(tail, comment, syntax)
}

fn consume_hash_comment(
    line: &str,
    tail: &str,
    index: usize,
    comment: &mut String,
    documentation: &mut bool,
    syntax: CommentSyntax,
) -> bool {
    if !syntax.hash
        || (syntax.shell && !shell_comment_starts_at(line, index))
        || !tail.starts_with('#')
    {
        return false;
    }
    if tail.starts_with("#:") || tail.starts_with("##") {
        *documentation = true;
    }
    if index != 0 || !line.starts_with("#!") {
        comment.push_str(&tail[1..]);
    }
    true
}

fn consume_dash_comment(tail: &str, comment: &mut String, syntax: CommentSyntax) -> bool {
    if !syntax.dash {
        return false;
    }
    let Some(rest) = tail.strip_prefix("--") else {
        return false;
    };
    comment.push_str(rest);
    true
}

fn shell_comment_starts_at(line: &str, index: usize) -> bool {
    index == 0
        || line[..index].chars().next_back().is_some_and(|character| {
            character.is_whitespace()
                || matches!(character, ';' | '&' | '|' | '(' | ')' | '<' | '>')
        })
}

fn mask_comment_scanner_quote(
    line: &str,
    index: usize,
    character: char,
    syntax: CommentSyntax,
    state: &mut CommentScanState,
    code: &mut String,
) -> usize {
    if let Some(end) = mask_triple_quoted_literal(line, index, character, syntax, state) {
        return end;
    }
    code.push(' ');
    if syntax.rust && character == '\'' && RUST_LIFETIME.is_match(&line[index..]) {
        code.push('\'');
        return index + 1;
    }
    if let Some(end) = mask_quoted_body(line, index + character.len_utf8(), character, code) {
        return end;
    }
    if syntax.multiline_strings && (syntax.rust || character == '`') {
        state.multiline_quote = Some(character.to_string());
        state.multiline_escapes = true;
    }
    line.len()
}

fn mask_triple_quoted_literal(
    line: &str,
    index: usize,
    character: char,
    syntax: CommentSyntax,
    state: &mut CommentScanState,
) -> Option<usize> {
    if !syntax.triple_quotes {
        return None;
    }
    let delimiter = match character {
        '"' => "\"\"\"",
        '\'' => "'''",
        '`' => "```",
        _ => unreachable!(),
    };
    let remainder = line[index..].strip_prefix(delimiter)?;
    if let Some(relative) = remainder.find(delimiter) {
        return Some(index + delimiter.len() + relative + delimiter.len());
    }
    state.multiline_quote = Some(delimiter.to_owned());
    Some(line.len())
}

fn mask_quoted_body(
    line: &str,
    mut index: usize,
    delimiter: char,
    code: &mut String,
) -> Option<usize> {
    let mut escaped = false;
    for character in line[index..].chars() {
        code.push(' ');
        index += character.len_utf8();
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == delimiter {
            return Some(index);
        }
    }
    None
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
        .iter()
        .filter(|(path, _)| !excluded_comment_density_path(path))
        .filter_map(|(path, source)| summarize_comment_file(path, source, &facts_by_path[path]))
        .collect()
}

fn summarize_comment_file<'a>(
    path: &'a str,
    source: &str,
    facts: &[LineFacts],
) -> Option<CommentFile<'a>> {
    let mut file = CommentFile {
        path,
        code: 0,
        comments: 0,
        baseline_comments: 0,
        first: 0,
    };
    let header_end =
        leading_license_end(facts).max(leading_shell_contract_end(path, source, facts));
    let informative = informative_comment_lines(facts, source);
    for (index, fact) in facts.iter().enumerate().skip(header_end) {
        if !fact.code.trim().is_empty() {
            file.code += 1;
        }
        if fact.comment.trim().is_empty() {
            continue;
        }
        file.baseline_comments += 1;
        if !fact.documentation
            && fact.code.trim().is_empty()
            && !is_density_comment_noise(&fact.comment)
            && !informative[index]
        {
            file.comments += 1;
            if file.first == 0 {
                file.first = index + 1;
            }
        }
    }
    (file.code + file.baseline_comments >= 20).then_some(file)
}

fn is_density_comment_noise(comment: &str) -> bool {
    let trimmed = comment.trim();
    trimmed.is_empty()
        || trimmed
            .chars()
            .all(|character| !character.is_alphanumeric())
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || COMMENT_DIRECTIVE.is_match(trimmed)
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
    if file.comments < 10 || file.code < 5 {
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
    for (index, fact) in facts.iter().enumerate() {
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
    let license_markers = [
        "licensed under",
        "license information",
        "mit license",
        "mit licence",
        "spdx-license-identifier",
        "permission to copy",
        "permission is hereby granted",
        "gnu general public license",
        "gnu lesser general public license",
    ];
    if text.contains("copyright") && license_markers.iter().any(|marker| text.contains(marker)) {
        end
    } else {
        0
    }
}

#[derive(Clone, Copy)]
enum ShellContractSection {
    Environment,
    Usage,
}

fn leading_shell_contract_end(path: &str, source: &str, facts: &[LineFacts]) -> usize {
    if !crate::languages::shell::is_shell_source(path, source) {
        return 0;
    }
    let mut section = None;
    let mut contract = false;
    let mut end = 0;
    for (index, fact) in facts.iter().enumerate() {
        if !fact.code.trim().is_empty() {
            break;
        }
        let comment = fact.comment.trim();
        if comment.is_empty() {
            continue;
        }
        end = index + 1;
        if SHELL_ENVIRONMENT_HEADER.is_match(comment) {
            section = Some(ShellContractSection::Environment);
        } else if let Some(captures) = SHELL_USAGE_HEADER.captures(comment) {
            section = Some(ShellContractSection::Usage);
            contract |= SHELL_USAGE_ARGUMENT.is_match(&captures[1]);
        } else {
            contract |= match section {
                Some(ShellContractSection::Environment) => {
                    SHELL_ENVIRONMENT_ENTRY.is_match(comment)
                }
                Some(ShellContractSection::Usage) => SHELL_USAGE_ARGUMENT.is_match(comment),
                None => false,
            };
        }
    }
    if contract { end } else { 0 }
}

fn narrating_implementation_comments(
    context: &SourceAnalysisContext<'_>,
    facts_by_path: &BTreeMap<String, Vec<LineFacts>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context.sources() {
        if excluded_comment_path(path) {
            continue;
        }
        let facts = &facts_by_path[path];
        let informative = informative_comment_lines(facts, source);
        for (index, fact) in facts.iter().enumerate() {
            if !fact.documentation && NARRATION.is_match(&fact.comment) && !informative[index] {
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

fn informative_comment_lines(facts: &[LineFacts], source: &str) -> Vec<bool> {
    let mut informative = vec![false; facts.len()];
    let mut lines = facts.iter().zip(source.split('\n')).enumerate().peekable();
    while let Some((start, (fact, _))) = lines.next() {
        if !comment_only_line(fact) {
            informative[start] = comment_explains_intent(&fact.comment);
            continue;
        }
        let mut end = start + 1;
        let mut explains_intent = comment_explains_intent(&fact.comment);
        while let Some((index, (fact, line))) = lines.peek()
            && (comment_only_line(fact) || line.trim().is_empty())
        {
            end = *index + 1;
            explains_intent |= comment_explains_intent(&fact.comment);
            lines.next();
        }
        if explains_intent {
            informative[start..end].fill(true);
        }
    }
    informative
}

fn comment_explains_intent(comment: &str) -> bool {
    COMMENT_RATIONALE.is_match(comment) || COMMENT_CONTRACT.is_match(comment)
}

fn comment_only_line(fact: &LineFacts) -> bool {
    fact.code.trim().is_empty() && fact.commented
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
    Regex::new(r"(?i)\.(?:py|pyi|rb|sh|bash|zsh|fish|pl|pm|r|jl|nim|mojo|php|toml|ya?ml)$").unwrap()
});
static DASH_COMMENT_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(?:lua|luau|sql|hs)$").unwrap());
static GO_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:package\s+\w+|(?:type|var|const)\s+(?:\w+|\()|func\s+(?:\([^)]*\)\s*)?\w+)")
        .unwrap()
});
static GO_DECLARATION_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*type\s+\w+\s+(?:interface|struct)\s*\{").unwrap());
static SHELL_ENVIRONMENT_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:(?:expected|required|optional)\s+)?environment(?:\s+variables)?\s*:$")
        .unwrap()
});
static SHELL_ENVIRONMENT_ENTRY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*:\s+\S").unwrap());
static SHELL_USAGE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:usage|synopsis)\s*:\s*(.*)$").unwrap());
static SHELL_USAGE_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[[^\]]+\]|<[^>]+>|--[A-Za-z]|\$\{?0\b").unwrap());
static RUST_RAW_QUOTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^(?:br|cr|r)(?P<hashes>#{0,255})""#).unwrap());
static RUST_LIFETIME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^'[A-Za-z_]\w*(?:\b|$)(?:[^']|$)").unwrap());
static NARRATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:(?:first|next|now|then|finally),?\s+(?:we|i)(?:\s+will|\s+need\s+to|\s+can|\s+should)?|(?:we|i)\s+(?:will|need\s+to|are\s+going\s+to)\s+(?:first|next|now|then))\b").unwrap()
});
static COMMENT_RATIONALE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:because|otherwise|instead|when|unless|if|could|but|so|(?:this|that|which|it)\s+(?:allows?|enables?)\s+(?:us\s+)?to|to avoid|without|trade[- ]?off|in order to|such that|to ensure|specified in|see the (?:doc|documentation|comment|section|issue))\b",
    )
    .unwrap()
});
static COMMENT_CONTRACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:equations?|formulas?|specification|spec-mandated|invariants?|compatibility|SAFETY|required|requires|must|guarantees?|return values|examples?)\b|\bRFC\s*\d+|https?://|```|::=",
    )
    .unwrap()
});
static COMMENT_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(return|returns|increment|increments|decrement|decrements|set|sets|assign|assigns|call|calls|invoke|invokes)\s+(?:the\s+)?([A-Za-z_]\w*)[.!]?\s*$").unwrap()
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());
static COMMENT_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:@ts-|cspell|coverage:|deno-lint-ignore(?:-file)?\b|eslint(?:-|\s)|fmt:|mypy:|noqa\b|noinspection\b|pylint:|region\b|spellchecker|type:\s*ignore\b)",
    )
    .unwrap()
});
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
        let sphinx = scan_lines("api.py", "#: Public API documentation.\nvalue = 1");
        assert!(sphinx[0].documentation);

        let lua = scan_lines("tool.lua", "local text = \"-- literal\"\n-- actual comment");
        assert!(lua[0].comment.is_empty());
        assert_eq!(lua[1].comment.trim(), "actual comment");

        let dart = scan_lines("lib/api.dart", "/** API documentation */\nfinal value = 1;");
        assert!(dart[0].documentation);
        assert_eq!(dart[0].comment.trim(), "API documentation");

        let shell = scan_lines(
            "tool.sh",
            "#!/usr/bin/env bash\nshort=${value#prefix}\nbase=${value##*/}\nparent=${value%/*}\nurl=https://example.test/path\ncolor=#ffffff\necho value # explanation",
        );
        assert!(shell[0].comment.is_empty());
        assert!(shell[1].comment.is_empty());
        assert!(shell[2].comment.is_empty());
        assert!(shell[3].comment.is_empty());
        assert!(shell[4].comment.is_empty());
        assert!(shell[5].comment.is_empty());
        assert_eq!(shell[6].comment.trim(), "explanation");
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
    fn ignores_small_files_with_limited_explanatory_comments() {
        let mut sources = ordinary_sources("ts");
        sources.insert(
            "src/protocol.ts".to_owned(),
            (0..8)
                .map(|line| format!("// protocol constraint {line}"))
                .chain((0..24).map(|line| format!("const value{line} = {line};")))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());
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

        let mut python_sources = ordinary_sources("py");
        python_sources.insert(
            "documented.py".to_owned(),
            (0..8)
                .map(|line| format!("#: API field {line}"))
                .chain((0..12).map(|line| format!("value_{line} = {line}")))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&python_sources);
        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());

        let mut annotation_sources = ordinary_sources("ts");
        annotation_sources.insert(
            "src/annotations.ts".to_owned(),
            (0..8)
                .map(|line| format!("const color{line} = {line} // rgb({line}, 0, 0)"))
                .chain((0..8).flat_map(|section| {
                    [
                        "// ----------------------------------------".to_owned(),
                        format!("// @ts-ignore compatibility declaration {section}"),
                        format!("const value{section} = {section}"),
                    ]
                }))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&annotation_sources);
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
            "format.cc".to_owned(),
            format!(
                "// Formatting library\n//\n// Copyright 2026 The Authors\n// All rights reserved.\n//\n// For the license information refer to LICENSE.\n// Project header\n// Source header\n{}",
                (0..12)
                    .map(|line| format!("int value{line} = {line};"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        );
        licensed_sources.insert(
            "gpl.c".to_owned(),
            format!(
                "/*\n * Copyright 2026 The Authors\n *\n * This program is free software; you can redistribute it and/or modify\n * it under the terms of the GNU General Public License as published by\n * the Free Software Foundation; either version 2 of the License, or\n * (at your option) any later version.\n */\n{}",
                (0..12)
                    .map(|line| format!("int value{line} = {line};"))
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
    fn excludes_leading_shell_environment_and_usage_contracts_from_density() {
        let mut sources = ordinary_sources("sh");
        let code = (0..24)
            .map(|line| format!("value_{line}={line}"))
            .collect::<Vec<_>>()
            .join("\n");
        sources.insert(
            "scripts/package.sh".to_owned(),
            format!(
                "#!/bin/bash\n# Create an archive for distribution.\n#\n# Expected environment variables:\n#\n# TARGET: target to publish\n# BIN_PATH: binary to package\n# STAGING: directory for package files\n# NAME: output name\n#   defaults to the package name and version\n# VERSION: version to publish\n# OUTPUT: file for published paths\n{code}\n{}",
                (0..6)
                    .flat_map(|section| {
                        [
                            format!("# Package section {section}"),
                            format!("printf '%s\\n' \"$value_{section}\""),
                        ]
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        );
        for (name, usage) in [
            (
                "inline.bash",
                "# Usage: package [--target TARGET] <archive>",
            ),
            (
                "multiline.sh",
                "# Synopsis:\n#   package [OPTIONS] <archive>",
            ),
        ] {
            sources.insert(
                format!("scripts/{name}"),
                format!(
                    "#!/bin/sh\n# Package a release for distribution.\n{usage}\n{}\n{code}",
                    (0..12)
                        .map(|line| format!("# Documented invocation constraint {line}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            );
        }
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());
    }

    #[test]
    fn keeps_noisy_shell_headers_and_nonleading_contract_comments_in_density() {
        let noisy = (0..16)
            .map(|line| format!("# explanation number {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let variables = (0..16)
            .map(|line| format!("# VALUE_{line}: an implementation detail"))
            .collect::<Vec<_>>()
            .join("\n");
        let code = (0..8)
            .map(|line| format!("value_{line}={line}"))
            .collect::<Vec<_>>()
            .join("\n");
        for (body, first) in [
            (format!("{noisy}\n{code}"), 2),
            (
                format!("# Usage: increment the counter\n{noisy}\n{code}"),
                2,
            ),
            (
                format!("# Expected environment variables:\n{noisy}\n{code}"),
                2,
            ),
            (
                format!("value=0\n# Expected environment variables:\n{variables}\n{code}"),
                3,
            ),
            (
                format!("printf '%s\\n' '# Environment:'\n{variables}\n{code}"),
                3,
            ),
            (
                format!("# Environment:\n# VALUE: initial value\nvalue=0\n{noisy}\n{code}"),
                5,
            ),
        ] {
            let mut sources = ordinary_sources("sh");
            sources.insert("scripts/noisy.sh".to_owned(), format!("#!/bin/sh\n{body}"));
            let context = SourceAnalysisContext::unchanged(&sources);
            let findings = excessive_comment_density(&context, &facts(&context));

            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].code, "excessive-comment-density");
            assert_eq!(findings[0].path, "scripts/noisy.sh");
            assert_eq!(findings[0].line, first);
            assert_eq!(findings[0].confidence, "medium");
            assert!(findings[0].related_files.is_empty());
        }
    }

    #[test]
    fn reports_first_person_narration_but_not_rationale_or_documentation() {
        let sources = BTreeMap::from([
            (
                "lib/source.dart".to_owned(),
                "// First, we load the cache.\nloadCache();\n// Keep this order because the server signs canonical bytes.\nsignPayload();\n/// Next, we describe the public API.\nvoid api() {}\n// When paths are sorted during traversal,\n// then we can emit them immediately.\nwalk();\n// We could preserve every option,\n// but that would retain needless state.\n// Now we choose one.\nselect();\n// Now we prepend fills such that they remain below content.\nrender();\n// Now we run the simulation to ensure rowspans have enough height.\nsimulate();\n// Now we apply adjustment specified in the layout requirements.\nadjust();\n// Then we process groups. See the doc comment for the contract.\nprocess();".to_owned(),
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

    #[test]
    fn excludes_raw_samples_and_template_contents_from_comment_advice() {
        let sources = BTreeMap::from([
            (
                "src/sample.rs".to_owned(),
                r####"fn sample(value: &'static str) {
    let embedded = r###"
// First, we load the cache.
// Return result.
"##
// Next, we save the result.
"###;
    let bytes = br#"
// Then we return the bytes.
"#;
}
"####
                    .to_owned(),
            ),
            (
                "src/sample.mjs".to_owned(),
                "const sample = `\n// First, we load the cache.\n// Return result.\n`;\n"
                    .to_owned(),
            ),
            (
                "src/live.rs".to_owned(),
                "// First, we load the cache.\nload();\n// Return result.\nreturn result;"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);
        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.path.as_str(),
                    finding.line,
                    finding.confidence.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("narrating-implementation-comment", "src/live.rs", 1, "high"),
                ("trivial-comment-restatement", "src/live.rs", 3, "high"),
            ]
        );
    }

    #[test]
    fn protects_derivations_and_complete_contract_blocks_without_hiding_narration() {
        let mut sources = ordinary_sources("rs");
        let contract = (0..16)
            .map(|line| format!("// Constraint detail {line}."))
            .collect::<Vec<_>>()
            .join("\n");
        let code = (0..24)
            .map(|line| format!("let value{line} = {line};"))
            .collect::<Vec<_>>()
            .join("\n");
        sources.insert(
            "src/contract.rs".to_owned(),
            format!(
                "// First, we establish the clipping plane.\n//\n{contract}\n// This must match the projection specification.\n{code}\n// Finally, we have the revised equation (10), M3 = M4 - aC.\n// This simplifies to the homogeneous plane.\nlet plane = m4 - c * a;"
            ),
        );
        sources.insert(
            "src/narrated.rs".to_owned(),
            format!("// First, we load the cache.\nload();\n{code}"),
        );
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "narrating-implementation-comment");
        assert_eq!(findings[0].path, "src/narrated.rs");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn excludes_long_reuse_licenses_and_embedded_samples_from_density() {
        let mut sources = ordinary_sources("rs");
        let legal = (0..48)
            .map(|line| format!("// License condition {line}."))
            .collect::<Vec<_>>()
            .join("\n");
        let code = (0..24)
            .map(|line| format!("let value{line} = {line};"))
            .collect::<Vec<_>>()
            .join("\n");
        sources.insert(
            "src/licensed.rs".to_owned(),
            format!("// Copyright Authors\n// Permission to copy and distribute this work.\n{legal}\n{code}"),
        );
        sources.insert(
            "src/sample.rs".to_owned(),
            format!("let sample = r###\"\n{legal}\n\"###;\n{code}"),
        );
        let context = SourceAnalysisContext::unchanged(&sources);
        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());
    }

    #[test]
    fn excludes_repeated_linter_directives_from_density() {
        let mut sources = ordinary_sources("ts");
        sources.insert(
            "src/compatibility.ts".to_owned(),
            (0..16)
                .flat_map(|line| {
                    [
                        "// deno-lint-ignore no-explicit-any".to_owned(),
                        format!("let value{line}: any = {line};"),
                    ]
                })
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let context = SourceAnalysisContext::unchanged(&sources);
        assert!(excessive_comment_density(&context, &facts(&context)).is_empty());
    }

    #[test]
    fn protects_causal_and_failure_constraints_without_hiding_adjacent_narration() {
        let mut sources = ordinary_sources("rs");
        let details = (0..12)
            .map(|line| format!("// Constraint detail {line}."))
            .collect::<Vec<_>>()
            .join("\n");
        let code = (0..24)
            .map(|line| format!("let value{line} = {line};"))
            .collect::<Vec<_>>()
            .join("\n");
        for (name, rationale) in [
            (
                "causal",
                "The flag only applies to binaries, so we emit separate library flags.",
            ),
            (
                "avoid",
                "Port numbers include the user ID to avoid conflicts.",
            ),
            (
                "failure",
                "Without hiding these symbols, interposition aborts the runtime.",
            ),
            (
                "allows",
                "This allows us to normalize vertex normals efficiently.",
            ),
            (
                "enables",
                "This enables us to reuse the normalized coordinates.",
            ),
        ] {
            sources.insert(
                format!("src/{name}.rs"),
                format!("// First, we calculate the value.\n\n{details}\n\n// {rationale}\n{code}"),
            );
        }
        sources.insert(
            "src/live.rs".to_owned(),
            format!("// First, we load the cache.\nload();\n{code}"),
        );
        sources.insert(
            "tests/narrated.rs".to_owned(),
            "// First, we load the cache.\nload();".to_owned(),
        );
        sources.insert(
            "src/sample.rs".to_owned(),
            "let sample = r###\"\n// First, we load the cache.\n\"###;".to_owned(),
        );
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "narrating-implementation-comment");
        assert_eq!(findings[0].path, "src/live.rs");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].confidence, "high");
    }

    #[test]
    fn preserves_rationale_across_blank_lines_but_not_code_or_quoted_statements() {
        let sources = BTreeMap::from([
            (
                "src/geometry.rs".to_owned(),
                "// Now we build the lateral surface.\n \n// The normal is perpendicular to the surface.\n// This allows us to normalize vertex normals efficiently.\nfn build() {}".to_owned(),
            ),
            (
                "src/relative.rs".to_owned(),
                "// First we prepare the cached inputs.\n//\n\n// This enables us to reuse the normalized coordinates.\nfn prepare() {}".to_owned(),
            ),
            (
                "src/no_rationale.rs".to_owned(),
                "// Next we create a list.\n\n// The list stores entries.\nfn create() {}".to_owned(),
            ),
            (
                "src/quoted.py".to_owned(),
                "# First we prepare the state.\n'not a blank line'\n# This allows us to reuse the coordinates.\nprepare()".to_owned(),
            ),
            (
                "src/unrelated.rs".to_owned(),
                "// First we prepare the state.\nfn prepare() {}\n// This allows us to reuse the coordinates.\nfn reuse() {}".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            [
                ("narrating-implementation-comment", "src/no_rationale.rs", 1),
                ("narrating-implementation-comment", "src/quoted.py", 1),
                ("narrating-implementation-comment", "src/unrelated.rs", 1),
            ]
        );
        assert!(findings.iter().all(|finding| finding.confidence == "high"));
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
