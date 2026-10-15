use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::dart_core_rules::{mask_comments, mask_comments_preserving_strings};
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{index::DartSourceIndex, matching_delimiter, split_top_level};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        let masked = mask_comments(index.masked_lines(path)).join("\n");
        let original = index.source(path);
        let scopes = scopes(&masked);
        let if_regions = parse_if_regions(&masked);
        findings.extend(throw_string_findings(path, original, &masked));
        findings.extend(catch_findings(path, &masked, original, &scopes));
        findings.extend(invocation_findings(path, &masked, &scopes, &if_regions));
    }
    findings
}
#[derive(Debug)]
pub(crate) struct AsyncContextUse {
    pub start: usize,
    pub name: String,
}

pub(crate) fn unguarded_context_uses(source: &str) -> Vec<AsyncContextUse> {
    let scopes = scopes(source);
    let if_regions = parse_if_regions(source);
    let mut reported = BTreeSet::new();
    let mut uses = Vec::new();
    for context in CONTEXT_USE.find_iter(source) {
        let suffix = source[context.end()..].trim_start();
        if suffix.starts_with(".mounted") || suffix.starts_with(':') {
            continue;
        }
        let Some(scope) = enclosing_scope(&scopes, context.start()) else {
            continue;
        };
        if !scope.is_async
            || !has_reachable_await_before(source, scope, context.start(), &if_regions)
            || has_mounted_guard(source, scope, context.start(), &if_regions)
            || !reported.insert((scope.start, scope.end))
        {
            continue;
        }
        uses.push(AsyncContextUse {
            start: scope.start,
            name: scope.name.clone(),
        });
    }
    uses
}

#[derive(Debug)]
struct Scope {
    start: usize,
    body_start: usize,
    end: usize,
    parameters: BTreeSet<String>,
    return_type: Option<String>,
    is_async: bool,
    name: String,
}

fn scopes(source: &str) -> Vec<Scope> {
    let mut scopes = Vec::new();
    for captures in NAMED_FUNCTION.captures_iter(source) {
        let return_type = captures.name("return").unwrap().as_str();
        let name = captures.name("name").unwrap().as_str();
        if matches!(return_type, "await" | "else")
            || matches!(name, "for" | "if" | "while" | "switch" | "catch")
        {
            continue;
        }
        let marker = captures.name("marker").unwrap();
        let Some((body_start, end)) = scope_range(source, marker) else {
            continue;
        };
        scopes.push(Scope {
            start: captures.get(0).unwrap().start(),
            name: name.to_owned(),
            body_start,
            end,
            parameters: parameter_names(captures.name("parameters").unwrap().as_str()),
            return_type: Some(return_type.to_owned()),
            is_async: captures.name("async").is_some(),
        });
    }
    for captures in NAMED_GETTER.captures_iter(source) {
        let marker = captures.name("marker").unwrap();
        let Some((body_start, end)) = scope_range(source, marker) else {
            continue;
        };
        scopes.push(Scope {
            start: captures.get(0).unwrap().start(),
            name: captures.name("name").unwrap().as_str().to_owned(),
            body_start,
            end,
            parameters: BTreeSet::new(),
            return_type: Some(captures.name("return").unwrap().as_str().to_owned()),
            is_async: captures.name("async").is_some(),
        });
    }
    for captures in CLOSURE.captures_iter(source) {
        let complete = captures.get(0).unwrap();
        if source[..complete.start()]
            .trim_end()
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b')' | b']'))
        {
            continue;
        }
        let marker = captures.name("marker").unwrap();
        let Some((body_start, end)) = scope_range(source, marker) else {
            continue;
        };
        scopes.push(Scope {
            start: complete.start(),
            name: "async callback".to_owned(),
            body_start,
            end,
            parameters: parameter_names(captures.name("parameters").unwrap().as_str()),
            return_type: None,
            is_async: captures.name("async").is_some(),
        });
    }
    scopes
}

fn scope_range(source: &str, marker: regex::Match<'_>) -> Option<(usize, usize)> {
    if marker.as_str() == "{" {
        Some((
            marker.end(),
            matching_delimiter(source, marker.start(), b'{', b'}')?,
        ))
    } else {
        let end = expression_end(source, marker.end());
        Some((marker.end(), end))
    }
}

fn expression_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depths = [0usize; 3];
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        match *byte {
            b'(' => depths[0] += 1,
            b')' if depths[0] > 0 => depths[0] -= 1,
            b'[' => depths[1] += 1,
            b']' if depths[1] > 0 => depths[1] -= 1,
            b'{' => depths[2] += 1,
            b'}' if depths[2] > 0 => depths[2] -= 1,
            b',' | b';' if depths == [0, 0, 0] => return index,
            _ => {}
        }
    }
    source.len()
}

fn parameter_names(parameters: &str) -> BTreeSet<String> {
    split_top_level(parameters, b',')
        .into_iter()
        .filter_map(|parameter| {
            IDENTIFIER
                .find_iter(parameter.split('=').next().unwrap_or(parameter))
                .map(|identifier| identifier.as_str())
                .filter(|identifier| {
                    !matches!(
                        *identifier,
                        "required" | "final" | "const" | "covariant" | "this" | "super"
                    )
                })
                .last()
                .map(str::to_owned)
        })
        .collect()
}

fn enclosing_scope(scopes: &[Scope], offset: usize) -> Option<&Scope> {
    scopes
        .iter()
        .filter(|scope| scope.start <= offset && offset < scope.end)
        .min_by_key(|scope| scope.end - scope.start)
}

fn containing_scopes(scopes: &[Scope], offset: usize) -> impl Iterator<Item = &Scope> {
    scopes
        .iter()
        .filter(move |scope| scope.start <= offset && offset < scope.end)
}

fn throw_string_findings(path: &str, original: &str, masked: &str) -> Vec<Finding> {
    THROW_KEYWORD
        .find_iter(masked)
        .filter(|matched| {
            let suffix = original[matched.end()..].trim_start();
            suffix.starts_with(['\'', '"'])
                || suffix
                    .strip_prefix(['r', 'R'])
                    .is_some_and(|raw| raw.starts_with(['\'', '"']))
        })
        .map(|matched| {
            finding(
                "dart-throw-string",
                path,
                line_at(masked, matched.start()),
                "a string is thrown instead of an exception",
            )
        })
        .collect()
}

#[derive(Debug)]
struct CatchClause<'a> {
    start: usize,
    body_start: usize,
    body_end: usize,
    exception: Option<&'a str>,
    stack: Option<&'a str>,
}

fn catch_clauses(source: &str) -> Vec<CatchClause<'_>> {
    CATCH_START
        .captures_iter(source)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            if whole.as_str().trim_start().starts_with("on ")
                && !source[..whole.start()].trim_end().ends_with('}')
            {
                return None;
            }
            let open = whole.end() - 1;
            let close = matching_delimiter(source, open, b'{', b'}')?;
            let parameters = captures
                .name("typed_parameters")
                .or_else(|| captures.name("untyped_parameters"))
                .map(|value| value.as_str())
                .unwrap_or("");
            let mut names = parameters
                .split(',')
                .map(str::trim)
                .filter(|name| IDENTIFIER.is_match(name));
            Some(CatchClause {
                start: whole.start(),
                body_start: open + 1,
                body_end: close,
                exception: names.next(),
                stack: names.next(),
            })
        })
        .collect()
}

fn catch_findings(path: &str, source: &str, original: &str, scopes: &[Scope]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for clause in catch_clauses(source) {
        let body = &source[clause.body_start..clause.body_end];
        let original_body =
            mask_comments_preserving_strings(&original[clause.body_start..clause.body_end]);
        let line = line_at(source, clause.start);
        let end_line = line_at(source, clause.body_end);
        if RETURN_NULL.is_match(body) && !intentional_nullable_fallback(&clause, body, scopes) {
            findings.push(range_finding(
                "dart-catch-return-null",
                path,
                line,
                end_line,
                "catch clause converts a failure to null",
            ));
        }
        if let Some(exception) = clause.exception
            && clause.stack.is_none()
            && logs_exception_without_stack(&original_body, exception)
            && !THROWS_FAILURE.is_match(body)
        {
            findings.push(range_finding(
                "dart-catch-without-stack-trace",
                path,
                line,
                end_line,
                "caught exception is logged without its stack trace",
            ));
        }
    }
    findings
}

fn intentional_nullable_fallback(clause: &CatchClause<'_>, body: &str, scopes: &[Scope]) -> bool {
    clause.exception.is_none()
        && RETURN_NULL_ONLY.is_match(body)
        && enclosing_scope(scopes, clause.start)
            .and_then(|scope| scope.return_type.as_deref())
            .is_some_and(|return_type| return_type.ends_with('?'))
}

fn logs_exception_without_stack(body: &str, exception: &str) -> bool {
    Regex::new(&format!(
        r"(?m)(?:(?:\b(?:logger|log)\s*\.\s*(?:debug|info|warn|warning|error|severe))|(?:^|[^.\w])(?:print|log|debug|info|warn|warning|error|severe))\s*\([^)]*\b{}\b",
        regex::escape(exception)
    ))
    .unwrap()
    .is_match(body)
}

#[derive(Debug)]
struct Invocation<'a> {
    target: &'a str,
    method: &'a str,
    start: usize,
    method_start: usize,
    end: usize,
}

fn invocations(source: &str) -> Vec<Invocation<'_>> {
    INVOCATION
        .captures_iter(source)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            let close = matching_delimiter(source, whole.end() - 1, b'(', b')')?;
            let method = captures.name("method")?;
            Some(Invocation {
                target: captures.name("target").map_or("", |value| value.as_str()),
                method: method.as_str(),
                start: invocation_start(source, whole.start(), method.start()),
                method_start: method.start(),
                end: close + 1,
            })
        })
        .collect()
}

fn invocation_start(source: &str, whole_start: usize, method_start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = method_start;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    if cursor == 0 || bytes[cursor - 1] != b'.' {
        return whole_start;
    }
    cursor -= 1;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    expression_start_backward(source, cursor)
}

enum BackwardComponent {
    Identifier,
    Suffix,
}

enum BackwardBoundary {
    ContinueFrom(usize),
    ExpressionStart,
}

fn expression_start_backward(source: &str, mut cursor: usize) -> usize {
    let bytes = source.as_bytes();
    while let Some(component) = consume_backward_component(bytes, &mut cursor) {
        let component_start = cursor;
        match classify_backward_boundary(bytes, cursor, component) {
            BackwardBoundary::ContinueFrom(next_cursor) => cursor = next_cursor,
            BackwardBoundary::ExpressionStart => return component_start,
        }
    }
    cursor
}

fn consume_backward_component(bytes: &[u8], cursor: &mut usize) -> Option<BackwardComponent> {
    match bytes.get(cursor.wrapping_sub(1)) {
        Some(b']') => {
            *cursor = matching_open_backward(bytes, *cursor - 1, b'[', b']')?;
            Some(BackwardComponent::Suffix)
        }
        Some(b')') => {
            *cursor = matching_open_backward(bytes, *cursor - 1, b'(', b')')?;
            Some(BackwardComponent::Suffix)
        }
        Some(byte) if byte.is_ascii_alphanumeric() || *byte == b'_' => {
            while *cursor > 0
                && (bytes[*cursor - 1].is_ascii_alphanumeric() || bytes[*cursor - 1] == b'_')
            {
                *cursor -= 1;
            }
            Some(BackwardComponent::Identifier)
        }
        _ => None,
    }
}

fn classify_backward_boundary(
    bytes: &[u8],
    mut cursor: usize,
    component: BackwardComponent,
) -> BackwardBoundary {
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    if cursor > 0 && bytes[cursor - 1] == b'.' {
        cursor -= 1;
        while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
            cursor -= 1;
        }
        return BackwardBoundary::ContinueFrom(cursor);
    }
    if matches!(component, BackwardComponent::Suffix)
        && cursor > 0
        && can_precede_backward_suffix(bytes[cursor - 1])
    {
        return BackwardBoundary::ContinueFrom(cursor);
    }
    BackwardBoundary::ExpressionStart
}

fn can_precede_backward_suffix(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b')' | b']')
}

fn matching_open_backward(bytes: &[u8], close: usize, opening: u8, closing: u8) -> Option<usize> {
    let mut depth = 0usize;
    for index in (0..=close).rev() {
        if bytes[index] == closing {
            depth += 1;
        } else if bytes[index] == opening {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn invocation_findings(
    path: &str,
    source: &str,
    scopes: &[Scope],
    if_regions: &[IfRegion],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for invocation in invocations(source) {
        let line = line_at(source, invocation.start);
        if SYNC_FILE_METHODS.contains(&invocation.method)
            && enclosing_scope(scopes, invocation.method_start).is_some_and(|scope| scope.is_async)
        {
            findings.push(range_finding(
                "dart-synchronous-file-io-in-async",
                path,
                line,
                line_at(source, invocation.end),
                &format!(
                    "synchronous filesystem operation `{}` runs in async code",
                    invocation.method
                ),
            ));
        }
        let flutter_set_state = invocation.method == "setState"
            && matches!(invocation.target, "" | "this")
            && !containing_scopes(scopes, invocation.method_start)
                .any(|scope| scope.parameters.contains("setState"));
        if flutter_set_state
            && let Some(scope) = enclosing_scope(scopes, invocation.method_start)
            && has_reachable_await_before(source, scope, invocation.method_start, if_regions)
            && !has_mounted_guard(source, scope, invocation.method_start, if_regions)
        {
            findings.push(range_finding(
                "flutter-set-state-after-await",
                path,
                line,
                line_at(source, invocation.end),
                "setState occurs after an async gap without a mounted guard",
            ));
        }
    }
    findings
}

#[derive(Debug)]
struct IfRegion {
    start: usize,
    condition: String,
    then_range: (usize, usize),
    else_range: Option<(usize, usize)>,
    then_exits: bool,
    else_exits: bool,
    end: usize,
}

fn parse_if_regions(source: &str) -> Vec<IfRegion> {
    let mut regions = Vec::new();
    for matched in IF_START.find_iter(source) {
        let open = matched.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        let Some((then_start, then_end, then_exits)) = statement_range(source, close + 1) else {
            continue;
        };
        let after_then = skip_whitespace(source, then_end);
        let mut else_range = None;
        let mut else_exits = false;
        let mut end = then_end;
        if source[after_then..].starts_with("else")
            && let Some((start, finish, exits)) = statement_range(source, after_then + 4)
        {
            else_range = Some((start, finish));
            else_exits = exits;
            end = finish;
        }
        regions.push(IfRegion {
            start: matched.start(),
            condition: source[open + 1..close].trim().to_owned(),
            then_range: (then_start, then_end),
            else_range,
            then_exits,
            else_exits,
            end,
        });
    }
    regions
}

fn statement_range(source: &str, offset: usize) -> Option<(usize, usize, bool)> {
    let start = skip_whitespace(source, offset);
    if source.as_bytes().get(start) == Some(&b'{') {
        let close = matching_delimiter(source, start, b'{', b'}')?;
        let body = source[start + 1..close].trim_end();
        return Some((start, close + 1, EXITING_STATEMENT_END.is_match(body)));
    }
    let end = source[start..]
        .find(';')
        .map(|relative| start + relative + 1)?;
    Some((
        start,
        end,
        EXITING_STATEMENT_START.is_match(source[start..end].trim_start()),
    ))
}

fn has_reachable_await_before(
    source: &str,
    scope: &Scope,
    invocation: usize,
    if_regions: &[IfRegion],
) -> bool {
    if invocation <= scope.body_start {
        return false;
    }
    AWAIT
        .find_iter(&source[scope.body_start..invocation])
        .map(|matched| {
            (
                scope.body_start + matched.start(),
                scope.body_start + matched.end(),
            )
        })
        .any(|(await_offset, await_end)| {
            await_completes_before(source, await_end, invocation)
                && !if_regions.iter().any(|region| {
                    region.start >= scope.start
                        && region.end <= scope.end
                        && mutually_exclusive(region, await_offset, invocation)
                })
        })
}

fn await_completes_before(source: &str, await_end: usize, invocation: usize) -> bool {
    source[await_end..invocation]
        .bytes()
        .any(|byte| matches!(byte, b';' | b'}'))
}

fn mutually_exclusive(region: &IfRegion, await_offset: usize, invocation: usize) -> bool {
    let await_then = contains(region.then_range, await_offset);
    let await_else = region
        .else_range
        .is_some_and(|range| contains(range, await_offset));
    let target_then = contains(region.then_range, invocation);
    let target_else = region
        .else_range
        .is_some_and(|range| contains(range, invocation));
    (await_then && target_else)
        || (await_else && target_then)
        || (invocation >= region.end
            && (await_then && region.then_exits || await_else && region.else_exits))
}

fn has_mounted_guard(
    source: &str,
    scope: &Scope,
    invocation: usize,
    if_regions: &[IfRegion],
) -> bool {
    for region in if_regions
        .iter()
        .filter(|region| region.start >= scope.start && region.end <= scope.end)
    {
        if contains(region.then_range, invocation) && requires_mounted_true(&region.condition) {
            return true;
        }
        if region
            .else_range
            .is_some_and(|range| contains(range, invocation))
            && requires_mounted_false(&region.condition)
        {
            return true;
        }
    }
    let Some(last_await) = AWAIT
        .find_iter(&source[scope.body_start..invocation])
        .map(|matched| scope.body_start + matched.start())
        .max()
    else {
        return false;
    };
    if_regions.iter().any(|region| {
        region.start > last_await
            && region.end <= invocation
            && region.then_exits
            && requires_mounted_false(&region.condition)
    })
}

fn requires_mounted_true(condition: &str) -> bool {
    let condition = strip_outer_parentheses(condition.trim());
    if let Some(index) = top_level_operator(condition, "&&") {
        return requires_mounted_true(&condition[..index])
            || requires_mounted_true(&condition[index + 2..]);
    }
    if let Some(index) = top_level_operator(condition, "||") {
        return requires_mounted_true(&condition[..index])
            && requires_mounted_true(&condition[index + 2..]);
    }
    MOUNTED.is_match(condition.trim())
}

fn requires_mounted_false(condition: &str) -> bool {
    let condition = strip_outer_parentheses(condition.trim());
    if let Some(operand) = condition.strip_prefix('!') {
        return requires_mounted_true(operand);
    }
    if let Some(index) = top_level_operator(condition, "&&") {
        return requires_mounted_false(&condition[..index])
            && requires_mounted_false(&condition[index + 2..]);
    }
    if let Some(index) = top_level_operator(condition, "||") {
        return requires_mounted_false(&condition[..index])
            || requires_mounted_false(&condition[index + 2..]);
    }
    false
}

fn strip_outer_parentheses(mut source: &str) -> &str {
    while source.starts_with('(')
        && source.ends_with(')')
        && matching_delimiter(source, 0, b'(', b')') == Some(source.len() - 1)
    {
        source = source[1..source.len() - 1].trim();
    }
    source
}

fn top_level_operator(source: &str, operator: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let operator = operator.as_bytes();
    let mut depth = 0usize;
    for index in 0..=bytes.len().saturating_sub(operator.len()) {
        match bytes[index] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            _ if depth == 0 && bytes[index..].starts_with(operator) => return Some(index),
            _ => {}
        }
    }
    None
}

fn contains(range: (usize, usize), offset: usize) -> bool {
    range.0 <= offset && offset < range.1
}

fn skip_whitespace(source: &str, mut offset: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    offset
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn range_finding(code: &str, path: &str, line: usize, end_line: usize, message: &str) -> Finding {
    let mut finding = finding(code, path, line, message);
    finding.end_line = end_line;
    finding
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart reliability metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart reliability severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const SYNC_FILE_METHODS: [&str; 13] = [
    "copySync",
    "createSync",
    "deleteSync",
    "existsSync",
    "listSync",
    "openSync",
    "readAsBytesSync",
    "readAsLinesSync",
    "readAsStringSync",
    "renameSync",
    "statSync",
    "writeAsBytesSync",
    "writeAsStringSync",
];

static NAMED_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:external|static|abstract|covariant)[ \t]+)*(?P<return>(?:[A-Za-z_]\w*(?:<[^{};\n]+>)?\??|[A-Za-z_]\w*<\(\{[^;\n]*\}\)>\??))[ \t]+(?P<name>[A-Za-z_]\w*)(?:<[^{};()\n]+>)?[ \t]*\((?P<parameters>(?:[^;()]|\([^;()]*\))*)\)[ \t\r\n]*(?P<async>async\*?[ \t\r\n]*)?(?P<marker>\{|=>)").unwrap()
});
static NAMED_GETTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:external|static|abstract|covariant)[ \t]+)*(?P<return>[A-Za-z_]\w*(?:<[^{};\n]+>)?\??)[ \t]+get[ \t]+(?P<name>[A-Za-z_]\w*)[ \t\r\n]*(?P<async>async\*?[ \t\r\n]*)?(?P<marker>\{|=>)").unwrap()
});
static CLOSURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\((?P<parameters>[^;{}()]*)\)[ \t\r\n]*(?P<async>async\*?[ \t\r\n]*)?(?P<marker>\{|=>)",
    )
    .unwrap()
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]\w*").unwrap());
static THROW_KEYWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bthrow\b").unwrap());
static CATCH_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:(?:\bon\s+[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:<[^>]+>)?\s+)(?:catch\s*\((?P<typed_parameters>[^)]*)\)\s*)?|\bcatch\s*\((?P<untyped_parameters>[^)]*)\)\s*)\{").unwrap()
});
static RETURN_NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\breturn\s+null\s*;").unwrap());
static RETURN_NULL_ONLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*return\s+null\s*;\s*$").unwrap());
static THROWS_FAILURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\brethrow\b|\bthrow\b").unwrap());
static INVOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:(?P<target>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*)?(?P<method>[A-Za-z_]\w*)\s*\(",
    )
    .unwrap()
});
static IF_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bif\s*\(").unwrap());
static AWAIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bawait\b").unwrap());
static CONTEXT_USE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bcontext\b").unwrap());
static MOUNTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:(?:this|context)\.)?mounted$").unwrap());
static EXITING_STATEMENT_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^return\b").unwrap());
static EXITING_STATEMENT_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\breturn\b[^;]*;\s*$").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn finds_string_throws_and_failure_erasing_catches() {
        let fixture = Fixture::new([(
            "lib/failures.dart",
            "Object? parse() {\n  try {\n    return decode();\n  } catch (error) {\n    logger.error(error);\n    return null;\n  }\n}\nNever fail() => throw 'invalid';",
        )]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-catch-return-null".to_owned(), 4),
                ("dart-catch-without-stack-trace".to_owned(), 4),
                ("dart-throw-string".to_owned(), 9),
            ]
        );
    }

    #[test]
    fn accepts_intentional_nullable_fallbacks_and_preserved_failures() {
        let fixture = Fixture::new([(
            "lib/safe.dart",
            "Object? readCache({required String key}) {\n  try { return decodeCache(); } on Object { return null; }\n}\nint? parseWidth(String source) {\n  try { return int.parse(source); } on FormatException { return null; }\n}\nvoid forward() {\n  try { decode(); } catch (error, stackTrace) { logger.error(error, stackTrace); rethrow; }\n}\nResponse handle() {\n  try { return execute(); } on Exception catch (error) { return Response.error(500, error.toString()); }\n}",
        )]);

        assert!(analyze(&fixture.context()).is_empty());
    }

    #[test]
    fn reports_logged_exceptions_only_when_stack_context_is_discarded() {
        let fixture = Fixture::new([(
            "lib/catches.dart",
            "void unsafe() {\n  try { decode(); } catch (error) { logger.error(error); }\n}\nvoid safeStack() {\n  try { decode(); } catch (error, stack) { logger.error(error, stack); }\n}\nvoid safeThrow() {\n  try { decode(); } catch (error) { logger.error(error); rethrow; }\n}",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-catch-without-stack-trace")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn reports_synchronous_file_operations_only_inside_async_scopes() {
        let fixture = Fixture::new([(
            "lib/io.dart",
            r#"Future<String> load(File source) async => source.readAsStringSync();
String loadBlocking(File source) => source.readAsStringSync();
void register() {
  callback(() async { file.writeAsBytesSync(bytes); });
}
Future<void> persist(
  String fileName, {
  FileSystem fs = const LocalFileSystem(),
}) async {
  fs.file(fileName).existsSync();
}
Future<Iterable<File>> get targets async {
  return directory.listSync();
}
Stream<File> enumerate(Directory directory) async* {
  if (directory.existsSync()) {
    yield* directory.list();
  }
}
Future<void> offload(File file) async {
  await Isolate.run(() {
    file.readAsStringSync();
  });
}
Future<void> branch(File file, bool enabled) async {
  if (enabled) {
    await prepare();
  } else if (file.existsSync()) {
    await recover();
  }
}"#,
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-synchronous-file-io-in-async")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1, 4, 10, 13, 16, 28]
        );
    }

    #[test]
    fn limits_set_state_findings_to_reachable_unguarded_flutter_calls() {
        let fixture = Fixture::new([(
            "lib/state.dart",
            "class DemoState {\n  Future<void> load(bool existing) async {\n    if (existing) {\n      await save();\n    } else {\n      setState(() {});\n    }\n    await refresh();\n    server.setState((state) => state);\n    this.setState(() {});\n  }\n  Future<void> recover() async {\n    try {\n      await fetch();\n    } catch (_) {\n      setState(() {});\n    }\n  }\n  Future<void> guarded() async {\n    await fetch();\n    if (updated && this.mounted) {\n      setState(() {});\n    }\n  }\n  Future<void> early(Object? result) async {\n    await fetch();\n    if (result == null || !mounted) return;\n    setState(() {});\n  }\n  Future<void> delegated(bool useDelegate) async {\n    if (useDelegate) {\n      return await loadFromDelegate();\n    }\n    setState(() {});\n  }\n}\nFuture<void> updateWithCallback(void Function(void Function()) setState) async {\n  await fetch();\n  setState(() {});\n}",
        )]);

        assert_eq!(
            findings_for(&fixture, "flutter-set-state-after-await")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![10, 16]
        );
    }

    #[test]
    fn handles_malformed_scopes_and_interpolated_catch_logging() {
        let fixture = Fixture::new([
            (
                "lib/broken.dart",
                "void broken() {\n  try {\n    decode();\n",
            ),
            (
                "lib/catch.dart",
                "void load() {\n  try { decode(); } catch (error) {\n    logger.error('decode failed: $error');\n    return null;\n  }\n}\n",
            ),
        ]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-catch-return-null".to_owned(), 2),
                ("dart-catch-without-stack-trace".to_owned(), 2),
            ]
        );
    }

    #[test]
    fn skips_malformed_catches_and_invocations_without_losing_valid_findings() {
        let fixture = Fixture::new([
            (
                "lib/broken_catch.dart",
                "void broken() {\n  try { decode(); } catch (error) {\n    logger.error(error);\n",
            ),
            (
                "lib/broken_invocation.dart",
                "Future<void> broken(File file) async {\n  file.readAsStringSync(\n",
            ),
            (
                "lib/valid.dart",
                "Future<void> load(File file) async {\n  file.readAsStringSync();\n}\nvoid parse() {\n  try { decode(); } catch (error) {\n    logger.error(error);\n    return null;\n  }\n}\n",
            ),
        ]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-catch-return-null".to_owned(), 5),
                ("dart-catch-without-stack-trace".to_owned(), 5),
                ("dart-synchronous-file-io-in-async".to_owned(), 2),
            ]
        );
    }

    fn findings_for(fixture: &Fixture, code: &str) -> Vec<Finding> {
        analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == code)
            .collect()
    }

    fn code_lines(fixture: &Fixture) -> Vec<(String, usize)> {
        let mut findings = analyze(&fixture.context())
            .into_iter()
            .map(|finding| (finding.code, finding.line))
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
