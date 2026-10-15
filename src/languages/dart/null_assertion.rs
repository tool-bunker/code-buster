use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::dart_core_rules::mask_comments;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{index::DartSourceIndex, matching_delimiter};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        analyze_path(index, path, &mut findings);
    }
    findings
}

fn analyze_path(index: &DartSourceIndex<'_>, path: &str, findings: &mut Vec<Finding>) {
    let masked =
        dart_source_with_interpolations(index.source(path), &index.masked_lines(path).join("\n"));
    let masked_lines = masked.split('\n').map(str::to_owned).collect::<Vec<_>>();
    let masked = mask_comments(&masked_lines).join("\n");
    let if_regions = parse_if_regions(&masked);
    let mut reported_lines = BTreeSet::new();

    for assertion in assertions(&masked) {
        if assertion_is_safe(&masked, &assertion, &if_regions)
            || !reported_lines.insert(assertion.line)
        {
            continue;
        }
        findings.push(finding(path, assertion.line, assertion.end_line));
    }
}

fn assertion_is_safe(source: &str, assertion: &Assertion, if_regions: &[IfRegion]) -> bool {
    if assertion.guaranteed {
        return true;
    }
    let Some(target) = assertion.target.as_deref() else {
        return false;
    };
    key_proven_by_iteration(source, assertion.start, target)
        || lexically_proven_non_null(source, assertion.start, target)
        || proven_non_null(
            source,
            assertion.start,
            target,
            if_regions,
            &getter_conditions_at(source, assertion.start),
        )
}

pub(crate) fn dart_source_with_interpolations(source: &str, masked: &str) -> String {
    let mut output = masked.as_bytes().to_vec();
    scan_dart_code(source.as_bytes(), &mut output, 0, false, false);
    String::from_utf8(output).expect("interpolation masking must preserve UTF-8")
}

enum DartScanTransition {
    ContinueAt(usize),
    CompleteAt(usize),
}

fn scan_dart_code(
    source: &[u8],
    output: &mut [u8],
    mut index: usize,
    copy: bool,
    stop_at_closing_brace: bool,
) -> usize {
    let mut brace_depth = 0usize;
    while index < source.len() {
        match dart_code_transition(
            source,
            output,
            index,
            copy,
            stop_at_closing_brace,
            &mut brace_depth,
        ) {
            DartScanTransition::ContinueAt(next) => index = next,
            DartScanTransition::CompleteAt(end) => return end,
        }
    }
    index
}

fn dart_code_transition(
    source: &[u8],
    output: &mut [u8],
    index: usize,
    copy: bool,
    stop_at_closing_brace: bool,
    brace_depth: &mut usize,
) -> DartScanTransition {
    if source[index..].starts_with(b"//") {
        return DartScanTransition::ContinueAt(skip_dart_line_comment(source, index + 2));
    }
    if source[index..].starts_with(b"/*") {
        return DartScanTransition::ContinueAt(skip_dart_block_comment(source, index + 2));
    }
    if matches!(source[index], b'\'' | b'"') {
        return DartScanTransition::ContinueAt(scan_dart_string(source, output, index));
    }
    if let Some(transition) = dart_brace_transition(
        source[index],
        output,
        index,
        copy,
        stop_at_closing_brace,
        brace_depth,
    ) {
        return transition;
    }
    if copy {
        output[index] = source[index];
    }
    DartScanTransition::ContinueAt(index + 1)
}

fn skip_dart_line_comment(source: &[u8], mut index: usize) -> usize {
    while index < source.len() && source[index] != b'\n' {
        index += 1;
    }
    index
}

fn skip_dart_block_comment(source: &[u8], mut index: usize) -> usize {
    let mut depth = 1usize;
    while index < source.len() && depth > 0 {
        if source[index..].starts_with(b"/*") {
            depth += 1;
            index += 2;
        } else if source[index..].starts_with(b"*/") {
            depth -= 1;
            index += 2;
        } else {
            index += 1;
        }
    }
    index
}

fn dart_brace_transition(
    byte: u8,
    output: &mut [u8],
    index: usize,
    copy: bool,
    stop_at_closing_brace: bool,
    brace_depth: &mut usize,
) -> Option<DartScanTransition> {
    if !stop_at_closing_brace {
        return None;
    }
    match byte {
        b'{' => {
            *brace_depth += 1;
            None
        }
        b'}' => {
            if copy {
                output[index] = byte;
            }
            if *brace_depth == 0 {
                Some(DartScanTransition::CompleteAt(index + 1))
            } else {
                *brace_depth -= 1;
                Some(DartScanTransition::ContinueAt(index + 1))
            }
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct DartStringState {
    delimiter: u8,
    delimiter_width: usize,
    raw: bool,
}

impl DartStringState {
    fn at(source: &[u8], quote: usize) -> Self {
        let delimiter = source[quote];
        Self {
            delimiter,
            delimiter_width: dart_string_delimiter_width(source, quote, delimiter),
            raw: is_raw_dart_string(source, quote),
        }
    }

    fn closes_at(self, source: &[u8], index: usize) -> bool {
        source[index] == self.delimiter
            && (self.delimiter_width == 1
                || (source.get(index + 1) == Some(&self.delimiter)
                    && source.get(index + 2) == Some(&self.delimiter)))
    }
}

fn dart_string_delimiter_width(source: &[u8], quote: usize, delimiter: u8) -> usize {
    if source.get(quote + 1) == Some(&delimiter) && source.get(quote + 2) == Some(&delimiter) {
        3
    } else {
        1
    }
}

fn is_raw_dart_string(source: &[u8], quote: usize) -> bool {
    quote > 0
        && matches!(source[quote - 1], b'r' | b'R')
        && (quote == 1 || !(source[quote - 2].is_ascii_alphanumeric() || source[quote - 2] == b'_'))
}

fn scan_dart_string(source: &[u8], output: &mut [u8], quote: usize) -> usize {
    let state = DartStringState::at(source, quote);
    output[quote..quote + state.delimiter_width].fill(b' ');
    let mut index = quote + state.delimiter_width;
    while index < source.len() {
        match dart_string_transition(source, output, index, state) {
            DartScanTransition::ContinueAt(next) => index = next,
            DartScanTransition::CompleteAt(end) => return end,
        }
    }
    index
}

fn dart_string_transition(
    source: &[u8],
    output: &mut [u8],
    index: usize,
    state: DartStringState,
) -> DartScanTransition {
    if !state.raw && source[index] == b'\\' {
        let end = (index + 2).min(source.len());
        for byte in &mut output[index..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        return DartScanTransition::ContinueAt(end);
    }
    if state.closes_at(source, index) {
        output[index..index + state.delimiter_width].fill(b' ');
        return DartScanTransition::CompleteAt(index + state.delimiter_width);
    }
    if !state.raw && source[index..].starts_with(b"${") {
        output[index] = b'$';
        output[index + 1] = b'{';
        let next = scan_dart_code(source, output, index + 2, true, true);
        return DartScanTransition::ContinueAt(next);
    }
    if source[index] != b'\n' {
        output[index] = b' ';
    }
    DartScanTransition::ContinueAt(index + 1)
}

#[derive(Debug)]
struct Assertion {
    start: usize,
    line: usize,
    end_line: usize,
    target: Option<String>,
    guaranteed: bool,
}

#[derive(Clone, Copy)]
struct AssertionCandidate {
    marker: usize,
    operand_end: usize,
}

fn assertions(source: &str) -> Vec<Assertion> {
    let bytes = source.as_bytes();
    bytes
        .iter()
        .enumerate()
        .filter_map(|(index, _)| assertion_candidate(bytes, index))
        .map(|candidate| qualify_assertion(source, candidate))
        .collect()
}

fn assertion_candidate(bytes: &[u8], marker: usize) -> Option<AssertionCandidate> {
    if bytes[marker] != b'!' {
        return None;
    }
    let operand_end = skip_horizontal_whitespace_backward(bytes, marker);
    if operand_end == 0 || !can_end_assertion_operand(bytes[operand_end - 1]) {
        return None;
    }
    let after = skip_horizontal_whitespace_forward(bytes, marker + 1);
    can_follow_assertion(bytes.get(after)).then_some(AssertionCandidate {
        marker,
        operand_end,
    })
}

fn skip_horizontal_whitespace_backward(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t') {
        cursor -= 1;
    }
    cursor
}

fn skip_horizontal_whitespace_forward(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
        cursor += 1;
    }
    cursor
}

fn can_end_assertion_operand(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'_'
            | b')'
            | b']'
            | 0x80..=0xff
    )
}

fn can_follow_assertion(byte: Option<&u8>) -> bool {
    matches!(byte, Some(b'.' | b';' | b')' | b']'))
}

fn qualify_assertion(source: &str, candidate: AssertionCandidate) -> Assertion {
    let operand_start = postfix_operand_start(source, candidate.operand_end);
    let operand = source[operand_start..candidate.operand_end].trim();
    Assertion {
        start: candidate.marker,
        line: line_at(source, operand_start),
        end_line: line_at(source, candidate.marker),
        target: SIMPLE_TARGET.is_match(operand).then(|| operand.to_owned()),
        guaranteed: WHOLE_MATCH.is_match(operand),
    }
}

fn postfix_operand_start(source: &str, before: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = skip_whitespace_backward(bytes, before);
    while let Some(suffix) = consume_postfix_component(source, &mut cursor) {
        let component_start = cursor;
        cursor = skip_whitespace_backward(bytes, cursor);
        if consume_member_separator(bytes, &mut cursor) {
            continue;
        }
        if suffix && previous_byte_can_end_operand(bytes, cursor) {
            continue;
        }
        return component_start;
    }
    cursor
}

fn consume_postfix_component(source: &str, cursor: &mut usize) -> Option<bool> {
    let bytes = source.as_bytes();
    match bytes.get(cursor.wrapping_sub(1)) {
        Some(b']') => consume_balanced_suffix(bytes, cursor, b'[', b']'),
        Some(b')') => consume_balanced_suffix(bytes, cursor, b'(', b')'),
        Some(byte) if is_identifier_byte(*byte) => {
            consume_identifier_backward(source, cursor);
            Some(false)
        }
        _ => None,
    }
}

fn consume_balanced_suffix(
    bytes: &[u8],
    cursor: &mut usize,
    opening: u8,
    closing: u8,
) -> Option<bool> {
    *cursor = matching_open_backward(bytes, *cursor - 1, opening, closing)?;
    Some(true)
}

fn consume_identifier_backward(source: &str, cursor: &mut usize) {
    let bytes = source.as_bytes();
    *cursor -= 1;
    while *cursor > 0 && is_identifier_byte(bytes[*cursor - 1]) {
        *cursor -= 1;
    }
    while !source.is_char_boundary(*cursor) {
        *cursor -= 1;
    }
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

fn skip_whitespace_backward(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    cursor
}

fn consume_member_separator(bytes: &[u8], cursor: &mut usize) -> bool {
    if *cursor == 0 || bytes[*cursor - 1] != b'.' {
        return false;
    }
    *cursor -= 1;
    if *cursor > 0 && bytes[*cursor - 1] == b'?' {
        *cursor -= 1;
    }
    *cursor = skip_whitespace_backward(bytes, *cursor);
    true
}

fn previous_byte_can_end_operand(bytes: &[u8], cursor: usize) -> bool {
    cursor > 0
        && (is_identifier_byte(bytes[cursor - 1]) || matches!(bytes[cursor - 1], b')' | b']'))
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

fn key_proven_by_iteration(source: &str, assertion: usize, target: &str) -> bool {
    let Some(lookup) = MAP_LOOKUP.captures(target) else {
        return false;
    };
    let map = lookup.name("map").unwrap().as_str();
    let key = lookup.name("key").unwrap().as_str();
    let expected = Regex::new(&format!(
        r"\bfor\s*\([^;{{}}]*\b{}\s+in\s+{}\.keys(?:\.toList\(\)\.\.sort\(\))?\s*\)",
        regex::escape(key),
        regex::escape(map)
    ))
    .unwrap();
    let incomplete = FOR_START
        .find_iter(&source[..assertion])
        .filter(|matched| {
            let open = matched.end() - 1;
            matching_delimiter(source, open, b'(', b')').is_some_and(|close| close >= assertion)
        })
        .max_by_key(|matched| matched.start());
    if incomplete.is_some() {
        return false;
    }
    let nearest = FOR_HEADER
        .find_iter(&source[..assertion])
        .filter(|matched| {
            let after = skip_whitespace(source, matched.end());
            if source.as_bytes().get(after) == Some(&b'{') {
                matching_delimiter(source, after, b'{', b'}').is_some_and(|end| assertion < end)
            } else {
                !source[matched.end()..assertion].contains([';', '}'])
            }
        })
        .max_by_key(|matched| matched.start());
    nearest.is_some_and(|matched| expected.is_match(matched.as_str()))
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
    parent_block: Option<usize>,
}

fn parse_if_regions(source: &str) -> Vec<IfRegion> {
    let mut regions = Vec::new();
    for matched in IF_START.find_iter(source) {
        let open = matched.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        let statement_start = skip_whitespace(source, close + 1);
        if source[statement_start..].starts_with("...") {
            continue;
        }
        let Some((then_start, then_end, then_exits)) = statement_range(source, close + 1) else {
            continue;
        };
        let after_then = skip_whitespace(source, then_end);
        let mut else_range = None;
        let mut else_exits = false;
        let mut end = then_end;
        if source[after_then..].starts_with("else")
            && is_keyword_boundary(source, after_then, after_then + 4)
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
            parent_block: enclosing_braces(source, matched.start()).last().copied(),
        });
    }
    regions
}

fn statement_range(source: &str, offset: usize) -> Option<(usize, usize, bool)> {
    let start = skip_whitespace(source, offset);
    if source.as_bytes().get(start) == Some(&b'{') {
        let close = matching_delimiter(source, start, b'{', b'}')?;
        let body = &source[start + 1..close];
        return Some((start, close + 1, block_always_exits(body)));
    }
    let end = statement_end(source, start)?;
    let statement = source[start..end].trim_start();
    Some((start, end, statement_always_exits(statement)))
}

fn statement_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut round = 0usize;
    let mut square = 0usize;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => round += 1,
            b')' => round = round.saturating_sub(1),
            b'[' => square += 1,
            b']' => square = square.saturating_sub(1),
            b';' if round == 0 && square == 0 => return Some(index + 1),
            _ => {}
        }
        index += 1;
    }
    None
}

fn block_always_exits(body: &str) -> bool {
    let trimmed = body.trim_end();
    let start = trimmed
        .rfind([';', '}'])
        .map_or(0, |delimiter| delimiter.saturating_add(1));
    statement_always_exits(trimmed[start..].trim_start()) || EXITING_STATEMENT_END.is_match(trimmed)
}

fn statement_always_exits(statement: &str) -> bool {
    EXITING_STATEMENT_START.is_match(statement)
}

#[derive(Clone, Copy)]
struct ProofConstraint<'a> {
    condition: &'a str,
    expected: bool,
}

struct ProofQualification {
    assertion: usize,
    scope_start: usize,
    last_write: usize,
    assertion_blocks: Vec<usize>,
}

impl ProofQualification {
    fn at(source: &str, assertion: usize, target: &str) -> Self {
        let scope_start = source[..assertion]
            .rfind("=>")
            .filter(|arrow| !source[arrow + 2..assertion].contains([';', '}']))
            .map_or(0, |arrow| arrow + 2);
        Self {
            assertion,
            scope_start,
            last_write: last_write_before(source, assertion, target),
            assertion_blocks: enclosing_braces(source, assertion),
        }
    }

    fn includes(&self, region: &IfRegion) -> bool {
        region.start >= self.scope_start
    }

    fn completed_guard_applies(&self, region: &IfRegion) -> bool {
        region.end <= self.assertion
            && region.start > self.last_write
            && region
                .parent_block
                .is_some_and(|block| self.assertion_blocks.contains(&block))
    }
}

fn proven_non_null(
    source: &str,
    assertion: usize,
    target: &str,
    if_regions: &[IfRegion],
    getters: &BTreeMap<String, String>,
) -> bool {
    if !SIMPLE_TARGET.is_match(target) {
        return false;
    }
    let qualification = ProofQualification::at(source, assertion, target);
    let mut constraints = region_proof_constraints(if_regions, assertion, &qualification);
    constraints.extend(line_expression_constraints(source, assertion));
    constraints_prove_non_null(&constraints, target, getters)
}

fn region_proof_constraints<'a>(
    if_regions: &'a [IfRegion],
    assertion: usize,
    qualification: &ProofQualification,
) -> Vec<ProofConstraint<'a>> {
    let mut constraints = Vec::new();
    for region in if_regions {
        if !qualification.includes(region) {
            continue;
        }
        constraints.extend(active_branch_constraint(region, assertion));
        constraints.extend(completed_guard_constraint(region, qualification));
    }
    constraints
}

fn active_branch_constraint(region: &IfRegion, assertion: usize) -> Option<ProofConstraint<'_>> {
    if contains(region.then_range, assertion) {
        Some(ProofConstraint {
            condition: &region.condition,
            expected: true,
        })
    } else if region
        .else_range
        .is_some_and(|range| contains(range, assertion))
    {
        Some(ProofConstraint {
            condition: &region.condition,
            expected: false,
        })
    } else {
        None
    }
}

fn completed_guard_constraint<'a>(
    region: &'a IfRegion,
    qualification: &ProofQualification,
) -> Option<ProofConstraint<'a>> {
    if !qualification.completed_guard_applies(region) {
        return None;
    }
    match (region.then_exits, region.else_exits) {
        (true, false) => Some(ProofConstraint {
            condition: &region.condition,
            expected: false,
        }),
        (false, true) => Some(ProofConstraint {
            condition: &region.condition,
            expected: true,
        }),
        _ => None,
    }
}

fn constraints_prove_non_null(
    constraints: &[ProofConstraint<'_>],
    target: &str,
    getters: &BTreeMap<String, String>,
) -> bool {
    if constraints.is_empty() {
        return false;
    }
    let expressions = constraints
        .iter()
        .map(|constraint| {
            (
                parse_condition(constraint.condition, target, getters, &mut BTreeSet::new()),
                constraint.expected,
            )
        })
        .collect::<Vec<_>>();
    let atoms = expressions
        .iter()
        .flat_map(|(expression, _)| expression.atoms())
        .collect::<BTreeSet<_>>();
    if atoms.len() > 12 {
        return false;
    }
    let atom_list = atoms.into_iter().collect::<Vec<_>>();
    for mask in 0..(1usize << atom_list.len()) {
        let assignment = atom_list
            .iter()
            .enumerate()
            .map(|(index, atom)| (atom.as_str(), mask & (1 << index) != 0))
            .collect::<BTreeMap<_, _>>();
        if expressions
            .iter()
            .all(|(expression, expected)| expression.evaluate(&assignment) == *expected)
        {
            return false;
        }
    }
    true
}

fn line_expression_constraints(source: &str, assertion: usize) -> Vec<ProofConstraint<'_>> {
    let statement_start = statement_floor(source, assertion);
    let prefix = &source[statement_start..assertion];
    let mut constraints = Vec::new();

    if let Some((condition, expected)) = ternary_branch_constraint(prefix) {
        constraints.push(ProofConstraint {
            condition,
            expected,
        });
    }

    if let Some((operator, index)) = last_boolean_operator(prefix) {
        let condition = expression_tail(&prefix[..index]);
        if !condition.is_empty() {
            constraints.push(ProofConstraint {
                condition,
                expected: operator == "&&",
            });
        }
    }
    constraints
}

fn ternary_branch_constraint(prefix: &str) -> Option<(&str, bool)> {
    let bytes = prefix.as_bytes();
    let mut depths = [0usize; 3];
    let mut question = None;
    let mut colon_after_question = false;
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'[' => depths[1] += 1,
            b']' => depths[1] = depths[1].saturating_sub(1),
            b'{' => depths[2] += 1,
            b'}' => depths[2] = depths[2].saturating_sub(1),
            b'?' if bytes.get(index.wrapping_sub(1)) != Some(&b'?')
                && bytes.get(index + 1) != Some(&b'?')
                && bytes.get(index + 1) != Some(&b'.') =>
            {
                question = Some((index, depths));
                colon_after_question = false;
            }
            b':' if question.is_some_and(|(_, question_depths)| question_depths == depths) => {
                colon_after_question = true;
            }
            _ => {}
        }
    }
    let (question, _) = question?;
    let condition = expression_tail(&prefix[..question]);
    (!condition.is_empty()).then_some((condition, !colon_after_question))
}

fn last_boolean_operator(prefix: &str) -> Option<(&'static str, usize)> {
    let bytes = prefix.as_bytes();
    let mut depth = 0usize;
    let mut operator_depth = None;
    let mut result = None;
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        match bytes[index] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'&' if bytes[index + 1] == b'&' => {
                if operator_depth.is_none_or(|current| depth <= current) {
                    operator_depth = Some(depth);
                    result = Some(("&&", index));
                }
                index += 1;
            }
            b'|' if bytes[index + 1] == b'|' => {
                if operator_depth.is_none_or(|current| depth <= current) {
                    operator_depth = Some(depth);
                    result = Some(("||", index));
                }
                index += 1;
            }
            _ => {}
        }
        index += 1;
    }
    result
}

fn lexically_proven_non_null(source: &str, assertion: usize, target: &str) -> bool {
    let floor = statement_floor(source, assertion);
    let prefix = &source[floor..assertion];
    for (comparison, operator) in [(r"!=\s*null", "&&"), (r"==\s*null", "||")] {
        let Ok(guard) = Regex::new(&format!(r"\b{}\s*{}", regex::escape(target), comparison))
        else {
            return false;
        };
        if let Some(matched) = guard.find_iter(prefix).last()
            && last_boolean_operator(&prefix[matched.end()..])
                .is_some_and(|(last, _)| last == operator)
        {
            return true;
        }
    }
    let Ok(null_guard) = Regex::new(&format!(r"\b{}\s*==\s*null", regex::escape(target))) else {
        return false;
    };
    null_guard.find_iter(prefix).last().is_some_and(|matched| {
        let suffix = &prefix[matched.end()..];
        suffix
            .find('?')
            .zip(suffix.rfind(':'))
            .is_some_and(|(question, colon)| question < colon)
    })
}

fn statement_floor(source: &str, offset: usize) -> usize {
    let bytes = source.as_bytes();
    let delimiter = (0..offset).rev().find(|index| {
        matches!(bytes[*index], b';' | b',' | b'}')
            || bytes[*index] == b'{' && bytes.get(index.wrapping_sub(1)) != Some(&b'$')
    });
    delimiter
        .map(|index| index + 1)
        .into_iter()
        .chain(source[..offset].rfind("=>").map(|index| index + 2))
        .max()
        .unwrap_or(0)
}

fn expression_tail(source: &str) -> &str {
    let mut start = 0usize;
    for delimiter in ["=>", "return ", ";", "{"] {
        if let Some(index) = source.rfind(delimiter) {
            start = start.max(index + delimiter.len());
        }
    }
    let bytes = source.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] == b'='
            && !matches!(
                bytes.get(index.wrapping_sub(1)),
                Some(b'=' | b'!' | b'<' | b'>')
            )
            && !matches!(bytes.get(index + 1), Some(b'=' | b'>'))
        {
            start = start.max(index + 1);
        }
    }
    let expression = source[start..].trim();
    ["if", "while"]
        .iter()
        .find_map(|keyword| {
            expression
                .strip_prefix(keyword)?
                .trim_start()
                .strip_prefix('(')
        })
        .map_or(expression, str::trim)
}

fn last_write_before(source: &str, assertion: usize, target: &str) -> usize {
    let pattern = Regex::new(&format!(
        r"(?:^|[^=!<>])\b{}\s*(?:=|\+\+|--|\?\?=)",
        regex::escape(target)
    ))
    .unwrap();
    pattern
        .find_iter(&source[..assertion])
        .filter(|matched| {
            source.as_bytes().get(matched.end()) != Some(&b'=')
                || !matched.as_str().trim_end().ends_with('=')
        })
        .map(|matched| matched.start())
        .max()
        .unwrap_or(0)
}

fn getter_conditions(source: &str) -> BTreeMap<String, String> {
    let mut getters = BTreeMap::new();
    for captures in EXPRESSION_GETTER.captures_iter(source) {
        getters.insert(
            captures.get(1).unwrap().as_str().to_owned(),
            captures.get(2).unwrap().as_str().trim().to_owned(),
        );
    }
    for captures in BLOCK_GETTER.captures_iter(source) {
        getters.insert(
            captures.get(1).unwrap().as_str().to_owned(),
            captures.get(2).unwrap().as_str().trim().to_owned(),
        );
    }
    getters
}

fn getter_conditions_at(source: &str, offset: usize) -> BTreeMap<String, String> {
    CLASS_START
        .find_iter(&source[..offset])
        .filter_map(|matched| {
            let open = matched.end() - 1;
            let close = matching_delimiter(source, open, b'{', b'}')?;
            (offset < close).then_some((open, close))
        })
        .max_by_key(|(open, _)| *open)
        .map_or_else(BTreeMap::new, |(open, close)| {
            getter_conditions(&source[open + 1..close])
        })
}

#[derive(Clone, Debug)]
enum BoolExpr {
    Known(bool),
    Atom(String),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

impl BoolExpr {
    fn atoms(&self) -> Vec<String> {
        match self {
            Self::Known(_) => Vec::new(),
            Self::Atom(atom) => vec![atom.clone()],
            Self::Not(inner) => inner.atoms(),
            Self::And(left, right) | Self::Or(left, right) => {
                let mut atoms = left.atoms();
                atoms.extend(right.atoms());
                atoms
            }
        }
    }

    fn evaluate(&self, assignment: &BTreeMap<&str, bool>) -> bool {
        match self {
            Self::Known(value) => *value,
            Self::Atom(atom) => assignment[atom.as_str()],
            Self::Not(inner) => !inner.evaluate(assignment),
            Self::And(left, right) => left.evaluate(assignment) && right.evaluate(assignment),
            Self::Or(left, right) => left.evaluate(assignment) || right.evaluate(assignment),
        }
    }
}

fn parse_condition(
    source: &str,
    target: &str,
    getters: &BTreeMap<String, String>,
    expanding: &mut BTreeSet<String>,
) -> BoolExpr {
    let source = strip_outer_parentheses(source.trim());
    if let Some(index) = top_level_operator(source, "||") {
        return BoolExpr::Or(
            Box::new(parse_condition(
                &source[..index],
                target,
                getters,
                expanding,
            )),
            Box::new(parse_condition(
                &source[index + 2..],
                target,
                getters,
                expanding,
            )),
        );
    }
    if let Some(index) = top_level_operator(source, "&&") {
        return BoolExpr::And(
            Box::new(parse_condition(
                &source[..index],
                target,
                getters,
                expanding,
            )),
            Box::new(parse_condition(
                &source[index + 2..],
                target,
                getters,
                expanding,
            )),
        );
    }
    if let Some(operand) = source.strip_prefix('!') {
        return BoolExpr::Not(Box::new(parse_condition(
            operand, target, getters, expanding,
        )));
    }

    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if compact == format!("{target}==null") || compact == format!("null=={target}") {
        return BoolExpr::Known(true);
    }
    if compact == format!("{target}!=null") || compact == format!("null!={target}") {
        return BoolExpr::Known(false);
    }
    if let Some(lookup) = MAP_LOOKUP.captures(target) {
        let presence = format!(
            "{}.containsKey({})",
            lookup.name("map").unwrap().as_str(),
            lookup.name("key").unwrap().as_str()
        );
        if compact == presence {
            return BoolExpr::Known(false);
        }
    }
    if compact == "true" {
        return BoolExpr::Known(true);
    }
    if compact == "false" {
        return BoolExpr::Known(false);
    }
    if let Some(getter) = getters.get(source)
        && expanding.insert(source.to_owned())
    {
        let expression = parse_condition(getter, target, getters, expanding);
        expanding.remove(source);
        return expression;
    }
    BoolExpr::Atom(source.to_owned())
}

fn strip_outer_parentheses(mut source: &str) -> &str {
    loop {
        if !source.starts_with('(') || !source.ends_with(')') {
            return source;
        }
        if matching_delimiter(source, 0, b'(', b')') != Some(source.len() - 1) {
            return source;
        }
        source = source[1..source.len() - 1].trim();
    }
}

fn top_level_operator(source: &str, operator: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let operator = operator.as_bytes();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index + operator.len() <= bytes.len() {
        match bytes[index] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            _ if depth == 0 && bytes[index..].starts_with(operator) => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

fn enclosing_braces(source: &str, offset: usize) -> Vec<usize> {
    let mut stack = Vec::new();
    for (index, byte) in source.as_bytes()[..offset].iter().enumerate() {
        if *byte == b'{' {
            stack.push(index);
        } else if *byte == b'}' {
            stack.pop();
        }
    }
    stack
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

fn is_keyword_boundary(source: &str, start: usize, end: usize) -> bool {
    let identifier = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_';
    source
        .as_bytes()
        .get(start.wrapping_sub(1))
        .is_none_or(|byte| !identifier(byte))
        && source
            .as_bytes()
            .get(end)
            .is_none_or(|byte| !identifier(byte))
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding(path: &str, line: usize, end_line: usize) -> Finding {
    let metadata = rule_catalog::metadata("dart-null-assertion")
        .expect("Dart null assertion metadata must exist");
    Finding {
        code: "dart-null-assertion".to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart null assertion severity must be valid"),
        path: path.to_owned(),
        line,
        end_line,
        message: "null assertion used".to_owned(),
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static WHOLE_MATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\?\.|\.)group\s*\(\s*0\s*\)$").unwrap()
});
static MAP_LOOKUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<map>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\[(?P<key>[A-Za-z_]\w*)\]$").unwrap()
});
static SIMPLE_TARGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[^\]]+\])*$").unwrap());
static IF_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bif\s*\(").unwrap());
static FOR_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfor\s*\([^{}]*\)").unwrap());
static FOR_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfor\s*\(").unwrap());
static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+[A-Za-z_]\w*[^{;]*\{").unwrap());
static EXITING_STATEMENT_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:return\b|break(?:\s+\w+)?\s*;|continue(?:\s+\w+)?\s*;|throw\b)").unwrap()
});
static EXITING_STATEMENT_END: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:return\b[^;]*;|break(?:\s+\w+)?\s*;|continue(?:\s+\w+)?\s*;|throw\b[^;]*;)\s*$")
        .unwrap()
});
static EXPRESSION_GETTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:bool\s+)?get\s+([A-Za-z_]\w*)\s*=>\s*([^;]+);").unwrap());
static BLOCK_GETTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\b(?:bool\s+)?get\s+([A-Za-z_]\w*)\s*\{\s*return\s+([^;]+);\s*\}").unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn reports_unsafe_assertions_but_accepts_whole_match_access() {
        let fixture = Fixture::new([(
            "lib/matches.dart",
            "String unsafe(String? value) => value!;\nString whole(Match match) => match.group(0)!;\nString optionalWhole(Match? match) => match?.group(0)!;\nString capture(Match match) => match.group(1)!;\nbool check(String? value) => value != null;\nbool absent(String? value) => value == null || !value.isEmpty;",
        )]);

        assert_eq!(lines(&fixture), vec![1, 4]);
    }

    #[test]
    fn accepts_map_lookups_while_iterating_matching_keys() {
        let fixture = Fixture::new([(
            "lib/null_assertions.dart",
            "String unsafe(Map<String, String> values, String key) => values[key]!;\nList<int> safe(Map<String, String> values) {\n  final output = <int>[];\n  for (final key in values.keys.toList()..sort()) {\n    output.add(values[key]!.length);\n  }\n  return <int>[\n    for (final key in values.keys) values[key]!.length,\n  ];\n}",
        )]);

        assert_eq!(lines(&fixture), vec![1]);
    }

    #[test]
    fn accepts_matching_presence_guards_only() {
        let fixture = Fixture::new([(
            "lib/config.dart",
            "String? guarded(Map<String, String> values, String key, String other) {\n  if (!values.containsKey(key)) return null;\n  final String found = values[key]!;\n  if (values.containsKey(other)) return found + values[key]!;\n  return found + values[other]!;\n}",
        )]);

        assert_eq!(lines(&fixture), vec![5]);
    }

    #[test]
    fn recognizes_local_flow_guards_and_getter_conditions() {
        let fixture = Fixture::new([(
            "lib/null_assertions.dart",
            "class Gesture {\n  (int, int)? _start;\n  bool _cancelled = false;\n\n  bool get active => _start != null && !_cancelled;\n\n  int preview() {\n    if (!active) return 0;\n    return _start!.$1;\n  }\n\n  int unsafePreview() => _start!.$1;\n}\n\nString guardedBranch(String? item, bool erase) {\n  if (item == null && !erase) return 'none';\n  final behavior = erase ? 'erase' : item!.toUpperCase();\n  if (behavior == 'paint' && !erase) return item!;\n  return behavior;\n}\n\nvoid immediateGuard(Holder holder) {\n  if (holder.value != null) consume(holder.value!);\n}\n\nString incompleteGuard(String? value, bool enabled) {\n  if (value == null && enabled) return 'none';\n  return value!;\n}\n\nString invalidatedGuard(String? value) {\n  if (value == null) return 'none';\n  value = null;\n  return value!;\n}",
        )]);

        assert_eq!(lines(&fixture), vec![12, 28, 34]);
    }

    #[test]
    fn accepts_multiline_property_short_circuit_guards() {
        let source = "void visit(Field field) {\n  if (!field.isStatic &&\n      field.getter != null &&\n      (field.getter!.isAbstract || !field.getter!.isOriginDeclaration)) {\n    use(field);\n  }\n}";
        let assertion = source.find("field.getter!").unwrap() + "field.getter".len();
        assert!(lexically_proven_non_null(source, assertion, "field.getter"));
        let fixture = Fixture::new([("lib/guard.dart", source)]);
        assert!(lines(&fixture).is_empty());
    }

    #[test]
    fn applies_getter_guards_across_repeated_conditions() {
        let source = "class Field {\n  Element element;\n  bool get isSerializable =>\n      element.getter != null && element.getter!.isAbstract;\n  void validate() {\n    if (isSerializable && element.getter!.returnType.isFunction) return;\n    if (isSerializable &&\n        element.getter!.returnType.isRecord) return;\n  }\n}";
        let fixture = Fixture::new([("lib/field.dart", source)]);
        assert!(lines(&fixture).is_empty());
    }

    #[test]
    fn uses_short_circuit_conditions_for_right_hand_assertions() {
        let fixture = Fixture::new([(
            "lib/short_circuit.dart",
            "bool safe(String? value) => value != null && value!.isNotEmpty;\nbool safeMulti(Holder guard) {\n  final bool exits = guard.value != null &&\n      use(guard.value!);\n  return exits;\n}\nbool unsafe(String? value, bool enabled) => enabled && value!.isNotEmpty;",
        )]);

        assert_eq!(lines(&fixture), vec![7]);
    }

    #[test]
    fn accepts_multiline_short_circuit_in_nested_calls() {
        let source = "void analyze(IfStatement guard) {\n  final bool thenExits = alwaysExits(guard.thenStatement);\n  final bool elseExits =\n      guard.elseStatement != null &&\n      alwaysExits(guard.elseStatement!);\n}";
        let fixture = Fixture::new([("lib/analyzer.dart", source)]);

        assert!(lines(&fixture).is_empty());
    }

    #[test]
    fn accepts_multiline_ternary_and_interpolation_guards() {
        let fixture = Fixture::new([(
            "lib/ternaries.dart",
            r#"String render(String? value, String? other) {
  final direct = value != null
      ? value!.length
      : 0;
  final inverse = value == null
      ? 0
      : value!.length;
  final nested = value == null
      ? other == null
          ? 0
          : other!.length
      : value!.length;
  final text =
      '${value != null ? value!.length : 0} ${other != null ? other!.length : 0}';
  if (other == null) return text;
  return '$text ${other!.length}';
}
int unsafe(String? value) => value!.length;"#,
        )]);

        assert_eq!(lines(&fixture), vec![18]);
    }

    #[test]
    fn handles_interpolation_guards_without_crossing_argument_boundaries() {
        let fixture = Fixture::new([(
            "lib/interpolation.dart",
            "bool safe(File? workspace) {\n  return workspace != null &&\n      File('${workspace!.path}.requested').existsSync();\n}\n\nvoid unsafe(File? workspace) {\n  assert(\n    workspace == null || workspace.path.isEmpty,\n    'invalid ${workspace!.path}',\n  );\n}",
        )]);

        assert_eq!(lines(&fixture), vec![9]);
    }

    #[test]
    fn finds_the_start_of_nested_postfix_chains() {
        let source = "préfixe?.items[index](argument).name";

        assert_eq!(postfix_operand_start(source, source.len()), 0);
        assert!(source.is_char_boundary(postfix_operand_start(source, source.len())));
    }

    fn lines(fixture: &Fixture) -> Vec<usize> {
        analyze(&fixture.context())
            .into_iter()
            .map(|finding| finding.line)
            .collect()
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
