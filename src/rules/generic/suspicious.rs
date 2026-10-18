#[derive(Clone, Copy)]
enum Marker {
    Todo,
    Fixme,
}

impl Marker {
    fn code(self) -> &'static str {
        match self {
            Self::Todo => "todo-comment",
            Self::Fixme => "fixme-comment",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Todo => "TODO marker left in source",
            Self::Fixme => "FIXME marker left in source",
        }
    }

    fn pattern(self) -> &'static Regex {
        match self {
            Self::Todo => &TODO_MARKER,
            Self::Fixme => &FIXME_MARKER,
        }
    }
}

fn comment_markers(
    sources: &BTreeMap<String, String>,
    todo_enabled: bool,
    fixme_enabled: bool,
) -> (Vec<Finding>, Vec<Finding>) {
    let mut todo_findings = Vec::new();
    let mut fixme_findings = Vec::new();
    for (path, source) in sources {
        let syntax = CommentSyntax::for_path(path);
        let mut state = CommentState::default();
        for (index, line) in source.split('\n').enumerate() {
            let comments = extract_comments(line, syntax, &mut state);
            if todo_enabled && Marker::Todo.pattern().is_match(&comments) {
                todo_findings.push(finding(
                    Marker::Todo.code(),
                    path,
                    index + 1,
                    Marker::Todo.message(),
                    "high",
                ));
            }
            if fixme_enabled && Marker::Fixme.pattern().is_match(&comments) {
                fixme_findings.push(finding(
                    Marker::Fixme.code(),
                    path,
                    index + 1,
                    Marker::Fixme.message(),
                    "high",
                ));
            }
        }
    }
    (todo_findings, fixme_findings)
}

fn operation_on_same_value(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        if !path.ends_with(".css") {
            append_same_value_operations(&mut findings, path, source);
        }
    }
    findings
}

fn append_same_value_operations(findings: &mut Vec<Finding>, path: &str, source: &str) {
    let lines = source.split('\n').collect::<Vec<_>>();
    let mut in_block_comment = false;
    for (index, line) in lines.iter().enumerate() {
        let stripped = strip_generic_strings(line);
        let code = strip_comments(&stripped, &mut in_block_comment);
        let Some(comparison) = same_value_comparison(&code) else {
            continue;
        };
        if excludes_same_value_candidate(&lines, index, &code, comparison) {
            continue;
        }
        findings.push(same_value_finding(path, index + 1, comparison));
    }
}

#[derive(Clone, Copy)]
struct ComparisonCandidate<'a> {
    complete: regex::Match<'a>,
    left: &'a str,
    operator: &'a str,
    right: &'a str,
}

#[derive(Clone, Copy)]
struct SameValueComparison<'a> {
    identifier: &'a str,
    operator: &'a str,
    start: usize,
}

fn same_value_comparison(code: &str) -> Option<SameValueComparison<'_>> {
    COMPARISON
        .captures_iter(code)
        .filter_map(parse_comparison_candidate)
        .find_map(|candidate| normalize_same_value_operands(code, candidate))
}

fn parse_comparison_candidate(
    captures: regex::Captures<'_>,
) -> Option<ComparisonCandidate<'_>> {
    Some(ComparisonCandidate {
        complete: captures.get(0)?,
        left: captures.name("left")?.as_str(),
        operator: captures.name("operator")?.as_str(),
        right: captures.name("right")?.as_str(),
    })
}

fn normalize_same_value_operands<'a>(
    code: &'a str,
    candidate: ComparisonCandidate<'a>,
) -> Option<SameValueComparison<'a>> {
    if candidate.left != candidate.right
        || candidate
            .complete
            .start()
            .checked_sub(1)
            .is_some_and(|index| code.as_bytes()[index] == b'.')
    {
        return None;
    }
    let tail = code[candidate.complete.end()..].trim_start();
    if tail.starts_with('.')
        || tail.starts_with('[')
        || tail.starts_with("->")
        || tail.starts_with("::")
        || continues_right_operand(tail)
    {
        return None;
    }
    Some(SameValueComparison {
        identifier: candidate.left,
        operator: candidate.operator,
        start: candidate.complete.start(),
    })
}
fn continues_right_operand(tail: &str) -> bool {
    let bytes = tail.as_bytes();
    match bytes {
        [b'&', rest @ ..] => rest.first() != Some(&b'&'),
        [b'|', rest @ ..] => rest.first() != Some(&b'|'),
        [b'^' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>', ..] => true,
        _ => false,
    }
}


fn excludes_same_value_candidate(
    lines: &[&str],
    line_index: usize,
    code: &str,
    comparison: SameValueComparison<'_>,
) -> bool {
    excludes_intentional_self_comparison(lines, line_index, comparison)
        || excludes_same_value_context(code, comparison)
}

fn excludes_intentional_self_comparison(
    lines: &[&str],
    line_index: usize,
    comparison: SameValueComparison<'_>,
) -> bool {
    matches!(comparison.operator, "==" | "!=")
        && (has_floating_point_declaration(lines, line_index, comparison.identifier)
            || has_nan_context(lines, line_index)
            || has_following_nan_guard(lines, line_index)
            || has_no_self_compare_directive(lines, line_index)
            || is_nan_ternary_comparison(lines, line_index, comparison.operator))
}

fn excludes_same_value_context(code: &str, comparison: SameValueComparison<'_>) -> bool {
    let prefix = code[..comparison.start].trim_end();
    prefix
        .as_bytes()
        .last()
        .is_some_and(|byte| b"&|^+-*/%!<>.".contains(byte))
        || LEADING_CAST.is_match(prefix)
        || inside_assertion_invocation(code, comparison.start)
}

fn same_value_finding(
    path: &str,
    line: usize,
    comparison: SameValueComparison<'_>,
) -> Finding {
    finding(
        "operation-on-same-value",
        path,
        line,
        &format!(
            "operation compares {} with itself",
            comparison.identifier
        ),
        "high",
    )
}

fn inside_assertion_invocation(source: &str, offset: usize) -> bool {
    let bytes = source.as_bytes();
    let mut index = offset;
    let mut nested_closers = 0;
    while let Some(opening) =
        previous_argument_boundary(bytes, &mut index, &mut nested_closers)
    {
        if invocation_name_before(source, opening).is_some_and(is_assertion_name) {
            return true;
        }
    }
    false
}

fn previous_argument_boundary(
    bytes: &[u8],
    index: &mut usize,
    nested_closers: &mut usize,
) -> Option<usize> {
    while *index > 0 {
        *index -= 1;
        match bytes[*index] {
            b')' => *nested_closers += 1,
            b'(' if *nested_closers > 0 => *nested_closers -= 1,
            b'(' => return Some(*index),
            _ => {}
        }
    }
    None
}

fn invocation_name_before(source: &str, opening: usize) -> Option<&str> {
    let bytes = source.as_bytes();
    let mut end = opening;
    while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_identifier_byte(bytes[start - 1]) {
        start -= 1;
    }
    (start < end).then_some(&source[start..end])
}

fn is_assertion_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "assert"
        || name.starts_with("assert_")
        || name.ends_with("assert")
        || name.contains("_assert_")
        || name == "expect"
        || name.starts_with("expect_")
}

fn has_floating_point_declaration(lines: &[&str], line_index: usize, identifier: &str) -> bool {
    let declaration = Regex::new(&format!(
        r"\b(?:float|double)\s+(?:[*&]\s*)?{}\b",
        regex::escape(identifier)
    ))
    .unwrap();
    let first_line = line_index.saturating_sub(20);
    for index in (first_line..=line_index).rev() {
        let code = strip_generic_strings(lines[index]);
        if declaration.is_match(&code) {
            return true;
        }
        if index != line_index && CLOSING_BRACE_LINE.is_match(&code) {
            break;
        }
    }
    false
}

fn has_nan_context(lines: &[&str], line_index: usize) -> bool {
    for index in (line_index.saturating_sub(2)..=line_index).rev() {
        if NAN_CONTEXT.is_match(&strip_generic_strings(lines[index])) {
            return true;
        }
        if index != line_index && CLOSING_BRACE_LINE.is_match(lines[index]) {
            break;
        }
    }
    false
}

fn has_following_nan_guard(lines: &[&str], line_index: usize) -> bool {
    let last_line = (line_index + 4).min(lines.len().saturating_sub(1));
    (line_index + 1..=last_line).any(|index| FOLLOWING_NAN_GUARD.is_match(lines[index]))
}

fn has_no_self_compare_directive(lines: &[&str], line_index: usize) -> bool {
    line_index > 0 && NO_SELF_COMPARE.is_match(lines[line_index - 1])
}

fn is_nan_ternary_comparison(lines: &[&str], line_index: usize, operator: &str) -> bool {
    let code = strip_generic_strings(lines[line_index]);
    let code = code.trim();
    if operator == "!=" && line_index + 1 < lines.len() {
        let left = trailing_same_value(code, "!=");
        let next = strip_generic_strings(lines[line_index + 1]);
        let right = leading_ternary_same_value(next.trim(), "==");
        return matches!((left, right), (Some(left), Some(right)) if left != right);
    }
    if operator == "==" && line_index > 0 {
        let left = leading_ternary_same_value(code, "==");
        let previous = strip_generic_strings(lines[line_index - 1]);
        let right = trailing_same_value(previous.trim(), "!=");
        return matches!((left, right), (Some(left), Some(right)) if left != right);
    }
    false
}

fn trailing_same_value<'a>(line: &'a str, operator: &str) -> Option<&'a str> {
    let comparison = same_value_comparison(line)?;
    (comparison.operator == operator
        && line[comparison.start..]
            .trim_end()
            .ends_with(comparison.identifier))
    .then_some(comparison.identifier)
}

fn leading_ternary_same_value<'a>(line: &'a str, operator: &str) -> Option<&'a str> {
    if !line.starts_with('?') {
        return None;
    }
    let comparison = same_value_comparison(&line[1..])?;
    (comparison.operator == operator).then_some(comparison.identifier)
}

fn suspicious_command_arguments(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let mut in_block_comment = false;
        for (index, line) in source.split('\n').enumerate() {
            let code = strip_command_comments(line, &mut in_block_comment);
            let Some(call) = COMMAND_CALL.find(&code) else {
                continue;
            };
            let arguments = &code[call.end()..];
            let has_embedded_space = ARGUMENT_LITERAL.captures_iter(arguments).any(|capture| {
                let Some(complete) = capture.get(0) else {
                    return false;
                };
                let Some(literal) = capture
                    .name("double")
                    .or_else(|| capture.name("single"))
                    .map(|literal| literal.as_str())
                else {
                    return false;
                };
                if !literal.chars().any(char::is_whitespace) {
                    return false;
                }
                let preceding = arguments[..complete.start()].trim_end();
                let following = arguments[complete.end()..].trim_start();
                !preceding.ends_with(".split") && !following.starts_with(".split(")
            });
            if has_embedded_space {
                findings.push(finding(
                    "suspicious-command-arg-space",
                    path,
                    index + 1,
                    "command argument appears to contain embedded spaces",
                    "medium",
                ));
            }
        }
    }
    findings
}
