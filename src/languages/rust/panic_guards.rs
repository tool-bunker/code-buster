//! Conservative local proofs for panic-prone Rust method calls.

use std::sync::LazyLock;

use regex::Regex;

static CONST_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bconst\s+([A-Za-z_]\w*)\s*:").unwrap());
static USE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\buse\s+[^;]+;").unwrap());
static MODULE_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bmod\s+[A-Za-z_]\w*\s*\{").unwrap());
static LET_SOME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*let\s+Some\s*\(").unwrap());

pub(super) fn locally_proven_invariant(source: &str, masked: &str, call_offset: usize) -> bool {
    if source.len() != masked.len() || call_offset > masked.len() {
        return false;
    }

    let Some(unwrap_dot) = unwrap_chain_dot(masked, call_offset) else {
        return false;
    };

    if option_guarded(source, masked, unwrap_dot)
        || assigned_some_is_invariant(masked, unwrap_dot)
        || cstring_literal_construction(source, masked, unwrap_dot)
    {
        return true;
    }

    let Some(access) = presence_preserving_access(masked, unwrap_dot) else {
        return false;
    };

    iterator_next_is_invariant(masked, &access)
        || containment_position_guarded(source, masked, &access)
        || option_access_short_circuit_guarded(source, masked, &access)
        || collection_access_guarded(source, masked, &access)
        || access_guarded(source, masked, &access)
}

fn presence_preserving_access(masked: &str, unwrap_dot: usize) -> Option<Call<'_>> {
    let access = call_before(masked, unwrap_dot)?;
    // These Option adapters preserve presence; arbitrary map/and_then callbacks do not.
    if matches!(access.method, "copied" | "cloned") && access.argument(masked).trim().is_empty() {
        call_before(masked, access.dot)
    } else {
        Some(access)
    }
}

fn containment_position_guarded(source: &str, masked: &str, position: &Call<'_>) -> bool {
    if position.method != "position" {
        return false;
    }
    let Some(iterator) = call_before(masked, position.dot) else {
        return false;
    };
    if iterator.method != "iter" || !iterator.argument(masked).trim().is_empty() {
        return false;
    }
    let Some(receiver) = slice_expression(masked, iterator.dot) else {
        return false;
    };
    let Some(needle) = position_literal(source, masked, position) else {
        return false;
    };
    let Some(block_open) = enclosing_block(masked, receiver.0) else {
        return false;
    };
    let Some(condition) = if_condition(masked, block_open) else {
        return false;
    };
    let Some(guard_end) = contains_conjunct(source, masked, condition, receiver, needle.as_str())
    else {
        return false;
    };

    // A later conjunct runs after the proof but before the body. Any reuse of an identifier from
    // the indexed expression may hide mutation through a call, so do not attempt to classify it.
    if expression_identifiers_occur(
        &masked[guard_end..condition.1],
        &masked[receiver.0..receiver.1],
    ) {
        return false;
    }

    // Completed expressions in the body may mutate either the collection or its slice cursor.
    // Within the current expression, ordinary cursor reads are safe, but receiver reuse, method
    // calls, assignments, and mutable borrows are not.
    let body_prefix = &masked[block_open + 1..receiver.0];
    let completed_end = completed_prefix_end(body_prefix);
    !expression_identifiers_occur(
        &body_prefix[..completed_end],
        &masked[receiver.0..receiver.1],
    ) && !current_expression_may_mutate(
        &body_prefix[completed_end..],
        &masked[receiver.0..receiver.1],
    )
}

fn contains_conjunct(
    source: &str,
    masked: &str,
    condition: (usize, usize),
    receiver: (usize, usize),
    needle: &str,
) -> Option<usize> {
    let condition = strip_parentheses(masked, condition);
    let bytes = masked.as_bytes();
    let mut depth = 0usize;
    let mut conjunct_start = condition.0;
    let mut guarded_end = None;
    let mut index = condition.0;
    while index < condition.1 {
        match conjunct_operator(bytes, index, &mut depth) {
            Some(b'|') => return None,
            Some(b'&') => {
                let conjunct = trim_range(masked, conjunct_start, index);
                if exact_contains_guard(source, masked, conjunct, receiver, needle) {
                    guarded_end = Some(index);
                }
                conjunct_start = index + 2;
                index += 2;
            }
            _ => index += 1,
        }
    }
    let conjunct = trim_range(masked, conjunct_start, condition.1);
    if exact_contains_guard(source, masked, conjunct, receiver, needle) {
        guarded_end = Some(condition.1);
    }
    guarded_end
}

fn conjunct_operator(bytes: &[u8], index: usize, depth: &mut usize) -> Option<u8> {
    match bytes[index] {
        b'(' | b'[' | b'{' => *depth += 1,
        b')' | b']' | b'}' => *depth = depth.saturating_sub(1),
        operator @ (b'|' | b'&') if *depth == 0 && bytes.get(index + 1) == Some(&operator) => {
            return Some(operator);
        }
        _ => {}
    }
    None
}

fn exact_contains_guard(
    source: &str,
    masked: &str,
    mut conjunct: (usize, usize),
    receiver: (usize, usize),
    needle: &str,
) -> bool {
    conjunct = strip_parentheses(masked, conjunct);
    let Some(call) = call_before(masked, conjunct.1) else {
        return false;
    };
    if call.close + 1 != conjunct.1 || call.method != "contains" {
        return false;
    }
    let Some(guarded) = slice_expression(masked, call.dot) else {
        return false;
    };
    guarded.0 == conjunct.0
        && same_expression(source, guarded, receiver)
        && referenced_literal(source, masked, &call).is_some_and(|literal| literal == needle)
}

fn position_literal(source: &str, masked: &str, position: &Call<'_>) -> Option<String> {
    let (start, end) = trim_range(source, position.open + 1, position.close);
    if top_level_comma(masked, start, end) {
        return None;
    }
    let argument = source[start..end].trim();
    let closure = argument.strip_prefix('|')?;
    let closure_bar = closure.find('|')?;
    let binding = closure[..closure_bar].trim();
    if binding.is_empty()
        || !is_ident_start(*binding.as_bytes().first()?)
        || !binding.as_bytes().iter().all(is_ident_continue)
    {
        return None;
    }
    let body = closure[closure_bar + 1..].trim();
    let (left, right) = body.split_once("==")?;
    if right.contains("==") || left.trim().strip_prefix('*')?.trim() != binding {
        return None;
    }
    decode_value_literal(right.trim())
}

fn referenced_literal(source: &str, masked: &str, call: &Call<'_>) -> Option<String> {
    let (start, end) = trim_range(source, call.open + 1, call.close);
    if top_level_comma(masked, start, end) {
        return None;
    }
    decode_value_literal(source[start..end].trim().strip_prefix('&')?.trim())
}

fn decode_value_literal(literal: &str) -> Option<String> {
    decode_literal(literal.strip_prefix('b').unwrap_or(literal))
}

fn slice_expression(masked: &str, dot: usize) -> Option<(usize, usize)> {
    let close = previous_nonspace(masked.as_bytes(), dot)?;
    if masked.as_bytes()[close] != b']' {
        return None;
    }
    let open = matching_open(masked.as_bytes(), close, b'[', b']')?;
    let base = simple_receiver(masked, open)?;
    Some((base.start, close + 1))
}

fn same_expression(source: &str, left: (usize, usize), right: (usize, usize)) -> bool {
    source[left.0..left.1]
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .eq(source[right.0..right.1]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace()))
}

fn completed_prefix_end(prefix: &str) -> usize {
    let mut brace_depth = 0usize;
    let mut boundary = 0usize;
    for (index, byte) in prefix.bytes().enumerate() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' if brace_depth > 0 => {
                brace_depth -= 1;
                if brace_depth == 0 {
                    boundary = index + 1;
                }
            }
            b';' if brace_depth == 0 => boundary = index + 1,
            _ => {}
        }
    }
    boundary
}

fn current_expression_may_mutate(prefix: &str, expression: &str) -> bool {
    let mut identifier_start = 0usize;
    let mut first_identifier = true;
    while let Some((start, end)) = next_identifier(expression, identifier_start) {
        if identifier_may_mutate(prefix, &expression[start..end], first_identifier) {
            return true;
        }
        first_identifier = false;
        identifier_start = end;
    }
    false
}

fn next_identifier(expression: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = expression.as_bytes();
    let identifier_start = bytes[start..]
        .iter()
        .position(|byte| is_ident_start(*byte))?
        + start;
    let mut identifier_end = identifier_start + 1;
    while identifier_end < bytes.len() && is_ident_continue(&bytes[identifier_end]) {
        identifier_end += 1;
    }
    Some((identifier_start, identifier_end))
}

fn identifier_may_mutate(prefix: &str, identifier: &str, first_identifier: bool) -> bool {
    for (at, _) in prefix.match_indices(identifier) {
        if occurrence_may_mutate(prefix, at, identifier.len(), first_identifier) {
            return true;
        }
    }
    false
}

fn occurrence_may_mutate(
    prefix: &str,
    at: usize,
    identifier_len: usize,
    first_identifier: bool,
) -> bool {
    let before = &prefix[..at];
    let after = &prefix[at + identifier_len..];
    if !identifier_is_bounded(before, after) {
        return false;
    }
    let after = after.trim_start();
    first_identifier
        || before.trim_end().ends_with("&mut")
        || after.starts_with('.')
        || starts_with_assignment_operator(after)
}

fn identifier_is_bounded(before: &str, after: &str) -> bool {
    before
        .as_bytes()
        .last()
        .is_none_or(|byte| !is_ident_continue(byte))
        && after
            .as_bytes()
            .first()
            .is_none_or(|byte| !is_ident_continue(byte))
}

fn starts_with_assignment_operator(value: &str) -> bool {
    ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="]
        .iter()
        .any(|operator| value.starts_with(operator))
}

fn expression_identifiers_occur(haystack: &str, expression: &str) -> bool {
    let bytes = expression.as_bytes();
    let mut start = 0usize;
    while start < bytes.len() {
        if !is_ident_start(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && is_ident_continue(&bytes[end]) {
            end += 1;
        }
        if contains_receiver(haystack, &expression[start..end]) {
            return true;
        }
        start = end;
    }
    false
}

fn cstring_literal_construction(source: &str, masked: &str, unwrap_dot: usize) -> bool {
    let bytes = masked.as_bytes();
    let Some(close) = previous_nonspace(bytes, unwrap_dot).filter(|at| bytes[*at] == b')') else {
        return false;
    };
    let Some(open) = matching_open(bytes, close, b'(', b')') else {
        return false;
    };
    let Some(end) = previous_nonspace(bytes, open).map(|at| at + 1) else {
        return false;
    };
    let start = masked[..end]
        .rfind(|ch: char| ch != ':' && ch != '_' && !ch.is_ascii_alphanumeric())
        .map_or(0, |at| at + 1);
    if !matches!(
        &masked[start..end],
        "CString::new" | "std::ffi::CString::new"
    ) {
        return false;
    }
    let argument = trim_range(source, open + 1, close);
    let text = &source[argument.0..argument.1];
    if text.starts_with('"') || text.starts_with("r\"") || text.starts_with("r#") {
        return decode_literal(text).is_some_and(|value| !value.contains('\0'));
    }
    if text.is_empty() || !text.bytes().all(|byte| is_ident_continue(&byte)) {
        return false;
    }
    root_str_constant(source, masked, text, start)
        .and_then(decode_literal)
        .is_some_and(|value| !value.contains('\0'))
}

fn root_str_constant<'a>(
    source: &'a str,
    masked: &str,
    name: &str,
    call_start: usize,
) -> Option<&'a str> {
    // Restrict resolution to an unambiguous root constant. Nested modules do not
    // inherit root names, and local imports can shadow them.
    if USE_DECLARATION
        .find_iter(masked)
        .any(|item| item.as_str().contains('*') || contains_receiver(item.as_str(), name))
        || MODULE_DECLARATION.find_iter(masked).any(|item| {
            let open = item.end() - 1;
            open < call_start
                && matching_close(masked.as_bytes(), open, b'{', b'}')
                    .is_some_and(|close| call_start < close)
        })
    {
        return None;
    }
    let mut declarations = CONST_DECLARATION
        .captures_iter(masked)
        .filter(|item| &item[1] == name);
    let declaration = declarations.next()?;
    if declarations.next().is_some() {
        return None;
    }
    let whole = declaration.get(0)?;
    if enclosing_block(masked, whole.start()).is_some() {
        return None;
    }
    let end = whole.end() + masked[whole.end()..].find(';')?;
    let equal = whole.end() + masked[whole.end()..end].find('=')?;
    if !masked[whole.end()..equal]
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .eq(b"&str".iter().copied())
    {
        return None;
    }
    let initializer = trim_range(source, equal + 1, end);
    Some(&source[initializer.0..initializer.1])
}

fn receiver_reused(prefix: &str, receiver: &str) -> bool {
    let mut fields = receiver.split('.').map(str::trim);
    let Some(root) = fields.next() else {
        return true;
    };
    prefix.match_indices(root).any(|(at, _)| {
        let before = &prefix[..at];
        let mut remaining = &prefix[at + root.len()..];
        if !identifier_is_bounded(before, remaining) {
            return false;
        }
        for field in fields.clone() {
            remaining = remaining.trim_start();
            let Some(after_dot) = remaining.strip_prefix('.') else {
                return true;
            };
            remaining = after_dot.trim_start();
            let end = remaining.bytes().take_while(is_ident_continue).count();
            if end == 0 {
                return true;
            }
            let actual = &remaining[..end];
            remaining = &remaining[end..];
            if actual != field {
                // Sibling fields are independent, but a method on a shared parent
                // could replace the guarded field.
                return remaining.trim_start().starts_with(['(', ':']);
            }
        }
        true
    })
}

fn iterator_next_is_invariant(masked: &str, next: &Call<'_>) -> bool {
    cursor_guarded(masked, next)
        || chars_count_guarded(masked, next)
        || char_case_iterator_next(masked, next)
        || split_iterator_access(masked, next)
}

fn chars_count_guarded(masked: &str, next: &Call<'_>) -> bool {
    let Some(chars) = next_chars_call(masked, next) else {
        return false;
    };
    let Some((receiver, condition)) = guarded_receiver(masked, &chars) else {
        return false;
    };
    let Some(left) = one_comparison_left(masked, condition) else {
        return false;
    };
    let Some(count) = call_before(masked, left.1) else {
        return false;
    };
    if count.close + 1 != left.1
        || count.method != "count"
        || !count.argument(masked).trim().is_empty()
    {
        return false;
    }
    let Some(guard_chars) = call_before(masked, count.dot) else {
        return false;
    };
    guard_chars.method == "chars"
        && guard_chars.argument(masked).trim().is_empty()
        && simple_receiver(masked, guard_chars.dot)
            .is_some_and(|guarded| guarded.start == left.0 && guarded.text() == receiver.text())
}

fn next_chars_call<'a>(masked: &'a str, next: &Call<'_>) -> Option<Call<'a>> {
    if !next.is_next(masked) {
        return None;
    }
    let chars = call_before(masked, next.dot)?;
    (chars.method == "chars" && chars.argument(masked).trim().is_empty()).then_some(chars)
}

fn char_case_iterator_next(masked: &str, next: &Call<'_>) -> bool {
    if !next.is_next(masked) {
        return false;
    }
    let Some(case) = call_before(masked, next.dot) else {
        return false;
    };
    if !matches!(case.method, "to_lowercase" | "to_uppercase")
        || !case.argument(masked).trim().is_empty()
    {
        return false;
    }
    let Some(receiver) = simple_receiver(masked, case.dot) else {
        return false;
    };
    // char case mappings yield one or more characters, unlike arbitrary iterators:
    // https://doc.rust-lang.org/std/primitive.char.html#method.to_lowercase
    // Establish the char from a local chars().next() binding, not the method name alone.
    immutable_binding_initializer(masked, receiver)
        .is_some_and(|initializer| chars_first_initializer(masked, initializer))
}

fn immutable_binding_initializer(masked: &str, receiver: Receiver<'_>) -> Option<(usize, usize)> {
    if !receiver.text().bytes().all(|byte| is_ident_continue(&byte)) {
        return None;
    }
    let (binding, _) = masked[..receiver.start]
        .rmatch_indices(receiver.text())
        .find(|(at, _)| {
            identifier_is_bounded(
                &masked[..*at],
                &masked[*at + receiver.text().len()..receiver.start],
            )
        })?;
    let before_let = masked[..binding].trim_end().strip_suffix("let")?;
    if before_let.as_bytes().last().is_some_and(is_ident_continue) {
        return None;
    }
    let scope = enclosing_block(masked, binding)?;
    if matching_close(masked.as_bytes(), scope, b'{', b'}')? < receiver.start {
        return None;
    }
    let after_binding = binding + receiver.text().len();
    let equal = trim_range(masked, after_binding, receiver.start).0;
    if masked.as_bytes().get(equal) != Some(&b'=') {
        return None;
    }
    let initializer_start = equal + 1;
    let end = initializer_start + masked[initializer_start..receiver.start].find(';')?;
    Some(trim_range(masked, initializer_start, end))
}

fn chars_first_initializer(masked: &str, initializer: (usize, usize)) -> bool {
    let Some(unwrapped) = call_before(masked, initializer.1) else {
        return false;
    };
    if !matches!(unwrapped.method, "unwrap" | "expect") {
        return false;
    }
    let Some(first) = call_before(masked, unwrapped.dot) else {
        return false;
    };
    let Some(chars) = next_chars_call(masked, &first) else {
        return false;
    };
    simple_receiver(masked, chars.dot).is_some_and(|text| text.start == initializer.0)
}

fn split_iterator_access(masked: &str, access: &Call<'_>) -> bool {
    matches!(access.method, "next" | "last" | "next_back")
        && access.argument(masked).trim().is_empty()
        && call_before(masked, access.dot)
            .is_some_and(|iterator| matches!(iterator.method, "split" | "rsplit"))
}

fn option_access_short_circuit_guarded(source: &str, masked: &str, access: &Call<'_>) -> bool {
    matches!(access.method, "first" | "last")
        && access.argument(masked).trim().is_empty()
        && simple_receiver(masked, access.dot).is_some_and(|receiver| {
            len_short_circuit_guarded(masked, receiver)
                || non_empty_short_circuit_guarded(source, masked, receiver)
        })
}

fn collection_access_guarded(source: &str, masked: &str, access: &Call<'_>) -> bool {
    let collection = if access.is_next(masked) {
        let Some(iterator) = call_before(masked, access.dot) else {
            return false;
        };
        if !matches!(
            iterator.method,
            "iter" | "iter_mut" | "keys" | "values" | "values_mut"
        ) || !iterator.argument(masked).trim().is_empty()
        {
            return false;
        }
        iterator
    } else if matches!(
        access.method,
        "first" | "last" | "first_mut" | "last_mut" | "pop" | "pop_front"
    ) && access.argument(masked).trim().is_empty()
    {
        *access
    } else {
        return false;
    };
    let Some(receiver) = simple_receiver(masked, collection.dot) else {
        return false;
    };
    let Some(block_open) = enclosing_block(masked, receiver.start) else {
        return false;
    };
    if collection_let_else_guarded(masked, block_open, receiver) {
        return true;
    }
    if receiver_reused_before_unwrap(&masked[block_open + 1..receiver.start], receiver.text()) {
        return false;
    }
    let Some(condition) = if_condition(masked, block_open)
        .or_else(|| while_condition(masked, block_open))
        .or_else(|| match_arm_condition(masked, block_open))
    else {
        return false;
    };
    conjunct_guard_end(masked, condition, |conjunct| {
        exact_len_one_guard(masked, conjunct, receiver.text())
            || guard_call(source, masked, conjunct, true, receiver.text(), "is_empty").is_some()
    })
    .is_some_and(|guard_end| !receiver_reused(&masked[guard_end..condition.1], receiver.text()))
}

fn collection_let_else_guarded(masked: &str, block_open: usize, receiver: Receiver<'_>) -> bool {
    preceding_sibling_blocks(masked, block_open, receiver.start).any(|(open, close)| {
        collection_let_else_header(masked, open, receiver.text())
            && unconditional_return(&masked[open + 1..close])
            && !receiver_reused_before_unwrap(&masked[close + 1..receiver.start], receiver.text())
    })
}

fn preceding_sibling_blocks(
    masked: &str,
    block_open: usize,
    before: usize,
) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut cursor = block_open + 1;
    std::iter::from_fn(move || {
        let open = cursor + masked[cursor..before].find('{')?;
        let close = matching_close(masked.as_bytes(), open, b'{', b'}')?;
        if close >= before {
            return None;
        }
        cursor = close + 1;
        Some((open, close))
    })
}

fn collection_let_else_header(masked: &str, open: usize, receiver: &str) -> bool {
    let boundary = masked[..open]
        .rfind([';', '{', '}'])
        .map_or(0, |index| index + 1);
    let header = &masked[boundary..open];
    let Some(pattern) = LET_SOME_PATTERN.find(header) else {
        return false;
    };
    let pattern_open = boundary + pattern.end() - 1;
    let Some(pattern_close) = matching_close(masked.as_bytes(), pattern_open, b'(', b')') else {
        return false;
    };
    if pattern_close >= open {
        return false;
    }
    if receiver_reused(&masked[pattern_open + 1..pattern_close], receiver) {
        return false;
    }
    let (assignment, _) = trim_range(masked, pattern_close + 1, open);
    if masked.as_bytes().get(assignment) != Some(&b'=') {
        return false;
    }
    let Some(before_else) = header.trim_end().strip_suffix("else") else {
        return false;
    };
    let end = boundary + before_else.trim_end().len();
    let Some(access) = call_before(masked, end) else {
        return false;
    };
    matches!(access.method, "first" | "last" | "first_mut" | "last_mut")
        && access.argument(masked).trim().is_empty()
        && access.close + 1 == end
        && simple_receiver(masked, access.dot).is_some_and(|guarded| {
            guarded.text() == receiver
                && guarded.start == trim_range(masked, assignment + 1, open).0
        })
}

fn match_arm_condition(masked: &str, block_open: usize) -> Option<(usize, usize)> {
    let (match_open, arrow_start) = match_arm_header(masked, block_open)?;
    // Search only this arm's top-level pattern/guard, never nested patterns or earlier arms.
    let bytes = masked.as_bytes();
    let mut cursor = arrow_start;
    while let Some(at) = previous_nonspace(bytes, cursor) {
        if at <= match_open || bytes[at] == b',' {
            return None;
        }
        match bytes[at] {
            b')' => cursor = matching_open(bytes, at, b'(', b')')?,
            b']' => cursor = matching_open(bytes, at, b'[', b']')?,
            b'}' => return None,
            byte if is_ident_continue(&byte) => {
                let start = identifier_start(bytes, at + 1);
                if &masked[start..at + 1] == "if" {
                    return Some(trim_range(masked, at + 1, arrow_start));
                }
                cursor = start;
            }
            _ => cursor = at,
        }
    }
    None
}

fn match_arm_header(masked: &str, block_open: usize) -> Option<(usize, usize)> {
    let arrow_end = previous_nonspace(masked.as_bytes(), block_open)? + 1;
    let arrow_start = arrow_end.checked_sub(2)?;
    if &masked[arrow_start..arrow_end] != "=>" {
        return None;
    }
    let match_open = enclosing_block(masked, block_open)?;
    let prefix = &masked[..match_open];
    let boundary = prefix.rfind([';', '{', '}']).map_or(0, |at| at + 1);
    let header = &masked[boundary..match_open];
    header
        .match_indices("match")
        .any(|(at, _)| identifier_is_bounded(&header[..at], &header[at + 5..]))
        .then_some((match_open, arrow_start))
}

fn access_guarded(source: &str, masked: &str, access: &Call<'_>) -> bool {
    let Some((receiver, condition)) = guarded_receiver(masked, access) else {
        return false;
    };

    match access.method {
        "find" => find_guarded(source, masked, access, receiver, condition),
        "split_once" => split_once_guarded(source, masked, access, receiver, condition),
        "first" if access.argument(masked).trim().is_empty() => {
            guard_call(source, masked, condition, true, receiver.text(), "is_empty").is_some()
        }
        _ => false,
    }
}

fn guarded_receiver<'a>(
    masked: &'a str,
    access: &Call<'_>,
) -> Option<(Receiver<'a>, (usize, usize))> {
    let receiver = simple_receiver(masked, access.dot)?;
    let block_open = enclosing_block(masked, receiver.start)?;
    let condition = if_condition(masked, block_open)?;

    // Reject even harmless intervening uses. This deliberately errs toward reporting: with no
    // type information an arbitrary method call on the receiver may mutate it through interior
    // mutability, and a repeated binding may shadow it.
    if receiver_reused(&masked[block_open + 1..receiver.start], receiver.text()) {
        return None;
    }

    Some((receiver, condition))
}

fn find_guarded(
    source: &str,
    masked: &str,
    access: &Call<'_>,
    receiver: Receiver<'_>,
    condition: (usize, usize),
) -> bool {
    let Some(needle) = literal_argument(source, masked, access) else {
        return false;
    };
    guard_call(
        source,
        masked,
        condition,
        false,
        receiver.text(),
        "contains",
    )
    .is_some_and(|guard| guard == needle)
}

fn split_once_guarded(
    source: &str,
    masked: &str,
    access: &Call<'_>,
    receiver: Receiver<'_>,
    condition: (usize, usize),
) -> bool {
    let Some(delimiter) = literal_argument(source, masked, access) else {
        return false;
    };
    guard_call(
        source,
        masked,
        condition,
        false,
        receiver.text(),
        "starts_with",
    )
    .is_some_and(|prefix| !delimiter.is_empty() && prefix.contains(&delimiter))
}

fn option_guarded(source: &str, masked: &str, unwrap_dot: usize) -> bool {
    let receiver = option_receiver(masked, unwrap_dot);
    let Some(receiver) = receiver else {
        return false;
    };
    if option_short_circuit_guarded(source, masked, receiver) {
        return true;
    }
    let Some(block_open) = enclosing_block(masked, receiver.start) else {
        return false;
    };
    if option_early_return_guarded(source, masked, block_open, receiver)
        || option_initialized_if_missing(source, masked, block_open, receiver)
    {
        return true;
    }
    let Some(condition) = if_condition(masked, block_open) else {
        return false;
    };
    if receiver_reused(&masked[block_open + 1..receiver.start], receiver.text()) {
        return false;
    }
    ["is_some", "is_ok"].iter().any(|method| {
        guard_call_conjunct(source, masked, condition, receiver.text(), method).is_some_and(
            |guard_end| !receiver_reused(&masked[guard_end..condition.1], receiver.text()),
        )
    })
}

fn option_receiver(masked: &str, unwrap_dot: usize) -> Option<Receiver<'_>> {
    match call_before(masked, unwrap_dot) {
        Some(call)
            if matches!(
                call.method,
                "as_ref" | "as_deref" | "as_mut" | "as_deref_mut"
            ) && call.argument(masked).trim().is_empty() =>
        {
            simple_receiver(masked, call.dot)
        }
        Some(_) => None,
        None => simple_receiver(masked, unwrap_dot),
    }
}

fn option_short_circuit_guarded(source: &str, masked: &str, receiver: Receiver<'_>) -> bool {
    let boundary = masked[..receiver.start]
        .rfind([';', '{', '}'])
        .map_or(0, |index| index + 1);
    let (start, _) = trim_range(masked, boundary, receiver.start);
    let Some(after_if) = masked[start..receiver.start].strip_prefix("if") else {
        return false;
    };
    if after_if.as_bytes().first().is_some_and(is_ident_continue) {
        return false;
    }
    let mut operand = start + 2;
    let mut cursor = operand;
    let mut depth = 0;
    let mut guard = None;
    while cursor < receiver.start {
        if let Some(operator) = conjunct_operator(masked.as_bytes(), cursor, &mut depth) {
            if guard.is_some_and(|(previous, _)| previous != operator) {
                guard = None;
            }
            let condition = trim_range(masked, operand, cursor);
            let methods = if operator == b'&' {
                ["is_some", "is_ok"]
            } else {
                ["is_none", "is_err"]
            };
            if methods.iter().any(|method| {
                guard_call(source, masked, condition, false, receiver.text(), method).is_some()
            }) {
                guard = Some((operator, cursor + 2));
            }
            operand = cursor + 2;
            cursor += 2;
        } else {
            cursor += 1;
        }
    }
    guard.is_some_and(|(_, end)| {
        !receiver_reused_before_unwrap(&masked[end..receiver.start], receiver.text())
    })
}

fn assigned_some_is_invariant(masked: &str, unwrap_dot: usize) -> bool {
    let receiver = option_receiver(masked, unwrap_dot);
    let Some(receiver) = receiver else {
        return false;
    };
    let Some((assignment, _)) = masked[..receiver.start]
        .rmatch_indices(receiver.text())
        .find(|(at, _)| {
            identifier_is_bounded(&masked[..*at], &masked[*at + receiver.text().len()..])
        })
    else {
        return false;
    };
    let Some(block) = enclosing_block(masked, receiver.start) else {
        return false;
    };
    let before = masked[..assignment].trim_end();
    if !before.ends_with([';', '{', '}']) || enclosing_block(masked, assignment) != Some(block) {
        return false;
    }
    let after_receiver = assignment + receiver.text().len();
    let after_receiver = masked[after_receiver..].trim_start();
    let Some(value) = after_receiver.strip_prefix('=') else {
        return false;
    };
    let value = value.trim_start();
    let Some(argument) = value.strip_prefix("Some") else {
        return false;
    };
    let open = masked.len() - argument.trim_start().len();
    if masked.as_bytes().get(open) != Some(&b'(') {
        return false;
    }
    let Some(close) = matching_close(masked.as_bytes(), open, b'(', b')') else {
        return false;
    };
    if close >= receiver.start {
        return false;
    }
    let end = trim_range(masked, close + 1, receiver.start).0;
    masked.as_bytes().get(end) == Some(&b';')
        && !receiver_reused_before_unwrap(&masked[end + 1..receiver.start], receiver.text())
}

fn option_initialized_if_missing(
    source: &str,
    masked: &str,
    block_open: usize,
    receiver: Receiver<'_>,
) -> bool {
    preceding_sibling_blocks(masked, block_open, receiver.start).any(|(open, close)| {
        let boundary = masked[..open]
            .rfind([';', '{', '}'])
            .map_or(0, |index| index + 1);
        let standalone = masked[boundary..open].trim_start().starts_with("if");
        standalone
            && if_condition(masked, open).is_some_and(|condition| {
                guard_call(source, masked, condition, false, receiver.text(), "is_none").is_some()
            })
            && exact_some_assignment(masked, (open + 1, close), receiver.text())
            && !masked[close + 1..receiver.start]
                .trim_start()
                .starts_with("else")
            && !receiver_reused_before_unwrap(&masked[close + 1..receiver.start], receiver.text())
    })
}

fn exact_some_assignment(masked: &str, body: (usize, usize), receiver: &str) -> bool {
    let (mut start, end) = trim_range(masked, body.0, body.1);
    // References and smart-pointer wrappers may assign through a single dereference.
    if masked.as_bytes().get(start) == Some(&b'*') {
        start = trim_range(masked, start + 1, end).0;
    }
    let Some(after_receiver) = masked[start..end].strip_prefix(receiver) else {
        return false;
    };
    let Some(value) = after_receiver.trim_start().strip_prefix('=') else {
        return false;
    };
    let Some(argument) = value.trim_start().strip_prefix("Some") else {
        return false;
    };
    let open = end - argument.trim_start().len();
    if masked.as_bytes().get(open) != Some(&b'(') {
        return false;
    }
    matching_close(masked.as_bytes(), open, b'(', b')')
        .is_some_and(|close| masked[close + 1..end].trim() == ";")
}

fn option_early_return_guarded(
    source: &str,
    masked: &str,
    block_open: usize,
    receiver: Receiver<'_>,
) -> bool {
    preceding_sibling_blocks(masked, block_open, receiver.start).any(|(open, close)| {
        let boundary = masked[..open]
            .rfind([';', '{', '}'])
            .map_or(0, |index| index + 1);
        // An else-if guard need not execute, so only a standalone if can dominate the call.
        let standalone_if = masked[boundary..open].trim_start().starts_with("if");
        standalone_if
            && if_condition(masked, open).is_some_and(|condition| {
                ["is_none", "is_err"].iter().any(|method| {
                    boolean_guard_end(masked, condition, b'|', |disjunct| {
                        guard_call(source, masked, disjunct, false, receiver.text(), method)
                            .is_some()
                    })
                    .is_some_and(|guard_end| {
                        !receiver_reused(&masked[guard_end..condition.1], receiver.text())
                    })
                })
            })
            && (unconditional_return(&masked[open + 1..close])
                || (is_loop_body(masked, block_open)
                    && unconditional_loop_exit(&masked[open + 1..close])))
            && !receiver_reused_before_unwrap(&masked[close + 1..receiver.start], receiver.text())
    })
}

fn is_loop_body(masked: &str, open: usize) -> bool {
    let boundary = masked[..open]
        .rfind([';', '{', '}'])
        .map_or(0, |index| index + 1);
    let header = masked[boundary..open].trim_start();
    ["for", "while", "loop"].iter().any(|keyword| {
        header.strip_prefix(keyword).is_some_and(|after| {
            after
                .as_bytes()
                .first()
                .is_none_or(|byte| !is_ident_continue(byte))
        })
    })
}

fn unconditional_loop_exit(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut cursor = 0;
    let mut statement_start = 0;
    while cursor < body.len() {
        match bytes[cursor] {
            b'(' | b'[' | b'{' => {
                let closing = match bytes[cursor] {
                    b'(' => b')',
                    b'[' => b']',
                    _ => b'}',
                };
                let Some(close) = matching_close(bytes, cursor, bytes[cursor], closing) else {
                    return false;
                };
                if bytes[cursor] == b'{' {
                    statement_start = close + 1;
                }
                cursor = close + 1;
            }
            b';' => {
                if !body[cursor + 1..].trim().is_empty() {
                    statement_start = cursor + 1;
                }
                cursor += 1;
            }
            _ => cursor += 1,
        }
    }
    matches!(
        body[statement_start..].trim(),
        "continue;" | "continue" | "break;" | "break"
    )
}

fn unconditional_return(body: &str) -> bool {
    // Simple completed statements (for example logging) may precede the terminal return.
    // Braces and closures remain unsupported so a nested return cannot prove dominance.
    let mut statement_start = 0;
    let mut statement_depth = 0usize;
    for (index, byte) in body.bytes().enumerate() {
        match byte {
            b'{' | b'}' | b'|' => return false,
            b'(' | b'[' => statement_depth += 1,
            b')' | b']' => statement_depth = statement_depth.saturating_sub(1),
            b';' if statement_depth == 0 && !body[index + 1..].trim().is_empty() => {
                statement_start = index + 1;
            }
            _ => {}
        }
    }
    let Some(expression) = body[statement_start..].trim().strip_prefix("return") else {
        return false;
    };
    if expression.as_bytes().first().is_some_and(is_ident_continue) {
        return false;
    }
    statement_depth == 0
}

fn receiver_reused_before_unwrap(prefix: &str, receiver: &str) -> bool {
    // A closure without braces does not introduce an enclosing_block boundary, and may run later.
    if prefix.contains('|') {
        return true;
    }
    let boundary = completed_prefix_end(prefix);
    let tail = prefix[boundary..].trim();
    let declaration = tail
        .strip_prefix("let ")
        .and_then(|binding| binding.strip_suffix('='))
        .map(str::trim)
        .map(|binding| binding.strip_prefix("mut ").unwrap_or(binding).trim());
    // A shadow binding is not in scope until its initializer finishes. Ignore only an exact
    // simple binding at the call, not earlier shadowing, assignments, or other receiver uses.
    if declaration == Some(receiver) {
        receiver_reused(&prefix[..boundary], receiver)
    } else {
        receiver_reused(prefix, receiver)
    }
}

fn guard_call_conjunct(
    source: &str,
    masked: &str,
    condition: (usize, usize),
    receiver: &str,
    method: &str,
) -> Option<usize> {
    conjunct_guard_end(masked, condition, |conjunct| {
        guard_call(source, masked, conjunct, false, receiver, method).is_some()
    })
}

fn conjunct_guard_end(
    masked: &str,
    condition: (usize, usize),
    proves: impl Fn((usize, usize)) -> bool,
) -> Option<usize> {
    boolean_guard_end(masked, condition, b'&', proves)
}

fn boolean_guard_end(
    masked: &str,
    condition: (usize, usize),
    separator: u8,
    proves: impl Fn((usize, usize)) -> bool,
) -> Option<usize> {
    let condition = strip_parentheses(masked, condition);
    let bytes = masked.as_bytes();
    let mut depth = 0usize;
    let mut conjunct_start = condition.0;
    let mut guarded_end = None;
    let mut index = condition.0;
    while index < condition.1 {
        match conjunct_operator(bytes, index, &mut depth) {
            Some(operator) if operator != separator => return None,
            Some(_) => {
                let conjunct = trim_range(masked, conjunct_start, index);
                if proves(conjunct) {
                    guarded_end = Some(index);
                }
                conjunct_start = index + 2;
                index += 2;
            }
            _ => index += 1,
        }
    }
    let conjunct = trim_range(masked, conjunct_start, condition.1);
    if proves(conjunct) {
        guarded_end = Some(condition.1);
    }
    guarded_end
}

fn non_empty_short_circuit_guarded(source: &str, masked: &str, receiver: Receiver<'_>) -> bool {
    short_circuit_guard(masked, receiver).is_some_and(|guard| {
        guard_call(source, masked, guard, true, receiver.text(), "is_empty").is_some()
    })
}

fn len_short_circuit_guarded(masked: &str, receiver: Receiver<'_>) -> bool {
    short_circuit_guard(masked, receiver)
        .is_some_and(|guard| exact_len_one_guard(masked, guard, receiver.text()))
}

fn short_circuit_guard(masked: &str, receiver: Receiver<'_>) -> Option<(usize, usize)> {
    let prefix = &masked[..receiver.start];
    let boundary = prefix.rfind([';', '{', '}']).map_or(0, |index| index + 1);
    let (start, end) = trim_range(masked, boundary, receiver.start);
    if !masked[start..end].starts_with("if")
        || masked
            .as_bytes()
            .get(start + 2)
            .is_some_and(is_ident_continue)
    {
        return None;
    }
    let (guard_start, guard_end) = trim_range(masked, start + 2, end);
    let and_start = guard_end.checked_sub(2)?;
    if &masked[and_start..guard_end] != "&&" {
        return None;
    }
    Some(trim_range(masked, guard_start, and_start))
}

fn one_comparison_left(masked: &str, guard: (usize, usize)) -> Option<(usize, usize)> {
    let guard = strip_parentheses(masked, guard);
    let equal = guard.0 + masked[guard.0..guard.1].find("==")?;
    let right = trim_range(masked, equal + 2, guard.1);
    (&masked[right.0..right.1] == "1").then(|| trim_range(masked, guard.0, equal))
}

fn exact_len_one_guard(masked: &str, guard: (usize, usize), receiver: &str) -> bool {
    let Some(left) = one_comparison_left(masked, guard) else {
        return false;
    };
    let Some(call) = call_before(masked, left.1) else {
        return false;
    };
    if call.close + 1 != left.1 || call.method != "len" || !call.argument(masked).trim().is_empty()
    {
        return false;
    }
    simple_receiver(masked, call.dot)
        .is_some_and(|guarded| guarded.start == left.0 && guarded.text() == receiver)
}

fn cursor_guarded(masked: &str, next: &Call<'_>) -> bool {
    let Some((slice_open, slice_close)) = cursor_chars_slice(masked, next) else {
        return false;
    };
    let Some(text) = simple_receiver(masked, slice_open) else {
        return false;
    };
    let (cursor_start, cursor_end) = trim_range(masked, slice_open + 1, slice_close);
    let Some(dots) = cursor_end.checked_sub(2) else {
        return false;
    };
    if &masked[dots..cursor_end] != ".." {
        return false;
    }
    let cursor_range = trim_range(masked, cursor_start, dots);
    let cursor = &masked[cursor_range.0..cursor_range.1];
    if cursor.is_empty()
        || !cursor
            .as_bytes()
            .first()
            .is_some_and(|byte| is_ident_start(*byte))
        || !cursor.as_bytes().iter().all(is_ident_continue)
    {
        return false;
    }
    let Some(block_open) = enclosing_block(masked, text.start) else {
        return false;
    };
    let Some(condition) = if_condition(masked, block_open) else {
        return false;
    };
    let intervening = &masked[block_open + 1..text.start];
    if contains_receiver(intervening, text.text()) || contains_receiver(intervening, cursor) {
        return false;
    }
    exact_cursor_guard(masked, condition, cursor, text.text())
}

fn cursor_chars_slice(masked: &str, next: &Call<'_>) -> Option<(usize, usize)> {
    let chars = next_chars_call(masked, next)?;
    let bytes = masked.as_bytes();
    let slice_close = previous_nonspace(bytes, chars.dot)?;
    if bytes[slice_close] != b']' {
        return None;
    }
    let slice_open = matching_open(bytes, slice_close, b'[', b']')?;
    Some((slice_open, slice_close))
}

fn exact_cursor_guard(
    masked: &str,
    mut condition: (usize, usize),
    cursor: &str,
    text: &str,
) -> bool {
    condition = strip_parentheses(masked, condition);
    let Some(less) = masked[condition.0..condition.1]
        .find('<')
        .map(|at| condition.0 + at)
    else {
        return false;
    };
    let left = trim_range(masked, condition.0, less);
    if &masked[left.0..left.1] != cursor {
        return false;
    }
    let right = trim_range(masked, less + 1, condition.1);
    let Some(call) = call_before(masked, right.1) else {
        return false;
    };
    if call.close + 1 != right.1 || call.method != "len" || !call.argument(masked).trim().is_empty()
    {
        return false;
    }
    simple_receiver(masked, call.dot)
        .is_some_and(|guarded| guarded.start == right.0 && guarded.text() == text)
}

#[derive(Clone, Copy)]
struct Call<'a> {
    method: &'a str,
    dot: usize,
    open: usize,
    close: usize,
}

impl Call<'_> {
    fn is_next(&self, text: &str) -> bool {
        self.method == "next" && self.argument(text).trim().is_empty()
    }

    fn argument<'a>(&self, text: &'a str) -> &'a str {
        &text[self.open + 1..self.close]
    }
}

#[derive(Clone, Copy)]
struct Receiver<'a> {
    start: usize,
    value: &'a str,
}

impl Receiver<'_> {
    fn text(&self) -> &str {
        self.value
    }
}

fn unwrap_chain_dot(masked: &str, call_offset: usize) -> Option<usize> {
    if masked.as_bytes().get(call_offset) == Some(&b'.') {
        Some(call_offset)
    } else {
        masked[..call_offset].rfind('.')
    }
}

fn call_before(masked: &str, end: usize) -> Option<Call<'_>> {
    let bytes = masked.as_bytes();
    let close = previous_nonspace(bytes, end)?;
    if bytes[close] != b')' {
        return None;
    }
    let open = matching_open(bytes, close, b'(', b')')?;
    let method_end = previous_nonspace(bytes, open)? + 1;
    let method_start = identifier_start(bytes, method_end);
    if method_start == method_end {
        return None;
    }
    let dot = previous_nonspace(bytes, method_start)?;
    if bytes[dot] != b'.' {
        return None;
    }
    Some(Call {
        method: &masked[method_start..method_end],
        dot,
        open,
        close,
    })
}

fn simple_receiver<'a>(masked: &'a str, dot: usize) -> Option<Receiver<'a>> {
    let bytes = masked.as_bytes();
    let mut end = previous_nonspace(bytes, dot)? + 1;
    let original_end = end;
    loop {
        let start = identifier_start(bytes, end);
        if start == end || !is_ident_start(bytes[start]) {
            return None;
        }
        let Some(separator) = previous_nonspace(bytes, start) else {
            return Some(Receiver {
                start,
                value: &masked[start..original_end],
            });
        };
        if bytes[separator] != b'.' {
            return Some(Receiver {
                start,
                value: &masked[start..original_end],
            });
        }
        end = separator;
    }
}

fn enclosing_block(masked: &str, offset: usize) -> Option<usize> {
    let mut stack = Vec::new();
    for (index, byte) in masked.as_bytes()[..offset].iter().enumerate() {
        match byte {
            b'{' => stack.push(index),
            b'}' => {
                stack.pop()?;
            }
            _ => {}
        }
    }
    stack.pop()
}

fn if_condition(masked: &str, block_open: usize) -> Option<(usize, usize)> {
    let prefix = &masked[..block_open];
    let boundary = prefix.rfind([';', '{', '}']).map_or(0, |index| index + 1);
    let (mut start, _) = trim_range(masked, boundary, block_open);
    if masked[start..block_open].starts_with("else")
        && masked
            .as_bytes()
            .get(start + 4)
            .is_some_and(u8::is_ascii_whitespace)
    {
        start = trim_range(masked, start + 4, block_open).0;
    }
    if !masked[start..block_open].starts_with("if")
        || masked
            .as_bytes()
            .get(start + 2)
            .is_some_and(is_ident_continue)
    {
        return None;
    }
    Some(trim_range(masked, start + 2, block_open))
}

fn while_condition(masked: &str, block_open: usize) -> Option<(usize, usize)> {
    let boundary = masked[..block_open]
        .rfind([';', '{', '}'])
        .map_or(0, |index| index + 1);
    let (start, _) = trim_range(masked, boundary, block_open);
    let condition = masked[start..block_open].strip_prefix("while")?;
    if condition.as_bytes().first().is_some_and(is_ident_continue) {
        return None;
    }
    Some(trim_range(masked, start + 5, block_open))
}

fn guard_call(
    source: &str,
    masked: &str,
    mut condition: (usize, usize),
    negated: bool,
    receiver: &str,
    method: &str,
) -> Option<String> {
    condition = strip_parentheses(masked, condition);
    let mut start = condition.0;
    let has_bang = masked.as_bytes().get(start) == Some(&b'!');
    if has_bang {
        start += 1;
        condition = trim_range(masked, start, condition.1);
        condition = strip_parentheses(masked, condition);
    }
    if has_bang != negated {
        return None;
    }
    let call = call_before(masked, condition.1)?;
    if call.close + 1 != condition.1 || call.method != method {
        return None;
    }
    let guard_receiver = simple_receiver(masked, call.dot)?;
    if guard_receiver.start != condition.0 || guard_receiver.text() != receiver {
        return None;
    }
    if matches!(
        method,
        "is_empty" | "is_some" | "is_none" | "is_ok" | "is_err"
    ) {
        return call.argument(masked).trim().is_empty().then(String::new);
    }
    literal_argument(source, masked, &call)
}

fn literal_argument(source: &str, masked: &str, call: &Call<'_>) -> Option<String> {
    let (start, end) = trim_range(source, call.open + 1, call.close);
    let argument = &source[start..end];
    if argument.is_empty() || top_level_comma(masked, start, end) {
        return None;
    }
    decode_literal(argument)
}

fn decode_literal(literal: &str) -> Option<String> {
    if literal.starts_with('r') {
        let quote = literal.find('"')?;
        let hashes = &literal[1..quote];
        if !hashes.bytes().all(|byte| byte == b'#') {
            return None;
        }
        let suffix = format!("\"{hashes}");
        let content = literal.strip_suffix(&suffix)?.get(quote + 1..)?;
        return (!content.contains(&suffix)).then(|| content.to_owned());
    }
    let quote = literal.as_bytes().first().copied()?;
    if literal.len() < 2
        || !matches!(quote, b'\'' | b'"')
        || literal.as_bytes().last() != Some(&quote)
    {
        return None;
    }
    let mut result = String::new();
    let mut chars = literal[1..literal.len() - 1].chars();
    while let Some(character) = chars.next() {
        if character == char::from(quote) {
            return None;
        }
        if character != '\\' {
            result.push(character);
            continue;
        }
        result.push(decode_literal_escape(chars.next()?)?);
    }
    Some(result)
}

fn decode_literal_escape(character: char) -> Option<char> {
    Some(match character {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        '\\' => '\\',
        '\'' => '\'',
        '"' => '"',
        '0' => '\0',
        _ => return None,
    })
}

fn contains_receiver(haystack: &str, receiver: &str) -> bool {
    haystack.match_indices(receiver).any(|(index, _)| {
        let before = index
            .checked_sub(1)
            .and_then(|at| haystack.as_bytes().get(at));
        let after = haystack.as_bytes().get(index + receiver.len());
        before.is_none_or(|byte| !is_ident_continue(byte))
            && after.is_none_or(|byte| !is_ident_continue(byte))
    })
}

fn strip_parentheses(masked: &str, mut range: (usize, usize)) -> (usize, usize) {
    loop {
        if masked.as_bytes().get(range.0) != Some(&b'(')
            || masked.as_bytes().get(range.1.saturating_sub(1)) != Some(&b')')
            || matching_close(masked.as_bytes(), range.0, b'(', b')') != Some(range.1 - 1)
        {
            return range;
        }
        range = trim_range(masked, range.0 + 1, range.1 - 1);
    }
}

fn trim_range(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && text.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while start < end && text.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn top_level_comma(masked: &str, start: usize, end: usize) -> bool {
    let mut depth = 0usize;
    for byte in &masked.as_bytes()[start..end] {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

fn matching_open(bytes: &[u8], close: usize, opening: u8, closing: u8) -> Option<usize> {
    let mut depth = 0usize;
    for index in (0..=close).rev() {
        if bytes[index] == closing {
            depth += 1;
        } else if bytes[index] == opening {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn matching_close(bytes: &[u8], open: usize, opening: u8, closing: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if *byte == opening {
            depth += 1;
        } else if *byte == closing {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn previous_nonspace(bytes: &[u8], before: usize) -> Option<usize> {
    (0..before)
        .rev()
        .find(|index| !bytes[*index].is_ascii_whitespace())
}

fn identifier_start(bytes: &[u8], mut end: usize) -> usize {
    while end > 0 && is_ident_continue(&bytes[end - 1]) {
        end -= 1;
    }
    end
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_continue(byte: &u8) -> bool {
    *byte == b'_' || byte.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::locally_proven_invariant;

    fn assert_panic_behavior(source: &str, reported: bool) {
        let sources =
            std::collections::BTreeMap::from([("src/lib.rs".to_owned(), source.to_owned())]);
        let findings = super::super::rules::analyze(&sources)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), usize::from(reported), "{source}");
        if let Some(finding) = findings.first() {
            assert_eq!(finding.path, "src/lib.rs");
            assert_eq!(finding.confidence, "high");
            assert!(finding.related_files.is_empty());
            let offset = source
                .find(".unwrap(")
                .or_else(|| source.find(".expect("))
                .unwrap();
            assert_eq!(
                finding.line,
                source[..offset]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1
            );
            assert_eq!(
                finding.code,
                if source[offset..].starts_with(".unwrap") {
                    "rust-unwrap"
                } else {
                    "rust-expect"
                }
            );
        }
    }

    #[test]
    fn production_failure_disjunctions_and_loop_exits_prove_fallthrough() {
        for source in [
            "fn f() { if value.is_none() || unavailable { return; } value.unwrap(); }",
            "fn f() { if unavailable || result.is_err() { return None; } result.expect(\"result\"); }",
            "fn f() { for item in items { if value.is_none() || missing { continue; }\nlet value = value.unwrap(); } }",
            "fn f() { while ready { if value.is_none() { break; } value.as_mut().unwrap(); } }",
            "fn f() { loop { if current.is_none() { if key == ROOT { save(); } continue; } current.as_mut().unwrap(); } }",
            "fn f() { if value.is_some() { value.as_deref_mut().expect(\"value\"); } }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { if value.is_none() && unavailable { return; } value.unwrap(); }",
            "fn f() { if value.is_none() || change(&mut value) { return; } value.unwrap(); }",
            "fn f() { if self.value.is_none() || self.reset() { return; } self.value.unwrap(); }",
            "fn f() { if other.is_none() || unavailable { return; } value.unwrap(); }",
            "fn f() { loop { if value.is_none() { if ready { continue; } } value.unwrap(); } }",
            "fn f() { loop { if value.is_none() { run(|| { return; }); } value.unwrap(); } }",
            "fn f() { loop { if value.is_none() { continue; } value.take(); value.unwrap(); } }",
            "fn f() { loop { if value.is_none() { continue; } let value = other; value.unwrap(); } }",
            "fn f() { loop { if value.is_none() { continue; } { value.unwrap(); } } }",
            "fn f() { loop { if ready { if value.is_none() { continue; } } value.unwrap(); } }",
            "fn f() { loop { let s = \"if value.is_none() { continue; }\"; value.unwrap(); } }",
            "fn f() { loop { /* if value.is_none() { continue; } */ value.unwrap(); } }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_option_short_circuit_presence_is_operand_local() {
        for source in [
            "fn f() { if center.is_none() || z != center.unwrap() {} }",
            "fn f() { if center.is_some() && z < center.unwrap() {} }",
            "fn f() { if result.is_err() || result.as_ref().expect(\"result\").ready() {} }",
            "fn f() { if value.is_none()\n|| consume(value.as_mut().unwrap()) {} }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { if value.is_some() || consume(value.unwrap()) {} }",
            "fn f() { if value.is_none() && consume(value.unwrap()) {} }",
            "fn f() { if value.is_some() && ready || consume(value.unwrap()) {} }",
            "fn f() { if other.is_none() || consume(value.unwrap()) {} }",
            "fn f() { if value.is_none() || change(&mut value) || consume(value.unwrap()) {} }",
            "fn f() { if self.value.is_none() || self.reset() || consume(self.value.unwrap()) {} }",
            "fn f() { if value.is_none() || run(|| value.unwrap()) {} }",
            "fn f() { if value.is_some() {} value.unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_some_assignments_prove_only_unreused_same_scope_receivers() {
        for source in [
            "fn f() { self.cached_file = Some(CachedFile {\nversion: buffer.version(),\n});\nself.cached_file.as_ref().unwrap(); }",
            "fn f() { value = Some(make()); value.expect(\"value\"); }",
            "fn f() { self.value = Some(make()); self.other = changed(); self.value.as_mut().unwrap(); }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { value = Some(make()); value = None; value.unwrap(); }",
            "fn f() { value = Some(make()); value.take(); value.unwrap(); }",
            "fn f() { value = Some(make()); replace(&mut value); value.unwrap(); }",
            "fn f() { self.value = Some(make()); self.reset(); self.value.unwrap(); }",
            "fn f() { value = Some(make()); let value = other; value.unwrap(); }",
            "fn f() { if ready { value = Some(make()); } value.unwrap(); }",
            "fn f() { value = Some(make()); { value.unwrap(); } }",
            "fn f() { value = Some(make()); run(|| value.unwrap()); }",
            "fn f() { value = Some(make()).filter(predicate); value.unwrap(); }",
            "fn f() { value = maybe(); value.unwrap(); }",
            "fn f() { let s = \"value = Some(make());\"; value.unwrap(); }",
            "fn f() { /* value = Some(make()); */ value.unwrap(); }",
            "fn f() { mutex.lock().unwrap(); }",
            "fn f() { arbitrary!().unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_missing_option_initialization_proves_only_exact_fallthrough() {
        for source in [
            "fn f() { if value.is_none() { value = Some(make()); } value.unwrap(); }",
            "fn f() { if system_state.is_none() {\n*system_state = Some(SystemState::new(&mut world));\n}\nlet system_state = system_state.as_mut().unwrap(); }",
            "fn f() { if self.buffer.is_none() { self.buffer = Some(make()); } self.other = changed(); self.buffer.as_ref().expect(\"buffer\"); }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { if value.is_some() { value = Some(make()); } value.unwrap(); }",
            "fn f() { if value.is_none() && ready { value = Some(make()); } value.unwrap(); }",
            "fn f() { if other.is_none() { value = Some(make()); } value.unwrap(); }",
            "fn f() { if value.is_none() { other = Some(make()); } value.unwrap(); }",
            "fn f() { if value.is_none() { if ready { value = Some(make()); } } value.unwrap(); }",
            "fn f() { if value.is_none() { run(|| value = Some(make())); } value.unwrap(); }",
            "fn f() { if ready {} else if value.is_none() { value = Some(make()); } value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()); } else { value = None; } value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()).filter(predicate); } value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()); value.take(); } value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()); } value.take(); value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()); } change(&mut value); value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()); } let value = other; value.unwrap(); }",
            "fn f() { if self.value.is_none() { self.value = Some(make()); } self.reset(); self.value.unwrap(); }",
            "fn f() { if value.is_none() { value = Some(make()); } run(|| value.unwrap()); }",
            "fn f() { if value.is_none() { value = Some(make()); } run(|| { value.unwrap(); }); }",
            "fn f() { if value.is_none() { value = Some(make()); } { value.unwrap(); } }",
            "fn f() { if result.is_err() { result = Err(error); } result.unwrap(); }",
            "fn f() { let text = \"if value.is_none() { value = Some(make()); }\"; value.unwrap(); }",
            "fn f() { /* if value.is_none() { value = Some(make()); } */ value.unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_missing_option_initialization_does_not_prove_inner_result() {
        let source = "fn f() {\nif result.is_none() { result = Some(load()); }\nresult.unwrap()\n.expect(\"load succeeded\");\n}";
        let sources =
            std::collections::BTreeMap::from([("src/lib.rs".to_owned(), source.to_owned())]);
        let findings = super::super::rules::analyze(&sources)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "rust-expect");
        assert_eq!(findings[0].path, "src/lib.rs");
        assert_eq!(findings[0].line, 4);
        assert_eq!(findings[0].confidence, "high");
        assert!(findings[0].related_files.is_empty());
    }

    #[test]
    fn production_while_cardinality_is_reestablished_at_the_body_entry() {
        for source in [
            "fn f() { while !manager.queue.is_empty()\n&& count < limit {\ncount += 1;\nlet item = manager.queue.pop_front().unwrap();\n} }",
            "fn f() { while !stack.is_empty() {\nlet &mut (ref node, ref mut successors) = stack.last_mut().unwrap();\nvisit(node, successors);\n} }",
            "fn f() { while ready && !items.is_empty() { items.pop().expect(\"item\"); } }",
            "fn f() { while items.len() == 1 { items.iter().next().unwrap(); } }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { while !items.is_empty() { items.clear(); items.pop().unwrap(); } }",
            "fn f() { while !items.is_empty() { let items = other; items.last().unwrap(); } }",
            "fn f() { while !items.is_empty() || ready { items.first().unwrap(); } }",
            "fn f() { while !items.is_empty() && drain(&mut items) { items.first().unwrap(); } }",
            "fn f() { while !self.items.is_empty() && self.reset() { self.items.first().unwrap(); } }",
            "fn f() { while !items.is_empty() { items.pop_front(); items.pop_front().unwrap(); } }",
            "fn f() { while !other.is_empty() { items.pop().unwrap(); } }",
            "fn f() { while !items.is_empty() { run(|| items.last().unwrap()); } }",
            "fn f() { while !items.is_empty() { run(|| { items.last().unwrap(); }); } }",
            "fn f() { while !items.is_empty() { { items.last().unwrap(); } } }",
            "fn f() { while !items.is_empty() { items.iter().filter(predicate).next().unwrap(); } }",
            "fn f() { while !items.is_empty() { items.get(index).unwrap(); } }",
            "fn f() { while !items.is_empty() {} items.last().unwrap(); }",
            "fn f() { let text = \"while !items.is_empty()\"; items.last().unwrap(); }",
            "fn f() { /* while !items.is_empty() {} */ items.last().unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_cardinality_guards_prove_only_preserved_presence() {
        for source in [
            "fn f() { if candidates.len() == 1 { candidates.first().copied().unwrap(); } }",
            "fn f() { if handles.len() == 1 { handles.keys().next().unwrap(); } }",
            "fn f() { if ready && buffers.len() == 1 { buffers.pop().unwrap(); } }",
            "fn f() { if selections.len() == 1 {\nselections.last().expect(\"selection\");\n} }",
            "fn f() { if !items.is_empty() { items.last_mut().expect(\"item\"); } }",
            "fn f() { if !items.is_empty() { items.iter().next().cloned().unwrap(); } }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { if items.len() == 1 { items.clear(); items.last().unwrap(); } }",
            "fn f() { if items.len() == 1 { let items = other; items.pop().unwrap(); } }",
            "fn f() { if items.len() == 1 && items.drain(..).count() == 1 { items.pop().unwrap(); } }",
            "fn f() { if items.len() == 1 || ready { items.last().unwrap(); } }",
            "fn f() { if other.len() == 1 { items.last().unwrap(); } }",
            "fn f() { if items.len() == 1 { items.iter().filter(predicate).next().unwrap(); } }",
            "fn f() { if items.len() == 1 { items.first().and_then(convert).unwrap(); } }",
            "fn f() { if items.len() == 1 { { items.last().unwrap(); } } }",
            "fn f() { if items.len() == 1 { run(|| items.last().unwrap()); } }",
            "fn f() { if items.len() == 1 { items.front().unwrap(); } }",
            "fn f() { if items.len() == 1 { items.get(index).unwrap(); } }",
            "fn f() { let text = \"if items.len() == 1\"; items.last().unwrap(); }",
            "fn f() { /* if items.len() == 1 */ items.last().unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_match_arm_cardinality_is_local_to_the_guarded_arm() {
        for source in [
            "fn f() { match node { Node::Template(tpl) if tpl.quasis.len() == 1 => {\nreturn Some(tpl.quasis.first().unwrap());\n}, _ => None } }",
            "fn f() { match items { items if !items.is_empty() => { items.iter().next().expect(\"item\"); }, _ => {} } }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { match node { Node::Template(tpl) if tpl.quasis.len() == 1 => {}, _ => { tpl.quasis.first().unwrap(); } } }",
            "fn f() { match node { Node::Template(tpl) if tpl.quasis.len() == 1 => { tpl.quasis.clear(); tpl.quasis.first().unwrap(); }, _ => {} } }",
            "fn f() { match node { Node::Template(tpl) if tpl.quasis.len() == 1 => { let tpl = other; tpl.quasis.first().unwrap(); }, _ => {} } }",
            "fn f() { match node { Node::Template(tpl) if tpl.quasis.len() == 1 => { { tpl.quasis.first().unwrap(); } }, _ => {} } }",
            "fn f() { match node { Node::Template(tpl) if tpl.quasis.len() == 0 => { tpl.quasis.first().unwrap(); }, _ => {} } }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_result_guards_preserve_dominance_and_receiver_boundaries() {
        for source in [
            "fn f() { if result.is_ok() { result.unwrap(); } }",
            "fn f() { if result.is_ok() && ready { result.as_ref().expect(\"result\"); } }",
            "fn f() { if result.is_err() { info!(\"unavailable\"); return; }\nregister();\nresult.unwrap(); }",
            "fn f() { if value.is_none() { warn!(\"missing\"); return None; } value.expect(\"value\"); }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { if result.is_err() { info!(\"unavailable\"); } result.unwrap(); }",
            "fn f() { if result.is_err() { if ready { return; } } result.unwrap(); }",
            "fn f() { if result.is_err() { let task = || return; task(); } result.unwrap(); }",
            "fn f() { if result.is_err() { return; } result = other; result.unwrap(); }",
            "fn f() { if result.is_err() { return; } let result = other; result.unwrap(); }",
            "fn f() { if result.is_err() && ready { return; } result.unwrap(); }",
            "fn f() { if result.is_ok() { result.take(); result.unwrap(); } }",
            "fn f() { if result.is_ok() && change(&mut result) { result.unwrap(); } }",
            "fn f() { if result.is_ok() { { result.unwrap(); } } }",
            "fn f() { if other.is_ok() { result.unwrap(); } }",
            "fn f() { if state.result.is_ok() { state.reset(); state.result.unwrap(); } }",
            "fn f() { if state.result.is_ok() { replace(&mut state); state.result.unwrap(); } }",
            "fn f() { OsString::from(input).into_string().unwrap(); }",
            "fn f() { evaluator.downcast_mut::<Evaluator>().unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    fn masked(source: &str) -> String {
        let mut result = source.as_bytes().to_vec();
        let mut index = 0;
        while index < result.len() {
            let quote = result[index];
            if !matches!(quote, b'\'' | b'"') {
                index += 1;
                continue;
            }
            let mut end = index + 1;
            while end < result.len() {
                if result[end] == b'\\' {
                    end += 2;
                } else if result[end] == quote {
                    end += 1;
                    break;
                } else {
                    end += 1;
                }
            }
            for byte in &mut result[index..end] {
                *byte = b' ';
            }
            index = end;
        }
        String::from_utf8(result).unwrap()
    }

    fn proven(source: &str) -> bool {
        let offset = source
            .find(".unwrap")
            .or_else(|| source.find(".expect"))
            .unwrap();
        locally_proven_invariant(source, &masked(source), offset)
    }

    #[test]
    fn proves_supported_guards_and_split_next() {
        assert!(proven(
            r#"if text.contains("/") { text.find("/").unwrap(); }"#
        ));
        assert!(proven(
            r#"if path.starts_with("root/") { path.split_once('/').expect("guarded"); }"#
        ));
        assert!(proven(r#"let first = value.split(',').next().unwrap();"#));
        assert!(proven(
            r#"let last = value.rsplit(dynamic).next().expect("nonempty iterator");"#
        ));
        assert!(proven("if !items.is_empty() { items.first().unwrap(); }"));
    }

    #[test]
    fn proves_option_len_and_cursor_guards() {
        assert!(proven("if value.is_some() { value.unwrap(); }"));
        assert!(proven(
            "if self.value.is_some() && ready() { self.value.unwrap(); }"
        ));
        assert!(proven(
            "if value.is_some() { value.as_ref().expect(\"guarded\"); }"
        ));
        assert!(proven("if value.is_some() { value.as_deref().unwrap(); }"));
        assert!(proven(
            "if items.len() == 1 && items.first().unwrap() == &expected {}"
        ));
        assert!(proven(
            "if !items.is_empty() && items.last().unwrap() == &expected {}"
        ));
        assert!(proven(
            "if cursor < text.len() { text[cursor..].chars().next().unwrap(); }"
        ));
        assert!(proven(
            "if cursor < text.len() { text[cursor..].chars().next().expect(\"in bounds\"); }"
        ));
    }

    #[test]
    fn proves_containment_before_position_for_identical_slice_expression() {
        assert!(proven(
            "if bytes[index + 1..].contains(&b'}') { \
                let close = index + 1 + bytes[index + 1..].iter()\
                    .position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(proven(
            "if index < bytes.len() && bytes[index..].contains(&b'}') { \
                bytes[index..].iter().position(|byte| *byte == b'}').expect(\"present\"); \
            }"
        ));
    }

    #[test]
    fn rejects_unsafe_containment_position_variants() {
        assert!(!proven(
            "if bytes[index + 1..].contains(&b'}') { \
                bytes[index + 2..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if left[index..].contains(&b'}') { \
                right[index..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if bytes[index..].contains(&b'}') { \
                bytes.clear(); \
                bytes[index..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if bytes[index..].contains(&b'}') { \
                index += 1; \
                bytes[index..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if !bytes[index..].contains(&b'}') { \
                bytes[index..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if bytes[index..].contains(&b'}') {} else { \
                bytes[index..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if ready || bytes[index..].contains(&b'}') { \
                bytes[index..].iter().position(|byte| *byte == b'}').unwrap(); \
            }"
        ));
        assert!(!proven(
            "if bytes[index..].contains(&b'}') { \
                bytes[index..].iter().position(|byte| *byte == b']').unwrap(); \
            }"
        ));
    }

    #[test]
    fn rejects_mismatched_or_invalidated_new_guards() {
        assert!(!proven("if left.is_some() { right.unwrap(); }"));
        assert!(!proven(
            "if value.is_some() { value.take(); value.unwrap(); }"
        ));
        assert!(!proven(
            "if value.is_some() { let value = replacement; value.unwrap(); }"
        ));
        assert!(!proven(
            "if left.len() == 1 && right.first().unwrap() == &expected {}"
        ));
        assert!(!proven(
            "if items.len() == 1 || items.first().unwrap() == &expected {}"
        ));
        assert!(!proven(
            "if items.len() == 1 && { items.clear(); items.first().unwrap(); true } {}"
        ));
        assert!(!proven(
            "if cursor < other.len() { text[cursor..].chars().next().unwrap(); }"
        ));
        assert!(!proven(
            "if cursor <= text.len() { text[cursor..].chars().next().unwrap(); }"
        ));
        assert!(!proven(
            "if cursor < text.len() { cursor += 1; text[cursor..].chars().next().unwrap(); }"
        ));
        assert!(!proven(
            "if cursor < text.len() { let text = replacement; text[cursor..].chars().next().unwrap(); }"
        ));
    }

    #[test]
    fn rejects_dynamic_or_custom_new_guards() {
        assert!(!proven("if value.available() { value.unwrap(); }"));
        assert!(!proven(
            "if items.size() == 1 && items.first().unwrap() == &expected {}"
        ));
        assert!(!proven(
            "if items.len() == expected && items.first().unwrap() == &value {}"
        ));
        assert!(!proven(
            "if cursor < text.byte_len() { text[cursor..].chars().next().unwrap(); }"
        ));
        assert!(!proven(
            "if cursor + 1 < text.len() { text[cursor..].chars().next().unwrap(); }"
        ));
        assert!(!proven(
            "if options[index].is_some() { options[index].unwrap(); }"
        ));
        assert!(!proven(
            "if rows[index].len() == 1 && rows[index].first().unwrap() == &value {}"
        ));
        assert!(!proven(
            "if cursor < texts[index].len() { texts[index][cursor..].chars().next().unwrap(); }"
        ));
    }

    #[test]
    fn rejects_mutation_receiver_mismatch_and_dynamic_values() {
        assert!(!proven(
            r#"if text.contains("/") { text.clear(); text.find("/").unwrap(); }"#
        ));
        assert!(!proven(
            r#"if left.contains("/") { right.find("/").unwrap(); }"#
        ));
        assert!(!proven(
            "if text.contains(needle) { text.find(needle).unwrap(); }"
        ));
        assert!(!proven(
            "if !items.is_empty() { items.push(1); items.first().unwrap(); }"
        ));
        assert!(!proven("if !left.is_empty() { right.first().unwrap(); }"));
    }

    #[test]
    fn rejects_non_dominating_or_insufficient_guards() {
        assert!(!proven(
            r#"if text.contains("/") {} text.find("/").unwrap();"#
        ));
        assert!(!proven(
            r#"if path.starts_with("root") { path.split_once('/').unwrap(); }"#
        ));
        assert!(!proven("if other.is_ok() { value.unwrap(); }"));
        assert!(!proven("if items.len() >= 1 { items.first().unwrap(); }"));
    }

    #[test]
    fn production_collection_let_else_presence_is_local_and_uninvalidated() {
        for source in [
            "fn combine() {\nlet Some(top) = self.stack.last() else { return Ok(()); };\nif top.graph_node != graph_node { return Ok(()); }\nlet Element { value, weight } = self.stack.pop().unwrap();\n}",
            "fn combine() {\nlet Some(&(_, node)) = self.stack.last() else {\n    return Ok(());\n};\nif node != graph_node { return Ok(()); }\nself.stack.pop().expect(\"stack\");\n}",
            "fn first() { let Some(item) = values.first_mut() else { return; }; inspect(item); values.first().unwrap(); }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn f() { let Some(top) = values.last() else { recover(); }; values.pop().unwrap(); }",
            "fn f() { let Some(top) = other.last() else { return; }; values.pop().unwrap(); }",
            "fn f() { let Some(top) = values.last() else { return; }; values.clear(); values.pop().unwrap(); }",
            "fn f() { let Some(top) = self.values.last() else { return; }; self.reset(); self.values.pop().unwrap(); }",
            "fn f() { let Some(top) = values.last() else { return; }; let values = other; values.pop().unwrap(); }",
            "fn f() { let Some(values) = values.last() else { return; }; values.pop().unwrap(); }",
            "fn f() { let Some(top) = values.last() else { return; }; run(|| values.pop().unwrap()); }",
            "fn f() { if ready { let Some(top) = values.last() else { return; }; } values.pop().unwrap(); }",
            "fn f() { let Some(top) = values.pop() else { return; }; values.pop().unwrap(); }",
            "fn f() { let Some(top) = values.iter().find(predicate) else { return; }; values.pop().unwrap(); }",
            "fn f() { /* let Some(top) = values.last() else { return; }; */ values.pop().unwrap(); }",
            "fn f() { let example = \"let Some(top) = values.last() else { return; };\"; values.pop().unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }

    #[test]
    fn production_fresh_split_tails_are_nonempty_without_filtering() {
        for source in [
            "fn name() { core::any::type_name::<M>().split(\"::\").last().unwrap(); }",
            "fn name() { text.rsplit('/').last().expect(\"segment\"); }",
            "fn name() { text\n    .split(\"::\")\n    .next_back()\n    .unwrap(); }",
        ] {
            assert_panic_behavior(source, false);
        }
        for source in [
            "fn name() { text.split_terminator(\"::\").last().unwrap(); }",
            "fn name() { text.split(\"::\").filter(predicate).last().unwrap(); }",
            "fn name() { iterator.last().unwrap(); }",
            "fn name() { iterator.next_back().unwrap(); }",
        ] {
            assert_panic_behavior(source, true);
        }
    }
}
