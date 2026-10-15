//! Conservative local proofs for panic-prone Rust method calls.

pub(super) fn locally_proven_invariant(source: &str, masked: &str, call_offset: usize) -> bool {
    if source.len() != masked.len() || call_offset > masked.len() {
        return false;
    }

    let Some(unwrap_dot) = unwrap_chain_dot(masked, call_offset) else {
        return false;
    };

    if option_guarded(source, masked, unwrap_dot) {
        return true;
    }

    let Some(access) = call_before(masked, unwrap_dot) else {
        return false;
    };

    cursor_guarded(masked, &access)
        || containment_position_guarded(source, masked, &access)
        || split_iterator_next(masked, &access)
        || first_len_guarded(masked, &access)
        || access_guarded(source, masked, &access)
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

fn split_iterator_next(masked: &str, access: &Call<'_>) -> bool {
    access.method == "next"
        && access.argument(masked).trim().is_empty()
        && call_before(masked, access.dot)
            .is_some_and(|iterator| matches!(iterator.method, "split" | "rsplit"))
}

fn first_len_guarded(masked: &str, access: &Call<'_>) -> bool {
    access.method == "first"
        && access.argument(masked).trim().is_empty()
        && simple_receiver(masked, access.dot)
            .is_some_and(|receiver| len_short_circuit_guarded(masked, receiver))
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
    if contains_receiver(&masked[block_open + 1..receiver.start], receiver.text()) {
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
    let receiver = match call_before(masked, unwrap_dot) {
        Some(call)
            if matches!(call.method, "as_ref" | "as_deref")
                && call.argument(masked).trim().is_empty() =>
        {
            simple_receiver(masked, call.dot)
        }
        Some(_) => None,
        None => simple_receiver(masked, unwrap_dot),
    };
    let Some(receiver) = receiver else {
        return false;
    };
    let Some(block_open) = enclosing_block(masked, receiver.start) else {
        return false;
    };
    let Some(condition) = if_condition(masked, block_open) else {
        return false;
    };
    if contains_receiver(&masked[block_open + 1..receiver.start], receiver.text()) {
        return false;
    }
    guard_call(source, masked, condition, false, receiver.text(), "is_some").is_some()
}

fn len_short_circuit_guarded(masked: &str, receiver: Receiver<'_>) -> bool {
    let prefix = &masked[..receiver.start];
    let boundary = prefix.rfind([';', '{', '}']).map_or(0, |index| index + 1);
    let (start, end) = trim_range(masked, boundary, receiver.start);
    if !masked[start..end].starts_with("if")
        || masked
            .as_bytes()
            .get(start + 2)
            .is_some_and(is_ident_continue)
    {
        return false;
    }
    let (guard_start, guard_end) = trim_range(masked, start + 2, end);
    let Some(and_start) = guard_end.checked_sub(2) else {
        return false;
    };
    if &masked[and_start..guard_end] != "&&" {
        return false;
    }
    let guard = trim_range(masked, guard_start, and_start);
    exact_len_one_guard(masked, guard, receiver.text())
}

fn exact_len_one_guard(masked: &str, mut guard: (usize, usize), receiver: &str) -> bool {
    guard = strip_parentheses(masked, guard);
    let Some(equal) = masked[guard.0..guard.1].find("==").map(|at| guard.0 + at) else {
        return false;
    };
    let left = trim_range(masked, guard.0, equal);
    let right = trim_range(masked, equal + 2, guard.1);
    if &masked[right.0..right.1] != "1" {
        return false;
    }
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
    if next.method != "next" || !next.argument(masked).trim().is_empty() {
        return None;
    }
    let chars = call_before(masked, next.dot)?;
    if chars.method != "chars" || !chars.argument(masked).trim().is_empty() {
        return None;
    }
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
    let bytes = masked.as_bytes();
    let mut start = call_offset;
    while start > 0 && bytes[start - 1].is_ascii_whitespace() {
        start -= 1;
    }
    if bytes.get(start) == Some(&b'.') {
        return Some(start);
    }
    masked[..call_offset].rfind('.')
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
    let mut start = boundary;
    while masked
        .as_bytes()
        .get(start)
        .is_some_and(u8::is_ascii_whitespace)
    {
        start += 1;
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
    if matches!(method, "is_empty" | "is_some") {
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
        return literal
            .ends_with(&suffix)
            .then(|| literal[quote + 1..literal.len() - suffix.len()].to_owned());
    }
    let quote = literal.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || literal.as_bytes().last() != Some(&quote) {
        return None;
    }
    let mut result = String::new();
    let mut chars = literal[1..literal.len() - 1].chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        result.push(match chars.next()? {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            '0' => '\0',
            _ => return None,
        });
    }
    Some(result)
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
            "if value.is_some() { value.as_ref().expect(\"guarded\"); }"
        ));
        assert!(proven("if value.is_some() { value.as_deref().unwrap(); }"));
        assert!(proven(
            "if items.len() == 1 && items.first().unwrap() == &expected {}"
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
        assert!(!proven("if value.is_ok() { value.unwrap(); }"));
        assert!(!proven("if items.len() >= 1 { items.first().unwrap(); }"));
    }
}
