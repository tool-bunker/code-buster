use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;
use crate::rust_rules::function_lexical_facts;

pub fn analyze(functions: &[FunctionSource]) -> Vec<Finding> {
    let mut ordered = functions.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
    });
    let parsed = ordered
        .iter()
        .map(|function| trivial_forwarder(function))
        .collect::<Vec<_>>();
    let eligible = eligible_wrappers(&ordered, &parsed);
    let starts = wrapper_chain_starts(&ordered, &eligible);
    let mut reported = vec![false; ordered.len()];
    starts
        .into_iter()
        .map(|(outermost, target)| {
            wrapper_finding(outermost, target, &ordered, &eligible, &mut reported)
        })
        .collect()
}

fn eligible_wrappers<'a>(
    ordered: &[&FunctionSource],
    parsed: &'a [Option<String>],
) -> Vec<Option<&'a str>> {
    let mut eligible = vec![None; ordered.len()];
    for (index, target) in parsed.iter().enumerate() {
        if let Some(target) = target {
            eligible[index] = eligible_wrapper_target(ordered, index, target);
        }
    }
    eligible
}

fn eligible_wrapper_target<'a>(
    ordered: &[&FunctionSource],
    index: usize,
    target: &'a str,
) -> Option<&'a str> {
    let wrapper = ordered[index];
    let target_matches = ordered
        .iter()
        .enumerate()
        .filter(|(candidate_index, candidate)| {
            *candidate_index != index && candidate.path == wrapper.path && candidate.name == target
        })
        .count();
    if target_matches != 1 {
        return None;
    }
    let callers = ordered
        .iter()
        .enumerate()
        .filter(|(candidate_index, candidate)| {
            *candidate_index != index
                && candidate.path == wrapper.path
                && calls_function(candidate, &wrapper.name)
        })
        .count();
    (callers == 1).then_some(target)
}

fn next_wrapper<'a>(
    ordered: &[&FunctionSource],
    eligible: &[Option<&'a str>],
    index: usize,
) -> Option<(usize, &'a str)> {
    let target = eligible[index]?;
    let mut matches =
        eligible
            .iter()
            .enumerate()
            .filter_map(|(candidate_index, candidate_target)| {
                let candidate_target = (*candidate_target)?;
                (ordered[candidate_index].path == ordered[index].path
                    && ordered[candidate_index].name == target)
                    .then_some((candidate_index, candidate_target))
            });
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}

fn wrapper_chain_starts<'a>(
    ordered: &[&FunctionSource],
    eligible: &[Option<&'a str>],
) -> Vec<(usize, &'a str)> {
    let mut nested = vec![false; ordered.len()];
    for (index, target) in eligible.iter().enumerate() {
        if target.is_some()
            && let Some((next, _)) = next_wrapper(ordered, eligible, index)
        {
            nested[next] = true;
        }
    }
    let mut starts = eligible
        .iter()
        .enumerate()
        .filter_map(|(index, target)| {
            let target = (*target)?;
            (!nested[index]).then_some((index, target))
        })
        .collect::<Vec<_>>();
    let mut reachable = vec![false; ordered.len()];
    for (start, _) in starts.iter().copied() {
        mark_wrapper_chain(ordered, eligible, start, &mut reachable);
    }
    for index in 0..ordered.len() {
        let Some(target) = eligible[index] else {
            continue;
        };
        if reachable[index] {
            continue;
        }
        starts.push((index, target));
        mark_wrapper_chain(ordered, eligible, index, &mut reachable);
    }
    starts
}

fn mark_wrapper_chain(
    ordered: &[&FunctionSource],
    eligible: &[Option<&str>],
    start: usize,
    reachable: &mut [bool],
) {
    let mut current = start;
    while !reachable[current] {
        reachable[current] = true;
        let Some((next, _)) = next_wrapper(ordered, eligible, current) else {
            break;
        };
        current = next;
    }
}

fn wrapper_finding<'a>(
    outermost: usize,
    mut terminal: &'a str,
    ordered: &[&FunctionSource],
    eligible: &[Option<&'a str>],
    reported: &mut [bool],
) -> Finding {
    let mut wrappers = Vec::new();
    let mut current = outermost;
    while !reported[current] {
        reported[current] = true;
        wrappers.push(current);
        let Some((next, next_target)) = next_wrapper(ordered, eligible, current) else {
            break;
        };
        if reported[next] {
            break;
        }
        current = next;
        terminal = next_target;
    }
    let is_chain = wrappers.len() > 1;
    let message = if is_chain {
        let mut path = wrappers
            .iter()
            .map(|index| ordered[*index].name.as_str())
            .collect::<Vec<_>>();
        path.push(terminal);
        format!(
            "{} single-use forwarding wrappers form the chain `{}`",
            wrappers.len(),
            path.join("` -> `")
        )
    } else {
        format!(
            "`{}` has one caller and only forwards unchanged arguments to `{terminal}`",
            ordered[outermost].name
        )
    };
    Finding {
        code: "single-use-trivial-wrapper".to_owned(),
        severity: Severity::Info,
        path: ordered[outermost].path.clone(),
        line: ordered[outermost].line,
        end_line: ordered[outermost].end_line
            + usize::from(ordered[outermost].path.ends_with(".rs")),
        message,
        confidence: "high".to_owned(),
        why: if is_chain {
            "A chain of single-use forwarding functions adds repeated navigation without owning policy, transformation, validation, or resource lifetime."
        } else {
            "A single-use forwarding function adds navigation without owning policy, transformation, validation, or resource lifetime."
        }
        .to_owned(),
        suggestion: if is_chain {
            "Collapse the chain into its caller unless a wrapper is an intentional extension or compatibility boundary."
        } else {
            "Inline the wrapper unless it is an intentional extension or compatibility boundary."
        }
        .to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

fn trivial_forwarder(function: &FunctionSource) -> Option<String> {
    let source = function.source.trim();
    let language = source_language(&function.path)?;
    if !matches!(
        language,
        "cpp" | "csharp" | "dart" | "go" | "java" | "javascript" | "typescript" | "python" | "rust"
    ) || !is_private(function, language)
        || contains_word_case_insensitive(source, "override")
    {
        return None;
    }

    let open = declaration_open(source, &function.name)?;
    if language == "cpp" && contains_word(&source[..open], "operator") {
        return None;
    }
    let close = matching_delimiter(source, open, b'(', b')')?;
    let parameters = forwarded_parameter_names(&source[open + 1..close], language)?;
    let (target, arguments) = direct_forwarding_call(&source[close + 1..])?;
    if target == function.name {
        return None;
    }
    let arguments = split_top_level(arguments)
        .into_iter()
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    (arguments == parameters).then(|| target.to_owned())
}
pub(crate) fn source_language(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit_once('.')?.1;
    match extension {
        "dart" => Some("dart"),
        "py" => Some("python"),
        "java" => Some("java"),
        "cs" => Some("csharp"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "ts" | "tsx" | "mts" | "cts" => Some("typescript"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" => Some("cpp"),
        _ => None,
    }
}

fn is_private(function: &FunctionSource, language: &str) -> bool {
    if function.name.starts_with('_') {
        return true;
    }
    let source = function.source.trim_start();
    match language {
        "cpp" => starts_with_word(source, "static"),
        "csharp" | "java" => contains_word(source, "private"),
        "go" => function.name.chars().next().is_some_and(char::is_lowercase),
        "rust" => !starts_with_word(source, "pub") && !source.starts_with("pub("),
        _ => false,
    }
}

pub(crate) fn declaration_open(source: &str, name: &str) -> Option<usize> {
    identifier_positions(source, name).find_map(|end| {
        let suffix = &source[end..];
        let whitespace = suffix.len() - suffix.trim_start().len();
        (suffix.as_bytes().get(whitespace) == Some(&b'(')).then_some(end + whitespace)
    })
}

fn direct_forwarding_call(tail: &str) -> Option<(&str, &str)> {
    let expression = direct_returned_expression(tail)?;
    let mut rest = expression.trim();
    for receiver in ["this.", "self."] {
        if let Some(stripped) = rest.strip_prefix(receiver) {
            rest = stripped;
            break;
        }
    }
    let target_end = rest
        .char_indices()
        .take_while(|(_, character)| is_identifier_char(*character))
        .last()
        .map(|(index, character)| index + character.len_utf8())?;
    let target = &rest[..target_end];
    if !target.chars().next().is_some_and(is_identifier_start) {
        return None;
    }
    let suffix = rest[target_end..].trim_start();
    if !suffix.starts_with('(') {
        return None;
    }
    let close = matching_delimiter(suffix, 0, b'(', b')')?;
    if !suffix[close + 1..].trim().is_empty() {
        return None;
    }
    let arguments = &suffix[1..close];
    if arguments.contains('(') || arguments.contains(')') {
        return None;
    }
    Some((target, arguments))
}

// code-buster-ignore complex-function: cross-language wrapper bodies are normalized by one bounded parser.
pub(crate) fn direct_returned_expression(tail: &str) -> Option<&str> {
    let mut body = tail.trim();
    if let Some(stripped) = body.strip_prefix("async ") {
        body = stripped.trim();
    }
    if let Some(stripped) = body.strip_prefix("=>") {
        body = stripped.trim();
    } else if body.starts_with('{') {
        body = body.strip_prefix('{')?.strip_suffix('}')?.trim();
    } else if let Some(stripped) = body.strip_prefix("->") {
        let colon = stripped.find(':');
        let brace = stripped.find('{');
        if colon.is_some_and(|colon| brace.is_none_or(|brace| colon < brace)) {
            body = stripped[colon? + 1..].trim();
        } else {
            let brace = brace?;
            body = stripped[brace + 1..].strip_suffix('}')?.trim();
        }
    } else if let Some(stripped) = body.strip_prefix(':') {
        if let Some(brace) = stripped.find('{') {
            body = stripped[brace + 1..].strip_suffix('}')?.trim();
        } else {
            body = stripped.trim();
        }
    } else {
        let brace = body.find('{')?;
        let return_type = body[..brace].trim();
        if return_type.is_empty() || return_type.contains([';', '=']) {
            return None;
        }
        body = body[brace + 1..].strip_suffix('}')?.trim();
    }
    if let Some(stripped) = body.strip_prefix("return ") {
        body = stripped.trim();
    }
    if let Some(stripped) = body.strip_prefix("await ") {
        body = stripped.trim();
    }
    if let Some(stripped) = body.strip_suffix(';') {
        body = stripped.trim();
    }
    Some(body)
}

pub(crate) fn forwarded_parameter_names<'a>(
    source: &'a str,
    language: &str,
) -> Option<Vec<&'a str>> {
    let mut result = Vec::new();
    for raw in split_top_level(source) {
        let mut parameter = raw.trim();
        if parameter.is_empty() || language == "cpp" && parameter == "void" {
            continue;
        }
        parameter = parameter.trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, '{' | '}' | '[' | ']')
        });
        if let Some((before_default, _)) = parameter.split_once('=') {
            parameter = before_default.trim();
        }
        if parameter.contains(['(', '{', '[']) {
            return None;
        }
        let name_source = parameter
            .split_once(':')
            .map_or(parameter, |(before_colon, _)| before_colon);
        let identifiers = identifier_slices(name_source).collect::<Vec<_>>();
        let name = if language == "go" {
            identifiers.first()
        } else {
            identifiers.last()
        }?;
        if !matches!(*name, "this" | "self") {
            result.push(*name);
        }
    }
    Some(result)
}

pub(crate) fn split_top_level(source: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0isize;
    let mut start = 0;
    for (index, character) in source.char_indices() {
        match character {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                result.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    result.push(&source[start..]);
    result
}

pub(crate) fn matching_delimiter(
    source: &str,
    open: usize,
    opening: u8,
    closing: u8,
) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        if *byte == opening {
            depth += 1;
        } else if *byte == closing {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn calls_function(function: &FunctionSource, name: &str) -> bool {
    let code = if function.path.ends_with(".rs") {
        function_lexical_facts(&function.source).0
    } else {
        mask_comments_and_strings(&function.source)
    };
    identifier_positions(&code, name).any(|end| {
        let suffix = &code[end..];
        let whitespace = suffix.len() - suffix.trim_start().len();
        suffix.as_bytes().get(whitespace) == Some(&b'(')
    })
}

pub(crate) fn mask_comments_and_strings(source: &str) -> String {
    CommentAndStringMasker::new(source).mask()
}

#[derive(Clone, Copy)]
enum MaskState {
    Code,
    LineComment,
    BlockComment,
    Quoted(QuotedMask),
}

#[derive(Clone, Copy)]
struct QuotedMask {
    opening: usize,
    output_start: usize,
    delimiter: u8,
    triple: bool,
    raw: bool,
}

impl QuotedMask {
    fn is_boundary(self, byte: u8) -> bool {
        byte == self.delimiter || byte == b'\n' || (!self.raw && byte == b'\\')
    }
}

struct CommentAndStringMasker<'a> {
    source: &'a str,
    bytes: &'a [u8],
    output: String,
    index: usize,
    state: MaskState,
}

impl<'a> CommentAndStringMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            output: String::with_capacity(source.len()),
            index: 0,
            state: MaskState::Code,
        }
    }

    fn mask(mut self) -> String {
        loop {
            while self.index < self.bytes.len() {
                self.advance();
            }
            if !self.reject_unterminated_literal() {
                return self.output;
            }
        }
    }

    fn advance(&mut self) {
        match self.state {
            MaskState::Code => self.advance_code(),
            MaskState::LineComment => self.advance_line_comment(),
            MaskState::BlockComment => self.advance_block_comment(),
            MaskState::Quoted(literal) => self.advance_quoted(literal),
        }
    }

    fn advance_code(&mut self) {
        if self.starts_with(b"//") {
            self.mask_bytes(2);
            self.state = MaskState::LineComment;
        } else if self.starts_with(b"/*") {
            self.mask_bytes(2);
            self.state = MaskState::BlockComment;
        } else if matches!(self.bytes[self.index], b'\'' | b'"') {
            self.begin_quoted();
        } else {
            self.copy_code_run();
        }
    }

    fn advance_line_comment(&mut self) {
        if self.bytes[self.index] == b'\n' {
            self.copy_newline();
            self.state = MaskState::Code;
            return;
        }

        let end = self.bytes[self.index..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(self.bytes.len(), |offset| self.index + offset);
        self.mask_bytes(end - self.index);
    }

    fn advance_block_comment(&mut self) {
        if self.starts_with(b"*/") {
            self.mask_bytes(2);
            self.state = MaskState::Code;
        } else if self.bytes[self.index] == b'\n' {
            self.copy_newline();
        } else {
            self.mask_block_comment_run();
        }
    }

    fn advance_quoted(&mut self, literal: QuotedMask) {
        if literal.triple {
            self.advance_triple_quoted(literal);
        } else {
            self.advance_single_quoted(literal);
        }
    }

    fn advance_single_quoted(&mut self, literal: QuotedMask) {
        let byte = self.bytes[self.index];
        if byte == literal.delimiter {
            self.mask_bytes(1);
            self.state = MaskState::Code;
        } else if byte == b'\n' {
            self.reject_literal(literal);
        } else if !literal.raw && byte == b'\\' {
            self.mask_escaped_pair();
        } else {
            self.mask_literal_run(literal);
        }
    }

    fn advance_triple_quoted(&mut self, literal: QuotedMask) {
        if self.starts_with(&[literal.delimiter; 3]) {
            self.mask_bytes(3);
            self.state = MaskState::Code;
        } else if !literal.raw && self.bytes[self.index] == b'\\' {
            self.mask_escaped_pair();
        } else if self.bytes[self.index] == b'\n' {
            self.copy_newline();
        } else {
            self.mask_literal_run(literal);
        }
    }

    fn begin_quoted(&mut self) {
        let delimiter = self.bytes[self.index];
        let triple = self.starts_with(&[delimiter; 3]);
        let literal = QuotedMask {
            opening: self.index,
            output_start: self.output.len(),
            delimiter,
            triple,
            raw: self.has_raw_prefix(),
        };
        self.mask_bytes(if triple { 3 } else { 1 });
        self.state = MaskState::Quoted(literal);
    }

    fn reject_unterminated_literal(&mut self) -> bool {
        let MaskState::Quoted(literal) = self.state else {
            return false;
        };
        self.reject_literal(literal);
        true
    }

    fn reject_literal(&mut self, literal: QuotedMask) {
        self.output.truncate(literal.output_start);
        self.output.push(literal.delimiter as char);
        self.index = literal.opening + 1;
        self.state = MaskState::Code;
    }

    fn copy_code_run(&mut self) {
        let start = self.index;
        self.index += 1;
        while self.index < self.bytes.len()
            && !matches!(self.bytes[self.index], b'/' | b'\'' | b'"')
        {
            self.index += 1;
        }
        self.output.push_str(&self.source[start..self.index]);
    }

    fn mask_block_comment_run(&mut self) {
        let start = self.index;
        self.index += 1;
        while self.index < self.bytes.len()
            && self.bytes[self.index] != b'\n'
            && !self.starts_with(b"*/")
        {
            self.index += 1;
        }
        self.output
            .extend(std::iter::repeat_n(' ', self.index - start));
    }

    fn mask_literal_run(&mut self, literal: QuotedMask) {
        let start = self.index;
        self.index += 1;
        while self.index < self.bytes.len() && !literal.is_boundary(self.bytes[self.index]) {
            self.index += 1;
        }
        self.output
            .extend(std::iter::repeat_n(' ', self.index - start));
    }

    fn mask_escaped_pair(&mut self) {
        let end = (self.index + 2).min(self.bytes.len());
        while self.index < end {
            if self.bytes[self.index] == b'\n' {
                self.copy_newline();
            } else {
                self.mask_bytes(1);
            }
        }
    }

    fn mask_bytes(&mut self, count: usize) {
        self.output.extend(std::iter::repeat_n(' ', count));
        self.index += count;
    }

    fn copy_newline(&mut self) {
        self.output.push('\n');
        self.index += 1;
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.bytes[self.index..].starts_with(needle)
    }

    fn has_raw_prefix(&self) -> bool {
        self.index > 0
            && matches!(self.bytes[self.index - 1], b'r' | b'R')
            && (self.index == 1
                || !(self.bytes[self.index - 2].is_ascii_alphanumeric()
                    || self.bytes[self.index - 2] == b'_'))
    }
}

fn identifier_positions<'a>(source: &'a str, name: &'a str) -> impl Iterator<Item = usize> + 'a {
    source.match_indices(name).filter_map(move |(start, _)| {
        let before = source[..start].chars().next_back();
        let end = start + name.len();
        let after = source[end..].chars().next();
        (!before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char))
            .then_some(end)
    })
}

fn identifier_slices(source: &str) -> impl Iterator<Item = &str> {
    let mut identifiers = Vec::new();
    let mut start = None;
    for (index, character) in source.char_indices() {
        if start.is_none() && is_identifier_start(character) {
            start = Some(index);
        } else if !is_identifier_char(character)
            && let Some(identifier_start) = start.take()
        {
            identifiers.push(&source[identifier_start..index]);
        }
    }
    if let Some(start) = start {
        identifiers.push(&source[start..]);
    }
    identifiers.into_iter()
}

fn contains_word(source: &str, word: &str) -> bool {
    identifier_positions(source, word).next().is_some()
}

fn contains_word_case_insensitive(source: &str, word: &str) -> bool {
    identifier_slices(source).any(|identifier| identifier.eq_ignore_ascii_case(word))
}

fn starts_with_word(source: &str, word: &str) -> bool {
    source
        .strip_prefix(word)
        .is_some_and(|suffix| !suffix.chars().next().is_some_and(is_identifier_char))
}

fn is_identifier_start(character: char) -> bool {
    character == '_' || character == '$' || character.is_ascii_alphabetic()
}

fn is_identifier_char(character: char) -> bool {
    is_identifier_start(character) || character.is_ascii_digit()
}
