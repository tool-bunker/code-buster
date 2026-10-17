fn dart_functions(path: &str, source: &str) -> Vec<FunctionSource> {
    let masked = mask_comments_and_strings(source);
    let mut candidates = DART_CALLABLE_PREFIX
        .captures_iter(&masked)
        .filter_map(|captures| {
            let complete = captures.get(0)?;
            let name = captures.name("name")?;
            Some((
                complete.start(),
                complete.end(),
                name.as_str().to_owned(),
                Some(complete.end() - 1),
            ))
        })
        .chain(
            DART_OPERATOR_PREFIX
                .captures_iter(&masked)
                .filter_map(|captures| {
                    let complete = captures.get(0)?;
                    let name = captures.name("name")?;
                    Some((
                        complete.start(),
                        complete.end(),
                        name.as_str().to_owned(),
                        Some(complete.end() - 1),
                    ))
                }),
        )
        .chain(
            DART_RECORD_RETURN_PREFIX
                .captures_iter(&masked)
                .filter_map(|captures| {
                    let complete = captures.get(0)?;
                    let name = captures.name("name")?;
                    Some((
                        complete.start(),
                        complete.end(),
                        name.as_str().to_owned(),
                        Some(complete.end() - 1),
                    ))
                }),
        )
        .chain(
            DART_POSITIONAL_RECORD_RETURN_PREFIX
                .captures_iter(&masked)
                .filter_map(|captures| {
                    let complete = captures.get(0)?;
                    let name = captures.name("name")?;
                    Some((
                        complete.start(),
                        complete.end(),
                        name.as_str().to_owned(),
                        Some(complete.end() - 1),
                    ))
                }),
        )
        .chain(DART_GETTER_PREFIX.captures_iter(&masked).filter_map(
            |captures| {
                let complete = captures.get(0)?;
                let name = captures.name("name")?;
                Some((
                    complete.start(),
                    complete.end(),
                    name.as_str().to_owned(),
                    None,
                ))
            },
        ))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| candidate.0);

    let mut functions = Vec::new();
    let mut bodies = BTreeSet::new();
    for (start, end, name, open) in candidates {
        let header = masked[start..end].trim_start();
        let first = header
            .split(|character: char| character.is_whitespace() || character == '(')
            .next()
            .unwrap_or_default();
        if is_control_keyword(&name)
            || matches!(
                first,
                "return"
                    | "await"
                    | "new"
                    | "case"
                    | "class"
                    | "enum"
                    | "mixin"
                    | "extension"
                    | "typedef"
                    | "for"
                    | "if"
                    | "while"
                    | "switch"
                    | "catch"
                    | "assert"
                    | "throw"
            )
            || header.contains('=') && !header.contains("operator")
        {
            continue;
        }
        let body_search = if let Some(open) = open {
            let Some(close) = matching_delimiter(&masked, open, b'(', b')') else {
                continue;
            };
            close + 1
        } else {
            end
        };
        let Some((body_start, body_end)) = dart_callable_body(&masked, body_search) else {
            continue;
        };
        if !bodies.insert(body_start) {
            continue;
        }
        let declaration_line = line_at(source, start);
        functions.push(FunctionSource {
            path: path.to_owned(),
            name,
            line: attached_declaration_line(source, declaration_line),
            end_line: line_at(source, body_end),
            contract_signature: false,
            source: normalize_dart_function_source(&source[start..=body_end]),
        });
    }
    functions
}

struct DartCallableBody<'a> {
    source: &'a str,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DartCallableBody<'a> {
    fn candidate(source: &'a str, offset: usize) -> Self {
        let mut candidate = Self {
            source,
            bytes: source.as_bytes(),
            offset,
        };
        candidate.skip_whitespace();
        candidate.skip_modifier();
        candidate
    }

    fn skip_whitespace(&mut self) {
        self.offset +=
            self.source[self.offset..].len() - self.source[self.offset..].trim_start().len();
    }

    fn skip_modifier(&mut self) {
        for modifier in ["async*", "async", "sync*"] {
            if self.is_modifier(modifier) {
                self.offset += modifier.len();
                self.skip_whitespace();
                break;
            }
        }
    }

    fn is_modifier(&self, modifier: &str) -> bool {
        self.source[self.offset..].starts_with(modifier)
            && self
                .bytes
                .get(self.offset + modifier.len())
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
    }

    fn has_body_boundary(&self) -> bool {
        self.source[self.offset..].starts_with("=>")
            || self.bytes.get(self.offset) == Some(&b'{')
            || self.bytes.get(self.offset) == Some(&b':')
    }

    fn parse(mut self) -> Option<(usize, usize)> {
        if !self.has_body_boundary() {
            return None;
        }
        while self.offset < self.bytes.len() {
            if self.bytes[self.offset..].starts_with(b"=>") {
                return self.arrow_body();
            }
            if self.bytes[self.offset] == b'{' {
                let end = matching_delimiter(self.source, self.offset, b'{', b'}')?;
                return Some((self.offset, end));
            }
            if self.bytes[self.offset] == b';' {
                return None;
            }
            self.offset += 1;
        }
        None
    }

    fn arrow_body(&self) -> Option<(usize, usize)> {
        let mut depths = [0usize; 3];
        for (index, byte) in self.bytes.iter().enumerate().skip(self.offset + 2) {
            match *byte {
                b'(' => depths[0] += 1,
                b')' => depths[0] = depths[0].saturating_sub(1),
                b'[' => depths[1] += 1,
                b']' => depths[1] = depths[1].saturating_sub(1),
                b'{' => depths[2] += 1,
                b'}' => depths[2] = depths[2].saturating_sub(1),
                b';' if depths == [0, 0, 0] => return Some((self.offset, index)),
                _ => {}
            }
        }
        None
    }
}

fn dart_callable_body(source: &str, offset: usize) -> Option<(usize, usize)> {
    DartCallableBody::candidate(source, offset).parse()
}


// code-buster-ignore complex-function: the single-pass normalizer keeps literal and whitespace state local.
fn normalize_dart_function_source(source: &str) -> String {
    let source = mask_comments_preserving_strings(source);
    let bytes = source.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    let mut pending_space = false;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            pending_space = !normalized.is_empty();
            index += 1;
            continue;
        }
        let (literal_start, raw) = if matches!(bytes[index], b'r' | b'R')
            && bytes
                .get(index + 1)
                .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
        {
            (index + 1, true)
        } else if matches!(bytes[index], b'\'' | b'"') {
            (index, false)
        } else {
            if pending_space {
                normalized.push(b' ');
                pending_space = false;
            }
            normalized.push(bytes[index]);
            index += 1;
            continue;
        };
        if pending_space {
            normalized.push(b' ');
            pending_space = false;
        }
        if literal_start > index {
            normalized.extend_from_slice(&bytes[index..literal_start]);
        }
        let end = dart_string_end(bytes, literal_start, raw);
        normalized.extend_from_slice(&bytes[literal_start..end]);
        index = end;
    }
    String::from_utf8(normalized).expect("normalized Dart function must remain UTF-8")
}

#[derive(Clone, Copy)]
struct DartQuoteShape {
    delimiter: u8,
    width: usize,
}

impl DartQuoteShape {
    fn at(bytes: &[u8], start: usize) -> Self {
        let delimiter = bytes[start];
        let triple = bytes.get(start..start + 3) == Some(&[delimiter, delimiter, delimiter]);
        Self {
            delimiter,
            width: if triple { 3 } else { 1 },
        }
    }

    fn closes_at(self, bytes: &[u8], index: usize) -> bool {
        if self.width == 1 {
            bytes[index] == self.delimiter
        } else {
            bytes.get(index..index + 3)
                == Some(&[self.delimiter, self.delimiter, self.delimiter])
        }
    }
}

enum DartStringTransition {
    ContinueAt(usize),
    CompleteAt(usize),
}

fn dart_string_end(bytes: &[u8], start: usize, raw: bool) -> usize {
    let shape = DartQuoteShape::at(bytes, start);
    let mut index = start + shape.width;
    while index < bytes.len() {
        match dart_string_transition(bytes, index, shape, raw) {
            DartStringTransition::ContinueAt(next) => index = next,
            DartStringTransition::CompleteAt(end) => return end,
        }
    }
    index
}

fn dart_string_transition(
    bytes: &[u8],
    index: usize,
    shape: DartQuoteShape,
    raw: bool,
) -> DartStringTransition {
    if shape.closes_at(bytes, index) {
        return DartStringTransition::CompleteAt(index + shape.width);
    }
    if !raw && bytes[index] == b'\\' {
        return DartStringTransition::ContinueAt((index + 2).min(bytes.len()));
    }
    if !raw && bytes.get(index..index + 2) == Some(b"${") {
        return DartStringTransition::ContinueAt(dart_interpolation_end(bytes, index + 2));
    }
    DartStringTransition::ContinueAt(index + 1)
}

fn dart_interpolation_end(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 1usize;
    while index < bytes.len() {
        if let Some((nested_start, nested_raw)) = dart_nested_string_start(bytes, index) {
            index = dart_string_end(bytes, nested_start, nested_raw);
            continue;
        }
        match bytes[index] {
            b'{' => depth += 1,
            b'}' if depth == 1 => return index + 1,
            b'}' => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    index
}

fn dart_nested_string_start(bytes: &[u8], index: usize) -> Option<(usize, bool)> {
    if matches!(bytes[index], b'r' | b'R')
        && bytes
            .get(index + 1)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
    {
        Some((index + 1, true))
    } else if matches!(bytes[index], b'\'' | b'"') {
        Some((index, false))
    } else {
        None
    }
}

fn matching_masked_brace(source: &str, opening: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in source.bytes().enumerate().skip(opening) {
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}
static DART_CALLABLE_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:external|static|abstract|covariant|const|factory)[ \t]+)*(?:(?:[A-Za-z_$(][^;{}\n]*?)[ \t]+)?(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)[ \t]*(?:<[^>{}]*>)?[ \t]*\(")
        .expect("Dart callable prefix regex must compile")
});
static DART_RECORD_RETURN_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:external|static|abstract|covariant)[ \t]+)*(?:(?:[A-Za-z_$][\w$]*[ \t]*<\(\{[^;\n]*\}\)>|\(\{[^;\n]*\}\))\??)[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:<[^>{}]*>)?[ \t]*\(")
        .expect("Dart record-return callable prefix regex must compile")
});
static DART_POSITIONAL_RECORD_RETURN_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*\((?:[^;{}()]|\([^;{}()]*\))*\)[ \t\r\n]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:<[^>{}]*>)?[ \t]*\(")
        .expect("Dart positional-record-return callable prefix regex must compile")
});
static DART_OPERATOR_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:external|static|abstract|covariant|const|factory)[ \t]+)*(?:[A-Za-z_$(][^;{}\n]*?[ \t]+)?operator[ \t]+(?P<name>[^\s(]+)[ \t]*\(")
        .expect("Dart operator prefix regex must compile")
});
static DART_GETTER_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:external|static|abstract|covariant)[ \t]+)*(?:[A-Za-z_$(][^;{}\n]*?[ \t]+)?get[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*")
        .expect("Dart getter prefix regex must compile")
});
