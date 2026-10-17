use std::collections::BTreeSet;

/// Returns zero-based source lines belonging to items that are unconditionally
/// test-only according to an attached `test` or `cfg` attribute.
pub(crate) fn test_lines(source: &str, masked: &str) -> BTreeSet<usize> {
    if source.len() != masked.len() {
        return BTreeSet::new();
    }
    let mut lines = BTreeSet::new();
    let bytes = masked.as_bytes();
    let line_starts: Vec<_> = std::iter::once(0)
        .chain(
            bytes
                .iter()
                .enumerate()
                .filter_map(|(offset, byte)| (*byte == b'\n').then_some(offset + 1)),
        )
        .collect();
    let mut cursor = 0;

    while cursor < bytes.len() {
        let Some(attribute) = outer_attribute(masked, cursor) else {
            cursor += 1;
            continue;
        };

        let attribute_start = cursor;
        let mut end = attribute.end;
        let mut implies_test = attribute_implies_test(attribute.content(source));

        loop {
            let next = skip_whitespace(bytes, end);
            let Some(attribute) = outer_attribute(masked, next) else {
                end = next;
                break;
            };
            implies_test |= attribute_implies_test(attribute.content(source));
            end = attribute.end;
        }

        if implies_test && let Some(item_end) = attributed_item_end(masked, end) {
            insert_line_range(&mut lines, &line_starts, attribute_start, item_end);
            cursor = item_end;
            continue;
        }

        // Resume at the prospective item rather than skipping it: a non-test
        // module can contain test-only items of its own.
        cursor = end.max(cursor + 1);
    }

    lines
}

struct Attribute {
    content_start: usize,
    content_end: usize,
    end: usize,
}

impl Attribute {
    fn content<'a>(&self, source: &'a str) -> &'a str {
        &source[self.content_start..self.content_end]
    }
}

fn outer_attribute(source: &str, start: usize) -> Option<Attribute> {
    let bytes = source.as_bytes();
    if bytes.get(start) != Some(&b'#') {
        return None;
    }
    let mut open = skip_whitespace(bytes, start + 1);
    if bytes.get(open) == Some(&b'!') {
        return None;
    }
    if bytes.get(open) != Some(&b'[') {
        return None;
    }
    let close = matching_delimiter(source, open)?;
    open += 1;
    Some(Attribute {
        content_start: open,
        content_end: close,
        end: close + 1,
    })
}

fn attribute_implies_test(content: &str) -> bool {
    let mut parser = Parser::new(content);
    let Some(name) = parser.identifier() else {
        return false;
    };
    if name == "test" {
        return parser.finished();
    }
    if name != "cfg" || !parser.consume(b'(') {
        return false;
    }
    let Ok(implies_test) = parser.cfg_expression() else {
        return false;
    };
    if parser.consume(b',') && parser.peek() != Some(b')') {
        return false;
    }
    parser.consume(b')') && parser.finished() && implies_test
}

struct Parser<'a> {
    source: &'a [u8],
    cursor: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            cursor: 0,
        }
    }

    fn cfg_expression(&mut self) -> Result<bool, ()> {
        let name = self.identifier().ok_or(())?;
        if self.consume(b'(') {
            return self.cfg_function(name);
        }
        self.cfg_atom(name)
    }

    fn cfg_function(&mut self, name: &str) -> Result<bool, ()> {
        match name {
            "all" => self.cfg_list(false, |result, branch| result || branch),
            "any" => self.cfg_list(true, |result, branch| result && branch),
            "not" => self.cfg_not(),
            _ => Err(()),
        }
    }

    fn cfg_not(&mut self) -> Result<bool, ()> {
        self.cfg_expression()?;
        if self.consume(b',') && self.peek() != Some(b')') {
            return Err(());
        }
        self.consume(b')').then_some(false).ok_or(())
    }

    fn cfg_atom(&mut self, name: &str) -> Result<bool, ()> {
        if self.consume(b'=') {
            let value = self.string_literal()?;
            return Ok(name == "feature" && value == "test");
        }
        Ok(name == "test")
    }

    fn cfg_list(
        &mut self,
        initial: bool,
        combine: impl Fn(bool, bool) -> bool,
    ) -> Result<bool, ()> {
        if self.consume(b')') {
            return Ok(false);
        }
        let mut result = initial;
        loop {
            result = combine(result, self.cfg_expression()?);
            if self.consume(b')') {
                return Ok(result);
            }
            if !self.consume(b',') {
                return Err(());
            }
            if self.consume(b')') {
                return Ok(result);
            }
        }
    }

    fn identifier(&mut self) -> Option<&'a str> {
        self.skip_whitespace();
        let start = self.cursor;
        if self.source.get(self.cursor) == Some(&b'r')
            && self.source.get(self.cursor + 1) == Some(&b'#')
        {
            self.cursor += 2;
        }
        let first = *self.source.get(self.cursor)?;
        if first != b'_' && !first.is_ascii_alphabetic() {
            self.cursor = start;
            return None;
        }
        self.cursor += 1;
        while self
            .source
            .get(self.cursor)
            .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
        {
            self.cursor += 1;
        }
        std::str::from_utf8(&self.source[start..self.cursor]).ok()
    }

    fn string_literal(&mut self) -> Result<&'a str, ()> {
        self.skip_whitespace();
        if self.source.get(self.cursor) != Some(&b'"') {
            return Err(());
        }
        self.cursor += 1;
        let start = self.cursor;
        while let Some(byte) = self.source.get(self.cursor) {
            match byte {
                b'\\' => {
                    self.cursor += 2;
                    if self.cursor > self.source.len() {
                        return Err(());
                    }
                }
                b'"' => {
                    let end = self.cursor;
                    self.cursor += 1;
                    return std::str::from_utf8(&self.source[start..end]).map_err(|_| ());
                }
                b'\n' | b'\r' => return Err(()),
                _ => self.cursor += 1,
            }
        }
        Err(())
    }

    fn consume(&mut self, expected: u8) -> bool {
        self.skip_whitespace();
        if self.source.get(self.cursor) == Some(&expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_whitespace();
        self.source.get(self.cursor).copied()
    }

    fn finished(&mut self) -> bool {
        self.skip_whitespace();
        self.cursor == self.source.len()
    }

    fn skip_whitespace(&mut self) {
        self.cursor = skip_whitespace(self.source, self.cursor);
    }
}

#[derive(Clone, Copy)]
enum ItemKind {
    Body,
    Semicolon,
    Macro,
}

fn attributed_item_end(source: &str, start: usize) -> Option<usize> {
    let start = skip_whitespace(source.as_bytes(), start);
    let kind = item_kind(source, start)?;
    match kind {
        ItemKind::Body => body_item_end(source, start),
        ItemKind::Semicolon => semicolon_item_end(source, start),
        ItemKind::Macro => macro_item_end(source, start),
    }
}

fn item_kind(source: &str, start: usize) -> Option<ItemKind> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    let mut saw_const = false;

    loop {
        let (word, end) = word_at(source, cursor)?;
        cursor = end;
        match word {
            "pub" => {
                cursor = skip_whitespace(bytes, cursor);
                if bytes.get(cursor) == Some(&b'(') {
                    cursor = matching_delimiter(source, cursor)? + 1;
                }
            }
            "async" | "unsafe" | "default" => {}
            "const" => saw_const = true,
            "extern" => {
                cursor = skip_quoted_string(bytes, cursor)?;
                cursor = skip_whitespace(bytes, cursor);
                if bytes.get(cursor) == Some(&b'{') {
                    return Some(ItemKind::Body);
                }
                let (next, next_end) = word_at(source, cursor)?;
                return match next {
                    "crate" => Some(ItemKind::Semicolon),
                    "fn" => Some(ItemKind::Body),
                    _ => {
                        cursor = next_end;
                        macro_kind(source, start, cursor)
                    }
                };
            }
            "fn" | "mod" | "struct" | "enum" | "union" | "trait" | "impl" => {
                return Some(ItemKind::Body);
            }
            "type" | "use" | "static" => return Some(ItemKind::Semicolon),
            "macro_rules" | "macro" => return Some(ItemKind::Macro),
            "auto" => {
                let (next, _) = word_at(source, cursor)?;
                return (next == "trait").then_some(ItemKind::Body);
            }
            _ if saw_const => return Some(ItemKind::Semicolon),
            _ => return macro_kind(source, start, cursor),
        }
    }
}

fn macro_kind(source: &str, start: usize, mut cursor: usize) -> Option<ItemKind> {
    let bytes = source.as_bytes();
    loop {
        cursor = skip_whitespace(bytes, cursor);
        if bytes.get(cursor) == Some(&b'!') {
            return Some(ItemKind::Macro);
        }
        if bytes.get(cursor..cursor + 2) != Some(b"::") {
            return None;
        }
        cursor += 2;
        let (_, end) = word_at(source, cursor)?;
        cursor = end;
        if cursor <= start {
            return None;
        }
    }
}

enum BodyScanStep {
    Advance,
    ContinueAt(usize),
    Complete(usize),
}

fn body_item_end(source: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    let mut delimiters = Vec::new();

    while cursor < source.len() {
        cursor = match body_scan_step(source, cursor, &mut delimiters)? {
            BodyScanStep::Advance => cursor + 1,
            BodyScanStep::ContinueAt(next) => next,
            BodyScanStep::Complete(end) => return Some(end),
        };
    }
    None
}

fn body_scan_step(source: &str, cursor: usize, delimiters: &mut Vec<u8>) -> Option<BodyScanStep> {
    let byte = source.as_bytes()[cursor];
    if delimiters.is_empty() {
        return top_level_body_step(source, cursor, byte, delimiters);
    }
    update_body_delimiters(byte, delimiters)?;
    Some(BodyScanStep::Advance)
}

fn top_level_body_step(
    source: &str,
    cursor: usize,
    byte: u8,
    delimiters: &mut Vec<u8>,
) -> Option<BodyScanStep> {
    match byte {
        b';' => Some(BodyScanStep::Complete(cursor + 1)),
        b'{' => top_level_brace_step(source, cursor),
        _ => {
            update_body_delimiters(byte, delimiters)?;
            Some(BodyScanStep::Advance)
        }
    }
}

fn top_level_brace_step(source: &str, open: usize) -> Option<BodyScanStep> {
    let bytes = source.as_bytes();
    let close = matching_delimiter(source, open)?;
    let next = skip_whitespace(bytes, close + 1);
    if bytes
        .get(next)
        .is_some_and(|byte| matches!(byte, b'>' | b',' | b')' | b']' | b':'))
    {
        Some(BodyScanStep::ContinueAt(close + 1))
    } else {
        Some(BodyScanStep::Complete(close + 1))
    }
}

fn update_body_delimiters(byte: u8, delimiters: &mut Vec<u8>) -> Option<()> {
    if let Some(closing) = closing_delimiter(byte) {
        delimiters.push(closing);
        return Some(());
    }
    if matches!(byte, b')' | b']' | b'}') {
        return (delimiters.pop() == Some(byte)).then_some(());
    }
    Some(())
}

fn closing_delimiter(byte: u8) -> Option<u8> {
    match byte {
        b'(' => Some(b')'),
        b'[' => Some(b']'),
        b'{' => Some(b'}'),
        _ => None,
    }
}

fn semicolon_item_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    let mut delimiters = Vec::new();
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'(' => delimiters.push(b')'),
            b'[' => delimiters.push(b']'),
            b'{' => delimiters.push(b'}'),
            b')' | b']' | b'}' => {
                if delimiters.pop() != Some(bytes[cursor]) {
                    return None;
                }
            }
            b';' if delimiters.is_empty() => return Some(cursor + 1),
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn macro_item_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let bang = bytes[start..].iter().position(|byte| *byte == b'!')? + start;
    let open = skip_whitespace(bytes, bang + 1);
    if !matches!(bytes.get(open), Some(b'(' | b'[' | b'{')) {
        return None;
    }
    let close = matching_delimiter(source, open)?;
    let after = skip_whitespace(bytes, close + 1);
    if bytes.get(after) == Some(&b';') {
        Some(after + 1)
    } else if bytes[open] == b'{' {
        Some(close + 1)
    } else {
        None
    }
}

fn matching_delimiter(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let closing = match bytes.get(open)? {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut stack = vec![closing];
    let mut cursor = open + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'(' => stack.push(b')'),
            b'[' => stack.push(b']'),
            b'{' => stack.push(b'}'),
            b')' | b']' | b'}' => {
                if stack.pop() != Some(bytes[cursor]) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(cursor);
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn word_at(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let start = skip_whitespace(bytes, start);
    let first = *bytes.get(start)?;
    if first != b'_' && !first.is_ascii_alphabetic() {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
    {
        end += 1;
    }
    Some((&source[start..end], end))
}

fn skip_quoted_string(bytes: &[u8], start: usize) -> Option<usize> {
    let start = skip_whitespace(bytes, start);
    if bytes.get(start) != Some(&b'"') {
        return Some(start);
    }
    let mut cursor = start + 1;
    while let Some(byte) = bytes.get(cursor) {
        match byte {
            b'\\' => cursor += 2,
            b'"' => return Some(cursor + 1),
            b'\n' | b'\r' => return None,
            _ => cursor += 1,
        }
    }
    None
}

fn skip_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

fn insert_line_range(lines: &mut BTreeSet<usize>, line_starts: &[usize], start: usize, end: usize) {
    let first = line_starts.partition_point(|line_start| *line_start <= start) - 1;
    let last_offset = end.saturating_sub(1);
    let last = line_starts.partition_point(|line_start| *line_start <= last_offset) - 1;
    lines.extend(first..=last);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(lines: impl IntoIterator<Item = usize>) -> BTreeSet<usize> {
        lines.into_iter().collect()
    }

    #[test]
    fn recognizes_test_attribute_forms_and_attached_attributes() {
        let source = "#[\n    test\n]\n#[ignore]\nfn multiline()\nwhere\n    (): Sized,\n{\n    assertion();\n}\n\n#[allow(dead_code)] #[test] fn same_line() {}\nproduction();";

        assert_eq!(test_lines(source, source), set((0..=9).chain([11])));
    }

    #[test]
    fn applies_cfg_implication_rules() {
        let source = "#[cfg(test)]\nfn direct() {}\n#[cfg(all(unix, test))]\nfn conjunction() {}\n#[cfg(any(all(test, unix), all(windows, test)))]\nfn alternatives() {}\n#[cfg(all(feature = \"   \", test))]\nfn masked_value() {}";

        assert_eq!(test_lines(source, source), set(0..=7));
    }

    #[test]
    fn treats_test_feature_items_as_test_only() {
        let source = "#[cfg(all(windows, feature = \"test\"))]\nmod support;\n#[cfg(any(unix, feature = \"test\"))]\nmod mixed;\n";

        assert_eq!(test_lines(source, source), set([0, 1]));
    }

    #[test]
    fn leaves_non_implying_unknown_and_malformed_cfg_items_reportable() {
        let source = "#[cfg(not(test))]\nfn negated() {}\n#[cfg(any(test, feature = \"   \"))]\nfn mixed() {}\n#[cfg_attr(test, allow(dead_code))]\nfn conditional_attribute() {}\n#[cfg(all(test, mystery(unix)))]\nfn unknown_expression() {}\n#[cfg(all(test, unix)]\nfn malformed() {}\n#[test(extra)]\nfn malformed_test() {}";

        assert!(test_lines(source, source).is_empty());
    }

    #[test]
    fn marks_nested_modules_without_consuming_following_items() {
        let source = "mod outer {\n    #[cfg(test)]\n    mod fixtures {\n        fn helper() {}\n        mod nested {\n            fn case() {}\n        }\n    }\n    fn live() {}\n}\nfn production() {}";

        assert_eq!(test_lines(source, source), set(1..=7));
    }

    #[test]
    fn handles_split_braces_and_semicolon_items() {
        let source = "#[test]\nfn split(\n)\nwhere\n    (): Sized\n{\n}\n#[cfg(test)]\ntype Fixture = Result<\n    (),\n    Error,\n>;\nfn live() {}";

        assert_eq!(test_lines(source, source), set(0..=11));
    }

    #[test]
    fn preserves_lines_when_masked_text_contained_braces() {
        let source = "fn before() {}\n#[test]\nfn fixture() {\n    let text = \"             \";\n                         \n    verify();\n}\nfn after() {\n    report();\n}";

        assert_eq!(test_lines(source, source), set(1..=6));
        assert!(!test_lines(source, source).contains(&8));
    }

    #[test]
    fn does_not_extend_an_attribute_past_its_single_item() {
        let source = "#[cfg(test)] fn fixture() {} fn production() {\n    report();\n}\n#[cfg(test)] const VALUE: usize = {\n    1\n};\nfn after() {}";

        assert_eq!(test_lines(source, source), set([0, 3, 4, 5]));
    }
}
