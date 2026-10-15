pub(crate) mod analyzer_config;
pub(crate) mod core;
pub(crate) mod flutter_build;
pub(crate) mod index;
pub(crate) mod lifecycle;
pub(crate) mod model_contracts;
pub(crate) mod model_duplication;
pub(crate) mod mvvm;
pub(crate) mod null_assertion;
pub(crate) mod oop;
pub(crate) mod package_cycle;
pub(crate) mod performance;
pub(crate) mod reliability;
pub(crate) mod security;

pub(crate) fn attached_declaration_line(source: &str, declaration_line: usize) -> usize {
    attached_line(
        source,
        declaration_line,
        is_attachable_declaration_prefix,
        is_documentation_start,
    )
}

pub(crate) fn attached_documentation_line(source: &str, declaration_line: usize) -> usize {
    attached_line(
        source,
        declaration_line,
        is_documentation_prefix,
        is_documentation_prefix,
    )
}

fn attached_line(
    source: &str,
    declaration_line: usize,
    is_attachable: impl Fn(&str) -> bool,
    marks_attachment: impl Fn(&str) -> bool,
) -> usize {
    let lines = source.split('\n').collect::<Vec<_>>();
    let mut index = declaration_line.saturating_sub(1);
    let mut attached = false;
    while index > 0 {
        let previous = lines[index - 1].trim();
        if !is_attachable(previous) {
            break;
        }
        attached |= marks_attachment(previous);
        index -= 1;
    }
    if attached {
        index + 1
    } else {
        declaration_line
    }
}

fn is_attachable_declaration_prefix(line: &str) -> bool {
    ["//", "/*", "*", "@"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        || line == "*/"
}

fn is_documentation_prefix(line: &str) -> bool {
    ["///", "/**", "*", "@"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

fn is_documentation_start(line: &str) -> bool {
    ["///", "/**", "@"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

struct QuoteAwareCodeBytes<'a> {
    bytes: &'a [u8],
    index: usize,
    quote: Option<u8>,
}

impl<'a> QuoteAwareCodeBytes<'a> {
    fn new(source: &'a str, start: usize) -> Self {
        Self {
            bytes: source.as_bytes(),
            index: start,
            quote: None,
        }
    }

    fn advance_quoted(&mut self, byte: u8, quote: u8) {
        if byte == b'\\' && self.index < self.bytes.len() {
            self.index += 1;
        } else if byte == quote {
            self.quote = None;
        }
    }
}

impl Iterator for QuoteAwareCodeBytes<'_> {
    type Item = (usize, u8);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let index = self.index;
            let &byte = self.bytes.get(index)?;
            self.index += 1;
            match self.quote {
                Some(quote) => self.advance_quoted(byte, quote),
                None if matches!(byte, b'\'' | b'"') => self.quote = Some(byte),
                None => return Some((index, byte)),
            }
        }
    }
}

fn matching_delimiter_in(
    code_bytes: impl Iterator<Item = (usize, u8)>,
    opening: u8,
    closing: u8,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in code_bytes {
        if byte == opening {
            depth += 1;
            continue;
        }
        if byte != closing {
            continue;
        }
        depth = depth.checked_sub(1)?;
        if depth == 0 {
            return Some(index);
        }
    }
    None
}

pub(crate) fn matching_delimiter(
    source: &str,
    open: usize,
    opening: u8,
    closing: u8,
) -> Option<usize> {
    let code_bytes = source.as_bytes().iter().copied().enumerate().skip(open);
    matching_delimiter_in(code_bytes, opening, closing)
}

pub(crate) fn quote_aware_matching_delimiter(
    source: &str,
    open: usize,
    opening: u8,
    closing: u8,
) -> Option<usize> {
    matching_delimiter_in(QuoteAwareCodeBytes::new(source, open), opening, closing)
}

pub(crate) fn top_level_arrow(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depths = [0usize; 3];
    let mut quote = None;
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        if let Some(current_quote) = quote {
            if bytes[index] == b'\\' {
                index += 2;
                continue;
            }
            if bytes[index] == current_quote {
                quote = None;
            }
        } else {
            match bytes[index] {
                b'\'' | b'"' => quote = Some(bytes[index]),
                b'(' => depths[0] += 1,
                b')' => depths[0] = depths[0].saturating_sub(1),
                b'[' => depths[1] += 1,
                b']' => depths[1] = depths[1].saturating_sub(1),
                b'{' => depths[2] += 1,
                b'}' => depths[2] = depths[2].saturating_sub(1),
                b'=' if depths == [0, 0, 0] && bytes[index + 1] == b'>' => {
                    return Some(index);
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

fn split_code_bytes<const TRACK_ANGLES: bool>(
    source: &str,
    separator: u8,
    code_bytes: impl Iterator<Item = (usize, u8)>,
) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut depths = [0usize; 4];
    for (index, byte) in code_bytes {
        match byte {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'[' => depths[1] += 1,
            b']' => depths[1] = depths[1].saturating_sub(1),
            b'{' => depths[2] += 1,
            b'}' => depths[2] = depths[2].saturating_sub(1),
            b'<' if TRACK_ANGLES => depths[3] += 1,
            b'>' if TRACK_ANGLES => depths[3] = depths[3].saturating_sub(1),
            value if value == separator && depths == [0, 0, 0, 0] => {
                result.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    result.push(&source[start..]);
    result
}

pub(crate) fn split_top_level(source: &str, separator: u8) -> Vec<&str> {
    let code_bytes = source.as_bytes().iter().copied().enumerate();
    split_code_bytes::<false>(source, separator, code_bytes)
}

pub(crate) fn quote_aware_split_top_level(source: &str, separator: u8) -> Vec<&str> {
    split_code_bytes::<false>(source, separator, QuoteAwareCodeBytes::new(source, 0))
}

pub(crate) fn quote_aware_split_top_level_with_angles(source: &str, separator: u8) -> Vec<&str> {
    split_code_bytes::<true>(source, separator, QuoteAwareCodeBytes::new(source, 0))
}
