use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::dart_core_rules::mask_comments_preserving_strings;
use crate::generic_rules::mask_inactive_preprocessor_branches;
use crate::languages::dart::attached_declaration_line;
use crate::rust_rules::function_lexical_facts;
use crate::trivial_wrappers::{mask_comments_and_strings, matching_delimiter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionSource {
    pub path: String,
    pub name: String,
    pub line: usize,
    pub end_line: usize,
    pub source: String,
}

pub fn extract(sources: &BTreeMap<String, String>) -> Vec<FunctionSource> {
    let mut result = Vec::new();
    let mut language_ranks = BTreeMap::new();
    let cpp_stringifiers = cpp_stringifying_macros(sources.values().map(String::as_str));
    for (path, source) in sources {
        let extension = Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        language_ranks.insert(path.as_str(), language_rank(&extension));
        match extension.as_str() {
            "py" | "mojo" | "nim" | "nims" => {
                result.extend(indentation_functions(path, source, &extension));
            }
            "rs" => result.extend(rust_functions(path, source)),
            "go" => result.extend(go_functions(path, source)),
            "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" => {
                result.extend(javascript_functions(path, source));
            }
            "dart" => result.extend(dart_functions(path, source)),
            "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "m" | "mm" => {
                result.extend(cpp_functions(path, source, &cpp_stringifiers));
            }
            "cs" => result.extend(csharp_functions(path, source)),
            "java" => result.extend(java_functions(path, source)),
            "wren" => result.extend(brace_functions(path, source, &[&BRACE_METHOD])),
            _ => {}
        }
    }
    result.sort_by(|left, right| {
        language_ranks
            .get(left.path.as_str())
            .cmp(&language_ranks.get(right.path.as_str()))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.name.cmp(&right.name))
    });
    result
}

fn language_rank(extension: &str) -> usize {
    match extension {
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "m" | "mm" => 0,
        "cs" => 1,
        "dart" => 2,
        "go" => 3,
        "java" => 4,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" => 5,
        "nim" | "nims" => 6,
        "mojo" => 7,
        "wren" => 8,
        "py" => 9,
        "rs" => 10,
        _ => usize::MAX,
    }
}

#[derive(Clone, Copy)]
enum BraceScanState {
    Code,
    LineComment,
    BlockComment,
    Quote(u8),
}

enum BraceScanTransition {
    Advance(usize),
    Opening,
    Closing,
}

impl BraceScanState {
    fn transition(&mut self, byte: u8, next: Option<u8>) -> BraceScanTransition {
        match *self {
            Self::Code => self.code_transition(byte, next),
            Self::LineComment => self.line_comment_transition(byte),
            Self::BlockComment => self.block_comment_transition(byte, next),
            Self::Quote(delimiter) => self.quote_transition(byte, delimiter),
        }
    }

    fn line_comment_transition(&mut self, byte: u8) -> BraceScanTransition {
        if byte == b'\n' {
            *self = Self::Code;
        }
        BraceScanTransition::Advance(1)
    }

    fn block_comment_transition(&mut self, byte: u8, next: Option<u8>) -> BraceScanTransition {
        if byte == b'*' && next == Some(b'/') {
            *self = Self::Code;
            BraceScanTransition::Advance(2)
        } else {
            BraceScanTransition::Advance(1)
        }
    }

    fn quote_transition(&mut self, byte: u8, delimiter: u8) -> BraceScanTransition {
        if byte == b'\\' {
            return BraceScanTransition::Advance(2);
        }
        if byte == delimiter {
            *self = Self::Code;
        }
        BraceScanTransition::Advance(1)
    }

    fn code_transition(&mut self, byte: u8, next: Option<u8>) -> BraceScanTransition {
        match (byte, next) {
            (b'/', Some(b'/')) => {
                *self = Self::LineComment;
                BraceScanTransition::Advance(2)
            }
            (b'/', Some(b'*')) => {
                *self = Self::BlockComment;
                BraceScanTransition::Advance(2)
            }
            (delimiter @ (b'\'' | b'"' | b'`'), _) => {
                *self = Self::Quote(delimiter);
                BraceScanTransition::Advance(1)
            }
            (b'{', _) => BraceScanTransition::Opening,
            (b'}', _) => BraceScanTransition::Closing,
            _ => BraceScanTransition::Advance(1),
        }
    }
}

fn matching_brace(source: &str, opening: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = opening;
    let mut state = BraceScanState::Code;

    while index < bytes.len() {
        let transition = state.transition(bytes[index], bytes.get(index + 1).copied());
        match transition {
            BraceScanTransition::Advance(width) => index += width,
            BraceScanTransition::Opening => {
                depth += 1;
                index += 1;
            }
            BraceScanTransition::Closing => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
                index += 1;
            }
        }
    }
    None
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn indent(line: &str, nim_tabs: bool) -> usize {
    line.bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .map(|byte| if nim_tabs && byte == b'\t' { 2 } else { 1 })
        .sum()
}

fn is_control_keyword(value: &str) -> bool {
    matches!(
        value,
        "if" | "for"
            | "foreach"
            | "while"
            | "switch"
            | "catch"
            | "try"
            | "using"
            | "lock"
            | "synchronized"
            | "final"
            | "var"
            | "const"
    )
}

include!("function_sources/brace.rs");
include!("function_sources/cpp.rs");
include!("function_sources/dart.rs");
include!("function_sources/go.rs");
include!("function_sources/indentation.rs");
include!("function_sources/javascript.rs");
include!("function_sources/rust.rs");

include!("function_sources/tests.rs");
