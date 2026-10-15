use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FunctionMetrics {
    cyclomatic: usize,
    cognitive: usize,
    length: usize,
}

pub fn analyze(
    functions: &[FunctionSource],
    sources: &BTreeMap<String, String>,
    config: &Config,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for function in functions {
        let metrics = measure(function);
        if metrics.cyclomatic as i64 > config.complexity_threshold
            || metrics.cognitive as i64 > config.cognitive_threshold
        {
            findings.push(Finding {
                code: "complex-function".to_owned(),
                severity: Severity::Warn,
                path: function.path.clone(),
                line: function.line,
                end_line: function.line,
                message: format!(
                    "{} complexity={} cognitive={}",
                    function.name, metrics.cyclomatic, metrics.cognitive
                ),
                confidence: String::new(),
                why: String::new(),
                suggestion: String::new(),
                related_files: Vec::new(),
                snippet: String::new(),
                code_flow: Vec::new(),
            });
        }
        if config.max_function_lines > 0 && metrics.length as i64 > config.max_function_lines {
            findings.push(Finding {
                code: "long-function".to_owned(),
                severity: Severity::Warn,
                path: function.path.clone(),
                line: function.line,
                end_line: function.line + metrics.length - 1,
                message: format!(
                    "{} has {} lines (threshold {})",
                    function.name, metrics.length, config.max_function_lines
                ),
                confidence: String::new(),
                why: String::new(),
                suggestion: String::new(),
                related_files: Vec::new(),
                snippet: String::new(),
                code_flow: Vec::new(),
            });
        }
    }
    findings.extend(file_findings(sources, config));
    findings
}

fn measure(function: &FunctionSource) -> FunctionMetrics {
    let mut cyclomatic = 1usize;
    let mut cognitive = 0usize;
    let mut depth = 0isize;
    let mut lexical = LexicalState::default();
    let dart = function.path.ends_with(".dart");
    for line in function.source.split('\n') {
        let code = strip_code(line, &mut lexical, dart);
        let cyclomatic_signals = CYCLOMATIC_SIGNAL.find_iter(&code).count();
        let cognitive_signals = COGNITIVE_SIGNAL.find_iter(&code).count();
        cyclomatic += cyclomatic_signals;
        cognitive += cognitive_signals * (1 + (depth - 1).max(0) as usize);
        depth += code.bytes().filter(|byte| *byte == b'{').count() as isize;
        depth -= code.bytes().filter(|byte| *byte == b'}').count() as isize;
        depth = depth.max(0);
    }
    FunctionMetrics {
        cyclomatic,
        cognitive,
        length: function.source.split('\n').count(),
    }
}

fn file_findings(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let line_count = source.split('\n').count();
        if config.max_file_lines > 0 && line_count as i64 > config.max_file_lines {
            findings.push(Finding {
                code: "large-file".to_owned(),
                severity: Severity::Warn,
                path: path.clone(),
                line: 1,
                end_line: 1,
                message: format!("{line_count} lines > {}", config.max_file_lines),
                confidence: "high".to_owned(),
                why: String::new(),
                suggestion: "Split the file along cohesive module responsibilities.".to_owned(),
                related_files: Vec::new(),
                snippet: String::new(),
                code_flow: Vec::new(),
            });
        }
        let extension = path
            .rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(extension.as_str(), "c" | "cs" | "h") {
            continue;
        }
        let mut lexical = LexicalState::default();
        let goto_lines = source
            .split('\n')
            .enumerate()
            .filter_map(|(index, line)| {
                GOTO_STATEMENT
                    .is_match(strip_code(line, &mut lexical, false).trim())
                    .then_some(index + 1)
            })
            .collect::<Vec<_>>();
        if goto_lines.is_empty() {
            continue;
        }
        findings.push(Finding {
            code: "goto-statement".to_owned(),
            severity: Severity::Warn,
            path: path.clone(),
            line: goto_lines[0],
            end_line: goto_lines[0],
            message: if goto_lines.len() == 1 {
                "use of goto makes control flow hard to review and analyze".to_owned()
            } else {
                format!(
                    "{} goto statements make control flow hard to review and analyze",
                    goto_lines.len()
                )
            },
            confidence: "high".to_owned(),
            why: String::new(),
            suggestion: "Use structured control flow, extraction, or early returns.".to_owned(),
            related_files: goto_lines
                .iter()
                .skip(1)
                .map(|line| format!("{path}:{line}"))
                .collect(),
            snippet: String::new(),
            code_flow: Vec::new(),
        });
    }
    findings
}

#[derive(Clone, Copy, Default)]
enum LexicalMode {
    #[default]
    Code,
    BlockComment,
    DartMultiline {
        quote: u8,
        raw: bool,
    },
}

#[derive(Default)]
struct LexicalState {
    mode: LexicalMode,
}

struct CodeStripper<'a> {
    bytes: &'a [u8],
    state: &'a mut LexicalState,
    output: String,
    index: usize,
    dart: bool,
    dart_escaped: bool,
}

impl<'a> CodeStripper<'a> {
    fn new(line: &'a str, state: &'a mut LexicalState, dart: bool) -> Self {
        Self {
            bytes: line.as_bytes(),
            state,
            output: String::with_capacity(line.len()),
            index: 0,
            dart,
            dart_escaped: false,
        }
    }

    fn strip(mut self) -> String {
        while self.index < self.bytes.len() {
            match self.state.mode {
                LexicalMode::Code => {
                    if !self.scan_code() {
                        break;
                    }
                }
                LexicalMode::BlockComment => self.scan_block_comment(),
                LexicalMode::DartMultiline { quote, raw } => {
                    self.scan_dart_multiline(quote, raw);
                }
            }
        }
        self.output
    }

    fn scan_code(&mut self) -> bool {
        if self.starts_with(b"//") {
            return false;
        }
        if self.starts_with(b"/*") {
            self.state.mode = LexicalMode::BlockComment;
            self.mask_bytes(2);
            return true;
        }

        let quote = self.bytes[self.index];
        if matches!(quote, b'\'' | b'"') {
            self.scan_quoted_literal(quote);
        } else {
            self.output.push(quote as char);
            self.index += 1;
        }
        true
    }

    fn scan_block_comment(&mut self) {
        if self.starts_with(b"*/") {
            self.state.mode = LexicalMode::Code;
            self.mask_bytes(2);
        } else {
            self.mask_bytes(1);
        }
    }

    fn scan_dart_multiline(&mut self, quote: u8, raw: bool) {
        let delimiter = [quote, quote, quote];
        if self.starts_with(&delimiter) && (raw || !self.dart_escaped) {
            self.state.mode = LexicalMode::Code;
            self.mask_bytes(3);
            self.dart_escaped = false;
            return;
        }

        let byte = self.bytes[self.index];
        self.dart_escaped = !raw && byte == b'\\' && !self.dart_escaped;
        self.mask_bytes(1);
    }

    fn scan_quoted_literal(&mut self, quote: u8) {
        let raw = self.dart && is_dart_raw_prefix(self.bytes, self.index);
        if self.dart && self.starts_with(&[quote, quote, quote]) {
            self.state.mode = LexicalMode::DartMultiline { quote, raw };
            self.mask_bytes(3);
            self.dart_escaped = false;
            return;
        }

        match quoted_literal_end(self.bytes, self.index, quote, raw)
            .or_else(|| self.dart.then_some(self.bytes.len()))
        {
            Some(end) => self.mask_bytes(end - self.index),
            None => {
                self.output.push(quote as char);
                self.index += 1;
            }
        }
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.bytes[self.index..].starts_with(needle)
    }

    fn mask_bytes(&mut self, count: usize) {
        self.output.extend(std::iter::repeat_n(' ', count));
        self.index += count;
    }
}

fn strip_code(line: &str, state: &mut LexicalState, dart: bool) -> String {
    CodeStripper::new(line, state, dart).strip()
}

fn is_dart_raw_prefix(bytes: &[u8], index: usize) -> bool {
    index > 0
        && matches!(bytes[index - 1], b'r' | b'R')
        && (index == 1 || !(bytes[index - 2].is_ascii_alphanumeric() || bytes[index - 2] == b'_'))
}

fn quoted_literal_end(bytes: &[u8], start: usize, quote: u8, raw: bool) -> Option<usize> {
    let mut index = start + 1;
    while index < bytes.len() {
        if !raw && bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else {
            let closing = bytes[index] == quote;
            index += 1;
            if closing {
                return Some(index);
            }
        }
    }
    None
}

static CYCLOMATIC_SIGNAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|[^A-Za-z0-9_])(if|elseif|else\s+if|for|foreach|while|case|catch)([^A-Za-z0-9_]|$)|&&|\|\|")
        .expect("cyclomatic signal regex must compile")
});
static COGNITIVE_SIGNAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|[^A-Za-z0-9_])(if|elseif|else\s+if|for|foreach|while|switch|catch)([^A-Za-z0-9_]|$)|&&|\|\|")
        .expect("cognitive signal regex must compile")
});
static GOTO_STATEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^goto\s+[A-Za-z_]\w*\s*;").expect("goto statement regex must compile")
});

#[cfg(test)]
mod tests {
    use super::{FunctionMetrics, measure};
    use crate::function_sources::FunctionSource;

    #[test]
    fn measures_nested_control_flow() {
        let function = FunctionSource {
            path: "lib/logic.dart".to_owned(),
            name: "logic".to_owned(),
            line: 3,
            end_line: 11,
            source: "void logic() {\n  if (first && second) {\n    for (final item in items) {\n      if (item.ready) {\n        save(item);\n      }\n    }\n  }\n}".to_owned(),
        };
        assert_eq!(
            measure(&function),
            FunctionMetrics {
                cyclomatic: 5,
                cognitive: 7,
                length: 9,
            }
        );
    }
    #[test]
    fn handles_raw_dart_strings_before_later_control_flow() {
        let function = FunctionSource {
            path: "lib/output.dart".to_owned(),
            name: "write".to_owned(),
            line: 1,
            end_line: 1,
            source: r#"Future<void> write() async { try { if (ready) run(); final normalized = path.replaceAll(r'\', '/'); } on Exception catch (error) { if (error != null) rethrow; } }"#.to_owned(),
        };

        assert_eq!(
            measure(&function),
            FunctionMetrics {
                cyclomatic: 4,
                cognitive: 3,
                length: 1,
            }
        );
    }
}
