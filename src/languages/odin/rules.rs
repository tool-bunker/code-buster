use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".odin"))
    {
        let code = odin_code(source);
        for (index, line) in code.split('\n').enumerate() {
            let line_number = index + 1;
            if contains_identifier_call(line, "panic") {
                findings.extend(finding(
                    "odin-panic-call",
                    path,
                    line_number,
                    "panic call can terminate the process",
                ));
            }
            if contains_identifier_call(line, "transmute") {
                findings.extend(finding(
                    "odin-transmute",
                    path,
                    line_number,
                    "transmute requires a representation invariant",
                ));
            }
            if contains_identifier(line, "rawptr") {
                findings.extend(finding(
                    "odin-raw-pointer",
                    path,
                    line_number,
                    "raw pointer use requires a memory-safety review",
                ));
            }
            if contains_undefined_value(line) {
                findings.extend(finding(
                    "odin-undefined-value",
                    path,
                    line_number,
                    "undefined value marker bypasses initialization",
                ));
            }
        }
    }
    findings
}

fn contains_identifier_call(line: &str, identifier: &str) -> bool {
    identifier_positions(line, identifier).any(|index| {
        line[index + identifier.len()..]
            .trim_start()
            .starts_with('(')
    })
}

fn contains_identifier(line: &str, identifier: &str) -> bool {
    identifier_positions(line, identifier).next().is_some()
}

fn identifier_positions<'a>(
    line: &'a str,
    identifier: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    let bytes = line.as_bytes();
    line.match_indices(identifier)
        .map(|(index, _)| index)
        .filter(move |index| {
            let before = bytes[..*index].last().copied();
            let after = bytes[*index + identifier.len()..].first().copied();
            before.is_none_or(is_identifier_boundary) && after.is_none_or(is_identifier_boundary)
        })
}

fn is_identifier_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && byte != b'_'
}

fn contains_undefined_value(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices("---").any(|(index, _)| {
        let before = line[..index].trim_end().as_bytes().last().copied();
        let after = bytes[index + 3..].first().copied();
        matches!(before, Some(b'=' | b':'))
            && after.is_none_or(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}'))
    })
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Option<Finding> {
    let metadata = rule_catalog::metadata(code)?;
    Some(Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)?,
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    })
}

fn odin_code(source: &str) -> String {
    OdinMasker::new(source).masked()
}

#[derive(Clone, Copy)]
enum OdinScanState {
    Code,
    LineComment,
    BlockComment(usize),
    Quote(u8),
}

struct OdinMasker<'a> {
    source: &'a [u8],
    code: Vec<u8>,
    index: usize,
    state: OdinScanState,
}

impl<'a> OdinMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            code: source.as_bytes().to_vec(),
            index: 0,
            state: OdinScanState::Code,
        }
    }

    fn masked(mut self) -> String {
        while self.index < self.source.len() {
            self.scan_next();
        }
        String::from_utf8(self.code).unwrap_or_default()
    }

    fn scan_next(&mut self) {
        if self.source[self.index] == b'\n' {
            if !matches!(self.state, OdinScanState::BlockComment(_)) {
                self.state = OdinScanState::Code;
            }
            self.index += 1;
            return;
        }
        match self.state {
            OdinScanState::Code => self.scan_code(),
            OdinScanState::LineComment => self.mask_byte(),
            OdinScanState::BlockComment(depth) => self.scan_block_comment(depth),
            OdinScanState::Quote(delimiter) => self.scan_quote(delimiter),
        }
    }

    fn scan_code(&mut self) {
        let byte = self.source[self.index];
        if self.starts_with(b'/', b'/') {
            self.mask_pair();
            self.state = OdinScanState::LineComment;
        } else if self.starts_with(b'/', b'*') {
            self.mask_pair();
            self.state = OdinScanState::BlockComment(1);
        } else if matches!(byte, b'"' | b'\'' | b'`') {
            self.code[self.index] = b' ';
            self.index += 1;
            self.state = OdinScanState::Quote(byte);
        } else {
            self.index += 1;
        }
    }

    fn scan_block_comment(&mut self, depth: usize) {
        self.code[self.index] = b' ';
        if self.starts_with(b'/', b'*') {
            self.mask_pair();
            self.state = OdinScanState::BlockComment(depth + 1);
        } else if self.starts_with(b'*', b'/') {
            self.mask_pair();
            self.state = if depth == 1 {
                OdinScanState::Code
            } else {
                OdinScanState::BlockComment(depth - 1)
            };
        } else {
            self.index += 1;
        }
    }

    fn scan_quote(&mut self, delimiter: u8) {
        let byte = self.source[self.index];
        self.code[self.index] = b' ';
        if delimiter != b'`'
            && byte == b'\\'
            && self
                .source
                .get(self.index + 1)
                .is_some_and(|next| *next != b'\n')
        {
            self.code[self.index + 1] = b' ';
            self.index += 2;
        } else {
            self.index += 1;
            if byte == delimiter {
                self.state = OdinScanState::Code;
            }
        }
    }

    fn starts_with(&self, first: u8, second: u8) -> bool {
        self.source[self.index] == first && self.source.get(self.index + 1).copied() == Some(second)
    }

    fn mask_byte(&mut self) {
        self.code[self.index] = b' ';
        self.index += 1;
    }

    fn mask_pair(&mut self) {
        self.code[self.index] = b' ';
        self.code[self.index + 1] = b' ';
        self.index += 2;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::analyze;
    use crate::source_analysis_context::SourceAnalysisContext;

    #[test]
    fn reports_failure_and_memory_safety_boundaries() {
        let sources = BTreeMap::from([(
            "main.odin".to_owned(),
            "package main\n\nrun :: proc() {\n    panic(\"failed\")\n    bits := transmute(u32)f32_value\n    pointer: rawptr = raw_data(value)\n    bytes: [16]u8 = ---\n}\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            vec![
                "odin-panic-call",
                "odin-transmute",
                "odin-raw-pointer",
                "odin-undefined-value",
            ]
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![4, 5, 6, 7]
        );
        assert!(findings.iter().all(|finding| finding.confidence == "high"));
    }

    #[test]
    fn ignores_rule_text_in_nested_comments_and_literals() {
        let sources = BTreeMap::from([(
            "main.odin".to_owned(),
            "package main\n\nrun :: proc() {\n    // panic(\"example\")\n    text := \"transmute(rawptr)\"\n    raw := `value = ---`\n    /* rawptr\n       /* panic(\"nested\") */\n       transmute(u32)value\n    */\n}\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(analyze(&context).is_empty());
    }
}
