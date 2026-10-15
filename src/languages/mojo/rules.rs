use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>, functions: &[FunctionSource]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources.iter().filter(|(path, _)| path.ends_with(".mojo")) {
        analyze_source(path, source, &mut findings);
    }
    analyze_functions(functions, &mut findings);
    findings
}

fn analyze_source(path: &str, source: &str, findings: &mut Vec<Finding>) {
    let code = mojo_code(source);
    for (index, line) in code.split('\n').enumerate() {
        let line_number = index + 1;
        for rule in &MOJO_LINE_RULES {
            if rule.pattern.is_match(line) {
                findings.push(finding(rule.code, path, line_number, rule.message));
            }
        }
    }
}

fn analyze_functions(functions: &[FunctionSource], findings: &mut Vec<Finding>) {
    for function in functions
        .iter()
        .filter(|function| function.path.ends_with(".mojo"))
    {
        let declaration = function.source.split('\n').next().unwrap_or_default();
        if RAISE.is_match(&mojo_code(&function.source)) && !RAISES.is_match(declaration) {
            findings.push(finding(
                "mojo-missing-raises",
                &function.path,
                function.line,
                &format!("`{}` raises without a raises declaration", function.name),
            ));
        }
    }
}

fn mojo_code(source: &str) -> String {
    MojoCodeScanner::new(source).masked_code()
}

#[derive(Clone, Copy)]
enum MojoScannerState {
    Code,
    Comment,
    Quoted { delimiter: u8, triple: bool },
}

struct MojoCodeScanner<'a> {
    source: &'a [u8],
    masked: Vec<u8>,
    index: usize,
    state: MojoScannerState,
}

impl<'a> MojoCodeScanner<'a> {
    fn new(source: &'a str) -> Self {
        let source = source.as_bytes();
        Self {
            source,
            masked: source.to_vec(),
            index: 0,
            state: MojoScannerState::Code,
        }
    }

    fn masked_code(mut self) -> String {
        while self.index < self.source.len() {
            match self.state {
                MojoScannerState::Code => self.scan_code(),
                MojoScannerState::Comment => self.scan_comment(),
                MojoScannerState::Quoted {
                    delimiter,
                    triple: true,
                } => self.scan_triple_quoted(delimiter),
                MojoScannerState::Quoted {
                    delimiter,
                    triple: false,
                } => self.scan_single_quoted(delimiter),
            }
        }
        String::from_utf8(self.masked).expect("masked Mojo must remain UTF-8")
    }

    fn scan_code(&mut self) {
        let byte = self.source[self.index];
        if byte == b'#' {
            self.masked[self.index] = b' ';
            self.index += 1;
            self.state = MojoScannerState::Comment;
        } else if matches!(byte, b'"' | b'\'') {
            let triple = self.at_triple_delimiter(byte);
            let delimiter_length = if triple { 3 } else { 1 };
            self.masked[self.index..self.index + delimiter_length].fill(b' ');
            self.index += delimiter_length;
            self.state = MojoScannerState::Quoted {
                delimiter: byte,
                triple,
            };
        } else {
            self.index += 1;
        }
    }

    fn scan_comment(&mut self) {
        if self.source[self.index] == b'\n' {
            self.state = MojoScannerState::Code;
        } else {
            self.masked[self.index] = b' ';
        }
        self.index += 1;
    }

    fn scan_triple_quoted(&mut self, delimiter: u8) {
        if self.source[self.index] == b'\n' {
            self.index += 1;
            return;
        }
        if self.at_triple_delimiter(delimiter) {
            self.masked[self.index..self.index + 3].fill(b' ');
            self.index += 3;
            self.state = MojoScannerState::Code;
            return;
        }

        self.masked[self.index] = b' ';
        self.index += 1;
    }

    fn scan_single_quoted(&mut self, delimiter: u8) {
        let byte = self.source[self.index];
        if byte == b'\n' {
            self.state = MojoScannerState::Code;
            self.index += 1;
            return;
        }

        self.masked[self.index] = b' ';
        if byte == b'\\' && self.source.get(self.index + 1).is_some() {
            self.masked[self.index + 1] = b' ';
            self.index += 2;
            return;
        }
        if byte == delimiter {
            self.state = MojoScannerState::Code;
        }
        self.index += 1;
    }

    fn at_triple_delimiter(&self, delimiter: u8) -> bool {
        self.source.get(self.index..self.index + 3)
            == Some([delimiter, delimiter, delimiter].as_slice())
    }
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Mojo rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

struct MojoLineRule {
    pattern: &'static LazyLock<Regex>,
    code: &'static str,
    message: &'static str,
}

static DEPRECATED_FN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*fn\s+[A-Za-z_]\w*").unwrap());
static DEPRECATED_LET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*let\s+[A-Za-z_]\w*").unwrap());
static DEPRECATED_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*alias\s+[A-Za-z_]\w*\s*=").unwrap());
static PARAMETER_DECORATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@parameter\b").unwrap());
static LEGACY_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:borrowed|inout|owned)\b").unwrap());
static LEGACY_STDLIB_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*from\s+(?:collections|memory|sys|os|pathlib)\s+import\b").unwrap()
});
static STRING_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:str|string|text|name|message)\w*\s*\[\s*\d+\s*\]").unwrap()
});
static RAISE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\braise\b").unwrap());
static RAISES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\braises\b").unwrap());

static MOJO_LINE_RULES: [MojoLineRule; 7] = [
    MojoLineRule {
        pattern: &DEPRECATED_FN,
        code: "mojo-deprecated-fn",
        message: "deprecated fn declaration; current Mojo uses def",
    },
    MojoLineRule {
        pattern: &DEPRECATED_LET,
        code: "mojo-deprecated-let",
        message: "deprecated let binding; current Mojo uses var",
    },
    MojoLineRule {
        pattern: &DEPRECATED_ALIAS,
        code: "mojo-deprecated-alias",
        message: "deprecated alias declaration; use comptime",
    },
    MojoLineRule {
        pattern: &PARAMETER_DECORATOR,
        code: "mojo-parameter-decorator",
        message: "deprecated @parameter decorator; use comptime",
    },
    MojoLineRule {
        pattern: &LEGACY_ARGUMENT,
        code: "mojo-legacy-argument-convention",
        message: "legacy Mojo argument convention",
    },
    MojoLineRule {
        pattern: &LEGACY_STDLIB_IMPORT,
        code: "mojo-legacy-stdlib-import",
        message: "standard-library import is missing the std prefix",
    },
    MojoLineRule {
        pattern: &STRING_INDEX,
        code: "mojo-string-index",
        message: "string-like value uses removed positional indexing",
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::function_sources;

    use super::*;

    #[test]
    fn reports_complete_mojo_rule_family() {
        let source = r#"from pathlib import Path

alias Size = Int

@parameter
fn legacy(inout value: Int):
    let text = "hello"
    print(text[0])

def fail():
    raise Error("failed")"#;
        let sources = BTreeMap::from([("main.mojo".to_owned(), source.to_owned())]);
        let functions = function_sources::extract(&sources);
        assert_eq!(
            analyze(&sources, &functions)
                .into_iter()
                .map(|finding| finding.code)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "mojo-deprecated-alias".to_owned(),
                "mojo-deprecated-fn".to_owned(),
                "mojo-deprecated-let".to_owned(),
                "mojo-legacy-argument-convention".to_owned(),
                "mojo-legacy-stdlib-import".to_owned(),
                "mojo-missing-raises".to_owned(),
                "mojo-parameter-decorator".to_owned(),
                "mojo-string-index".to_owned(),
            ])
        );
    }

    #[test]
    fn masks_comments_and_single_and_triple_quoted_strings() {
        let source = r#"# let ignored = 1
var example = "fn ignored()"
var docs = """
fn documented():
    let text = name[0]
    raise Error("ignored")
"""
def safe() raises:
    raise Error("handled by contract")"#;
        let sources = BTreeMap::from([("main.mojo".to_owned(), source.to_owned())]);
        let functions = function_sources::extract(&sources);
        assert!(analyze(&sources, &functions).is_empty());
    }
}
