use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use super::is_localization_path;
use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::function_sources::{FunctionSource, RustComplexityContext, rust_complexity_source};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FunctionMetrics {
    cyclomatic: usize,
    cognitive: usize,
    length: usize,
    declarative_map: bool,
}

pub fn analyze(
    functions: &[FunctionSource],
    sources: &BTreeMap<String, String>,
    config: &Config,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut localization_complexity = Vec::new();
    let rust_contexts = RustComplexityContext::for_sources(sources);
    for function in functions {
        let rust_context = rust_contexts.get(&function.path);
        let in_quote_template =
            rust_context.is_some_and(|context| context.contains_template_function(function.line));
        let metrics = measure(function, rust_context);
        if !in_quote_template
            && !metrics.declarative_map
            && (metrics.cyclomatic as i64 > config.complexity_threshold
                || metrics.cognitive as i64 > config.cognitive_threshold)
        {
            let finding = Finding {
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
            };
            if is_localization_path(&function.path) {
                localization_complexity.push(finding);
            } else {
                findings.push(finding);
            }
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
    if let Some(mut representative) = localization_complexity.first().cloned() {
        representative.related_files = localization_complexity
            .iter()
            .skip(1)
            .map(|finding| format!("{}:{}", finding.path, finding.line))
            .collect();
        if localization_complexity.len() > 1 {
            representative.message = format!(
                "{}; {} localization implementations grouped",
                representative.message,
                localization_complexity.len()
            );
        }
        findings.push(representative);
    }
    findings.extend(file_findings(sources, config));
    findings
}

fn measure(
    function: &FunctionSource,
    rust_context: Option<&RustComplexityContext>,
) -> FunctionMetrics {
    if function.path.ends_with(".rs") {
        return measure_rust(function, rust_context);
    }
    let mut cyclomatic = 1usize;
    let mut cognitive = 0usize;
    let mut depth = 0isize;
    let mut lexical = LexicalState::default();
    let dart = function.path.ends_with(".dart");
    let python = function.path.ends_with(".py");
    for line in function.source.split('\n') {
        let code = strip_code(line, &mut lexical, dart, python);
        let cyclomatic_signals = CYCLOMATIC_SIGNAL.find_iter(&code).count();
        let cognitive_controls = COGNITIVE_CONTROL.find_iter(&code).count();
        cyclomatic += cyclomatic_signals;
        cognitive += cognitive_controls * (1 + (depth - 1).max(0) as usize);
        cognitive += logical_operator_sequences(&code);
        depth += code.bytes().filter(|byte| *byte == b'{').count() as isize;
        depth -= code.bytes().filter(|byte| *byte == b'}').count() as isize;
        depth = depth.max(0);
    }
    FunctionMetrics {
        cyclomatic,
        cognitive,
        length: function.source.split('\n').count(),
        declarative_map: false,
    }
}

#[derive(Default)]
struct RustComplexityNesting {
    scopes: Vec<(bool, Option<usize>, usize)>,
    depth: usize,
    delimiters: usize,
    control_pending: Option<usize>,
    match_pending: bool,
    pattern_pending: bool,
    closure_pending: bool,
    expression_start: bool,
    async_block: bool,
}

impl RustComplexityNesting {
    fn scope_token(&mut self, token: &str) -> usize {
        let alternatives = match token {
            "{" => {
                self.open_scope();
                0
            }
            "}" => {
                if let Some((nested, _, _)) = self.scopes.pop() {
                    self.depth -= usize::from(nested);
                }
                0
            }
            "=>" => self.match_alternative(),
            _ => {
                self.expression_token(token);
                0
            }
        };
        self.expression_start = matches!(
            token,
            "(" | "[" | "{" | "=" | ":" | "," | "=>" | "move" | "async" | "return"
        );
        self.async_block = matches!(token, "async" | "move");
        alternatives
    }

    fn open_scope(&mut self) {
        let control = self.control_pending == Some(self.delimiters) && !self.pattern_pending;
        let nested = control || self.closure_pending || self.async_block;
        self.scopes.push((
            nested,
            (control && self.match_pending).then_some(0),
            self.delimiters,
        ));
        self.depth += usize::from(nested);
        self.closure_pending = false;
        if control {
            self.control_pending = None;
            self.match_pending = false;
        }
    }

    fn expression_token(&mut self, token: &str) {
        match token {
            "(" | "[" => self.delimiters += 1,
            ")" | "]" => self.delimiters = self.delimiters.saturating_sub(1),
            "|" if self.expression_start => self.closure_pending = true,
            "let" if self.control_pending.is_some() => self.pattern_pending = true,
            "=" | "in" => self.pattern_pending = false,
            ";" => self.closure_pending = false,
            "else" => self.control_pending = Some(self.delimiters),
            _ => {}
        }
    }

    fn match_alternative(&mut self) -> usize {
        self.closure_pending = false;
        let Some((_, Some(arms), delimiters)) = self.scopes.last_mut() else {
            return 0;
        };
        if *delimiters != self.delimiters {
            return 0;
        }
        self.control_pending = None;
        self.match_pending = false;
        self.pattern_pending = false;
        *arms += 1;
        usize::from(*arms > 1)
    }
}

fn measure_rust(
    function: &FunctionSource,
    context: Option<&RustComplexityContext>,
) -> FunctionMetrics {
    let source = rust_complexity_source(&function.source, context, function.line);
    let mut metrics = FunctionMetrics {
        cyclomatic: 1,
        cognitive: 0,
        length: function.source.split('\n').count(),
        declarative_map: false,
    };
    let mut nesting = RustComplexityNesting::default();
    let mut logical = None;
    for token in RUST_COMPLEXITY_TOKEN
        .find_iter(&source)
        .map(|token| token.as_str())
    {
        if matches!(token, "if" | "for" | "while" | "match") {
            metrics.cyclomatic += usize::from(token != "match");
            metrics.cognitive += 1 + nesting.depth;
            nesting.control_pending = Some(nesting.delimiters);
            nesting.match_pending = token == "match";
            nesting.pattern_pending = token == "for";
        } else if matches!(token, "&&" | "||") {
            metrics.cyclomatic += 1;
            metrics.cognitive += usize::from(logical.map(|(operator, _)| operator) != Some(token));
            logical = Some((token, nesting.delimiters));
        }
        metrics.cyclomatic += nesting.scope_token(token);
        if matches!(token, "{" | "}" | ";" | "=>")
            || token == "," && logical.is_some_and(|(_, depth)| nesting.delimiters <= depth)
        {
            logical = None;
        }
    }
    metrics.declarative_map = rust_declarative_map(&source, &function.source);
    metrics
}

fn rust_declarative_map(masked: &str, source: &str) -> bool {
    let Some(body) = RUST_DECLARATIVE_MAP
        .captures(masked)
        .and_then(|captures| captures.name("arms"))
    else {
        return false;
    };
    let mut end = 0;
    let mut arms = 0;
    for captures in RUST_MAP_ARM.captures_iter(body.as_str()) {
        let (Some(complete), Some(pattern), Some(value)) = (
            captures.get(0),
            captures.name("pattern"),
            captures.name("value"),
        ) else {
            return false;
        };
        if complete.start() != end || !rust_map_pattern(pattern.as_str()) {
            return false;
        }
        let value = body.start() + value.start()..body.start() + value.end();
        if !source
            .get(value)
            .is_some_and(|value| RUST_MAP_VALUE.is_match(value.trim()))
        {
            return false;
        }
        end = complete.end();
        arms += 1;
    }
    arms > 0 && body.as_str()[end..].trim().is_empty()
}

fn rust_map_pattern(pattern: &str) -> bool {
    pattern
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_ :|\t\r\n".contains(&byte))
        && !pattern.split_whitespace().any(|word| word == "if")
}

fn logical_operator_sequences(code: &str) -> usize {
    let mut previous = None;
    let mut sequences = 0;
    for operator in LOGICAL_OPERATOR
        .find_iter(code)
        .map(|matched| matched.as_str())
    {
        if previous != Some(operator) {
            sequences += 1;
            previous = Some(operator);
        }
    }
    sequences
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
        if extension != "cs" {
            continue;
        }
        let mut lexical = LexicalState::default();
        let goto_lines = source
            .split('\n')
            .enumerate()
            .filter_map(|(index, line)| {
                GOTO_STATEMENT
                    .is_match(strip_code(line, &mut lexical, false, false).trim())
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
    PythonMultiline {
        quote: u8,
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
    python: bool,
    multiline_escaped: bool,
}

impl<'a> CodeStripper<'a> {
    fn new(line: &'a str, state: &'a mut LexicalState, dart: bool, python: bool) -> Self {
        Self {
            bytes: line.as_bytes(),
            state,
            output: String::with_capacity(line.len()),
            index: 0,
            dart,
            python,
            multiline_escaped: false,
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
                LexicalMode::PythonMultiline { quote } => self.scan_python_multiline(quote),
            }
        }
        self.output
    }

    fn scan_code(&mut self) -> bool {
        if self.starts_with(b"//") || (self.python && self.starts_with(b"#")) {
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
        if self.starts_with(&delimiter) && (raw || !self.multiline_escaped) {
            self.state.mode = LexicalMode::Code;
            self.mask_bytes(3);
            self.multiline_escaped = false;
            return;
        }

        let byte = self.bytes[self.index];
        self.multiline_escaped = !raw && byte == b'\\' && !self.multiline_escaped;
        self.mask_bytes(1);
    }

    fn scan_python_multiline(&mut self, quote: u8) {
        let delimiter = [quote, quote, quote];
        if self.starts_with(&delimiter) && !self.multiline_escaped {
            self.state.mode = LexicalMode::Code;
            self.mask_bytes(3);
            return;
        }

        self.multiline_escaped = self.bytes[self.index] == b'\\' && !self.multiline_escaped;
        self.mask_bytes(1);
    }

    fn scan_quoted_literal(&mut self, quote: u8) {
        let raw = self.dart && is_dart_raw_prefix(self.bytes, self.index);
        if self.python && self.starts_with(&[quote, quote, quote]) {
            self.state.mode = LexicalMode::PythonMultiline { quote };
            self.mask_bytes(3);
            self.multiline_escaped = false;
            return;
        }
        if self.dart && self.starts_with(&[quote, quote, quote]) {
            self.state.mode = LexicalMode::DartMultiline { quote, raw };
            self.mask_bytes(3);
            self.multiline_escaped = false;
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

fn strip_code(line: &str, state: &mut LexicalState, dart: bool, python: bool) -> String {
    CodeStripper::new(line, state, dart, python).strip()
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
static COGNITIVE_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(^|[^A-Za-z0-9_])(if|elseif|else\s+if|for|foreach|while|switch|catch)([^A-Za-z0-9_]|$)",
    )
    .expect("cognitive control regex must compile")
});
static RUST_DECLARATIVE_MAP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\A[^{]*\{\s*(?:return\s+)?match\s+(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\{(?P<arms>[^{}]*)\}\s*;?\s*\}\s*\z")
        .expect("Rust declarative map regex must compile")
});
static RUST_MAP_ARM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)(?P<pattern>[^=]*?)=>(?P<value>\s*&\[[^\[\]]*\]|[^,]*)(?:,|$)")
        .expect("Rust map arm regex must compile")
});
static RUST_MAP_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    let scalar = r#"(?:true|false|-?[0-9][0-9_]*(?:\.[0-9][0-9_]*)?(?:[iu](?:8|16|32|64|128|size)|f(?:32|64))?|"(?:[^"\\]|\\.)*"|(?:[A-Za-z_]\w*::)*[A-Z][A-Z0-9_]*)"#;
    // Invariant: all interpolated regex fragments are fixed literals, not runtime input.
    Regex::new(&format!(
        r"\A(?:{scalar}|&\[\s*(?:{scalar}\s*(?:,\s*{scalar}\s*)*,?\s*)?\])\z"
    ))
    .expect("Rust map value regex must compile")
});
static RUST_COMPLEXITY_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"r#[A-Za-z_]\w*|[A-Za-z_]\w*|&&|\|\||=>|[{}();,:=|\[\]]")
        .expect("Rust complexity token regex must compile")
});
static LOGICAL_OPERATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&&|\|\|").expect("logical operator regex must compile"));
static GOTO_STATEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^goto\s+[A-Za-z_]\w*\s*;").expect("goto statement regex must compile")
});

#[cfg(test)]
mod tests {
    use super::{FunctionMetrics, analyze, measure};
    use crate::config::Config;
    use crate::function_sources::{FunctionSource, RustComplexityContext, extract};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn resolves_direct_quote_forwarding_without_hiding_evaluated_arguments() {
        let source = r#"use quote::quote;
macro_rules! emit {
    ($setup:tt, $body:tt) => {{ let _ = $setup; quote! $body }};
}
fn generate() {
    emit!(
        { if evaluated { first(); } else { second(); } },
        { if generated { while generated { run(); } } }
    );
    // emit!({}, { if not_code { run(); } });
    let text = "if not_code { run(); }";
    if actual { run(); }
    execute! { if runtime { run(); } }
}"#;
        let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let contexts = RustComplexityContext::for_sources(&sources);
        let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (4, 3));
    }

    #[test]
    fn resolves_explicit_sibling_quote_exports_and_aliases_but_keeps_generator_branches() {
        for binding in ["emit", "emit as tokens"] {
            let name = if binding.contains(" as ") {
                "tokens"
            } else {
                "emit"
            };
            let source = format!(
                r#"use quote::quote;
use super::state::{binding};
fn generate(fields: &[Field]) {{
    for field in fields {{
        if field.optional {{
            {name}!(state(first, second) => {{
                fn emitted() {{
                    if generated {{ while generated {{ run(); }} }}
                }}
            }});
        }}
    }}
    execute! {{ if runtime {{ run(); }} }}
    fn helper() {{
        if actual {{ run(); }}
    }}
}}"#
            );
            let sources = BTreeMap::from([
                (
                    "src/lib.rs".to_owned(),
                    "mod state;\nmod generator;".to_owned(),
                ),
                (
                    "src/state.rs".to_owned(),
                    r#"macro_rules! emit {
    ($state:ident($($fields:ident),*) => $body:tt) => {{
        $(let $fields = &$state.$fields;)*
        quote! $body
    }};
}
pub(crate) use emit;"#
                        .to_owned(),
                ),
                ("src/generator.rs".to_owned(), source),
            ]);
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let generator = functions
                .iter()
                .find(|function| function.name == "generate")
                .unwrap();
            let metrics = measure(generator, contexts.get("src/generator.rs"));
            assert_eq!((metrics.cyclomatic, metrics.cognitive), (4, 4), "{binding}");
            let mut config = Config::defaults(PathBuf::from("."));
            config.complexity_threshold = 1;
            config.cognitive_threshold = 100;
            config.max_function_lines = 0;
            let findings = analyze(&functions, &sources, &config);
            assert_eq!(findings.len(), 2, "{binding}");
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.code == "complex-function"
                        && finding.path == "src/generator.rs"
                        && finding.end_line == finding.line)
            );
            assert!(findings.iter().any(|finding| finding.line == 3
                && finding.message == "generate complexity=4 cognitive=4"));
            assert!(findings.iter().any(|finding| finding.line == 14
                && finding.message == "helper complexity=2 cognitive=1"));
        }
    }

    #[test]
    fn quote_forwarding_matches_empty_and_required_identifier_lists() {
        for (quantifier, fields) in [("*", ""), ("+", "first, second")] {
            let source = format!(
                "macro_rules! emit {{ ($state:ident($($fields:ident),{quantifier}) => $body:tt) => {{ quote::quote! $body }}; }}\n\
                 fn generate() {{ emit!(state({fields}) => {{ if generated {{ while generated {{ run(); }} }} }}); if actual {{ run(); }} }}"
            );
            let sources = BTreeMap::from([("src/generator.rs".to_owned(), source)]);
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
            assert_eq!(
                (metrics.cyclomatic, metrics.cognitive),
                (2, 1),
                "{quantifier}"
            );
        }
    }

    #[test]
    fn retains_unsafe_ambiguous_and_runtime_using_quote_forwarders() {
        for declaration in [
            "macro_rules! emit { ($body:tt) => {{ $body; quote! $body }}; }",
            "macro_rules! emit { ($body:tt) => { quote! $body }; ($other:tt) => { $other }; }",
            "macro_rules! emit { ($body:tt) => {{ if setup { run(); } quote! $body }}; }",
            "macro_rules! emit { ($body:tt) => {{ macro_rules! quote { ($other:tt) => { $other }; } quote! $body }}; }",
            "macro_rules! emit { ($body:tt) => { execute!(quote! $body) }; }",
            "macro_rules! emit { ($body:tt) => { runtime! $body }; }",
            "macro_rules! emit { ($body:tt) => { quote_spanned! { Span::call_site() => $body } }; }",
        ] {
            let source = format!(
                "use quote::{{quote, quote_spanned}};\n{declaration}\nfn generate() {{ emit!({{ if actual {{ run(); }} }}); }}"
            );
            let sources = BTreeMap::from([("src/generator.rs".to_owned(), source)]);
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
            assert_eq!(
                (metrics.cyclomatic, metrics.cognitive),
                (2, 1),
                "{declaration}"
            );
        }
    }

    #[test]
    fn quote_forwarding_preserves_local_shadowing_and_does_not_leak_sibling_scopes() {
        let source = r#"use quote::quote;
macro_rules! emit { ($body:tt) => { quote! $body }; }
fn generate() {
    emit!({ if generated { run(); } });
    {
        macro_rules! emit { ($body:tt) => { $body }; }
        emit!({ if actual { run(); } });
    }
    {
        macro_rules! quote { ($body:tt) => { $body }; }
        emit!({ if actual { run(); } });
    }
    emit!({ if generated { run(); } });
}"#;
        let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let contexts = RustComplexityContext::for_sources(&sources);
        let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (3, 2));
    }

    #[test]
    fn quote_semantics_require_unshadowed_namespaces_and_scoped_imports() {
        for source in [
            "use quote::quote;\nfn generate() {\n quote! { if generated { run(); } }\n quote::quote! { while generated { run(); } }\n if actual { run(); }\n}",
            "mod quote { pub use runtime::execute as quote; }\nfn generate() { quote::quote! { if actual { run(); } } }",
            "use runtime as quote;\nfn generate() { quote::quote! { if actual { run(); } } }",
            "extern crate runtime as quote;\nfn generate() { quote::quote! { if actual { run(); } } }",
            "use quote::quote as tokens;\nfn generate() {\n tokens! { if generated { run(); } }\n {\n use runtime::execute as tokens;\n tokens! { if actual { run(); } }\n }\n tokens! { if generated { run(); } }\n}",
        ] {
            let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
            assert_eq!((metrics.cyclomatic, metrics.cognitive), (2, 1), "{source}");
        }
    }

    #[test]
    fn quote_forwarding_requires_explicit_unambiguous_module_and_export_evidence() {
        for (parent, export, extra) in [
            ("mod generator;", "pub(crate) use emit;", None),
            ("mod state;\nmod generator;", "", None),
            (
                "mod state;\nmod generator;",
                "pub(crate) use emit;",
                Some(("src/state/mod.rs", "")),
            ),
            (
                "mod state;\nmod generator;",
                "pub(crate) use emit;",
                Some(("src/generator/mod.rs", "")),
            ),
            (
                "#[path = \"runtime.rs\"] mod state;\nmod generator;",
                "pub(crate) use emit;",
                None,
            ),
        ] {
            let mut sources = BTreeMap::from([
                ("src/lib.rs".to_owned(), parent.to_owned()),
                ("src/state.rs".to_owned(), format!("macro_rules! emit {{ ($body:tt) => {{ quote! $body }}; }}\n{export}")),
                ("src/generator.rs".to_owned(), "use quote::quote;\nuse super::state::emit;\nfn generate() { emit!({ if actual { run(); } }); }".to_owned()),
            ]);
            if let Some((path, source)) = extra {
                sources.insert(path.to_owned(), source.to_owned());
            }
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
            assert_eq!((metrics.cyclomatic, metrics.cognitive), (2, 1));
        }
    }

    #[test]
    fn measures_rust_nested_visitors_independently_without_changing_extracted_sources() {
        let source = r#"fn deserialize(value: bool) -> bool {
    struct Field;
    impl Read for Field {
        fn deserialize(value: bool) -> bool {
            struct FieldVisitor;
            impl Visitor for FieldVisitor {
                fn expecting() -> bool { true }
                fn visit_str(value: bool) -> bool {
                    if value { return true; }
                    false
                }
            }
            FieldVisitor::visit_str(value)
        }
    }
    struct RawBindingVisitor;
    impl Visitor for RawBindingVisitor {
        fn visit_map(values: &[bool]) -> bool {
            for value in values {
                if *value && values.len() > 1 {
                    return true;
                }
            }
            false
        }
    }
    RawBindingVisitor::visit_map(&[Field::deserialize(value)])
}"#;
        let sources = BTreeMap::from([("src/visitor.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        assert!(functions[0].source.contains("if *value"));
        assert_eq!(
            functions
                .iter()
                .map(|function| {
                    let metrics = measure(function, None);
                    (
                        function.name.as_str(),
                        function.line,
                        metrics.cyclomatic,
                        metrics.cognitive,
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("deserialize", 1, 1, 0),
                ("deserialize", 4, 1, 0),
                ("expecting", 7, 1, 0),
                ("visit_str", 8, 2, 1),
                ("visit_map", 18, 4, 4),
            ]
        );
        let mut config = Config::defaults(PathBuf::from("."));
        config.complexity_threshold = 2;
        config.cognitive_threshold = 100;
        config.max_function_lines = 0;
        let findings = analyze(&functions, &sources, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "complex-function");
        assert_eq!(findings[0].path, "src/visitor.rs");
        assert_eq!(findings[0].line, 18);
        assert_eq!(findings[0].end_line, 18);
        assert_eq!(findings[0].message, "visit_map complexity=4 cognitive=4");
    }

    #[test]
    fn retains_rust_owner_branches_and_closure_logic_around_nested_functions() {
        let source = r#"fn outer(value: bool) {
    fn helper(value: bool) {
        while value {
            if value { break; }
        }
    }
    if value { helper(value); }
    let callback = || {
        if value { helper(value); }
    };
    callback();
}"#;
        let sources = BTreeMap::from([("src/callback.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        assert_eq!(
            functions
                .iter()
                .map(|function| {
                    let metrics = measure(function, None);
                    (
                        function.name.as_str(),
                        metrics.cyclomatic,
                        metrics.cognitive,
                    )
                })
                .collect::<Vec<_>>(),
            [("outer", 3, 3), ("helper", 3, 3)]
        );
        let mut config = Config::defaults(PathBuf::from("."));
        config.complexity_threshold = 2;
        config.cognitive_threshold = 100;
        config.max_function_lines = 0;
        let findings = analyze(&functions, &sources, &config);
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            [("complex-function", 1), ("complex-function", 2)]
        );
    }

    #[test]
    fn distinguishes_empty_rust_closures_from_boolean_or() {
        for modifiers in ["", "move ", "async ", "async move "] {
            let source = format!(
                "fn probe(left: bool, right: bool) {{\n    let callback = {modifiers}|| {{\n        if left || right {{ return true; }}\n        false\n    }};\n    callback();\n}}"
            );
            let sources = BTreeMap::from([("src/closure.rs".to_owned(), source)]);
            let functions = extract(&sources);
            let metrics = measure(&functions[0], None);
            assert_eq!(
                (metrics.cyclomatic, metrics.cognitive),
                (3, 3),
                "{modifiers}"
            );
        }
        for name in ["r#move", "émove"] {
            let source = format!(
                "fn probe({name}: bool, right: bool) {{\n    if {name} || right {{ return; }}\n}}"
            );
            let sources = BTreeMap::from([("src/condition.rs".to_owned(), source)]);
            let functions = extract(&sources);
            let metrics = measure(&functions[0], None);
            assert_eq!((metrics.cyclomatic, metrics.cognitive), (3, 2), "{name}");
        }
    }

    #[test]
    fn excludes_proven_quote_templates_but_retains_generator_and_runtime_macro_branches() {
        let source = r#"use quote::{format_ident, quote as tokens};
fn generate(fields: &[Field]) -> Tokens {
    let base = tokens! {
        fn generated() {
            if never { while never { if never {} } }
        }
    };
    for field in fields {
        if field.optional {
            let extra = quote::quote! {
                if value.is_none() { continue; }
                #base
            };
            emit(extra);
        }
    }
    evaluate! {
        if ready { emit(base); }
    }
    base
}"#;
        let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let contexts = RustComplexityContext::for_sources(&sources);
        let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
        assert_eq!(metrics.cyclomatic, 4);
        assert_eq!(metrics.cognitive, 4);
        assert_eq!(metrics.length, 20);
        let mut config = Config::defaults(PathBuf::from("."));
        config.complexity_threshold = 2;
        config.cognitive_threshold = 100;
        config.max_function_lines = 0;
        let findings = analyze(&functions, &sources, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "complex-function");
        assert_eq!(findings[0].path, "src/generator.rs");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].message, "generate complexity=4 cognitive=4");
    }

    #[test]
    fn retains_unproven_and_shadowed_quote_macros_and_evaluated_span_expressions() {
        for source in [
            "fn generate() {\n    quote! { if ready { run(); } }\n}",
            "use quote::quote;\nmacro_rules! quote { ($($input:tt)*) => { $($input)* }; }\nfn generate() {\n    quote! { if ready { run(); } }\n}",
            "use quote::quote_spanned;\nfn generate() {\n    quote_spanned! { if ready { first } else { second } => value }\n}",
        ] {
            let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
            assert_eq!(metrics.cyclomatic, 2);
            assert_eq!(metrics.cognitive, 1);
        }
    }

    #[test]
    fn measures_field_deserializer_without_artificial_match_arm_nesting() {
        let source = r#"use quote::quote;
fn field_deserializer(fields: &mut Fields, field: &Field) {
    let assignment = quote! {
        match deserialize(value) {
            Ok(value) => config.field = value,
            Err(error) => { log(error); }
        }
    };
    for attr in &field.attrs {
        match attr.kind {
            Flatten => {
                if fields.has_flatten { return; }
            }
            Deprecated => {
                if let Some(warning) = attr.param { emit(warning); }
            }
            Alias => {
                if let Some(alias) = attr.param { emit(alias); }
            }
            _ => {}
        }
    }
    if let Type::Path(path) = &field.ty {
        if path.is_option {
            let assignment = quote! {
                if value.is_none() { continue; }
                #assignment
            };
        }
    }
}"#;
        let sources = BTreeMap::from([("src/derive.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let contexts = RustComplexityContext::for_sources(&sources);
        let metrics = measure(&functions[0], contexts.get("src/derive.rs"));
        assert_eq!(metrics.cyclomatic, 10);
        assert_eq!(metrics.cognitive, 15);
        let findings = analyze(&functions, &sources, &Config::defaults(PathBuf::from(".")));
        assert!(findings.is_empty());
    }

    #[test]
    fn keeps_match_metrics_without_refactoring_advice_for_declarative_tables() {
        for source in [
            "fn rank(value: &str) -> usize {\n match value {\n \"a\" | \"b\" => 0,\n \"c\" => 1,\n \"d\" => 2,\n _ => usize::MAX,\n }\n}",
            "fn group(value: Kind) -> &'static [&'static str] {\n match value {\n Kind::Core => &[\"correctness\", \"maintainability\"],\n Kind::Style => &[\"style\"],\n _ => &[],\n }\n}",
            "fn label(value: Kind) -> &'static str {\n match value {\n Kind::A => \"alpha\",\n Kind::B => \"beta\",\n _ => \"other\",\n }\n}",
        ] {
            let sources = BTreeMap::from([("src/table.rs".to_owned(), source.to_owned())]);
            let functions = extract(&sources);
            let metrics = measure(&functions[0], None);
            assert!(metrics.cyclomatic >= 3);
            assert_eq!(metrics.cognitive, 1);
            assert!(metrics.declarative_map);
            let mut config = Config::defaults(PathBuf::from("."));
            config.complexity_threshold = 1;
            config.cognitive_threshold = 0;
            config.max_function_lines = 0;
            assert!(analyze(&functions, &sources, &config).is_empty());
        }
    }

    #[test]
    fn retains_refactoring_advice_for_guarded_computed_and_nested_matches() {
        for source in [
            "fn decide(value: Kind) -> usize {\n match value {\n Kind::A if allowed() => 0,\n Kind::A => 1,\n _ => 2,\n }\n}",
            "fn decide(value: Kind) -> usize {\n match value {\n Kind::A => compute(),\n Kind::B => 1,\n _ => 2,\n }\n}",
            "fn decide(value: Kind) -> usize {\n match value {\n Kind::A => { record(); 0 },\n Kind::B => 1,\n _ => 2,\n }\n}",
            "fn decide(value: Kind) -> usize {\n match value {\n Kind::A => match other {\n Other::A => 0,\n _ => 1,\n },\n _ => 2,\n }\n}",
            "fn decide(value: Kind) -> usize {\n prepare();\n match value {\n Kind::A => 0,\n Kind::B => 1,\n _ => 2,\n }\n}",
            "fn decide(value: Kind) -> fn() {\n match value {\n Kind::A => handlers::first,\n Kind::B => handlers::second,\n _ => handlers::fallback,\n }\n}",
            "fn decide(character: char) -> usize {\n match character {\n value if value == '#' => 0,\n 'a' => 1,\n _ => 2,\n }\n}",
            "fn decide(value: Kind) -> State {\n match value {\n Kind::A => Factory::Continue(value),\n Kind::B => Factory::Stop(),\n _ => Factory::Fallback(value),\n }\n}",
        ] {
            let sources = BTreeMap::from([("src/decide.rs".to_owned(), source.to_owned())]);
            let functions = extract(&sources);
            assert!(!measure(&functions[0], None).declarative_map);
            let mut config = Config::defaults(PathBuf::from("."));
            config.complexity_threshold = 1;
            config.cognitive_threshold = 0;
            config.max_function_lines = 0;
            let findings = analyze(&functions, &sources, &config);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].code, "complex-function");
            assert_eq!(findings[0].path, "src/decide.rs");
            assert_eq!(findings[0].line, 1);
        }
    }

    #[test]
    fn measures_rust_match_alternatives_guards_and_nested_control_not_arm_braces() {
        let source = r#"fn dispatch(value: Kind) {
    match value {
        Kind::Named { ready, .. } if ready && allowed => {
            if retry { run(); }
        }
        Kind::Other => if fallback { run(); },
        _ => {}
    }
}"#;
        let sources = BTreeMap::from([("src/dispatch.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let metrics = measure(&functions[0], None);
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (7, 8));
        let mut config = Config::defaults(PathBuf::from("."));
        config.complexity_threshold = 6;
        config.cognitive_threshold = 100;
        config.max_function_lines = 0;
        let findings = analyze(&functions, &sources, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "complex-function");
        assert_eq!(findings[0].path, "src/dispatch.rs");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].message, "dispatch complexity=7 cognitive=8");
    }

    #[test]
    fn rust_boolean_sequences_ignore_newlines_but_separate_expressions_and_operators() {
        for source in [
            "fn check() { if a || b || c { run(); } }",
            "fn check() {\n if a\n || b\n || c {\n run();\n }\n}",
            "fn check() { if a || invoke(first, second) || c { run(); } }",
        ] {
            let sources = BTreeMap::from([("src/predicate.rs".to_owned(), source.to_owned())]);
            let functions = extract(&sources);
            let metrics = measure(&functions[0], None);
            assert_eq!((metrics.cyclomatic, metrics.cognitive), (4, 2));
        }
        let source = "fn check() { let first = a && b; let second = c && d; if first || second && ready { run(); } }";
        let sources = BTreeMap::from([("src/predicate.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let metrics = measure(&functions[0], None);
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (6, 5));
    }

    #[test]
    fn rust_structs_and_pattern_braces_do_not_add_cognitive_nesting() {
        let source = r#"fn build(input: Item) {
    let output = Output {
        enabled: if ready { true } else { false },
        callback: || { if allowed { run(); } },
    };
    if let Item { ready, .. } = input {
        if ready { run(); }
    }
    async { if ready { run(); } };
}"#;
        let sources = BTreeMap::from([("src/build.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let metrics = measure(&functions[0], None);
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (6, 8));
    }

    #[test]
    fn excludes_syn_ast_templates_and_spanned_tokens_but_keeps_span_evaluation() {
        let source = r#"use quote::quote_spanned as spanned;
use syn::{parse_quote as ast, parse_quote_spanned};
fn generate() {
    let body = ast!({
        for item in values { if generated { run(); } }
    });
    let other = syn::parse_quote!({ while generated { run(); } });
    let tokens = spanned! { (match kind {
        Kind::First => if ready { first } else { second },
        _ => fallback,
    }) =>
        fn emitted() {
            if generated { while generated { run(); } }
        }
    };
    let more = parse_quote_spanned!(span => { if generated { run(); } });
    execute! { if ready { run(); } }
}"#;
        let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let contexts = RustComplexityContext::for_sources(&sources);
        let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (4, 4));
        let mut config = Config::defaults(PathBuf::from("."));
        config.complexity_threshold = 2;
        config.cognitive_threshold = 100;
        config.max_function_lines = 0;
        let findings = analyze(&functions, &sources, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
        assert_eq!(findings[0].message, "generate complexity=4 cognitive=4");
    }

    #[test]
    fn keeps_unresolved_shadowed_and_ordinary_ast_named_macros() {
        for source in [
            "fn generate() { parse_quote! { if ready { run(); } } }",
            "use syn::parse_quote;\nmacro_rules! parse_quote { ($($input:tt)*) => { $($input)* }; }\nfn generate() { parse_quote! { if ready { run(); } } }",
            "fn generate() { custom::parse_quote! { if ready { run(); } } }",
        ] {
            let sources = BTreeMap::from([("src/generator.rs".to_owned(), source.to_owned())]);
            let functions = extract(&sources);
            let contexts = RustComplexityContext::for_sources(&sources);
            let metrics = measure(&functions[0], contexts.get("src/generator.rs"));
            assert_eq!((metrics.cyclomatic, metrics.cognitive), (2, 1));
        }
    }

    #[test]
    fn rust_tokens_ignore_comments_literals_and_raw_keyword_identifiers() {
        let source = r###"fn probe() {
    let r#if = true;
    let prose = r#"match value { _ => if false { a && b } }"#;
    // for item in values { while false { a || b } }
    if ready { run(); }
}"###;
        let sources = BTreeMap::from([("src/probe.rs".to_owned(), source.to_owned())]);
        let functions = extract(&sources);
        let metrics = measure(&functions[0], None);
        assert_eq!((metrics.cyclomatic, metrics.cognitive), (2, 1));
    }

    #[test]
    fn measures_nested_control_flow() {
        let function = FunctionSource {
            path: "lib/logic.dart".to_owned(),
            name: "logic".to_owned(),
            line: 3,
            end_line: 11,
            contract_signature: false,
            source: "void logic() {\n  if (first && second) {\n    for (final item in items) {\n      if (item.ready) {\n        save(item);\n      }\n    }\n  }\n}".to_owned(),
        };
        assert_eq!(
            measure(&function, None),
            FunctionMetrics {
                cyclomatic: 5,
                cognitive: 7,
                length: 9,
                declarative_map: false,
            }
        );
    }

    #[test]
    fn counts_a_flat_logical_chain_as_one_cognitive_sequence() {
        let function = FunctionSource {
            path: "src/predicate.rs".to_owned(),
            name: "matches".to_owned(),
            line: 1,
            end_line: 5,
            contract_signature: false,
            source: "fn matches() {\n  if first || second || third || fourth {\n    run();\n  }\n}"
                .to_owned(),
        };

        assert_eq!(
            measure(&function, None),
            FunctionMetrics {
                cyclomatic: 5,
                cognitive: 2,
                length: 5,
                declarative_map: false,
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
            contract_signature: false,
            source: r#"Future<void> write() async { try { if (ready) run(); final normalized = path.replaceAll(r'\', '/'); } on Exception catch (error) { if (error != null) rethrow; } }"#.to_owned(),
        };

        assert_eq!(
            measure(&function, None),
            FunctionMetrics {
                cyclomatic: 4,
                cognitive: 3,
                length: 1,
                declarative_map: false,
            }
        );
    }

    #[test]
    fn ignores_python_multiline_strings_and_comments() {
        let function = FunctionSource {
            path: "src/api.py".to_owned(),
            name: "route".to_owned(),
            line: 1,
            end_line: 10,
            contract_signature: false,
            source: "def route(value):\n\
    \"\"\"Explain if values are ready.\n\
    For callers that use this function.\n\
    while examples remain readable.\n\
    \"\"\"\n\
    details = '''case and catch are prose'''\n\
    # if fallback and retry\n\
    if value:\n\
        return details\n\
    return None"
                .to_owned(),
        };

        assert_eq!(
            measure(&function, None),
            FunctionMetrics {
                cyclomatic: 2,
                cognitive: 1,
                length: 10,
                declarative_map: false,
            }
        );
    }

    #[test]
    fn groups_complex_localization_implementations_without_hiding_other_complexity() {
        let complex_source = "fn render() {\n  if (first) { run(); }\n}";
        let functions = [
            ("src/logic.rs", "logic"),
            ("locales/en.rs", "message"),
            ("locales/sv.rs", "message"),
        ]
        .into_iter()
        .map(|(path, name)| FunctionSource {
            path: path.to_owned(),
            name: name.to_owned(),
            line: 1,
            end_line: 3,
            contract_signature: false,
            source: complex_source.to_owned(),
        })
        .collect::<Vec<_>>();
        let mut config = Config::defaults(PathBuf::from("."));
        config.complexity_threshold = 1;
        config.cognitive_threshold = 100;

        let findings = analyze(&functions, &BTreeMap::new(), &config);
        assert_eq!(findings.len(), 2);
        let localization = findings
            .iter()
            .find(|finding| finding.path == "locales/en.rs")
            .expect("localization complexity must remain visible");
        assert_eq!(localization.related_files, ["locales/sv.rs:1"]);
        assert!(
            localization
                .message
                .contains("2 localization implementations")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.path == "src/logic.rs")
        );
    }

    #[test]
    fn leaves_c_cleanup_gotos_to_language_specific_review() {
        let sources = BTreeMap::from([
            (
                "native/resource.c".to_owned(),
                "int load(void) {\n  if (failed()) goto cleanup;\ncleanup:\n  release();\n  return 0;\n}"
                    .to_owned(),
            ),
            (
                "src/Workflow.cs".to_owned(),
                "void Run() {\n  goto Finished;\nFinished:\n  return;\n}".to_owned(),
            ),
        ]);
        let findings = analyze(&[], &sources, &Config::defaults(PathBuf::from(".")));

        assert_eq!(
            findings
                .into_iter()
                .filter(|finding| finding.code == "goto-statement")
                .map(|finding| finding.path)
                .collect::<Vec<_>>(),
            ["src/Workflow.cs"]
        );
    }
}
