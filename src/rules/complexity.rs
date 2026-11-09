use std::borrow::Cow;
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
}

pub fn analyze(
    functions: &[FunctionSource],
    sources: &BTreeMap<String, String>,
    config: &Config,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut localization_complexity = Vec::new();
    let mut rust_contexts = BTreeMap::new();
    for function in functions {
        let rust_context = function.path.ends_with(".rs").then(|| {
            rust_contexts
                .entry(function.path.as_str())
                .or_insert_with(|| {
                    RustComplexityContext::new(
                        sources.get(&function.path).map_or("", String::as_str),
                    )
                })
        });
        let in_quote_template = rust_context
            .as_ref()
            .is_some_and(|context| context.contains_template_function(function.line));
        let metrics = measure(function, rust_context.as_deref());
        if !in_quote_template
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
    let mut cyclomatic = 1usize;
    let mut cognitive = 0usize;
    let mut depth = 0isize;
    let mut lexical = LexicalState::default();
    let dart = function.path.ends_with(".dart");
    let python = function.path.ends_with(".py");
    let rust_source = function
        .path
        .ends_with(".rs")
        .then(|| rust_complexity_source(&function.source, rust_context));
    for line in rust_source
        .as_deref()
        .unwrap_or(&function.source)
        .split('\n')
    {
        let code = if rust_source.is_some() {
            Cow::Borrowed(line)
        } else {
            Cow::Owned(strip_code(line, &mut lexical, dart, python))
        };
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
    }
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
        let context = RustComplexityContext::new(source);
        let metrics = measure(&functions[0], Some(&context));
        assert_eq!(metrics.cyclomatic, 4);
        assert_eq!(metrics.cognitive, 5);
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
        assert_eq!(findings[0].message, "generate complexity=4 cognitive=5");
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
            let context = RustComplexityContext::new(source);
            let metrics = measure(&functions[0], Some(&context));
            assert_eq!(metrics.cyclomatic, 2);
            assert_eq!(metrics.cognitive, 1);
        }
    }

    #[test]
    fn retains_actual_field_deserializer_complexity_after_ignoring_emitted_branches() {
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
        let context = RustComplexityContext::new(source);
        let metrics = measure(&functions[0], Some(&context));
        assert_eq!(metrics.cyclomatic, 7);
        assert_eq!(metrics.cognitive, 16);
        let findings = analyze(&functions, &sources, &Config::defaults(PathBuf::from(".")));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "complex-function");
        assert_eq!(findings[0].path, "src/derive.rs");
        assert_eq!(findings[0].line, 2);
        assert_eq!(
            findings[0].message,
            "field_deserializer complexity=7 cognitive=16"
        );
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
