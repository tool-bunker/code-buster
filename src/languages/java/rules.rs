use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let sources = context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".java"))
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<BTreeMap<_, _>>();
    if sources.is_empty() {
        return Vec::new();
    }

    let mut findings = line_findings(&sources);
    findings.extend(ignored_future_results(&sources));
    findings.extend(empty_catches(&sources));
    findings.extend(hardcoded_secrets(&sources));
    findings.extend(package_cycles(&sources));
    findings.extend(resources_not_closed(&sources));
    findings.extend(loop_performance_findings(&sources));
    findings.extend(too_many_parameters(&sources));
    findings.extend(weak_crypto(&sources));
    findings
}

#[derive(Clone, Copy)]
struct JavaLineFinding {
    code: &'static str,
    message: &'static str,
}

impl JavaLineFinding {
    fn emit(self, path: &str, line: usize) -> Finding {
        finding(self.code, path, line, self.message, "medium", Vec::new())
    }
}

fn line_findings(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let mut in_block_comment = false;
        let allow_console_output = is_java_test_or_command_line_source(path, source);
        let mut reported_object_input_stream = false;
        for (index, raw) in source.split('\n').enumerate() {
            let (without_comments, next_block_state) =
                java_code_without_comments(raw, in_block_comment);
            in_block_comment = next_block_state;
            let masked = mask_quoted_text(&without_comments);
            let line_number = index + 1;
            let candidates = classify_line_findings(
                raw,
                &without_comments,
                &masked,
                allow_console_output,
                &mut reported_object_input_stream,
            );
            findings.extend(
                candidates
                    .into_iter()
                    .flatten()
                    .map(|candidate| candidate.emit(path, line_number)),
            );
        }
    }
    findings
}

fn classify_line_findings(
    raw: &str,
    without_comments: &str,
    masked: &str,
    allow_console_output: bool,
    reported_object_input_stream: &mut bool,
) -> [Option<JavaLineFinding>; 8] {
    let catch_exception = CATCH_EXCEPTION.is_match(masked);
    let object_input_stream = !*reported_object_input_stream
        && !masked.trim_start().starts_with("import ")
        && OBJECT_INPUT_STREAM.is_match(masked);
    *reported_object_input_stream |= object_input_stream;
    let print_stacktrace = PRINT_STACKTRACE.is_match(masked);
    let sensitive_random =
        raw.contains("new Random(") && SENSITIVE_RANDOM.is_match(&raw.to_ascii_lowercase());
    let sql_string_build = has_sql_string_build(raw);
    let string_identity = has_string_identity_comparison(without_comments);
    let system_out = !allow_console_output && SYSTEM_OUT.is_match(masked);
    let thread_sleep = THREAD_SLEEP.is_match(masked);

    [
        catch_exception.then_some(JavaLineFinding {
            code: "java-catch-exception",
            message: "broad Java exception handler",
        }),
        object_input_stream.then_some(JavaLineFinding {
            code: "java-objectinputstream",
            message: "Java native deserialization used",
        }),
        print_stacktrace.then_some(JavaLineFinding {
            code: "java-print-stacktrace",
            message: "printStackTrace used",
        }),
        sensitive_random.then_some(JavaLineFinding {
            code: "java-random-security",
            message: "java.util.Random appears used for sensitive value",
        }),
        sql_string_build.then_some(JavaLineFinding {
            code: "java-sql-string-build",
            message: "SQL appears concatenated",
        }),
        string_identity.then_some(JavaLineFinding {
            code: "java-string-equals",
            message: "string compared with ==/!=",
        }),
        system_out.then_some(JavaLineFinding {
            code: "java-system-out",
            message: "System.out/System.err logging used",
        }),
        thread_sleep.then_some(JavaLineFinding {
            code: "java-thread-sleep",
            message: "Thread.sleep used",
        }),
    ]
}

fn has_sql_string_build(line: &str) -> bool {
    SQL_STRING_BUILD.captures_iter(line).any(|capture| {
        let suffix = &line[capture.get(0).unwrap().end()..];
        suffix
            .chars()
            .next()
            .is_some_and(|character| character != '"' && !character.is_whitespace())
    })
}

fn has_string_identity_comparison(line: &str) -> bool {
    STRING_IDENTITY.find_iter(line).any(|candidate| {
        !inside_java_quote(line, candidate.start())
            && !is_boolean_string_method_comparison(line, candidate.start(), candidate.end())
    })
}

fn is_boolean_string_method_comparison(line: &str, start: usize, end: usize) -> bool {
    BOOLEAN_OPERAND.is_match(&line[..start]) && line[end..].trim_start().starts_with('.')
}

#[derive(Clone, Copy)]
enum JavaQuotePosition {
    Code,
    Quoted { delimiter: u8, escaped: bool },
}

impl JavaQuotePosition {
    fn advance(self, byte: u8) -> Self {
        match self {
            Self::Code if matches!(byte, b'"' | b'\'') => Self::Quoted {
                delimiter: byte,
                escaped: false,
            },
            Self::Code => Self::Code,
            Self::Quoted {
                delimiter,
                escaped: true,
            } => Self::Quoted {
                delimiter,
                escaped: false,
            },
            Self::Quoted {
                delimiter,
                escaped: false,
            } if byte == b'\\' => Self::Quoted {
                delimiter,
                escaped: true,
            },
            Self::Quoted {
                delimiter,
                escaped: false,
            } if byte == delimiter => Self::Code,
            quoted @ Self::Quoted { .. } => quoted,
        }
    }
}

fn inside_java_quote(line: &str, offset: usize) -> bool {
    let state = line.as_bytes()[..offset]
        .iter()
        .copied()
        .fold(JavaQuotePosition::Code, JavaQuotePosition::advance);
    matches!(state, JavaQuotePosition::Quoted { .. })
}

fn is_java_test_or_command_line_source(path: &str, source: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    JAVA_TEST_PATH.is_match(&normalized)
        || JAVA_CLI_PATH.is_match(&normalized)
        || file_name.contains("CommandLine")
        || file_name.contains("Console")
        || file_name.ends_with("Cli.java")
        || JAVA_MAIN_METHOD.is_match(source)
        || PRINT_TO_CONSOLE_METHOD.is_match(source)
}

fn empty_catches(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, raw_source) in sources {
        let source = java_source_without_comments(raw_source);
        for catch_match in EMPTY_CATCH.find_iter(&source) {
            let original = &raw_source[catch_match.start()..catch_match.end()];
            if original.contains("//")
                || original.contains("/*")
                || IGNORED_CATCH_PARAMETER.is_match(original)
            {
                continue;
            }
            findings.push(finding(
                "java-empty-catch",
                path,
                line_at(&source, catch_match.start()),
                "catch block is empty",
                "high",
                Vec::new(),
            ));
        }
    }
    findings
}

fn hardcoded_secrets(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let mut in_block_comment = false;
        for (index, raw) in source.split('\n').enumerate() {
            let (line, next_block_state) = java_code_without_comments(raw, in_block_comment);
            in_block_comment = next_block_state;
            if is_hardcoded_secret_candidate(&line) {
                findings.push(hardcoded_secret_finding(path, index + 1));
            }
        }
    }
    findings
}

fn is_hardcoded_secret_candidate(line: &str) -> bool {
    let Some(assignment) = LITERAL_ASSIGNMENT.captures(line) else {
        return false;
    };
    let identifier = &assignment[1];
    let literal = &assignment[2];
    let lower_identifier = identifier.to_ascii_lowercase();
    let lower_literal = literal.to_ascii_lowercase();
    let normalized_identifier = normalize_alphanumeric(&lower_identifier);
    let normalized_literal = normalize_alphanumeric(&lower_literal);

    SECRET_IDENTIFIER.is_match(&lower_identifier)
        && !is_excluded_secret_assignment(
            line,
            identifier,
            literal,
            &lower_identifier,
            &lower_literal,
            &normalized_identifier,
            &normalized_literal,
        )
}

fn is_excluded_secret_assignment(
    line: &str,
    identifier: &str,
    literal: &str,
    lower_identifier: &str,
    lower_literal: &str,
    normalized_identifier: &str,
    normalized_literal: &str,
) -> bool {
    literal.trim().is_empty()
        || is_symbolic_credential_reference(
            identifier,
            literal,
            normalized_identifier,
            normalized_literal,
        )
        || is_non_credential_identifier(lower_identifier)
        || is_non_secret_literal(
            literal,
            lower_identifier,
            lower_literal,
            normalized_identifier,
            normalized_literal,
        )
        || is_runtime_secret_lookup(line)
}

fn is_non_credential_identifier(lower_identifier: &str) -> bool {
    NON_CREDENTIAL_KEY.is_match(lower_identifier) || NON_CREDENTIAL_ROLE.is_match(lower_identifier)
}

fn is_non_secret_literal(
    literal: &str,
    lower_identifier: &str,
    lower_literal: &str,
    normalized_identifier: &str,
    normalized_literal: &str,
) -> bool {
    normalized_identifier == normalized_literal
        || literal.trim().len() != literal.len()
        || (normalized_literal
            .chars()
            .all(|value| value.is_ascii_digit())
            && normalized_literal.len() < 8)
        || SYMBOLIC_LITERAL.is_match(literal)
        || PLACEHOLDER_LITERAL.is_match(normalized_literal)
        || (CREDENTIAL_PLACEHOLDER.is_match(lower_literal)
            && lower_identifier
                .split('_')
                .any(|part| part == lower_literal))
}

fn is_runtime_secret_lookup(line: &str) -> bool {
    line.to_ascii_lowercase().contains("system.getenv")
        || line.to_ascii_lowercase().contains("getproperty")
}

fn hardcoded_secret_finding(path: &str, line: usize) -> Finding {
    finding(
        "java-hardcoded-secret",
        path,
        line,
        "possible hardcoded secret",
        "medium",
        Vec::new(),
    )
}

fn normalize_alphanumeric(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}

fn is_symbolic_credential_reference(
    identifier: &str,
    literal: &str,
    normalized_identifier: &str,
    normalized_literal: &str,
) -> bool {
    if UPPERCASE_IDENTIFIER.is_match(identifier)
        && (literal.contains('%') || literal.contains("{{"))
    {
        return true;
    }
    if (literal.contains('-') || literal.contains('_'))
        && normalized_literal.ends_with(normalized_identifier)
    {
        return true;
    }
    ["key", "token", "password", "secret"].iter().any(|suffix| {
        normalized_identifier
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix == normalized_literal)
    })
}

fn weak_crypto(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let lines = source.split('\n').collect::<Vec<_>>();
        let mut in_block_comment = false;
        for (index, raw) in lines.iter().enumerate() {
            let (code, next_block_state) = java_code_without_comments(raw, in_block_comment);
            in_block_comment = next_block_state;
            if !(OBSOLETE_CIPHER.is_match(&code)
                || LEGACY_DIGEST.is_match(&code) && has_security_context(&lines, index))
            {
                continue;
            }
            findings.push(finding(
                "java-weak-crypto",
                path,
                index + 1,
                "weak cryptography referenced",
                "medium",
                Vec::new(),
            ));
        }
    }
    findings
}

fn has_security_context(lines: &[&str], index: usize) -> bool {
    let mut context = lines[index].to_ascii_lowercase();
    let first = index.saturating_sub(12);
    for previous in (first..index).rev() {
        let candidate = lines[previous];
        if METHOD_CONTEXT.is_match(candidate) {
            context.push(' ');
            context.push_str(&candidate.to_ascii_lowercase());
            break;
        }
    }
    SECURITY_CONTEXT.is_match(&context)
}

#[derive(Debug)]
struct JavaFunction<'a> {
    path: &'a str,
    name: String,
    line: usize,
    source: String,
}

fn java_functions<'a>(sources: &'a BTreeMap<&str, &str>) -> Vec<JavaFunction<'a>> {
    let mut functions = Vec::new();
    for (path, source) in sources {
        let lines = source.split('\n').collect::<Vec<_>>();
        let mut index = 0;
        while index < lines.len() {
            let declaration_line = LEADING_CLOSERS.replace(lines[index].trim_start(), "");
            let Some(method) = JAVA_METHOD.captures(&declaration_line) else {
                index += 1;
                continue;
            };
            if JAVA_CONTROL.is_match(&declaration_line) {
                index += 1;
                continue;
            }
            let mut depth = 0isize;
            let mut started = false;
            let mut end = index;
            while end < lines.len() {
                depth += lines[end].matches('{').count() as isize;
                depth -= lines[end].matches('}').count() as isize;
                started |= lines[end].contains('{');
                if started && depth <= 0 {
                    break;
                }
                end += 1;
            }
            let exclusive_end = (end + 1).min(lines.len());
            functions.push(JavaFunction {
                path,
                name: method[1].to_owned(),
                line: index + 1,
                source: lines[index..exclusive_end].join("\n"),
            });
            index = exclusive_end;
        }
    }
    functions
}

fn resources_not_closed(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for function in java_functions(sources) {
        for allocation in CLOSEABLE_ALLOCATION.captures_iter(&function.source) {
            let (Some(allocation_match), Some(variable)) = (allocation.get(0), allocation.get(1))
            else {
                continue;
            };
            let variable = variable.as_str();
            let escaped = regex::escape(variable);
            let Ok(close) = Regex::new(&format!(r"\b{escaped}\.close\s*\(")) else {
                continue;
            };
            let Ok(returned) = Regex::new(&format!(r"\breturn\s+{escaped}\s*;")) else {
                continue;
            };
            if close.is_match(&function.source)
                || TRY_WITH_RESOURCES.is_match(&function.source)
                || returned.is_match(&function.source)
            {
                continue;
            }
            findings.push(finding(
                "java-resource-not-closed",
                function.path,
                function.line
                    + function.source[..allocation_match.start()]
                        .matches('\n')
                        .count(),
                &format!("locally-created resource `{variable}` is not closed"),
                "high",
                Vec::new(),
            ));
        }
    }
    findings
}

fn too_many_parameters(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for function in java_functions(sources) {
        let Some(open) = function.source.find('(') else {
            continue;
        };
        if has_externally_defined_signature(sources[function.path], function.line)
            || is_forwarding_constructor(&function.source)
        {
            continue;
        }
        let Some(close) = matching_delimiter(&function.source, open, '(', ')') else {
            continue;
        };
        let count = parameter_count(&function.source[open + 1..close]);
        if count <= 7 {
            continue;
        }
        findings.push(finding(
            "java-too-many-parameters",
            function.path,
            function.line,
            &format!("`{}` has {count} parameters", function.name),
            "high",
            Vec::new(),
        ));
    }
    findings
}

fn has_externally_defined_signature(source: &str, declaration_line: usize) -> bool {
    let lines = source.split('\n').collect::<Vec<_>>();
    if declaration_line < 2 {
        return false;
    }
    let first = declaration_line.saturating_sub(12);
    for index in (first..declaration_line - 1).rev() {
        let line = lines[index].trim();
        if line.is_empty() {
            continue;
        }
        if let Some(annotation) = ANNOTATION.captures(line) {
            if EXTERNAL_SIGNATURE_ANNOTATIONS.contains(&&annotation[1]) {
                return true;
            }
            continue;
        }
        if line.contains(';') || line.contains('{') || line.contains('}') {
            break;
        }
    }
    false
}

fn is_forwarding_constructor(source: &str) -> bool {
    FORWARDING_CONSTRUCTOR.is_match(source)
}

fn parameter_count(parameters: &str) -> usize {
    let mut counter = ParameterCounter::default();
    for character in parameters.chars() {
        counter.consume(character);
    }
    counter.finish()
}

#[derive(Default)]
struct ParameterCounter {
    scan: ParameterScanState,
    separators: usize,
    has_content: bool,
}

impl ParameterCounter {
    fn consume(&mut self, character: char) {
        self.has_content |= !character.is_whitespace();
        if self.scan.consume(character) {
            self.separators += 1;
        }
    }

    fn finish(self) -> usize {
        if self.has_content {
            self.separators + 1
        } else {
            0
        }
    }
}

#[derive(Default)]
struct ParameterScanState {
    generic_depth: usize,
    annotation_depth: usize,
    delimiter_depth: usize,
}

impl ParameterScanState {
    fn consume(&mut self, character: char) -> bool {
        match character {
            '<' => self.generic_depth += 1,
            '>' => self.generic_depth = self.generic_depth.saturating_sub(1),
            '(' => self.annotation_depth += 1,
            ')' => self.annotation_depth = self.annotation_depth.saturating_sub(1),
            '[' => self.delimiter_depth += 1,
            ']' => self.delimiter_depth = self.delimiter_depth.saturating_sub(1),
            ',' => return self.at_parameter_boundary(),
            _ => {}
        }
        false
    }

    fn at_parameter_boundary(&self) -> bool {
        self.generic_depth == 0 && self.annotation_depth == 0 && self.delimiter_depth == 0
    }
}

fn ignored_future_results(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, raw_source) in sources {
        let comments_masked = java_source_without_comments(raw_source);
        let code = mask_quoted_text(&comments_masked);
        for call in JAVA_IGNORED_FUTURE.captures_iter(&code) {
            let whole = call.get(0).unwrap();
            if call.name("receiver").is_some_and(|receiver| {
                !java_variable_type_before(&code, receiver.as_str(), whole.start())
                    .is_some_and(|(_, kind)| java_executor_type(kind))
            }) {
                continue;
            }
            findings.push(finding(
                "java-ignored-future",
                path,
                line_at(&code, whole.start()),
                "Future-returning asynchronous work is started without retaining its result",
                "high",
                Vec::new(),
            ));
        }
    }
    findings
}

// code-buster-ignore complex-function: one loop traversal shares source ranges and deduplication across performance rules.
fn loop_performance_findings(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, raw_source) in sources {
        let comments_masked = java_source_without_comments(raw_source);
        let code = mask_quoted_text(&comments_masked);
        let mut reported = BTreeSet::new();
        for loop_match in LOOP.find_iter(&code) {
            let Some(relative_open) = code[loop_match.start()..].find('{') else {
                continue;
            };
            let open = loop_match.start() + relative_open;
            let Some(close) = matching_delimiter(&code, open, '{', '}') else {
                continue;
            };
            let body = &code[open + 1..close];
            for concatenation in JAVA_STRING_CONCAT.captures_iter(body) {
                let whole = concatenation.get(0).unwrap();
                let variable = &concatenation[1];
                let offset = open + 1 + whole.start();
                if !java_variable_type_before(&code, variable, offset)
                    .is_some_and(|(declaration, kind)| declaration < open && java_string_type(kind))
                    || concatenation
                        .get(2)
                        .is_some_and(|rhs| rhs.as_str() != variable)
                {
                    continue;
                }
                if reported.insert(("java-string-concat-in-loop", offset)) {
                    findings.push(finding(
                        "java-string-concat-in-loop",
                        path,
                        line_at(&code, offset),
                        &format!("String `{variable}` is concatenated inside a loop"),
                        "high",
                        Vec::new(),
                    ));
                }
            }
            let repeated_source = &comments_masked[open + 1..close];
            for compiled in JAVA_CONSTANT_PATTERN.captures_iter(repeated_source) {
                let whole = compiled.get(0).unwrap();
                let offset = open + 1 + whole.start();
                if reported.insert(("java-pattern-compile-in-loop", offset)) {
                    findings.push(finding(
                        "java-pattern-compile-in-loop",
                        path,
                        line_at(&code, offset),
                        "constant regular expression is compiled inside a loop",
                        "high",
                        Vec::new(),
                    ));
                }
            }
            for membership in JAVA_LINEAR_MEMBERSHIP.captures_iter(body) {
                let whole = membership.get(0).unwrap();
                let variable = &membership[1];
                let offset = open + 1 + whole.start();
                if !java_variable_type_before(&code, variable, offset).is_some_and(
                    |(declaration, kind)| declaration < open && java_linear_collection_type(kind),
                ) {
                    continue;
                }
                if reported.insert(("java-linear-membership-in-loop", offset)) {
                    findings.push(finding(
                        "java-linear-membership-in-loop",
                        path,
                        line_at(&code, offset),
                        &format!("List `{variable}` performs linear membership inside a loop"),
                        "high",
                        Vec::new(),
                    ));
                }
            }
            for access in JAVA_INDEXED_ACCESS.captures_iter(body) {
                let whole = access.get(0).unwrap();
                let variable = &access[1];
                let offset = open + 1 + whole.start();
                if !java_variable_type_before(&code, variable, offset).is_some_and(
                    |(declaration, kind)| declaration < open && java_linked_list_type(kind),
                ) {
                    continue;
                }
                if reported.insert(("java-linked-list-indexed-loop", offset)) {
                    findings.push(finding(
                        "java-linked-list-indexed-loop",
                        path,
                        line_at(&code, offset),
                        &format!("LinkedList `{variable}` is accessed by index inside a loop"),
                        "high",
                        Vec::new(),
                    ));
                }
            }
        }
    }
    findings
}

fn java_variable_type_before<'source>(
    code: &'source str,
    variable: &str,
    offset: usize,
) -> Option<(usize, &'source str)> {
    JAVA_VARIABLE_DECLARATION
        .captures_iter(&code[..offset])
        .filter(|capture| &capture[2] == variable)
        .last()
        .and_then(|capture| Some((capture.get(0)?.start(), capture.get(1)?.as_str().trim())))
}

fn java_string_type(variable_type: &str) -> bool {
    variable_type == "String" || variable_type.ends_with(".String")
}

fn java_linear_collection_type(variable_type: &str) -> bool {
    variable_type
        .split('<')
        .next()
        .and_then(|base| base.trim().rsplit('.').next())
        .is_some_and(|base| matches!(base, "List" | "ArrayList" | "LinkedList" | "Vector"))
}
fn java_linked_list_type(variable_type: &str) -> bool {
    variable_type
        .split('<')
        .next()
        .and_then(|base| base.trim().rsplit('.').next())
        == Some("LinkedList")
}

fn java_executor_type(variable_type: &str) -> bool {
    variable_type
        .split('<')
        .next()
        .and_then(|base| base.trim().rsplit('.').next())
        .is_some_and(|base| {
            matches!(
                base,
                "ExecutorService"
                    | "ScheduledExecutorService"
                    | "ListeningExecutorService"
                    | "ListeningScheduledExecutorService"
            )
        })
}

fn package_cycles(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let packages = index_packages(sources);
    let edges = build_package_graph(sources, &packages);
    emit_package_cycles(&edges)
}

struct PackageIndex<'a> {
    owners: BTreeMap<&'a str, (String, String)>,
    nodes_by_package: BTreeMap<String, BTreeSet<String>>,
}

fn index_packages<'a>(sources: &BTreeMap<&'a str, &str>) -> PackageIndex<'a> {
    let mut owners = BTreeMap::new();
    let mut nodes_by_package = BTreeMap::<String, BTreeSet<String>>::new();
    for (&path, source) in sources {
        let Some(package) = PACKAGE
            .captures(source)
            .map(|capture| capture[1].to_owned())
        else {
            continue;
        };
        let module = module_for(path).to_owned();
        let node = package_node(&module, &package);
        owners.insert(path, (module, package.clone()));
        nodes_by_package.entry(package).or_default().insert(node);
    }
    PackageIndex {
        owners,
        nodes_by_package,
    }
}

fn build_package_graph(
    sources: &BTreeMap<&str, &str>,
    packages: &PackageIndex<'_>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut edges = packages
        .nodes_by_package
        .values()
        .flatten()
        .map(|node| (node.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for (path, source) in sources {
        let Some((owner_module, owner_package)) = packages.owners.get(path) else {
            continue;
        };
        let owner_node = package_node(owner_module, owner_package);
        for import in IMPORT.captures_iter(source) {
            add_import_dependency(
                &mut edges,
                packages,
                owner_module,
                owner_package,
                &owner_node,
                &import[1],
            );
        }
    }
    edges
}

fn add_import_dependency(
    edges: &mut BTreeMap<String, BTreeSet<String>>,
    packages: &PackageIndex<'_>,
    owner_module: &str,
    owner_package: &str,
    owner_node: &str,
    imported: &str,
) {
    let Some(target) = resolve_import_target(packages, owner_module, owner_package, imported)
    else {
        return;
    };
    if target == owner_node {
        return;
    }
    let Some(owner_edges) = edges.get_mut(owner_node) else {
        return;
    };
    owner_edges.insert(target);
}

fn resolve_import_target(
    packages: &PackageIndex<'_>,
    owner_module: &str,
    owner_package: &str,
    imported: &str,
) -> Option<String> {
    let package = imported_package(&packages.nodes_by_package, imported)?;
    if package == owner_package {
        return None;
    }
    let candidates = &packages.nodes_by_package[package];
    let same_module = package_node(owner_module, package);
    if candidates.contains(&same_module) {
        Some(same_module)
    } else if candidates.len() == 1 {
        candidates.first().cloned()
    } else {
        None
    }
}

fn imported_package<'a>(
    nodes_by_package: &'a BTreeMap<String, BTreeSet<String>>,
    imported: &str,
) -> Option<&'a str> {
    nodes_by_package
        .keys()
        .filter(|candidate| {
            imported == candidate.as_str() || imported.starts_with(&format!("{candidate}."))
        })
        .max_by_key(|candidate| candidate.len())
        .map(String::as_str)
}

fn emit_package_cycles(edges: &BTreeMap<String, BTreeSet<String>>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for component in strongly_connected_components(edges) {
        if let Some(finding) = package_cycle_finding(edges, &component) {
            findings.push(finding);
        }
    }
    findings
}

fn package_cycle_finding(
    edges: &BTreeMap<String, BTreeSet<String>>,
    component: &BTreeSet<String>,
) -> Option<Finding> {
    if component.len() < 2 {
        return None;
    }
    let cycle = representative_cycle(edges, component)?;
    let cycle_start = cycle.first()?;
    let represented = cycle.iter().cloned().collect::<BTreeSet<_>>();
    let related = component
        .difference(&represented)
        .take(20)
        .map(|node| display_package_node(node))
        .collect::<Vec<_>>();
    let description = cycle.join(" -> ");
    let size_detail = if component.len() > represented.len() {
        format!(
            " ({} modules in strongly connected component)",
            component.len()
        )
    } else {
        String::new()
    };
    Some(finding(
        "java-package-cycle",
        &display_package_node(cycle_start),
        1,
        &format!("package cycle: {description}{size_detail}"),
        "high",
        related,
    ))
}

struct Tarjan<'a> {
    edges: &'a BTreeMap<String, BTreeSet<String>>,
    next_index: usize,
    indices: BTreeMap<String, usize>,
    low_links: BTreeMap<String, usize>,
    stack: Vec<String>,
    on_stack: BTreeSet<String>,
    components: Vec<BTreeSet<String>>,
}

impl<'a> Tarjan<'a> {
    fn new(edges: &'a BTreeMap<String, BTreeSet<String>>) -> Self {
        Self {
            edges,
            next_index: 0,
            indices: BTreeMap::new(),
            low_links: BTreeMap::new(),
            stack: Vec::new(),
            on_stack: BTreeSet::new(),
            components: Vec::new(),
        }
    }

    fn collect_components(mut self) -> Vec<BTreeSet<String>> {
        for node in self.edges.keys() {
            if !self.indices.contains_key(node) {
                self.visit(node);
            }
        }
        self.components
    }

    fn visit(&mut self, node: &str) {
        let Some(dependencies) = self.edges.get(node) else {
            return;
        };
        self.begin_visit(node);
        for dependency in dependencies {
            self.follow_dependency(node, dependency);
        }
        self.finalize_component(node);
    }

    fn begin_visit(&mut self, node: &str) {
        let index = self.next_index;
        self.next_index += 1;
        self.indices.insert(node.to_owned(), index);
        self.low_links.insert(node.to_owned(), index);
        self.stack.push(node.to_owned());
        self.on_stack.insert(node.to_owned());
    }

    fn follow_dependency(&mut self, node: &str, dependency: &str) {
        if !self.edges.contains_key(dependency) {
            return;
        }
        if !self.indices.contains_key(dependency) {
            self.visit(dependency);
            self.apply_child_low_link(node, dependency);
        } else if self.on_stack.contains(dependency) {
            self.apply_back_edge(node, dependency);
        }
    }

    fn apply_child_low_link(&mut self, node: &str, dependency: &str) {
        let low = self.low_links[node].min(self.low_links[dependency]);
        self.low_links.insert(node.to_owned(), low);
    }

    fn apply_back_edge(&mut self, node: &str, dependency: &str) {
        let low = self.low_links[node].min(self.indices[dependency]);
        self.low_links.insert(node.to_owned(), low);
    }

    fn finalize_component(&mut self, node: &str) {
        if self.low_links[node] != self.indices[node] {
            return;
        }
        let mut component = BTreeSet::new();
        loop {
            let Some(member) = self.stack.pop() else {
                return;
            };
            let is_root = member == node;
            self.on_stack.remove(&member);
            component.insert(member);
            if is_root {
                break;
            }
        }
        self.components.push(component);
    }
}

fn strongly_connected_components(
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<BTreeSet<String>> {
    Tarjan::new(edges).collect_components()
}

fn representative_cycle(
    edges: &BTreeMap<String, BTreeSet<String>>,
    component: &BTreeSet<String>,
) -> Option<Vec<String>> {
    fn search(
        current: &str,
        start: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        component: &BTreeSet<String>,
        path: &mut Vec<String>,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        path.push(current.to_owned());
        visited.insert(current.to_owned());
        let Some(dependencies) = edges.get(current) else {
            path.pop();
            return false;
        };
        for next in dependencies {
            if !component.contains(next) {
                continue;
            }
            if next == start {
                path.push(start.to_owned());
                return true;
            }
            if !visited.contains(next) && search(next, start, edges, component, path, visited) {
                return true;
            }
        }
        path.pop();
        false
    }
    let start = component.first()?;
    let mut path = Vec::new();
    let mut visited = BTreeSet::new();
    search(start, start, edges, component, &mut path, &mut visited).then_some(path)
}

fn module_for(path: &str) -> &str {
    const MARKER: &str = "/src/main/java/";
    path.find(MARKER).map_or(".", |index| &path[..index])
}

fn package_node(module: &str, package: &str) -> String {
    if module == "." {
        package.to_owned()
    } else {
        format!("{module}::{package}")
    }
}

fn display_package_node(node: &str) -> String {
    if let Some((module, package)) = node.split_once("::") {
        format!("{module}/src/main/java/{}", package.replace('.', "/"))
    } else {
        node.replace('.', "/")
    }
}

fn matching_delimiter(source: &str, open: usize, opening: char, closing: char) -> Option<usize> {
    let mut depth = 0;
    for (offset, character) in source[open..].char_indices() {
        if character == opening {
            depth += 1;
        } else if character == closing {
            depth -= 1;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn java_source_without_comments(source: &str) -> String {
    let mut in_block_comment = false;
    source
        .split('\n')
        .map(|line| {
            let (code, next) = java_code_without_comments(line, in_block_comment);
            in_block_comment = next;
            code
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Copy)]
enum JavaCommentScanState {
    Code,
    BlockComment,
    LineComment,
    Quoted(char),
}

impl JavaCommentScanState {
    fn consume(self, character: char, next: Option<char>, result: &mut String) -> (Self, bool) {
        match self {
            Self::Code => Self::consume_code(character, next, result),
            Self::BlockComment => Self::consume_block_comment(character, next, result),
            Self::LineComment => {
                result.push(' ');
                (Self::LineComment, false)
            }
            Self::Quoted(delimiter) => Self::consume_quoted(character, next, delimiter, result),
        }
    }

    fn consume_code(character: char, next: Option<char>, result: &mut String) -> (Self, bool) {
        match (character, next) {
            ('/', Some('/')) => {
                result.push_str("  ");
                (Self::LineComment, true)
            }
            ('/', Some('*')) => {
                result.push_str("  ");
                (Self::BlockComment, true)
            }
            (delimiter @ ('"' | '\''), _) => {
                result.push(delimiter);
                (Self::Quoted(delimiter), false)
            }
            _ => {
                result.push(character);
                (Self::Code, false)
            }
        }
    }

    fn consume_block_comment(
        character: char,
        next: Option<char>,
        result: &mut String,
    ) -> (Self, bool) {
        if character == '*' && next == Some('/') {
            result.push_str("  ");
            (Self::Code, true)
        } else {
            result.push(' ');
            (Self::BlockComment, false)
        }
    }

    fn consume_quoted(
        character: char,
        next: Option<char>,
        delimiter: char,
        result: &mut String,
    ) -> (Self, bool) {
        result.push(character);
        match (character, next) {
            ('\\', Some(escaped)) => {
                result.push(escaped);
                (Self::Quoted(delimiter), true)
            }
            _ if character == delimiter => (Self::Code, false),
            _ => (Self::Quoted(delimiter), false),
        }
    }
}

fn java_code_without_comments(line: &str, in_block_comment: bool) -> (String, bool) {
    let mut result = String::with_capacity(line.len());
    let mut state = if in_block_comment {
        JavaCommentScanState::BlockComment
    } else {
        JavaCommentScanState::Code
    };
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        let (next_state, consume_next) =
            state.consume(character, characters.peek().copied(), &mut result);
        state = next_state;
        if consume_next {
            let _ = characters.next();
        }
    }
    (result, matches!(state, JavaCommentScanState::BlockComment))
}

#[derive(Clone, Copy)]
enum JavaQuoteScanState {
    Code,
    Quoted(char),
}

impl JavaQuoteScanState {
    fn consume(self, character: char, next: Option<char>, result: &mut String) -> (Self, bool) {
        match self {
            Self::Code => Self::consume_code(character, result),
            Self::Quoted(delimiter) => Self::consume_quoted(character, next, delimiter, result),
        }
    }

    fn consume_code(character: char, result: &mut String) -> (Self, bool) {
        if matches!(character, '"' | '\'') {
            result.push(' ');
            (Self::Quoted(character), false)
        } else {
            result.push(character);
            (Self::Code, false)
        }
    }

    fn consume_quoted(
        character: char,
        next: Option<char>,
        delimiter: char,
        result: &mut String,
    ) -> (Self, bool) {
        result.push(masked_quote_character(character));
        if character == '\\' {
            return Self::consume_escape(next, delimiter, result);
        }
        if character == delimiter {
            (Self::Code, false)
        } else {
            (Self::Quoted(delimiter), false)
        }
    }

    fn consume_escape(escaped: Option<char>, delimiter: char, result: &mut String) -> (Self, bool) {
        if let Some(escaped) = escaped {
            result.push(masked_quote_character(escaped));
            (Self::Quoted(delimiter), true)
        } else {
            (Self::Quoted(delimiter), false)
        }
    }
}

fn masked_quote_character(character: char) -> char {
    if character == '\n' { '\n' } else { ' ' }
}

fn mask_quoted_text(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut state = JavaQuoteScanState::Code;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        let (next_state, consume_next) =
            state.consume(character, characters.peek().copied(), &mut result);
        state = next_state;
        if consume_next {
            let _ = characters.next();
        }
    }
    result
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset].matches('\n').count() + 1
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: &str,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Java rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const EXTERNAL_SIGNATURE_ANNOTATIONS: &[&str] = &[
    "Inject",
    "ModifyArg",
    "ModifyArgs",
    "ModifyConstant",
    "ModifyExpressionValue",
    "ModifyVariable",
    "Override",
    "Redirect",
    "WrapOperation",
    "WrapWithCondition",
];

static JAVA_LINEAR_MEMBERSHIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*contains\s*\(").unwrap());
static JAVA_CONSTANT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bPattern\s*\.\s*compile\s*\(\s*\"(?:\\.|[^\"\\])*\""#).unwrap()
});
static JAVA_STRING_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*(?:\+=|=\s*([A-Za-z_]\w*)\s*\+)").unwrap());
static CATCH_EXCEPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"catch\s*\(\s*(?:Exception|Throwable)\b").unwrap());
static OBJECT_INPUT_STREAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bObjectInputStream\b").unwrap());
static PRINT_STACKTRACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.printStackTrace\s*\(").unwrap());
static SENSITIVE_RANDOM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"token|secret|password|passwd|api_key|apikey|nonce|salt|key").unwrap()
});
static SQL_STRING_BUILD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"\s*(?:select\b[^"]*\bfrom\b|insert\s+into\b|update\b[^"]*\bset\b|delete\s+from\b)[^"]*"\s*\+\s*"#).unwrap()
});
static STRING_IDENTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:==|!=)\s*"(?:\\.|[^"\\])*"|"(?:\\.|[^"\\])*"\s*(?:==|!=)"#).unwrap()
});
static BOOLEAN_OPERAND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:true|false)\s*$").unwrap());
static SYSTEM_OUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"System\.(?:out|err)\.println\s*\(").unwrap());
static THREAD_SLEEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Thread\.sleep\s*\(").unwrap());
static JAVA_MAIN_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bpublic\s+static\s+void\s+main\s*\(\s*(?:final\s+)?String\s*(?:\[\s*\]\s*\w+|\w+\s*\[\s*\]|\.\.\.\s*\w+)",
    )
    .unwrap()
});
static PRINT_TO_CONSOLE_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bprintToConsole\s*\(").unwrap());
static JAVA_TEST_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|/)(?:src/test|tests?)(/|$)").unwrap());
static JAVA_CLI_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(?:cli|tools?|[^/]+-cli|[^/]*(?:-|_)tools?(?:[-_][^/]*)?)(/|$)").unwrap()
});
static EMPTY_CATCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\bcatch\s*\([^()]*\)\s*\{\s*\}").unwrap());
static IGNORED_CATCH_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bcatch\s*\([^()]*(?:\b(?:ignored?|unused)|_)\s*\)").unwrap()
});
static LITERAL_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[^\w$"'])([A-Za-z_$][\w$]*)\s*=\s*"((?:\\.|[^"\\])*)"\s*;"#).unwrap()
});
static SECRET_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|_)(?:token|secret|password|passwd|api_?(?:key|secret)|nonce|salt)(?:$|_)")
        .unwrap()
});
static NON_CREDENTIAL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|_)(?:map|preference|package|action|type|path|error|width|height|quality)(?:_|$)",
    )
    .unwrap()
});
static NON_CREDENTIAL_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|_)(?:prefix|suffix|cache|header|claim|message|name|path|pattern|regex|property|success|failure|template|format|metadata|descriptor|descriptors|label|field|xfield|column|location|description|parameter|expiration|id|redacted|invalid|missing|mismatch|mismatching|option|query)(?:_|$)").unwrap()
});
static UPPERCASE_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]*$").unwrap());
static SYMBOLIC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[A-Z][A-Z0-9_]*|[A-Za-z][A-Za-z0-9]*(?:[.:][A-Za-z0-9_]+)+|[A-Za-z0-9_]+[:_]|_[a-z0-9_]+|</?[A-Za-z][A-Za-z0-9_-]*>|\[[A-Za-z][A-Za-z0-9_-]*\]|[a-z]+(?:[A-Z][A-Za-z0-9]*)+)$",
    )
    .unwrap()
});
static PLACEHOLDER_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:changeme|placeholder|example|test|your(?:token|secret|password|apikey)|(?:fake|mock|dummy|test)[a-z0-9]*(?:key|token|secret|password|passwd)|(?:asdf){2,})$").unwrap()
});
static CREDENTIAL_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:token|secret|password|passwd|api[_-]?(?:key|secret)|nonce|salt)$").unwrap()
});
static LEGACY_DIGEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bMessageDigest\s*\.\s*getInstance\s*\(\s*"[^"]*\b(?:MD5|SHA-?1)\b"#).unwrap()
});
static OBSOLETE_CIPHER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:Cipher|Mac|SecretKeyFactory|KeyGenerator)\s*\.\s*getInstance\s*\(\s*"[^"]*\b(?:HmacSHA1|DES|RC4)\b"#).unwrap()
});
static METHOD_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_$][\w$]*\s*\([^;]*\)\s*(?:\{|$)").unwrap());
static SECURITY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:auth|credential|password|passwd|secret|token|signature|signing|certificate|encryption|encrypt|decrypt|keyderivation|key derivation)").unwrap()
});
static LEADING_CLOSERS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:}\s*)+(?:else\s+)?").unwrap());
static JAVA_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{").unwrap()
});
static JAVA_CONTROL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:if|for|while|switch|catch|try|synchronized)\b").unwrap());
static CLOSEABLE_ALLOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:FileInputStream|FileOutputStream|FileReader|FileWriter|Connection|Statement|ResultSet)\s+([A-Za-z_]\w*)\s*=\s*new\s+").unwrap()
});
static TRY_WITH_RESOURCES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btry\s*\(").unwrap());
static ANNOTATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)\b").unwrap());
static FORWARDING_CONSTRUCTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)\{\s*super\s*\([^;]*\);\s*}\s*$").unwrap());
static JAVA_VARIABLE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z_$][\w$.]*(?:\s*<[^;(){}=>\n]+>)?(?:\s*\[\])?)\s+([A-Za-z_$][\w$]*)\s*(?:=|,|\)|;|:)",
    )
    .unwrap()
});
static LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:(?:for|while)\s*\([^{}]*\)|do)\s*\{").unwrap());
static JAVA_INDEXED_ACCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(").unwrap());
static JAVA_IGNORED_FUTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*(?:submit|schedule|scheduleAtFixedRate|scheduleWithFixedDelay)|CompletableFuture\s*\.\s*(?:runAsync|supplyAsync))\s*\(",
    )
    .unwrap()
});
static PACKAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*package\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;").unwrap()
});
static IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_*]\w*)*)\s*;").unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::analyze;
    use crate::source_analysis_context::SourceAnalysisContext;

    #[test]
    fn reports_all_standalone_java_rules() {
        let sources = BTreeMap::from([
            (
                "src/a/A.java".to_owned(),
                "package app.a;\nimport app.b.B;\nclass A { B value; }\n".to_owned(),
            ),
            (
                "src/b/B.java".to_owned(),
                "package app.b;\nimport app.a.A;\nclass B { A value; }\n".to_owned(),
            ),
            (
                "Main.java".to_owned(),
                "class Main {\n\
+  void run(int a, int b, int c, int d, int e, int f, int g, int h) {\n\
+    String password = \"real-secret-value\";\n\
+    ObjectInputStream input = open();\n\
+    FileInputStream file = new FileInputStream(path);\n\
+    String text = \"\";\n\
+    for (String value : values) { text += value; }\n\
+    if (text == \"ready\") System.out.println(text);\n\
+    Thread.sleep(1);\n\
+    error.printStackTrace();\n\
+    Random tokenRandom = new Random();\n\
+    String query = \"SELECT * FROM users WHERE id=\" + id;\n\
+    Cipher.getInstance(\"DES\");\n\
+    try { work(); } catch (Exception error) {}\n\
+    String mismatch = \"vector dimensions incompatible: \" + left + \"!= \" + right;\n\
+  }\n\
+}\n"
                    .replace("\n+", "\n"),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context);
        assert!(findings.iter().all(|finding| finding.end_line == 0));
        let codes = findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            codes,
            BTreeSet::from([
                "java-catch-exception".to_owned(),
                "java-empty-catch".to_owned(),
                "java-hardcoded-secret".to_owned(),
                "java-objectinputstream".to_owned(),
                "java-package-cycle".to_owned(),
                "java-print-stacktrace".to_owned(),
                "java-random-security".to_owned(),
                "java-resource-not-closed".to_owned(),
                "java-sql-string-build".to_owned(),
                "java-string-concat-in-loop".to_owned(),
                "java-string-equals".to_owned(),
                "java-system-out".to_owned(),
                "java-thread-sleep".to_owned(),
                "java-too-many-parameters".to_owned(),
                "java-weak-crypto".to_owned(),
            ])
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("java-catch-exception", "Main.java", 14),
                ("java-empty-catch", "Main.java", 14),
                ("java-hardcoded-secret", "Main.java", 3),
                ("java-objectinputstream", "Main.java", 4),
                ("java-package-cycle", "app/a", 1),
                ("java-print-stacktrace", "Main.java", 10),
                ("java-random-security", "Main.java", 11),
                ("java-resource-not-closed", "Main.java", 5),
                ("java-sql-string-build", "Main.java", 12),
                ("java-string-concat-in-loop", "Main.java", 7),
                ("java-string-equals", "Main.java", 8),
                ("java-system-out", "Main.java", 8),
                ("java-thread-sleep", "Main.java", 9),
                ("java-too-many-parameters", "Main.java", 2),
                ("java-weak-crypto", "Main.java", 13),
            ])
        );
    }

    #[test]
    fn applies_java_exclusions_and_once_per_file_behavior() {
        let sources = BTreeMap::from([
            (
                "Orders.java".to_owned(),
                "class Orders {\n\
  void acceptable(Map<String, Integer> values, int b, int c, int d, int e, int f, int g) {}\n\
  void excessive(int a, int b, int c, int d, int e, int f, int g, int h) {}\n\
  @Inject(method = \"render\")\n\
  void injected(int a, int b, int c, int d, int e, int f, int g, int h) {}\n\
  @Override\n\
  void callback(int a, int b, int c, int d, int e, int f, int g, int h) {}\n\
}\n\
class Derived extends Base {\n\
  Derived(int a, int b, int c, int d, int e, int f, int g, int h) { super(a, b, c, d, e, f, g, h); }\n\
}\n"
                    .to_owned(),
            ),
            (
                "Loader.java".to_owned(),
                "class Loader {\n\
 void load() {\n\
  try { first(); } catch (IOException error) {}\n\
  try { second(); } catch (IOException error) { /* intentionally ignored */ }\n\
  try { third(); } catch (IOException ignored) {}\n\
  try { fourth(); } catch (IOException _) {}\n\
 }\n\
}\n"
                    .to_owned(),
            ),
            (
                "Main.java".to_owned(),
                "import java.io.ObjectInputStream;\n\
ObjectInputStream first = open();\n\
ObjectInputStream second = reopen();\n\
Thread.sleep(100);\n\
String sleepExample = \"Thread.sleep(100)\";\n\
error.printStackTrace();\n\
String traceExample = \"error.printStackTrace()\";\n\
Random tokenRandom = new Random();\n\
Random animationRandom = new Random();\n\
System.out.println(value);\n\
String outputExample = \"System.err.println(value)\";\n"
                    .to_owned(),
            ),
            (
                "src/test/java/AppTest.java".to_owned(),
                "System.out.println(\"fixture\");".to_owned(),
            ),
            (
                "app-cli/src/main/java/Command.java".to_owned(),
                "System.out.println(result);".to_owned(),
            ),
            (
                "tools/src/main/java/MetadataCommand.java".to_owned(),
                "System.out.println(metadata);".to_owned(),
            ),
            (
                "build-tools-internal/src/main/java/BuildReporter.java".to_owned(),
                "System.out.println(summary);".to_owned(),
            ),
            (
                "service/src/main/java/Command.java".to_owned(),
                "public static void main(String[] args) {\n\
                 System.out.println(result);\n\
                 }"
                .to_owned(),
            ),
            (
                "service/src/main/java/CommandLineUtils.java".to_owned(),
                "System.err.println(message);".to_owned(),
            ),
            (
                "service/src/main/java/ViolationReporter.java".to_owned(),
                "void printToConsole() {\n\
                 System.out.println(report);\n\
                 }"
                .to_owned(),
            ),
            (
                "service/src/main/java/Worker.java".to_owned(),
                "System.out.println(debugValue);".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .filter(|finding| {
                [
                    "java-empty-catch",
                    "java-objectinputstream",
                    "java-print-stacktrace",
                    "java-random-security",
                    "java-system-out",
                    "java-thread-sleep",
                    "java-too-many-parameters",
                ]
                .contains(&finding.code.as_str())
            })
            .map(|finding| (finding.code, finding.path, finding.line))
            .collect::<BTreeSet<_>>();

        assert_eq!(
            findings,
            BTreeSet::from([
                ("java-empty-catch".to_owned(), "Loader.java".to_owned(), 3),
                (
                    "java-objectinputstream".to_owned(),
                    "Main.java".to_owned(),
                    2,
                ),
                (
                    "java-print-stacktrace".to_owned(),
                    "Main.java".to_owned(),
                    6,
                ),
                ("java-random-security".to_owned(), "Main.java".to_owned(), 8,),
                ("java-system-out".to_owned(), "Main.java".to_owned(), 10),
                (
                    "java-system-out".to_owned(),
                    "service/src/main/java/Worker.java".to_owned(),
                    1,
                ),
                ("java-thread-sleep".to_owned(), "Main.java".to_owned(), 4),
                (
                    "java-too-many-parameters".to_owned(),
                    "Orders.java".to_owned(),
                    3,
                ),
            ])
        );
    }
    #[test]
    fn reports_java_loop_performance_patterns() {
        let sources = BTreeMap::from([(
            "src/main/java/app/Scan.java".to_owned(),
            "class Scan {\n\
+  void scan(List<String> blocked, List<String> values) {\n\
+    String output = \"\";\n\
+    for (String value : values) {\n\
+      Pattern matcher = Pattern.compile(\"^[a-z]+$\");\n\
+      if (blocked.contains(value)) output += value;\n\
+    }\n\
+  }\n\
+}\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "java-pattern-compile-in-loop"
                            | "java-linear-membership-in-loop"
                            | "java-string-concat-in-loop"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("java-string-concat-in-loop".to_owned(), 6),
                ("java-pattern-compile-in-loop".to_owned(), 5),
                ("java-linear-membership-in-loop".to_owned(), 6),
            ]
        );
    }

    #[test]
    fn accepts_java_loop_performance_safe_variants() {
        let sources = BTreeMap::from([(
            "src/main/java/app/SafeScan.java".to_owned(),
            "class SafeScan {\n\
+  String result = \"\";\n\
+  void scan(String pattern, Set<String> allowed, List<String> values) {\n\
+    Pattern stable = Pattern.compile(\"^[a-z]+$\");\n\
+    StringBuilder output = new StringBuilder();\n\
+    int result = 0;\n\
+    for (String value : values) {\n\
+      Pattern dynamic = Pattern.compile(pattern);\n\
+      String perIteration = \"\";\n\
+      perIteration += value;\n\
+      if (allowed.contains(value)) output.append(value);\n\
+      result += 1;\n\
+      // Pattern.compile(\"commented\");\n\
+      String example = \"Pattern.compile(\\\"literal\\\")\";\n\
+    }\n\
+  }\n\
+}\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "java-pattern-compile-in-loop"
                        | "java-linear-membership-in-loop"
                        | "java-string-concat-in-loop"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn reports_ignored_futures_and_indexed_linked_list_loops() {
        let sources = BTreeMap::from([(
            "src/main/java/app/AsyncWork.java".to_owned(),
            r#"class AsyncWork {
  void run(ExecutorService executor, LinkedList<String> queue) {
    executor.submit(this::work);
    CompletableFuture.runAsync(this::work);
    Future<?> retained = executor.submit(this::work);
    for (int index = 0; index < queue.size(); index++) {
      consume(queue.get(index));
    }
  }
}"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "java-ignored-future" | "java-linked-list-indexed-loop"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("java-ignored-future".to_owned(), 3),
                ("java-ignored-future".to_owned(), 4),
                ("java-linked-list-indexed-loop".to_owned(), 7),
            ]
        );
    }

    #[test]
    fn distinguishes_secrets_from_symbolic_token_labels() {
        let sources = BTreeMap::from([(
            "Secrets.java".to_owned(),
            "String api_token = \"real-secret-value\";\n\
             String DEFAULT_SUPERUSER_PASSWORD = \"cassandra\";\n\
             String DEFAULT_UNK_TOKEN = \"<unk>\";\n\
             String MASK_TOKEN = \"[MASK]\";\n\
             String BY_TOKEN = \" by \";\n\
             String TOKEN_METADATA_NAME = \"saml_nameid_val\";\n\
             String API_KEY_ID_KEY = \"_security_api_key_id\";\n\
             String WEB_IDENTITY_TOKEN_FILE_LOCATION = \"service/token-file\";\n\
             String MISSING_PASSWORD_MESSAGE = \"No password is configured.\";\n\
             String AUTH_API_KEY = \"apiKey\";\n\
             String API_KEY_EXPIRATION = \"30m\";\n\
             String COLUMN_TOKEN_VALUE = \"token_value\";\n\
             String REMOVED_TOKEN = \"removed\";\n\
             String TOKEN = \"ownership_token\";\n\
             String PASSWD_OPTION = \"password\";\n\
             String MISMATCHING_TOKEN = \"token did not match\";\n\
             String TOKEN_QUERY = \"/latest/api/token\";"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "java-hardcoded-secret")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn distinguishes_string_identity_from_boolean_string_methods() {
        let sources = BTreeMap::from([(
            "Comparisons.java".to_owned(),
            "if (false == \"http\".equals(scheme)) {}\n\
             if (\"js\" == language) {}"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "java-string-equals")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }
}
