use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::dart_core_rules::mask_comments;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{index::DartSourceIndex, matching_delimiter, split_top_level};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        let original = index.source(path);
        let masked = mask_comments(index.masked_lines(path)).join("\n");
        let functions = functions(&masked);
        let classes = classes(&masked);
        let sql_constants = sql_constants(original, &masked, &classes);
        findings.extend(certificate_findings(path, &masked));
        findings.extend(invocation_findings(
            path,
            original,
            &masked,
            &functions,
            &classes,
            &sql_constants,
        ));
    }
    findings
}

#[derive(Debug)]
struct Function {
    start: usize,
    end: usize,
    parameters: BTreeSet<String>,
    locals: BTreeSet<String>,
}

fn functions(source: &str) -> Vec<Function> {
    let mut result = Vec::new();
    for captures in FUNCTION_START.captures_iter(source) {
        let name = captures.name("name").unwrap().as_str();
        if CONTROL_KEYWORDS.contains(&name) {
            continue;
        }
        let marker = captures.name("marker").unwrap();
        let end = if marker.as_str() == "{" {
            let Some(close) = matching_delimiter(source, marker.start(), b'{', b'}') else {
                continue;
            };
            close + 1
        } else {
            source[marker.end()..]
                .find(';')
                .map_or(source.len(), |relative| marker.end() + relative + 1)
        };
        let parameters = parameter_names(captures.name("parameters").unwrap().as_str());
        let locals = LOCAL_DECLARATION
            .captures_iter(&source[marker.end()..end])
            .filter_map(|declaration| declaration.get(1).map(|name| name.as_str().to_owned()))
            .collect();
        result.push(Function {
            start: captures.get(0).unwrap().start(),
            end,
            parameters,
            locals,
        });
    }
    result
}

fn parameter_names(parameters: &str) -> BTreeSet<String> {
    split_top_level(parameters, b',')
        .into_iter()
        .filter_map(|parameter| {
            let declaration = parameter.split('=').next().unwrap_or(parameter).trim();
            IDENTIFIER
                .find_iter(declaration)
                .map(|identifier| identifier.as_str())
                .filter(|identifier| {
                    !matches!(
                        *identifier,
                        "required" | "final" | "const" | "covariant" | "this" | "super"
                    )
                })
                .last()
                .map(str::to_owned)
        })
        .collect()
}

fn enclosing_function(functions: &[Function], offset: usize) -> Option<&Function> {
    functions
        .iter()
        .filter(|function| function.start <= offset && offset < function.end)
        .min_by_key(|function| function.end - function.start)
}

#[derive(Debug)]
struct Class {
    name: String,
    start: usize,
    end: usize,
}

fn classes(source: &str) -> Vec<Class> {
    CLASS_START
        .captures_iter(source)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            let name = captures.get(1)?;
            let open = whole.end().checked_sub(1)?;
            Some(Class {
                name: name.as_str().to_owned(),
                start: whole.start(),
                end: matching_delimiter(source, open, b'{', b'}')?,
            })
        })
        .collect()
}

fn enclosing_class(classes: &[Class], offset: usize) -> Option<&Class> {
    classes
        .iter()
        .filter(|class| class.start <= offset && offset < class.end)
        .min_by_key(|class| class.end - class.start)
}

#[derive(Default)]
struct SqlConstants {
    top_level: BTreeSet<String>,
    by_class: BTreeMap<String, BTreeSet<String>>,
}

fn sql_constants(original: &str, masked: &str, classes: &[Class]) -> SqlConstants {
    let mut constants = SqlConstants::default();
    for captures in CONST_STRING.captures_iter(original) {
        let matched = captures.get(0).unwrap();
        let name = captures.get(1).unwrap().as_str().to_owned();
        if let Some(class) = enclosing_class(classes, matched.start()) {
            if matched.as_str().contains("static")
                && brace_depth(masked, class.start, matched.start()) == 1
            {
                constants
                    .by_class
                    .entry(class.name.clone())
                    .or_default()
                    .insert(name);
            }
        } else if brace_depth(masked, 0, matched.start()) == 0 {
            constants.top_level.insert(name);
        }
    }
    constants
}

fn certificate_findings(path: &str, source: &str) -> Vec<Finding> {
    CERTIFICATE_CALLBACK
        .find_iter(source)
        .map(|matched| {
            finding(
                "dart-bad-certificate-callback",
                path,
                line_at(source, matched.start()),
                "certificate callback accepts every certificate",
            )
        })
        .collect()
}

struct Invocation<'a> {
    target: &'a str,
    method: &'a str,
    start: usize,
    open: usize,
    close: usize,
}

fn invocations(source: &str) -> Vec<Invocation<'_>> {
    let mut result = Vec::new();
    for captures in INVOCATION.captures_iter(source) {
        let whole = captures.get(0).unwrap();
        let open = whole.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        result.push(Invocation {
            target: captures.name("target").map_or("", |value| value.as_str()),
            method: captures.name("method").unwrap().as_str(),
            start: captures.name("method").unwrap().start(),
            open,
            close,
        });
    }
    result
}

fn invocation_findings(
    path: &str,
    original: &str,
    masked: &str,
    functions: &[Function],
    classes: &[Class],
    constants: &SqlConstants,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for invocation in invocations(masked) {
        let arguments = &original[invocation.open + 1..invocation.close];
        let function = enclosing_function(functions, invocation.start);
        let qualification = qualify_invocation(
            &invocation,
            arguments,
            function,
            original,
            masked,
            classes,
            constants,
        );
        emit_invocation_findings(path, masked, &invocation, qualification, &mut findings);
    }
    findings
}

#[derive(Clone, Copy)]
enum PathInvocationKind {
    Constructor,
    Method,
}

struct InvocationQualification {
    sql_interpolation: bool,
    process_untrusted_argument: bool,
    path_traversal: Option<PathInvocationKind>,
    sensitive_data_logging: bool,
}

fn qualify_invocation(
    invocation: &Invocation<'_>,
    arguments: &str,
    function: Option<&Function>,
    original: &str,
    masked: &str,
    classes: &[Class],
    constants: &SqlConstants,
) -> InvocationQualification {
    let sql_interpolation = SQL_METHODS.contains(&invocation.method)
        && unsafe_sql(arguments, invocation.start, function, classes, constants);
    let process_untrusted_argument = invocation.target == "Process"
        && PROCESS_METHODS.contains(&invocation.method)
        && references_parameter(arguments, function, &COMMAND_INPUT_NAME);
    let path_kind = match (
        invocation.target.is_empty() && matches!(invocation.method, "File" | "Directory"),
        PATH_METHODS.contains(&invocation.method)
            && matches!(invocation.target, "File" | "Directory" | "p" | "path"),
    ) {
        (true, _) => Some(PathInvocationKind::Constructor),
        (false, true) => Some(PathInvocationKind::Method),
        (false, false) => None,
    };
    let path_traversal = path_kind.filter(|_| {
        references_unguarded_path_parameter(arguments, invocation.start, function, original, masked)
    });
    let sensitive_data_logging = (LOGGING_METHODS.contains(&invocation.method)
        || invocation.method == "print" && invocation.target.is_empty())
        && logs_sensitive_data(arguments);
    InvocationQualification {
        sql_interpolation,
        process_untrusted_argument,
        path_traversal,
        sensitive_data_logging,
    }
}

fn emit_invocation_findings(
    path: &str,
    masked: &str,
    invocation: &Invocation<'_>,
    qualification: InvocationQualification,
    findings: &mut Vec<Finding>,
) {
    let line = line_at(masked, invocation.start);
    if qualification.sql_interpolation {
        let mut issue = finding(
            "dart-sql-interpolation",
            path,
            line,
            &format!("interpolated SQL reaches `{}`", invocation.method),
        );
        issue.end_line = line_at(masked, invocation.close);
        findings.push(issue);
    }
    if qualification.process_untrusted_argument {
        let mut process_finding = finding(
            "dart-process-untrusted-argument",
            path,
            line,
            "function input reaches a process invocation",
        );
        process_finding.end_line = line_at(masked, invocation.close);
        findings.push(process_finding);
    }
    if let Some(path_kind) = qualification.path_traversal {
        findings.push(finding(
            "dart-path-traversal",
            path,
            line,
            match path_kind {
                PathInvocationKind::Constructor => "function input is used as a filesystem path",
                PathInvocationKind::Method => {
                    "function input is used to construct a filesystem path"
                }
            },
        ));
    }
    if qualification.sensitive_data_logging {
        findings.push(finding(
            "dart-sensitive-data-logging",
            path,
            line,
            "sensitive value may be written to logs",
        ));
    }
}

fn unsafe_sql(
    arguments: &str,
    offset: usize,
    function: Option<&Function>,
    classes: &[Class],
    constants: &SqlConstants,
) -> bool {
    if STRING_CONCATENATION.is_match(arguments) {
        return true;
    }
    INTERPOLATION.captures_iter(arguments).any(|captures| {
        let Some(expression) = captures
            .name("braced")
            .or_else(|| captures.name("simple"))
            .map(|matched| matched.as_str().trim())
        else {
            return true;
        };
        !literal_sql_constant(expression, offset, function, classes, constants)
    })
}

fn literal_sql_constant(
    expression: &str,
    offset: usize,
    function: Option<&Function>,
    classes: &[Class],
    constants: &SqlConstants,
) -> bool {
    if !SIMPLE_EXPRESSION.is_match(expression) {
        return false;
    }
    if let Some((prefix, name)) = expression.split_once('.') {
        return constants
            .by_class
            .get(prefix)
            .is_some_and(|names| names.contains(name));
    }
    if function.is_some_and(|function| {
        function.parameters.contains(expression) || function.locals.contains(expression)
    }) {
        return false;
    }
    enclosing_class(classes, offset)
        .and_then(|class| constants.by_class.get(&class.name))
        .is_some_and(|names| names.contains(expression))
        || constants.top_level.contains(expression)
}

fn references_parameter(arguments: &str, function: Option<&Function>, pattern: &Regex) -> bool {
    function.is_some_and(|function| {
        function.parameters.iter().any(|parameter| {
            pattern.is_match(parameter) && contains_identifier(arguments, parameter)
        })
    })
}

fn references_unguarded_path_parameter(
    arguments: &str,
    invocation: usize,
    function: Option<&Function>,
    original: &str,
    masked: &str,
) -> bool {
    let Some(function) = function else {
        return false;
    };
    function.parameters.iter().any(|parameter| {
        PATH_INPUT_NAME.is_match(parameter)
            && contains_identifier(arguments, parameter)
            && !has_complete_path_guard(original, masked, function.start, invocation, parameter)
    })
}

fn has_complete_path_guard(
    original: &str,
    masked: &str,
    function_start: usize,
    invocation: usize,
    parameter: &str,
) -> bool {
    for matched in IF_START.find_iter(&masked[function_start..invocation]) {
        let open = function_start + matched.end() - 1;
        let Some(close) = matching_delimiter(masked, open, b'(', b')') else {
            continue;
        };
        let Some((statement_end, exits)) = statement_end(masked, close + 1) else {
            continue;
        };
        if statement_end > invocation || !exits {
            continue;
        }
        let after = skip_whitespace(masked, statement_end);
        if masked[after..].starts_with("else") {
            continue;
        }
        let condition = &original[open + 1..close];
        if rejects_unsafe_path(condition, parameter) {
            return true;
        }
    }
    false
}

fn rejects_unsafe_path(condition: &str, parameter: &str) -> bool {
    let name = regex::escape(parameter);
    let Ok(unix) = Regex::new(&format!(r"{name}\s*\.\s*startsWith\s*\([^)]*/[^)]*\)")) else {
        return false;
    };
    let Ok(windows) = Regex::new(&format!(r"{name}\s*\.\s*startsWith\s*\([^)]*\\[^)]*\)")) else {
        return false;
    };
    let Ok(drive) = Regex::new(&format!(r"\w+\s*\.\s*hasMatch\s*\(\s*{name}\s*\)")) else {
        return false;
    };
    let Ok(parent) = Regex::new(&format!(
        r"{name}\s*\.\s*split\s*\([^)]*\)\s*\.\s*contains\s*\([^)]*\.\.[^)]*\)"
    )) else {
        return false;
    };
    unix.is_match(condition)
        && windows.is_match(condition)
        && drive.is_match(condition)
        && parent.is_match(condition)
}

fn statement_end(source: &str, offset: usize) -> Option<(usize, bool)> {
    let start = skip_whitespace(source, offset);
    if source.as_bytes().get(start) == Some(&b'{') {
        let close = matching_delimiter(source, start, b'{', b'}')?;
        let body = source[start + 1..close].trim_end();
        return Some((close + 1, EXITING_STATEMENT_END.is_match(body)));
    }
    let semicolon = source[start..]
        .find(';')
        .map(|relative| start + relative + 1)?;
    Some((
        semicolon,
        EXITING_STATEMENT_START.is_match(source[start..semicolon].trim_start()),
    ))
}

fn logs_sensitive_data(arguments: &str) -> bool {
    let interpolation_names = INTERPOLATION
        .captures_iter(arguments)
        .filter_map(|captures| captures.name("braced").or_else(|| captures.name("simple")))
        .flat_map(|expression| expression_identifiers(expression.as_str()))
        .collect::<BTreeSet<_>>();
    let outside_strings = mask_string_contents(arguments);
    let mut names = expression_identifiers(&outside_strings);
    names.extend(interpolation_names);
    names.iter().any(|name| sensitive_identifier(name))
        || RESET_PASSWORD_TOKEN.is_match(arguments)
            && names.iter().any(|name| name.eq_ignore_ascii_case("token"))
}

fn expression_identifiers(expression: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for identifier in IDENTIFIER.find_iter(expression) {
        let after = &expression[identifier.end()..];
        if after.trim_start().starts_with('.') {
            continue;
        }
        names.insert(identifier.as_str().to_owned());
    }
    names
}

fn sensitive_identifier(name: &str) -> bool {
    SENSITIVE_NAME.is_match(name) && !SENSITIVE_METADATA_SUFFIX.is_match(name)
}

fn mask_string_contents(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut quote = None;
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(delimiter) = quote {
            if bytes[index] == b'\\' {
                masked[index] = b' ';
                if index + 1 < bytes.len() {
                    masked[index + 1] = b' ';
                }
                index += 2;
            } else if bytes[index] == delimiter {
                quote = None;
                index += 1;
            } else {
                masked[index] = b' ';
                index += 1;
            }
        } else if matches!(bytes[index], b'\'' | b'"') {
            quote = Some(bytes[index]);
            index += 1;
        } else {
            index += 1;
        }
    }
    String::from_utf8(masked).expect("ASCII string masking preserves UTF-8")
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .unwrap()
        .is_match(source)
}

fn brace_depth(source: &str, start: usize, end: usize) -> usize {
    source.as_bytes()[start..end]
        .iter()
        .fold(0usize, |depth, byte| match *byte {
            b'{' => depth + 1,
            b'}' => depth.saturating_sub(1),
            _ => depth,
        })
}

fn skip_whitespace(source: &str, mut offset: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    offset
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart security metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart security severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: if matches!(
            code,
            "dart-sql-interpolation" | "dart-process-untrusted-argument"
        ) {
            "high"
        } else {
            "medium"
        }
        .to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const CONTROL_KEYWORDS: [&str; 6] = ["if", "for", "while", "switch", "catch", "assert"];
const SQL_METHODS: [&str; 6] = [
    "execute",
    "query",
    "rawDelete",
    "rawInsert",
    "rawQuery",
    "rawUpdate",
];
const PROCESS_METHODS: [&str; 4] = ["run", "start", "runSync", "startDetached"];
const PATH_METHODS: [&str; 5] = ["join", "resolve", "open", "readAsString", "writeAsString"];
const LOGGING_METHODS: [&str; 7] = ["debug", "error", "info", "log", "severe", "warning", "warn"];

static FUNCTION_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<name>[A-Za-z_]\w*)\s*\((?P<parameters>(?:[^;()]|\([^;()]*\))*)\)\s*(?:async\s*)?(?P<marker>\{|=>)",
    )
    .unwrap()
});
static LOCAL_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:final|var|const|late(?:\s+final)?|[A-Za-z_]\w*(?:<[^;=]+>)?\??)\s+([A-Za-z_]\w*)\s*(?:=|;)").unwrap()
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]\w*").unwrap());
static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+([A-Za-z_]\w*)[^\{;]*\{").unwrap());
static CONST_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:static\s+)?const\s+String\s+([A-Za-z_]\w*)\s*=\s*(?:r)?['"][^'"\r\n]*['"]\s*;"#,
    )
    .unwrap()
});
static CERTIFICATE_CALLBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\b(?:badCertificateCallback|onBadCertificate)\s*=\s*(?:\([^;{}]*\)\s*=>\s*true\b|\([^;{}]*\)\s*\{[^{}]*\breturn\s+true\s*;[^{}]*\})").unwrap()
});
static INVOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:(?P<target>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*)?(?P<method>[A-Za-z_]\w*)\s*\(",
    )
    .unwrap()
});
static INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:\{(?P<braced>[^}]+)\}|(?P<simple>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?))").unwrap()
});
static SIMPLE_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?$").unwrap());
static STRING_CONCATENATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['\"]\s*\+|\+\s*['\"]"#).unwrap());
static COMMAND_INPUT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)command|cmd|request|user|input").unwrap());
static PATH_INPUT_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)relativePath|requestPath|upload|userPath|inputPath").unwrap()
});
static IF_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bif\s*\(").unwrap());
static EXITING_STATEMENT_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:return\b|break(?:\s+\w+)?\s*;|continue(?:\s+\w+)?\s*;|throw\b)").unwrap()
});
static EXITING_STATEMENT_END: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:return\b[^;]*;|break(?:\s+\w+)?\s*;|continue(?:\s+\w+)?\s*;|throw\b[^;]*;)\s*$")
        .unwrap()
});
static SENSITIVE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)password|secret|api_?key|access_?token|auth_?token|authorization|cookie|private_?key",
    )
    .unwrap()
});
static SENSITIVE_METADATA_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:length|limit|minimum|maximum|name|policy|requirements?)$").unwrap()
});
static RESET_PASSWORD_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)reset[\s_-]+password[\s_-]+token").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn finds_certificate_sql_process_path_and_logging_risks() {
        let fixture = Fixture::new([(
            "lib/advanced.dart",
            "class Risky {\n  void init() {\n    client.badCertificateCallback = (_, __, ___) => true;\n  }\n  Future<void> load(String command, String userPath, String password) async {\n    Process.run(command, <String>[userPath]);\n    final file = File(userPath);\n    db.rawQuery('SELECT * FROM users WHERE name = $password');\n    logger.info('password=$password');\n  }\n}",
        )]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-bad-certificate-callback".to_owned(), 3),
                ("dart-path-traversal".to_owned(), 7),
                ("dart-process-untrusted-argument".to_owned(), 6),
                ("dart-sensitive-data-logging".to_owned(), 9),
                ("dart-sql-interpolation".to_owned(), 8),
            ]
        );
    }

    #[test]
    fn detects_both_unconditional_certificate_callback_names() {
        let fixture = Fixture::new([(
            "lib/client.dart",
            "void configure(dynamic config) {\n  config.onBadCertificate = (_) => true;\n  config.badCertificateCallback = (_) { return true; };\n}",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-bad-certificate-callback")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn allows_literal_sql_constants_but_reports_runtime_and_shadowed_values() {
        let fixture = Fixture::new([(
            "lib/queries.dart",
            "const String logTable = 'logs';\nclass Schema {\n  static const String idColumn = '_id';\n  static const String messageColumn = 'message';\n  void safe() { db.execute('create table $logTable (${Schema.idColumn}, $messageColumn)'); }\n  void query(String column) { db.rawQuery('select $column from $logTable'); }\n  void shadow() { final logTable = runtimeTable(); db.execute('delete from $logTable'); }\n  void concatenate(String suffix) { db.execute('select * from ' + suffix); }\n}",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-sql-interpolation")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![6, 7, 8]
        );
    }

    #[test]
    fn logs_secret_values_but_not_sensitive_metadata_or_plain_text() {
        let fixture = Fixture::new([(
            "lib/logging.dart",
            "void report(validationResponse, passwordReset, config, password, cookieName, String apiKey) {\n  log(validationResponse.passwordHash);\n  log(password);\n  log(passwordReset.userId);\n  log(config.minPasswordLength);\n  log(cookieName);\n  print('No --service-key provided');\n  print('Using $apiKey');\n}\nvoid validate(String email, String token) {\n  Log.info('Validate reset password token: $email, $token');\n}\nvoid parse(String token) {\n  Log.info('Parsed token: $token');\n}",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-sensitive-data-logging")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2, 3, 8, 11]
        );
    }

    #[test]
    fn requires_untrusted_provenance_and_complete_prior_path_guards() {
        let fixture = Fixture::new([(
            "lib/paths.dart",
            "final windowsAbsolutePath = RegExp(r'^[A-Za-z]:[\\\\/]');\nfinal pathSeparator = RegExp(r'[\\\\/]');\nFile bundled(String fileName) => File(join(root, fileName));\nFile guarded(String root, String relativePath) {\n  if (relativePath.startsWith('/') || relativePath.startsWith(r'\\') || windowsAbsolutePath.hasMatch(relativePath) || relativePath.split(pathSeparator).contains('..')) {\n    return null;\n  }\n  return File('$root/$relativePath');\n}\nFile incomplete(String root, String relativePath) {\n  if (relativePath.startsWith('/') || relativePath.split(pathSeparator).contains('..')) throw ArgumentError.value(relativePath);\n  return File('$root/$relativePath');\n}\nFile late(String root, String relativePath) {\n  final file = File('$root/$relativePath');\n  if (relativePath.startsWith('/') || relativePath.startsWith(r'\\') || windowsAbsolutePath.hasMatch(relativePath) || relativePath.split(pathSeparator).contains('..')) throw ArgumentError.value(relativePath);\n  return file;\n}\nvoid safeProcess(String fileName) { Process.run('cat', <String>[fileName]); }",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-path-traversal")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![12, 15]
        );
        assert!(findings_for(&fixture, "dart-process-untrusted-argument").is_empty());
    }

    #[test]
    fn malformed_security_syntax_does_not_hide_valid_findings() {
        let fixture = Fixture::new([(
            "lib/malformed.dart",
            "class Broken {\n  void malformed(String password) {\n    final = password;\n    db.rawQuery('SELECT ${');\n    logger.info('password=${');\n  }\n  void valid(String password) {\n    db.rawQuery('SELECT $password');\n    logger.info('password=$password');\n  }",
        )]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-sensitive-data-logging".to_owned(), 9),
                ("dart-sql-interpolation".to_owned(), 8),
            ]
        );
    }

    fn findings_for(fixture: &Fixture, code: &str) -> Vec<Finding> {
        analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == code)
            .collect()
    }

    fn code_lines(fixture: &Fixture) -> Vec<(String, usize)> {
        let mut findings = analyze(&fixture.context())
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        findings.sort();
        findings
    }

    struct Fixture {
        sources: BTreeMap<String, String>,
    }

    impl Fixture {
        fn new<const N: usize>(sources: [(&str, &str); N]) -> Self {
            Self {
                sources: sources
                    .into_iter()
                    .map(|(path, source)| (path.to_owned(), source.to_owned()))
                    .collect(),
            }
        }

        fn context(&self) -> SourceAnalysisContext<'_> {
            SourceAnalysisContext::unchanged(&self.sources)
        }
    }
}
