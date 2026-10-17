use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use toml::Value;

use crate::findings::{Finding, Severity};
#[cfg(test)]
use crate::function_sources;
use crate::function_sources::FunctionSource;
use crate::object_soup_rules;
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let functions = function_sources::extract(context.sources());
    analyze_with_functions(context, &functions)
}

pub fn analyze_with_functions(
    context: &SourceAnalysisContext<'_>,
    functions: &[FunctionSource],
) -> Vec<Finding> {
    let disabled = disabled_by_project_policy(context);
    let mut findings = object_soup_rules::python(functions);
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".py"))
    {
        analyze_source(path, source, &disabled, &mut findings);
    }
    findings
}

fn analyze_source(
    path: &str,
    source: &str,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let lines = source.split('\n').collect::<Vec<_>>();
    let monkey_patch_replacements = monkey_patch_replacements(&lines);
    let mut state = PythonScanState::default();

    for (index, raw) in lines.iter().enumerate() {
        let current = state.scan(index, raw);
        analyze_style(path, &current, disabled, findings);
        analyze_language_constructs(
            path,
            &lines,
            &current,
            &monkey_patch_replacements,
            disabled,
            findings,
        );
        analyze_security(path, &lines, &current, disabled, findings);
        analyze_runtime(path, &lines, &current, disabled, findings);
        state.finish(&current);
    }
}

#[derive(Default)]
struct PythonScanState {
    saw_code: bool,
    import_continuation_depth: isize,
    type_checking_indent: Option<usize>,
    async_indent: Option<usize>,
    continued_string_quote: Option<char>,
    triple_quoted_string_delimiter: Option<String>,
}

impl PythonScanState {
    fn scan<'a>(&mut self, index: usize, raw: &'a str) -> PythonLine<'a> {
        let starts_in_continued_string = self.continued_string_quote.is_some();
        let code = self.scan_code(raw, starts_in_continued_string);
        let comment = if starts_in_continued_string {
            ""
        } else {
            &raw[code_before_comment(raw).len()..]
        };
        let stripped = strip_quoted_strings(&code);
        let line = stripped.trim();
        let indent = leading_indent(raw);
        let in_import_continuation = self.import_continuation_depth > 0;
        let in_type_checking_block = self
            .type_checking_indent
            .is_some_and(|value| indent > value);
        self.update_type_checking_scope(line, indent);
        self.update_async_scope(line, indent);

        PythonLine {
            index,
            raw,
            code,
            stripped,
            comment,
            indent,
            in_import_continuation,
            in_type_checking_block,
            in_async_function: self.async_indent.is_some(),
            saw_code: self.saw_code,
        }
    }

    fn scan_code(&mut self, raw: &str, starts_in_continued_string: bool) -> String {
        if starts_in_continued_string {
            self.continued_string_quote =
                continued_string_quote_after(raw, self.continued_string_quote);
            return String::new();
        }

        let scanned =
            code_outside_triple_quoted_strings(raw, self.triple_quoted_string_delimiter.take());
        self.triple_quoted_string_delimiter = scanned.1;
        self.continued_string_quote = self
            .triple_quoted_string_delimiter
            .is_none()
            .then(|| continued_string_quote_after(&scanned.0, None))
            .flatten();
        code_before_comment(&scanned.0).to_owned()
    }

    fn update_type_checking_scope(&mut self, line: &str, indent: usize) {
        if self.type_checking_indent.is_some_and(|value| {
            !line.is_empty() && indent <= value && !line.starts_with("if TYPE_CHECKING:")
        }) {
            self.type_checking_indent = None;
        }
        if line.starts_with("if TYPE_CHECKING:") {
            self.type_checking_indent = Some(indent);
        }
    }

    fn update_async_scope(&mut self, line: &str, indent: usize) {
        if line.starts_with("async def ") {
            self.async_indent = Some(indent);
        }
        if self.async_indent.is_some_and(|value| {
            !line.is_empty() && indent <= value && !line.starts_with("async def ")
        }) {
            self.async_indent = None;
        }
    }

    fn finish(&mut self, current: &PythonLine<'_>) {
        if is_executable_python_line(current) {
            self.saw_code = true;
        }
        self.update_import_continuation(current);
    }

    fn update_import_continuation(&mut self, current: &PythonLine<'_>) {
        let starts_import = is_import(current.line());
        if !current.in_import_continuation && !starts_import {
            return;
        }
        let bracket_delta = bracket_delta(&mask_strings(current.raw));
        if current.in_import_continuation {
            self.import_continuation_depth += bracket_delta;
        } else if bracket_delta > 0 {
            self.import_continuation_depth = bracket_delta;
        }
    }
}

fn is_executable_python_line(current: &PythonLine<'_>) -> bool {
    let line = current.line();
    if line.is_empty() || current.in_import_continuation {
        return false;
    }
    !["#", "import ", "from ", "\"\"\"", "'''", "__"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

fn is_import(line: &str) -> bool {
    line.starts_with("import ") || line.starts_with("from ")
}

struct PythonLine<'a> {
    index: usize,
    raw: &'a str,
    code: String,
    stripped: String,
    comment: &'a str,
    indent: usize,
    in_import_continuation: bool,
    in_type_checking_block: bool,
    in_async_function: bool,
    saw_code: bool,
}

impl PythonLine<'_> {
    fn line(&self) -> &str {
        self.stripped.trim()
    }

    fn number(&self) -> usize {
        self.index + 1
    }
}

fn add_finding(
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
    path: &str,
    id: &'static str,
    line: usize,
    message: &'static str,
) {
    if !disabled.contains(id) {
        findings.push(finding(id, path, line, message));
    }
}

fn analyze_style(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    report_multiple_imports(path, current, disabled, findings);
    report_wildcard_import(path, current, disabled, findings);
    report_late_import(path, current, disabled, findings);
    report_compound_statement(path, current, disabled, findings);
    report_extraneous_whitespace(path, current, disabled, findings);
    report_backslash_continuation(path, current, disabled, findings);
}

fn report_multiple_imports(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    if line.starts_with("import ") && line.contains(',') {
        add_finding(
            disabled,
            findings,
            path,
            "py-multiple-imports",
            current.number(),
            "multiple modules imported on one line",
        );
    }
}

fn report_wildcard_import(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    if line.starts_with("from ") && line.ends_with(" import *") {
        add_finding(
            disabled,
            findings,
            path,
            "py-wildcard-import",
            current.number(),
            "wildcard import used",
        );
    }
}

fn report_late_import(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !is_import(current.line())
        || current.indent != 0
        || !current.saw_code
        || current.in_type_checking_block
        || has_noqa_for(current.comment, "E402")
    {
        return;
    }
    add_finding(
        disabled,
        findings,
        path,
        "py-import-not-top",
        current.number(),
        "import appears after executable code",
    );
}

fn report_compound_statement(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    let compound_header = line.rfind(':').is_some_and(|colon| {
        COMPOUND_HEADER.is_match(line) && !line[colon + 1..].trim().is_empty()
    });
    if compound_header || COMPOUND_AFTER_SEMICOLON.is_match(line) {
        add_finding(
            disabled,
            findings,
            path,
            "py-compound-statement",
            current.number(),
            "compound statement on one line",
        );
    }
}

fn report_extraneous_whitespace(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if EXTRANEOUS_WHITESPACE.is_match(&mask_strings(current.code.trim())) {
        add_finding(
            disabled,
            findings,
            path,
            "py-extraneous-whitespace",
            current.number(),
            "extraneous whitespace in expression",
        );
    }
}

fn report_backslash_continuation(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if current.code.trim_end().ends_with('\\') {
        add_finding(
            disabled,
            findings,
            path,
            "py-backslash-continuation",
            current.number(),
            "backslash line continuation used",
        );
    }
}

fn analyze_language_constructs(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    monkey_patch_replacements: &BTreeSet<String>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let function = FUNCTION
        .captures(current.line())
        .and_then(|captures| captures.get(1))
        .map(|name| name.as_str());
    report_function_name(
        path,
        lines,
        current,
        function,
        monkey_patch_replacements,
        disabled,
        findings,
    );
    report_mutable_default(path, current, function, disabled, findings);
    report_exception_handler(path, current, disabled, findings);
    report_dynamic_execution(path, current, function, disabled, findings);
    report_shell_execution(path, current, disabled, findings);
    report_runtime_assert(path, current, disabled, findings);
}

fn report_function_name(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    function: Option<&str>,
    monkey_patch_replacements: &BTreeSet<String>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let Some(name) = function else {
        return;
    };
    if !name.chars().any(|character| character.is_ascii_uppercase())
        || HTTP_REQUEST_HANDLER_METHOD.is_match(name)
        || PYTHON_TEST_LIFECYCLE_METHOD.is_match(name)
    {
        return;
    }
    if is_com_interface_method(lines, current.index, current.indent)
        || monkey_patch_replacements.contains(name)
    {
        return;
    }
    add_finding(
        disabled,
        findings,
        path,
        "py-function-naming",
        current.number(),
        "function name is not lower_snake_case",
    );
}

fn report_mutable_default(
    path: &str,
    current: &PythonLine<'_>,
    function: Option<&str>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if function.is_some() && MUTABLE_DEFAULT.is_match(current.line()) {
        add_finding(
            disabled,
            findings,
            path,
            "py-mutable-default",
            current.number(),
            "mutable default argument used",
        );
    }
}

fn report_exception_handler(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    if line == "except:" || line.starts_with("except:") {
        add_finding(
            disabled,
            findings,
            path,
            "py-bare-except",
            current.number(),
            "bare except catches all exceptions",
        );
    }
    if line.starts_with("except Exception") || line.starts_with("except BaseException") {
        add_finding(
            disabled,
            findings,
            path,
            "py-broad-except",
            current.number(),
            "broad exception handler",
        );
    }
}

fn report_dynamic_execution(
    path: &str,
    current: &PythonLine<'_>,
    function: Option<&str>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    if function.is_none()
        && (DYNAMIC_EXECUTION.is_match(line) || BUILTINS_DYNAMIC_EXECUTION.is_match(line))
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-eval-exec",
            current.number(),
            "dynamic code execution used",
        );
    }
}

fn report_shell_execution(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    if (line.contains("subprocess.") && line.contains("shell=True"))
        || line.contains("os.system(")
        || line.contains("popen(")
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-subprocess-shell",
            current.number(),
            "shell command execution needs review",
        );
    }
}

fn report_runtime_assert(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if current.line().starts_with("assert ") && !is_test_path(path) {
        add_finding(
            disabled,
            findings,
            path,
            "py-assert-runtime",
            current.number(),
            "assert used outside tests",
        );
    }
}

fn analyze_security(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    report_requests_call(path, lines, current, disabled, findings);
    report_yaml_load(path, lines, current, disabled, findings);
    report_pickle_load(path, current, disabled, findings);
    report_dynamic_sql(path, current, disabled, findings);
    report_hardcoded_secret(path, current, disabled, findings);
    report_weak_hash(path, lines, current, disabled, findings);
    report_unsafe_tempfile(path, current, disabled, findings);
    report_debug_enabled(path, current, disabled, findings);
}

fn report_requests_call(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !REQUESTS_CALL.is_match(current.line()) {
        return;
    }
    let call = continued_call(lines, current.index);
    if !TIMEOUT_ARGUMENT.is_match(&call) {
        add_finding(
            disabled,
            findings,
            path,
            "py-requests-timeout",
            current.number(),
            "requests call has no timeout",
        );
    }
    if DISABLED_TLS.is_match(&call) {
        add_finding(
            disabled,
            findings,
            path,
            "py-insecure-tls",
            current.number(),
            "requests call disables TLS certificate verification",
        );
    }
}

fn report_yaml_load(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    if !line.contains("yaml.load(")
        || line.contains("SafeLoader")
        || line.contains("safe_load")
        || uses_safe_ruamel_yaml(lines, current.index)
    {
        return;
    }
    add_finding(
        disabled,
        findings,
        path,
        "py-yaml-load",
        current.number(),
        "yaml.load without SafeLoader",
    );
}

fn report_pickle_load(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if PICKLE_LOAD.is_match(current.line()) {
        add_finding(
            disabled,
            findings,
            path,
            "py-pickle",
            current.number(),
            "pickle usage needs trust-boundary review",
        );
    }
}

fn report_dynamic_sql(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if has_dynamic_sql_string_expression(&current.code) {
        add_finding(
            disabled,
            findings,
            path,
            "py-sql-string-build",
            current.number(),
            "SQL appears dynamically constructed",
        );
    }
}

fn report_hardcoded_secret(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if has_hardcoded_secret(&current.code, path) {
        add_finding(
            disabled,
            findings,
            path,
            "py-hardcoded-secret",
            current.number(),
            "possible hardcoded secret",
        );
    }
}

fn report_weak_hash(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if WEAK_HASH.is_match(&current.code)
        && !WEAK_HASH_SAFE_INTENT.is_match(&continued_call(lines, current.index))
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-weak-hash",
            current.number(),
            "weak hash algorithm used",
        );
    }
}

fn report_unsafe_tempfile(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if current.line().contains("tempfile.mktemp(") {
        add_finding(
            disabled,
            findings,
            path,
            "py-tempfile-mktemp",
            current.number(),
            "tempfile.mktemp is race-prone",
        );
    }
}

fn report_debug_enabled(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if DEBUG_ENABLED.is_match(current.line()) {
        add_finding(
            disabled,
            findings,
            path,
            "py-debug-enabled",
            current.number(),
            "debug mode appears enabled",
        );
    }
}

fn analyze_runtime(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    report_open_without_encoding(path, lines, current, disabled, findings);
    report_printed_exception(path, lines, current, disabled, findings);
    report_async_blocking_call(path, current, disabled, findings);
}

fn report_open_without_encoding(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !OPEN_CALL.is_match(current.line()) || expects_open_failure(lines, current.index) {
        return;
    }
    let call = continued_call(lines, current.index);
    if !call.contains("encoding=") && !BINARY_OPEN_MODE.is_match(&call) {
        add_finding(
            disabled,
            findings,
            path,
            "py-open-no-encoding",
            current.number(),
            "text file opened without explicit encoding",
        );
    }
}

fn report_printed_exception(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    let is_exception = line.starts_with("except ") || line == "except:";
    if !is_exception || current.index + 1 >= lines.len() {
        return;
    }
    let handler_output = strip_quoted_strings(lines[current.index + 1])
        .trim()
        .to_owned();
    if !handler_output.starts_with("print(")
        || STDERR_PRINT_TARGET.is_match(&handler_output)
        || exception_handler_terminates(lines, current.index)
    {
        return;
    }
    add_finding(
        disabled,
        findings,
        path,
        "py-logging-exception",
        current.index + 2,
        "exception handler prints instead of logging",
    );
}

fn report_async_blocking_call(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if current.in_async_function && ASYNC_BLOCKING_CALL.is_match(current.line()) {
        add_finding(
            disabled,
            findings,
            path,
            "py-async-blocking-call",
            current.number(),
            "blocking call inside async function",
        );
    }
}

fn disabled_by_project_policy(context: &SourceAnalysisContext<'_>) -> BTreeSet<&'static str> {
    let Some(source) = context.auxiliary_files().get("pyproject.toml") else {
        return BTreeSet::new();
    };
    let Ok(document) = toml::from_str::<Value>(source) else {
        return BTreeSet::new();
    };
    let pylint = document
        .get("tool")
        .and_then(|value| value.get("pylint"))
        .and_then(|value| value.get("messages_control"))
        .and_then(|value| value.get("disable"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let ruff = document
        .get("tool")
        .and_then(|value| value.get("ruff"))
        .and_then(|value| value.get("lint"))
        .and_then(|value| value.get("ignore"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_ascii_uppercase)
        .collect::<BTreeSet<_>>();
    let mut disabled = BTreeSet::new();
    if pylint.contains("invalid-name") {
        disabled.insert("py-function-naming");
    }
    if pylint.contains("dangerous-default-value") {
        disabled.insert("py-mutable-default");
    }
    if pylint.contains("broad-exception-caught") {
        disabled.insert("py-broad-except");
    }
    if ruff.contains("E402") {
        disabled.insert("py-import-not-top");
    }
    if ruff.contains("E722") {
        disabled.insert("py-bare-except");
    }
    disabled
}

fn exception_handler_terminates(lines: &[&str], except_index: usize) -> bool {
    let handler_indent = leading_indent(lines[except_index]);
    let mut body_indent = None;
    for raw in lines.iter().skip(except_index + 1) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indent = leading_indent(raw);
        if indent <= handler_indent {
            break;
        }
        let body_indent = *body_indent.get_or_insert(indent);
        if indent == body_indent && TERMINATING_HANDLER.is_match(line) {
            return true;
        }
    }
    false
}

fn leading_indent(line: &str) -> usize {
    line.chars()
        .take_while(|character| *character == ' ' || *character == '\t')
        .count()
}

fn bracket_delta(line: &str) -> isize {
    line.chars().fold(0, |depth, character| match character {
        '(' | '[' | '{' => depth + 1,
        ')' | ']' | '}' => depth - 1,
        _ => depth,
    })
}

fn continued_call(lines: &[&str], start: usize) -> String {
    let mut call = String::new();
    let mut depth = 0;
    for line in lines.iter().skip(start) {
        if !call.is_empty() {
            call.push('\n');
        }
        call.push_str(line);
        depth += bracket_delta(&mask_strings(line));
        if depth <= 0 {
            break;
        }
    }
    call
}

fn uses_safe_ruamel_yaml(lines: &[&str], index: usize) -> bool {
    for line_index in (0..index).rev() {
        let candidate = code_before_comment(lines[line_index]).trim();
        if YAML_CONSTRUCTION.is_match(candidate) {
            return SAFE_YAML_TYPE.is_match(&continued_call(lines, line_index));
        }
    }
    false
}

fn has_dynamic_sql_string_expression(code: &str) -> bool {
    for literal_match in QUOTED_STRING.find_iter(code) {
        let literal = literal_match.as_str();
        if !SQL_STATEMENT.is_match(literal) {
            continue;
        }
        let before = &code[..literal_match.start()];
        let after = &code[literal_match.end()..];
        let interpolated_f_string =
            PYTHON_F_STRING_PREFIX.is_match(before) && has_unescaped_f_string_field(literal);
        if interpolated_f_string
            || DYNAMIC_SQL_LITERAL_SUFFIX.is_match(after)
            || DYNAMIC_SQL_LITERAL_PREFIX.is_match(before)
        {
            return true;
        }
    }
    false
}

fn has_unescaped_f_string_field(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'{' || bytes.get(index.wrapping_sub(1)) == Some(&b'{') {
            continue;
        }
        let Some(relative_close) = bytes[index + 1..].iter().position(|byte| *byte == b'}') else {
            continue;
        };
        let close = index + 1 + relative_close;
        if close > index + 1 && bytes.get(close + 1) != Some(&b'}') {
            return true;
        }
    }
    false
}

fn is_com_interface_method(lines: &[&str], method_index: usize, method_indent: usize) -> bool {
    for index in (0..method_index).rev() {
        let candidate = lines[index].trim();
        if candidate.is_empty() || candidate.starts_with('#') {
            continue;
        }
        let candidate_indent = leading_indent(lines[index]);
        if candidate_indent >= method_indent {
            continue;
        }
        if !COM_INTERFACE_CLASS.is_match(candidate) {
            return false;
        }
        return lines[index + 1..method_index]
            .iter()
            .any(|line| line.trim_start().starts_with("_com_interfaces_"));
    }
    false
}

fn monkey_patch_replacements(lines: &[&str]) -> BTreeSet<String> {
    let mut replacements = BTreeSet::new();
    for raw in lines {
        let line = code_before_comment(raw);
        if let Some(assignment) = MONKEY_PATCH_ASSIGNMENT.captures(line) {
            replacements.insert(assignment[1].to_owned());
        }
        for patch in MONKEY_PATCH_CALL.captures_iter(line) {
            replacements.extend(
                PYTHON_IDENTIFIER
                    .find_iter(&patch[1])
                    .map(|identifier| identifier.as_str().to_owned()),
            );
        }
    }
    replacements
}

fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    PYTHON_TEST_DIRECTORY.is_match(&normalized)
        || name.starts_with("test_")
        || name.ends_with("_test.py")
}

fn has_noqa_for(comment: &str, code: &str) -> bool {
    let Some(directive) = NOQA.captures(comment) else {
        return false;
    };
    let Some(listed_codes) = directive.get(1) else {
        return true;
    };
    listed_codes
        .as_str()
        .split(|character: char| character.is_whitespace() || character == ',')
        .any(|listed| listed.eq_ignore_ascii_case(code))
}

fn code_before_comment(line: &str) -> &str {
    let mut state = QuoteContinuationState::Code;
    let comment_start =
        line.char_indices()
            .find_map(|(index, character)| match state.transition(character) {
                QuoteContinuationTransition::Continue(next) => {
                    state = next;
                    None
                }
                QuoteContinuationTransition::Stop => Some(index),
            });
    comment_start.map_or(line, |index| &line[..index])
}

#[derive(Clone, Copy)]
enum QuoteContinuationState {
    Code,
    Quoted(char),
    Escaped(char),
}

enum QuoteContinuationTransition {
    Continue(QuoteContinuationState),
    Stop,
}

impl QuoteContinuationState {
    fn new(quote: Option<char>) -> Self {
        quote.map_or(Self::Code, Self::Quoted)
    }

    fn transition(self, character: char) -> QuoteContinuationTransition {
        match self {
            Self::Code if matches!(character, '"' | '\'') => {
                QuoteContinuationTransition::Continue(Self::Quoted(character))
            }
            Self::Code if character == '#' => QuoteContinuationTransition::Stop,
            Self::Code => QuoteContinuationTransition::Continue(Self::Code),
            Self::Quoted(delimiter) if character == '\\' => {
                QuoteContinuationTransition::Continue(Self::Escaped(delimiter))
            }
            Self::Quoted(delimiter) if character == delimiter => {
                QuoteContinuationTransition::Continue(Self::Code)
            }
            Self::Quoted(delimiter) => {
                QuoteContinuationTransition::Continue(Self::Quoted(delimiter))
            }
            Self::Escaped(delimiter) => {
                QuoteContinuationTransition::Continue(Self::Quoted(delimiter))
            }
        }
    }

    fn quote(self) -> Option<char> {
        match self {
            Self::Code => None,
            Self::Quoted(delimiter) | Self::Escaped(delimiter) => Some(delimiter),
        }
    }
}

fn continued_string_quote_after(line: &str, quote: Option<char>) -> Option<char> {
    let mut state = QuoteContinuationState::new(quote);
    for character in line.chars() {
        match state.transition(character) {
            QuoteContinuationTransition::Continue(next) => state = next,
            QuoteContinuationTransition::Stop => break,
        }
    }
    state.quote().filter(|_| line.trim_end().ends_with('\\'))
}

enum PythonScannerState {
    Code,
    TripleQuoted(String),
}

enum PythonScanTransition {
    Continue,
    Stop,
    OpenTripleQuoted(String),
    CloseTripleQuoted,
}

struct PythonLineScanner<'a> {
    line: &'a str,
    code: String,
    cursor: usize,
    state: PythonScannerState,
}

impl<'a> PythonLineScanner<'a> {
    fn new(line: &'a str, delimiter: Option<String>) -> Self {
        let state = match delimiter {
            Some(delimiter) => PythonScannerState::TripleQuoted(delimiter),
            None => PythonScannerState::Code,
        };
        Self {
            line,
            code: String::new(),
            cursor: 0,
            state,
        }
    }

    fn scan(mut self) -> (String, Option<String>) {
        while self.cursor < self.line.len() {
            let transition = if matches!(&self.state, PythonScannerState::Code) {
                self.advance_code()
            } else {
                self.advance_triple_quoted()
            };
            match transition {
                PythonScanTransition::Continue => {}
                PythonScanTransition::Stop => break,
                PythonScanTransition::OpenTripleQuoted(delimiter) => {
                    self.state = PythonScannerState::TripleQuoted(delimiter);
                }
                PythonScanTransition::CloseTripleQuoted => {
                    self.state = PythonScannerState::Code;
                }
            }
        }
        let delimiter = match self.state {
            PythonScannerState::Code => None,
            PythonScannerState::TripleQuoted(delimiter) => Some(delimiter),
        };
        (self.code, delimiter)
    }

    fn advance_code(&mut self) -> PythonScanTransition {
        if self.line.as_bytes()[self.cursor] == b'#' {
            return PythonScanTransition::Stop;
        }
        let Some((quote, end)) = python_string_start(self.line, self.cursor) else {
            self.copy_next_character();
            return PythonScanTransition::Continue;
        };
        if !is_python_token_boundary(self.line, self.cursor) {
            self.copy_next_character();
            return PythonScanTransition::Continue;
        }
        if quote.len() == 3 {
            self.cursor = end;
            return PythonScanTransition::OpenTripleQuoted(quote.to_owned());
        }
        self.copy_quoted_literal(quote, end);
        PythonScanTransition::Continue
    }

    fn advance_triple_quoted(&mut self) -> PythonScanTransition {
        let PythonScannerState::TripleQuoted(delimiter) = &self.state else {
            return PythonScanTransition::Continue;
        };
        let Some(closing) = find_unescaped_delimiter(self.line, self.cursor, delimiter.as_str())
        else {
            return PythonScanTransition::Stop;
        };
        self.cursor = closing + delimiter.len();
        PythonScanTransition::CloseTripleQuoted
    }

    fn copy_next_character(&mut self) {
        let Some(character) = self.line[self.cursor..].chars().next() else {
            self.cursor = self.line.len();
            return;
        };
        self.code.push(character);
        self.cursor += character.len_utf8();
    }

    fn copy_quoted_literal(&mut self, quote: &str, end: usize) {
        let literal_start = self.cursor;
        self.cursor = end;
        let mut escaped = false;
        while self.cursor < self.line.len() {
            let character = self.line.as_bytes()[self.cursor];
            self.cursor += 1;
            if escaped {
                escaped = false;
            } else if character == b'\\' {
                escaped = true;
            } else if character == quote.as_bytes()[0] {
                break;
            }
        }
        self.code.push_str(&self.line[literal_start..self.cursor]);
    }
}

fn code_outside_triple_quoted_strings(
    line: &str,
    delimiter: Option<String>,
) -> (String, Option<String>) {
    PythonLineScanner::new(line, delimiter).scan()
}

fn is_python_token_boundary(line: &str, cursor: usize) -> bool {
    cursor == 0
        || !line.as_bytes()[cursor - 1].is_ascii_alphanumeric()
            && line.as_bytes()[cursor - 1] != b'_'
}

fn find_unescaped_delimiter(line: &str, cursor: usize, delimiter: &str) -> Option<usize> {
    let mut search_start = cursor;
    loop {
        let relative_closing = line[search_start..].find(delimiter)?;
        let closing = search_start + relative_closing;
        if !is_escaped(line, closing) {
            return Some(closing);
        }
        search_start = closing + delimiter.len();
    }
}

fn python_string_start(line: &str, cursor: usize) -> Option<(&str, usize)> {
    let tail = &line[cursor..];
    let prefix_length = tail
        .bytes()
        .take(2)
        .take_while(|byte| matches!(byte.to_ascii_lowercase(), b'r' | b'u' | b'b' | b'f'))
        .count();
    let quote_start = cursor + prefix_length;
    let quote_tail = &line[quote_start..];
    for quote in ["\"\"\"", "'''", "\"", "'"] {
        if quote_tail.starts_with(quote) {
            return Some((quote, quote_start + quote.len()));
        }
    }
    None
}

fn is_escaped(source: &str, offset: usize) -> bool {
    source.as_bytes()[..offset]
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
        % 2
        == 1
}

fn expects_open_failure(lines: &[&str], index: usize) -> bool {
    index > 0 && EXPECTED_OPEN_FAILURE.is_match(lines[index - 1].trim())
}

fn strip_quoted_strings(line: &str) -> String {
    QUOTED_STRING.replace_all(line, "").into_owned()
}

fn mask_strings(line: &str) -> Cow<'_, str> {
    QUOTED_STRING.replace_all(line, |captures: &regex::Captures<'_>| {
        let Some(matched) = captures.get(0) else {
            return String::new();
        };
        "x".repeat(matched.as_str().len())
    })
}

fn has_hardcoded_secret(code: &str, path: &str) -> bool {
    let secret = HARDCODED_SECRET_ASSIGNMENT
        .find(code)
        .or_else(|| HARDCODED_SECRET_MAP_ENTRY.find(code));
    let Some(secret) = secret else {
        return false;
    };
    let text = secret.as_str();
    if REPEATED_FILLER_SECRET.is_match(code)
        || EMPTY_HARDCODED_SECRET.is_match(code)
        || is_symbolic_secret_value(text)
        || is_placeholder_secret(text, path)
    {
        return false;
    }
    true
}

fn is_symbolic_secret_value(text: &str) -> bool {
    let Some(name) = SECRET_NAME.find(text) else {
        return false;
    };
    let Some(literal) = SECRET_STRING_LITERAL.captures_iter(text).last() else {
        return false;
    };
    let value = literal
        .get(1)
        .or_else(|| literal.get(2))
        .map_or("", |value| value.as_str());
    normalize_secret(name.as_str()) == normalize_secret(value)
}

fn normalize_secret(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_placeholder_secret(text: &str, path: &str) -> bool {
    let Some(literal) = SECRET_STRING_LITERAL.captures_iter(text).last() else {
        return false;
    };
    let value = literal
        .get(1)
        .or_else(|| literal.get(2))
        .map_or("", |value| value.as_str())
        .trim();
    DOCUMENTATION_SECRET_PLACEHOLDER.is_match(value)
        || is_test_path(path) && TEST_SECRET_PLACEHOLDER.is_match(value)
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Python rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static COMPOUND_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:if|for|while|try|except|finally)\b").unwrap());
static COMPOUND_AFTER_SEMICOLON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r";\s*\S").unwrap());
static EXTRANEOUS_WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(\s|\s[,;]|\s[)\]}]").unwrap());
static FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:async\s+)?def\s+([A-Za-z_]\w*)").unwrap());
static MUTABLE_DEFAULT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"=\s*(?:\[\]|\{}|set\(|dict\(|list\()").unwrap());
static DYNAMIC_EXECUTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^\w.])(?:eval|exec)\s*\(").unwrap());
static BUILTINS_DYNAMIC_EXECUTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bbuiltins\.(?:eval|exec)\s*\(").unwrap());
static REQUESTS_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"requests\.(?:get|post|put|patch|delete|request)\(").unwrap());
static TIMEOUT_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btimeout\s*=").unwrap());
static DISABLED_TLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bverify\s*=\s*False\b").unwrap());
static PICKLE_LOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bpickle\.loads?\s*\(|\bfrom\s+pickle\s+import\b[^#]*\bloads?\b").unwrap()
});
static WEAK_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)hashlib\.(?:md5|sha1)\(|\.new\(["'](?:md5|sha1)["']"#).unwrap()
});
static WEAK_HASH_SAFE_INTENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\busedforsecurity\s*=\s*False\b").unwrap());
static DEBUG_ENABLED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bdebug\s*=\s*true").unwrap());
static OPEN_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[^\w.])open\s*\(").unwrap());
static BINARY_OPEN_MODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)["'][rwa+x]*b[rwa+x]*["']"#).unwrap());
static STDERR_PRINT_TARGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfile\s*=\s*sys\.stderr\b").unwrap());
static ASYNC_BLOCKING_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:time\.sleep|requests\.(?:get|post)|subprocess\.run)\(").unwrap()
});
static TERMINATING_HANDLER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:return\b|raise\b|(?:sys\.)?exit\s*\()").unwrap());
static YAML_CONSTRUCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\byaml\s*=\s*YAML\s*\(").unwrap());
static SAFE_YAML_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\btyp\s*=\s*["']safe["']"#).unwrap());
static SQL_STATEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:select\b[^\n]*\bfrom\b|insert\s+into\b|update\s+[A-Za-z_][\w.]*\s+set\b|delete\s+from\b)").unwrap()
});
static PYTHON_F_STRING_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[^\w])(?:f[r]?|r[f])$").unwrap());
static DYNAMIC_SQL_LITERAL_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*(?:\.format\s*\(|%\s*[A-Za-z_(\[]|\+\s*[^"'])"#).unwrap());
static DYNAMIC_SQL_LITERAL_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\([^)]*\))?|\)|\])\s*\+\s*$").unwrap()
});
static COM_INTERFACE_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^class\s+\w+\s*\([^)]*\bcomtypes\.COMObject\b[^)]*\)\s*:").unwrap()
});
static MONKEY_PATCH_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.[A-Za-z_]\w*\s*=\s*([A-Za-z_]\w*)\b").unwrap());
static MONKEY_PATCH_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpatch(?:es)?\.patch\s*\(([^#\n]*)").unwrap());
static PYTHON_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\b").unwrap());
static PYTHON_TEST_DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|/)(?:test|tests|__tests__)(?:/|$)").unwrap());
static NOQA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)#\s*noqa\b(?:\s*:\s*([A-Z0-9_,\s]+))?").unwrap());
static HTTP_REQUEST_HANDLER_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^do_(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)$").unwrap()
});
static PYTHON_TEST_LIFECYCLE_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:setUp|tearDown)(?:Class|Module)?$").unwrap());
static EXPECTED_OPEN_FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:with\s+)?(?:(?:self\.)?assertRaises|pytest\.raises)\(\s*(?:FileNotFoundError|PermissionError|IsADirectoryError)\s*\)\s*:\s*$").unwrap()
});
static QUOTED_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"#).unwrap()
});
static HARDCODED_SECRET_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)\s*=\s*[rRuUbBfF]{0,2}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*(?:[,}\])]|$)"#).unwrap()
});
static HARDCODED_SECRET_MAP_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)["'](?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)["']\s*:\s*[rRuUbBfF]{0,2}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*(?:[,}\])]|$)"#).unwrap()
});
static EMPTY_HARDCODED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:\b(?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)\s*=)|(?:["'](?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)["']\s*:))\s*[rRuUbBfF]{0,2}(?:"\s*"|'\s*')"#).unwrap()
});
static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:^|\b|["'])(password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)(?:\b|["'])"#).unwrap()
});
static SECRET_STRING_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[rRuUbBfF]{0,2}(?:"([^"]*)"|'([^']*)')"#).unwrap());
static DOCUMENTATION_SECRET_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:none|null|undefined)$|(?:^|[-_])your(?:[-_])(?:[a-z0-9]+[-_])*(?:key|token|secret|password|credential)(?:$|[-_])|(?:^|[-_])replace[-_]?me(?:$|[-_])").unwrap()
});
static TEST_SECRET_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:test|test[-_](?:api[-_]?key|key|token|secret|password)|fc[-_]test)$")
        .unwrap()
});
static REPEATED_FILLER_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:password|passwd|secret|api_key|apikey|token)\w*\s*=\s*[rRuUbBfF]{0,2}["'][^"'\\]["']\s*\*\s*\(?\s*\d+"#).unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{analyze, code_outside_triple_quoted_strings};
    use crate::source_analysis_context::SourceAnalysisContext;

    #[test]
    fn reports_complete_python_rule_family() {
        let sources = BTreeMap::from([(
            "app.py".to_owned(),
            "import os, sys\n\
+from module import *\n\
+value = eval(input())\n\
+import late\n\
+def BadName(items=[]):\n\
+    assert items\n\
+    requests.get(url, verify=False)\n\
+async def load():\n\
+    time.sleep(1)\n\
+password = \"real-secret-value\"\n\
+data = yaml.load(payload)\n\
+query = f\"SELECT * FROM users WHERE id = {value}\"\n\
+handle = open(\"data.txt\")\n\
+tempfile.mktemp()\n\
+if ready: run()\n\
+values = call( value )\n\
+total = first + \\\n+    second\n\
+try:\n\
+    run()\n\
+except Exception:\n\
+    print(error)\n\
+except:\n\
+    pass\n\
+pickle.load(stream)\n\
+hashlib.md5(data)\n\
+debug = True\n\
+subprocess.run(command, shell=True)\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context);
        assert!(findings.iter().all(|finding| {
            finding.path == "app.py"
                && finding.end_line == finding.line
                && finding.confidence == "medium"
        }));
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("py-multiple-imports", 1),
                ("py-wildcard-import", 2),
                ("py-eval-exec", 3),
                ("py-import-not-top", 4),
                ("py-function-naming", 5),
                ("py-mutable-default", 5),
                ("py-assert-runtime", 6),
                ("py-requests-timeout", 7),
                ("py-insecure-tls", 7),
                ("py-async-blocking-call", 9),
                ("py-hardcoded-secret", 10),
                ("py-yaml-load", 11),
                ("py-sql-string-build", 12),
                ("py-open-no-encoding", 13),
                ("py-tempfile-mktemp", 14),
                ("py-compound-statement", 15),
                ("py-extraneous-whitespace", 16),
                ("py-backslash-continuation", 17),
                ("py-broad-except", 21),
                ("py-logging-exception", 22),
                ("py-bare-except", 23),
                ("py-pickle", 25),
                ("py-weak-hash", 26),
                ("py-debug-enabled", 27),
                ("py-subprocess-shell", 28),
            ]
        );
    }

    #[test]
    fn preserves_import_and_async_scope_state() {
        let sources = BTreeMap::from([(
            "state.py".to_owned(),
            "from package import (\n\
+    value,\n\
+)\n\
+import still_top\n\
+work = True\n\
+import late\n\
+async def load():\n\
+    time.sleep(1)\n\
+time.sleep(1)\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("py-import-not-top", 6), ("py-async-blocking-call", 8)]
        );
    }

    #[test]
    fn accepts_explicit_safe_python_variants() {
        let sources = BTreeMap::from([(
            "main.py".to_owned(),
            "from ruamel.yaml import YAML\n\
yaml = YAML(typ=\"safe\")\n\
data = yaml.load(payload)\n\
requests.get(url, timeout=10, verify=True)\n\
digest = hashlib.md5(payload, usedforsecurity=False)\n\
with pytest.raises(FileNotFoundError):\n\
    open(\"missing.txt\")\n\
binary = open(\"image.bin\", \"wb\")\n\
cursor.execute(\"SELECT id FROM jobs WHERE id = %s\", (job_id,))\n\
def do_GET(self):\n\
    pass\n\
def setUp(self):\n\
    pass\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn honors_pylint_and_ruff_project_suppressions() {
        let sources = BTreeMap::from([(
            "app.py".to_owned(),
            "value = 1\n\
import late\n\
def CamelCase(values=[]):\n\
    try:\n\
        return values\n\
    except Exception:\n\
        return []\n\
    except:\n\
        return None\n"
                .to_owned(),
        )]);
        let auxiliary = BTreeMap::from([(
            "pyproject.toml".to_owned(),
            "[tool.pylint.messages_control]\n\
disable = [\"invalid-name\", \"dangerous-default-value\", \"broad-exception-caught\"]\n\
[tool.ruff.lint]\n\
ignore = [\"E402\", \"E722\"]\n"
                .to_owned(),
        )]);
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);

        assert!(analyze(&context).is_empty());
    }
    #[test]
    fn scans_unicode_before_python_string_literals() {
        assert_eq!(
            code_outside_triple_quoted_strings("label = \"Øresund\"", None),
            ("label = \"Øresund\"".to_owned(), None)
        );
    }
}
