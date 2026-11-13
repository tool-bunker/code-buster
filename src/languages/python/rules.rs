use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
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
    let policy = python_project_policy(context);
    let mut findings = object_soup_rules::python(functions);
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".py"))
    {
        analyze_source(path, source, &policy, &mut findings);
    }
    analyze_mock_targets(context.sources(), &policy.disabled, &mut findings);
    findings
}

fn analyze_source(
    path: &str,
    source: &str,
    policy: &PythonProjectPolicy,
    findings: &mut Vec<Finding>,
) {
    let lines = source.split('\n').collect::<Vec<_>>();
    let monkey_patch_replacements = monkey_patch_replacements(&lines);
    let mut state = PythonScanState::default();
    let mut sanitized = Vec::with_capacity(lines.len());
    let mut expression_continuations = Vec::with_capacity(lines.len());

    for (index, raw) in lines.iter().enumerate() {
        let current = state.scan(index, raw);
        state.update_performance_facts(&current);
        analyze_style(path, &current, &policy.disabled, findings);
        analyze_language_constructs(
            path,
            &PythonSourceLines {
                raw: &lines,
                sanitized: &sanitized,
            },
            &current,
            &monkey_patch_replacements,
            &policy.disabled,
            &mut state,
            findings,
        );
        analyze_security(path, &lines, &sanitized, &current, policy, findings);
        analyze_runtime(
            path,
            &lines,
            &current,
            &policy.disabled,
            &mut state,
            findings,
        );
        analyze_performance(
            path,
            &lines,
            &mut state,
            &current,
            &policy.disabled,
            findings,
        );
        state.finish(&current);
        expression_continuations.push(current.in_expression_continuation);
        sanitized.push(current.stripped);
    }
    analyze_structured_python_rules(
        path,
        &lines,
        &sanitized,
        &expression_continuations,
        &policy.disabled,
        findings,
    );
}

struct PythonSourceLines<'a> {
    raw: &'a [&'a str],
    sanitized: &'a [String],
}

#[derive(Default)]
struct PythonScanState {
    saw_code: bool,
    import_continuation_depth: isize,
    expression_depth: isize,
    expression_start: Option<usize>,
    type_checking_indent: Option<usize>,
    function_scopes: Vec<(usize, bool)>,
    loop_indents: Vec<usize>,
    loop_suspension_indents: Vec<usize>,
    list_variables: BTreeSet<String>,
    immutable_sequence_variables: BTreeSet<String>,
    numpy_aliases: BTreeSet<String>,
    string_variables: BTreeMap<String, usize>,
    logging_bindings: BTreeMap<String, (usize, bool)>,
    sequence_variable_indents: BTreeMap<String, usize>,
    variable_assignment_indents: BTreeMap<String, usize>,
    continued_string_quote: Option<char>,
    triple_quoted_string_delimiter: Option<String>,
    runtime_assert_reported: bool,
    subprocess_timeout_reported: bool,
    eager_logging_reported: bool,
    broad_exception_reported: bool,
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
        let in_expression_continuation = self.expression_depth > 0;
        let expression_start = self.expression_start;
        let in_type_checking_block = self
            .type_checking_indent
            .is_some_and(|value| indent > value);
        self.update_type_checking_scope(line, indent);
        let in_async_function = self.update_function_scope(line, indent);
        let in_loop = self.update_loop_scope(line, indent);

        PythonLine {
            index,
            raw,
            code,
            stripped,
            comment,
            indent,
            in_import_continuation,
            in_expression_continuation,
            expression_start,
            in_type_checking_block,
            in_async_function,
            in_loop,
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
            !line.is_empty() && indent <= value && !is_type_checking_header(line)
        }) {
            self.type_checking_indent = None;
        }
        if is_type_checking_header(line) {
            self.type_checking_indent = Some(indent);
        }
    }

    fn update_function_scope(&mut self, line: &str, indent: usize) -> bool {
        if !line.is_empty() {
            while self
                .function_scopes
                .last()
                .is_some_and(|(scope_indent, _)| indent <= *scope_indent)
            {
                self.function_scopes.pop();
            }
        }
        if is_python_function_header(line) {
            self.function_scopes
                .push((indent, line.starts_with("async def ")));
        }
        self.function_scopes
            .last()
            .is_some_and(|(_, is_async)| *is_async)
    }

    fn update_loop_scope(&mut self, line: &str, indent: usize) -> bool {
        self.leave_completed_loop_scopes(line, indent);
        let inside_loop = self.inside_tracked_loop();
        if inside_loop && is_python_function_header(line) {
            self.loop_suspension_indents.push(indent);
            return false;
        }
        let starts_while = line.starts_with("while ");
        if self.loop_suspension_indents.is_empty() && is_python_loop_header(line) {
            self.loop_indents.push(indent);
        }
        inside_loop || starts_while
    }

    fn leave_completed_loop_scopes(&mut self, line: &str, indent: usize) {
        if line.is_empty() {
            return;
        }
        pop_dedented_scopes(&mut self.loop_suspension_indents, indent);
        pop_dedented_scopes(&mut self.loop_indents, indent);
    }

    fn inside_tracked_loop(&self) -> bool {
        !self.loop_indents.is_empty() && self.loop_suspension_indents.is_empty()
    }

    fn update_performance_facts(&mut self, current: &PythonLine<'_>) {
        self.update_logging_bindings(current);
        if is_python_function_header(current.line()) {
            self.list_variables.clear();
            self.string_variables.clear();
            self.immutable_sequence_variables.clear();
            self.sequence_variable_indents.clear();
            self.variable_assignment_indents.clear();
        }
        for capture in PYTHON_LIST_DECLARATION.captures_iter(&current.code) {
            self.list_variables.insert(capture[1].to_owned());
            self.sequence_variable_indents
                .insert(capture[1].to_owned(), current.indent);
        }
        for capture in PYTHON_STRING_DECLARATION.captures_iter(&current.code) {
            self.string_variables
                .insert(capture[1].to_owned(), current.indent);
        }
        for capture in PYTHON_IMMUTABLE_SEQUENCE_DECLARATION.captures_iter(&current.code) {
            self.immutable_sequence_variables
                .insert(capture[1].to_owned());
            self.sequence_variable_indents
                .insert(capture[1].to_owned(), current.indent);
        }
        if !PYTHON_NUMPY_GROW.is_match(current.line())
            && let Some(capture) = PYTHON_SIMPLE_ASSIGNMENT.captures(current.line())
        {
            self.variable_assignment_indents
                .insert(capture[1].to_owned(), current.indent);
        }
        if let Some(capture) = NUMPY_IMPORT.captures(current.line()) {
            self.numpy_aliases.insert(
                capture
                    .get(1)
                    .map_or("numpy", |alias| alias.as_str())
                    .to_owned(),
            );
        }
    }

    fn update_logging_bindings(&mut self, current: &PythonLine<'_>) {
        let line = current.line();
        if line.is_empty() {
            return;
        }
        self.logging_bindings
            .retain(|_, (indent, _)| *indent <= current.indent);
        if is_python_function_header(line) {
            self.logging_bindings
                .retain(|name, _| !identifier_token_occurs(line, name));
        }
        if let Some(import) = STANDARD_LOGGING_IMPORT.captures(line) {
            let name = import.get(1).map_or("logging", |alias| alias.as_str());
            self.logging_bindings
                .insert(name.to_owned(), (current.indent, true));
        }
        if let Some(assignment) = LOGGING_ASSIGNMENT.captures(line) {
            let name = &assignment[1];
            let is_logger = STANDARD_LOGGER_FACTORY
                .captures(&assignment[2])
                .is_some_and(|factory| {
                    self.logging_bindings
                        .get(&factory[1])
                        .is_some_and(|(_, module)| *module)
                });
            self.logging_bindings.remove(name);
            if is_logger {
                self.logging_bindings
                    .insert(name.to_owned(), (current.indent, false));
            }
        }
    }

    fn finish(&mut self, current: &PythonLine<'_>) {
        if is_executable_python_line(current) {
            self.saw_code = true;
        }
        self.update_import_continuation(current);
        let previous_depth = self.expression_depth;
        self.expression_depth =
            (previous_depth + bracket_delta(&mask_strings(&current.code))).max(0);
        if previous_depth == 0 && self.expression_depth > 0 {
            self.expression_start = Some(current.index);
        } else if self.expression_depth == 0 {
            self.expression_start = None;
        }
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

fn pop_dedented_scopes(scopes: &mut Vec<usize>, indent: usize) {
    while scopes.last().is_some_and(|scope| indent <= *scope) {
        scopes.pop();
    }
}

fn is_python_function_header(line: &str) -> bool {
    line.starts_with("def ") || line.starts_with("async def ")
}

fn is_type_checking_header(line: &str) -> bool {
    matches!(line, "if TYPE_CHECKING:" | "if typing.TYPE_CHECKING:")
}

fn is_python_loop_header(line: &str) -> bool {
    (line.starts_with("while ") || line.starts_with("for ") || line.starts_with("async for "))
        && line.ends_with(':')
}

fn is_executable_python_line(current: &PythonLine<'_>) -> bool {
    let line = current.line();
    if line.is_empty()
        || current.in_import_continuation
        || current.in_type_checking_block
        || is_type_checking_header(line)
    {
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
    in_expression_continuation: bool,
    expression_start: Option<usize>,
    in_type_checking_block: bool,
    in_async_function: bool,
    in_loop: bool,
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
    if has_noqa_for(current.comment, "F403") || is_package_init(path) {
        return;
    }
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
    if has_inline_compound_body(line) || COMPOUND_AFTER_SEMICOLON.is_match(line) {
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
    lines: &PythonSourceLines<'_>,
    current: &PythonLine<'_>,
    monkey_patch_replacements: &BTreeSet<String>,
    disabled: &BTreeSet<&'static str>,
    state: &mut PythonScanState,
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
    report_exception_handler(path, lines.raw, current, disabled, state, findings);
    report_dynamic_execution(path, current, function, disabled, findings);
    report_shell_execution(path, current, disabled, findings);
    report_runtime_assert(path, current, disabled, state, findings);
}

fn report_function_name(
    path: &str,
    lines: &PythonSourceLines<'_>,
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
        || PYTHON_VISITOR_METHOD.is_match(name)
    {
        return;
    }
    if is_com_interface_method(lines.raw, current.index, current.indent)
        || has_naming_contract_decorator(lines, current.indent, name)
        || monkey_patch_replacements.contains(name)
        || has_noqa_for(current.comment, "N802")
        || has_pylint_disable(current.comment, &["invalid-name", "c0103"])
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
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    state: &mut PythonScanState,
    findings: &mut Vec<Finding>,
) {
    let line = current.line();
    let catches_broad_exception = catches_broad_exception(line);
    if catches_broad_exception && exception_handler_is_swallowed(lines, current) {
        add_finding(
            disabled,
            findings,
            path,
            "py-exception-swallowed",
            current.number(),
            "exception handler silently discards the failure",
        );
        return;
    }
    if (line == "except:" || line.starts_with("except:"))
        && !broad_handler_unconditionally_raises(lines, current)
        && !has_noqa_for(current.comment, "E722")
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-bare-except",
            current.number(),
            "bare except catches all exceptions",
        );
    }
    if !catches_broad_exception
        || reviewed_broad_exception_handler(lines, current, state.broad_exception_reported)
    {
        return;
    }
    add_finding(
        disabled,
        findings,
        path,
        "py-broad-except",
        current.number(),
        "broad exception handler",
    );
    state.broad_exception_reported = true;
}

fn reviewed_broad_exception_handler(
    lines: &[&str],
    current: &PythonLine<'_>,
    already_reported: bool,
) -> bool {
    current.line().starts_with("except:")
        || broad_handler_unconditionally_raises(lines, current)
        || has_noqa_for(current.comment, "BLE001")
        || has_pylint_disable(current.comment, &["broad-except", "broad-exception-caught"])
        || already_reported
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
    state: &mut PythonScanState,
    findings: &mut Vec<Finding>,
) {
    if current.line().starts_with("assert ")
        && !is_test_path(path)
        && !state.runtime_assert_reported
    {
        state.runtime_assert_reported = true;
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
    previous_lines: &[String],
    current: &PythonLine<'_>,
    policy: &PythonProjectPolicy,
    findings: &mut Vec<Finding>,
) {
    let disabled = &policy.disabled;
    report_requests_call(path, lines, current, disabled, findings);
    report_yaml_load(path, lines, current, disabled, findings);
    report_pickle_load(path, current, disabled, findings);
    report_dynamic_sql(path, lines, current, disabled, findings);
    report_hardcoded_secret(path, lines, current, disabled, findings);
    report_weak_hash(path, lines, current, disabled, findings);
    report_unsafe_tempfile(path, current, disabled, findings);
    report_archive_extraction(path, lines, previous_lines, current, policy, findings);
    report_insecure_random_token(path, current, disabled, findings);
    report_sensitive_data_logging(path, current, disabled, findings);
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
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if has_dynamic_sql_string_expression(&current.code)
        && !uses_literal_sql_identifier_choice(lines, current)
        && !expression_has_noqa(lines, current, "S608")
    {
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
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if has_hardcoded_secret(&current.code, path, current.in_expression_continuation)
        && !is_secret_form_metadata(lines, current)
    {
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
            "MD5 or SHA-1 use needs a security-context review",
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
    let continued_keyword = current.in_expression_continuation
        && current
            .line()
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("debug"));
    if DEBUG_ENABLED.is_match(&current.code) && !continued_keyword {
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

fn report_archive_extraction(
    path: &str,
    lines: &[&str],
    previous_lines: &[String],
    current: &PythonLine<'_>,
    policy: &PythonProjectPolicy,
    findings: &mut Vec<Finding>,
) {
    let Some(captures) = ARCHIVE_EXTRACTION.captures(current.line()) else {
        return;
    };
    let receiver = &captures[1];
    let Some(kind) = archive_receiver_kind(previous_lines, receiver) else {
        return;
    };
    let call = continued_call(lines, current.index);
    if kind == PythonArchiveKind::Tar
        && (policy.tar_data_filter_default || ARCHIVE_DATA_FILTER.is_match(&call))
    {
        return;
    }
    add_finding(
        &policy.disabled,
        findings,
        path,
        "py-unsafe-archive-extract",
        current.number(),
        "archive extraction does not establish a traversal-safe destination",
    );
}

fn report_insecure_random_token(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if INSECURE_RANDOM_TOKEN.is_match(&current.stripped) {
        add_finding(
            disabled,
            findings,
            path,
            "py-insecure-random-token",
            current.number(),
            "security-sensitive value uses the predictable random module",
        );
    }
}

fn report_sensitive_data_logging(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if current.stripped.contains("request.")
        || (!SENSITIVE_LOGGING_CALL.is_match(&current.stripped)
            && !SENSITIVE_FSTRING_LOGGING.is_match(&current.code))
    {
        return;
    }
    add_finding(
        disabled,
        findings,
        path,
        "py-sensitive-data-logging",
        current.number(),
        "logging call includes credential-shaped data",
    );
}

fn analyze_runtime(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    state: &mut PythonScanState,
    findings: &mut Vec<Finding>,
) {
    report_open_without_encoding(path, lines, current, disabled, findings);
    report_printed_exception(path, lines, current, disabled, findings);
    report_async_blocking_call(path, current, disabled, findings);
    report_dangling_asyncio_task(path, current, disabled, findings);
    report_subprocess_safety(path, lines, current, disabled, state, findings);
}

fn report_dangling_asyncio_task(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !current.in_expression_continuation
        && !has_noqa_for(current.comment, "RUF006")
        && (current.line().starts_with("asyncio.create_task(")
            || current.line().starts_with("asyncio.ensure_future("))
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-asyncio-dangling-task",
            current.number(),
            "asyncio task is created without retaining its handle",
        );
    }
}

fn report_subprocess_safety(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    state: &mut PythonScanState,
    findings: &mut Vec<Finding>,
) {
    if current.in_expression_continuation || !current.line().contains("subprocess.run(") {
        return;
    }
    let call = continued_call(lines, current.index);
    let unchecked_discard = current.line().starts_with("subprocess.run(")
        && !SUBPROCESS_CHECK_ARGUMENT.is_match(&call)
        && !call.contains(".check_returncode(");
    if unchecked_discard {
        add_finding(
            disabled,
            findings,
            path,
            "py-subprocess-run-unchecked",
            current.number(),
            "discarded subprocess result does not make exit-code handling explicit",
        );
        return;
    }
    if (!TIMEOUT_ARGUMENT.is_match(&call) || NONE_TIMEOUT_ARGUMENT.is_match(&call))
        && !state.subprocess_timeout_reported
    {
        state.subprocess_timeout_reported = true;
        add_finding(
            disabled,
            findings,
            path,
            "py-subprocess-no-timeout",
            current.number(),
            "subprocess call has no execution timeout",
        );
    }
}

fn report_open_without_encoding(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if defines_function_named(current.line(), "open")
        || !OPEN_CALL.is_match(current.line())
        || expects_open_failure(lines, current.index)
    {
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
    let handler_call = continued_call(lines, current.index + 1);
    let handler_output = mask_strings(&handler_call);
    let handler_output = handler_output.trim();
    if !handler_output.starts_with("print(")
        || prints_to_stderr(handler_output)
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

fn prints_to_stderr(call: &str) -> bool {
    let Some(mut arguments) = parenthesized_body(call, "print".len()) else {
        return false;
    };
    loop {
        let argument = first_call_argument(arguments);
        if STDERR_PRINT_TARGET.is_match(argument) {
            return true;
        }
        let Some(remaining) = arguments[argument.len()..].strip_prefix(',') else {
            return false;
        };
        arguments = remaining;
    }
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

fn analyze_performance(
    path: &str,
    lines: &[&str],
    state: &mut PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    report_eager_any_all(path, lines, current, disabled, findings);
    report_quadratic_list_flattening(path, lines, current, disabled, findings);
    report_eager_logging_format(path, lines, current, disabled, state, findings);

    if !current.in_loop {
        return;
    }
    report_regex_compilation(path, current, disabled, findings);
    report_linear_list_membership(path, state, current, disabled, findings);
    report_repeated_list_search(path, lines, state, current, disabled, findings);
    report_list_front_removal(path, state, current, disabled, findings);
    report_string_concatenation(path, lines, state, current, disabled, findings);
    report_sequence_rebuild(path, lines, state, current, disabled, findings);
    report_numpy_growth(path, lines, state, current, disabled, findings);
    report_loop_query(path, lines, current, disabled, findings);
}

fn report_regex_compilation(
    path: &str,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if PYTHON_CONSTANT_REGEX.is_match(&current.code) && !current.line().contains("lambda") {
        add_finding(
            disabled,
            findings,
            path,
            "py-regex-compile-in-loop",
            current.number(),
            "constant regular expression is compiled inside a loop",
        );
    }
}

fn report_linear_list_membership(
    path: &str,
    state: &PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if has_linear_list_membership(current.line(), state) {
        add_finding(
            disabled,
            findings,
            path,
            "py-linear-membership-in-loop",
            current.number(),
            "linear list membership is checked inside a loop",
        );
    }
}

fn report_repeated_list_search(
    path: &str,
    lines: &[&str],
    state: &PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if has_repeated_list_search(current.line(), state) && !next_statement_is_break(lines, current) {
        add_finding(
            disabled,
            findings,
            path,
            "py-list-search-in-loop",
            current.number(),
            "linear list search is repeated inside a loop",
        );
    }
}

fn report_list_front_removal(
    path: &str,
    state: &PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if PYTHON_LIST_FRONT_REMOVAL
        .captures_iter(&current.code)
        .any(|capture| state.list_variables.contains(&capture[1]))
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-list-front-removal-in-loop",
            current.number(),
            "removing the first list element repeatedly shifts the remaining elements",
        );
    }
}

fn report_string_concatenation(
    path: &str,
    lines: &[&str],
    state: &PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if PYTHON_IN_PLACE_CONCAT
        .captures(current.line())
        .is_some_and(|capture| {
            state
                .string_variables
                .get(&capture[1])
                .is_some_and(|indent| {
                    state
                        .loop_indents
                        .last()
                        .is_some_and(|loop_indent| indent <= loop_indent)
                })
        })
        && !next_statement_is_break(lines, current)
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-string-concat-in-loop",
            current.number(),
            "immutable string is concatenated inside a loop",
        );
    }
}

fn report_loop_query(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if PYTHON_LOOP_QUERY.is_match(current.line())
        || (PYTHON_SESSION_GET_OPEN.is_match(current.line())
            && PYTHON_LOOP_QUERY
                .is_match(strip_quoted_strings(&continued_call(lines, current.index)).trim()))
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-query-in-loop",
            current.number(),
            "database query executes inside a loop",
        );
    }
}

fn report_eager_any_all(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !EAGER_ANY_ALL_OPEN.is_match(current.line()) {
        return;
    }
    let raw_call = continued_call(lines, current.index);
    let call = strip_quoted_strings(&raw_call);
    if has_eager_any_all_list_comprehension(&call)
        && !identifier_token_occurs(&call, "await")
        && !has_eager_evaluation_rationale(lines, current.index, raw_call.lines().count())
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-eager-any-all-comprehension",
            current.number(),
            "list comprehension prevents any or all from short-circuiting",
        );
    }
}

fn has_eager_evaluation_rationale(lines: &[&str], index: usize, call_lines: usize) -> bool {
    let start = index.saturating_sub(2);
    let end = (index + call_lines).min(lines.len());
    lines[start..end].iter().any(|line| {
        let code = code_before_comment(line);
        code.len() < line.len() && EAGER_EVALUATION_RATIONALE.is_match(&line[code.len()..])
    })
}

fn report_quadratic_list_flattening(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !SUM_CALL_OPEN.is_match(current.line()) {
        return;
    }
    let call = strip_quoted_strings(&continued_call(lines, current.index));
    if sum_uses_empty_list_start(&call) {
        add_finding(
            disabled,
            findings,
            path,
            "py-quadratic-list-flattening",
            current.number(),
            "sum with an empty list repeatedly copies the accumulated prefix",
        );
    }
}

fn report_eager_logging_format(
    path: &str,
    lines: &[&str],
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    state: &mut PythonScanState,
    findings: &mut Vec<Finding>,
) {
    let Some(candidate) = EAGER_LOGGING_CALL.captures(current.line()) else {
        return;
    };
    if !state.logging_bindings.contains_key(&candidate[1]) {
        return;
    }
    let call = continued_call(lines, current.index);
    let masked = mask_strings(&call);
    let Some(call_open) = EAGER_LOGGING_CALL.find(&masked) else {
        return;
    };
    let argument = first_call_argument(&call[call_open.end()..]).trim();
    let eager = EAGER_FSTRING_ARGUMENT.is_match(argument)
        || STRING_FORMAT_ARGUMENT.is_match(argument)
        || (QUOTED_STRING.is_match(argument) && contains_top_level_plus(argument));
    if eager && !state.eager_logging_reported {
        state.eager_logging_reported = true;
        add_finding(
            disabled,
            findings,
            path,
            "py-logging-eager-format",
            current.number(),
            "debug or info logging eagerly formats its message",
        );
    }
}

fn has_repeated_list_search(line: &str, state: &PythonScanState) -> bool {
    PYTHON_LIST_SEARCH
        .captures_iter(line)
        .any(|capture| state.list_variables.contains(&capture[1]))
}

fn report_sequence_rebuild(
    path: &str,
    lines: &[&str],
    state: &PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let assigned_rebuild = PYTHON_SEQUENCE_REBUILD
        .captures(current.line())
        .is_some_and(|capture| {
            capture[1] == capture[2]
                && sequence_declared_before_loop(state, &capture[1])
                && (state.list_variables.contains(&capture[1])
                    || state.immutable_sequence_variables.contains(&capture[1]))
        });
    let immutable_in_place = PYTHON_IN_PLACE_SEQUENCE_CONCAT
        .captures(current.line())
        .is_some_and(|capture| {
            state.immutable_sequence_variables.contains(&capture[1])
                && sequence_declared_before_loop(state, &capture[1])
        });
    if (assigned_rebuild || immutable_in_place) && !next_statement_is_break(lines, current) {
        add_finding(
            disabled,
            findings,
            path,
            "py-sequence-rebuild-in-loop",
            current.number(),
            "growing sequence is rebuilt and copied inside a loop",
        );
    }
}

fn sequence_declared_before_loop(state: &PythonScanState, variable: &str) -> bool {
    state
        .sequence_variable_indents
        .get(variable)
        .zip(state.loop_indents.last())
        .is_some_and(|(declaration, loop_indent)| declaration <= loop_indent)
}

fn report_numpy_growth(
    path: &str,
    lines: &[&str],
    state: &PythonScanState,
    current: &PythonLine<'_>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    if !PYTHON_NUMPY_GROW.is_match(current.line()) {
        return;
    }
    let call = strip_quoted_strings(&continued_call(lines, current.index));
    let call = call.trim();
    let Some(capture) = PYTHON_NUMPY_GROW.captures(call) else {
        return;
    };
    let Some(matched) = capture.get(0) else {
        return;
    };
    let accumulator = &capture[1];
    if state.numpy_aliases.contains(&capture[2])
        && variable_assigned_before_loop(state, accumulator)
        && parenthesized_body(call, matched.end() - 1)
            .is_some_and(|body| identifier_token_occurs(body, accumulator))
    {
        add_finding(
            disabled,
            findings,
            path,
            "py-numpy-grow-in-loop",
            current.number(),
            "NumPy array is repeatedly reallocated while growing inside a loop",
        );
    }
}

fn variable_assigned_before_loop(state: &PythonScanState, variable: &str) -> bool {
    state
        .variable_assignment_indents
        .get(variable)
        .zip(state.loop_indents.last())
        .is_some_and(|(assignment, loop_indent)| assignment <= loop_indent)
}

fn has_eager_any_all_list_comprehension(source: &str) -> bool {
    EAGER_ANY_ALL_OPEN.find_iter(source).any(|matched| {
        parenthesized_body(source, matched.end() - 1)
            .map(first_call_argument)
            .is_some_and(is_direct_list_comprehension)
    })
}

fn is_direct_list_comprehension(argument: &str) -> bool {
    let argument = argument.trim();
    if !argument.starts_with('[') {
        return false;
    }
    parenthesized_body(argument, 0).is_some_and(|body| {
        top_level_identifier_occurs(body, "for")
            && suffix_after_matching_delimiter(argument, 0)
                .is_some_and(|suffix| suffix.trim().is_empty())
    })
}

fn top_level_identifier_occurs(source: &str, identifier: &str) -> bool {
    let masked = mask_strings(source);
    let mut depth = 0_isize;
    let mut token_start = None;
    for (offset, character) in masked.char_indices() {
        if character.is_ascii_alphanumeric() || character == '_' {
            if depth == 0 && token_start.is_none() {
                token_start = Some(offset);
            }
            continue;
        }
        if token_start
            .take()
            .is_some_and(|start| &masked[start..offset] == identifier)
        {
            return true;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    token_start.is_some_and(|start| &masked[start..] == identifier)
}

fn suffix_after_matching_delimiter(source: &str, open: usize) -> Option<&str> {
    let masked = mask_strings(source);
    let mut depth = 0_isize;
    for (relative, character) in masked[open..].char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return source.get(open + relative + 1..);
                }
            }
            _ => {}
        }
    }
    None
}

fn sum_uses_empty_list_start(source: &str) -> bool {
    SUM_CALL_OPEN.find_iter(source).any(|matched| {
        parenthesized_body(source, matched.end() - 1)
            .and_then(top_level_second_argument)
            .is_some_and(|argument| EMPTY_LIST_SUM_START.is_match(argument.trim()))
    })
}

fn parenthesized_body(source: &str, open: usize) -> Option<&str> {
    let masked = mask_strings(source);
    let mut depth = 0_isize;
    for (relative, character) in masked[open..].char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return source.get(open + 1..open + relative);
                }
            }
            _ => {}
        }
    }
    None
}

fn top_level_second_argument(source: &str) -> Option<&str> {
    let masked = mask_strings(source);
    let mut depth = 0_isize;
    for (offset, character) in masked.char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return source.get(offset + 1..),
            _ => {}
        }
    }
    None
}

fn first_call_argument(source: &str) -> &str {
    let masked = mask_strings(source);
    let mut depth = 0_isize;
    for (offset, character) in masked.char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return &source[..offset],
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return &source[..offset],
            _ => {}
        }
    }
    source
}

fn contains_top_level_plus(source: &str) -> bool {
    let masked = mask_strings(source);
    let mut depth = 0_isize;
    masked.chars().any(|character| match character {
        '(' | '[' | '{' => {
            depth += 1;
            false
        }
        ')' | ']' | '}' => {
            depth -= 1;
            false
        }
        '+' => depth == 0,
        _ => false,
    })
}

fn identifier_token_occurs(source: &str, identifier: &str) -> bool {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == identifier)
}

fn has_linear_list_membership(line: &str, state: &PythonScanState) -> bool {
    !line.starts_with("for ")
        && !line.starts_with("async for ")
        && PYTHON_MEMBERSHIP.captures_iter(line).any(|capture| {
            state.list_variables.contains(&capture[1])
                && sequence_declared_before_loop(state, &capture[1])
                && !is_iteration_clause(line, capture.get(0).unwrap().start())
        })
}

fn is_iteration_clause(line: &str, membership_start: usize) -> bool {
    line[..membership_start]
        .trim_end()
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .next_back()
        == Some("for")
}

fn next_statement_is_break(lines: &[&str], current: &PythonLine<'_>) -> bool {
    lines[current.index + 1..]
        .iter()
        .map(|line| (leading_indent(line), line.trim()))
        .find(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .is_some_and(|(indent, line)| indent == current.indent && line == "break")
}

fn analyze_structured_python_rules(
    path: &str,
    lines: &[&str],
    sanitized: &[String],
    expression_continuations: &[bool],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    report_unawaited_coroutines(
        path,
        sanitized,
        expression_continuations,
        disabled,
        findings,
    );
    report_unclosed_resources(path, lines, sanitized, disabled, findings);
    report_finally_control_flow(path, lines, sanitized, disabled, findings);
    report_unbounded_retry_loops(path, lines, sanitized, disabled, findings);
    report_destroyed_tracebacks(path, lines, sanitized, disabled, findings);
}

fn report_unawaited_coroutines(
    path: &str,
    sanitized: &[String],
    expression_continuations: &[bool],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let mut async_functions = sanitized
        .iter()
        .filter_map(|line| ASYNC_FUNCTION.captures(line.trim()))
        .map(|captures| captures[1].to_owned())
        .collect::<BTreeSet<_>>();
    for line in sanitized
        .iter()
        .map(|line| line.trim())
        .filter(|line| line.starts_with("def "))
    {
        if let Some(captures) = FUNCTION.captures(line) {
            async_functions.remove(&captures[1]);
        }
    }
    if async_functions.is_empty() {
        return;
    }
    for (index, line) in sanitized.iter().enumerate() {
        if expression_continuations[index] {
            continue;
        }
        let Some(captures) = DIRECT_CALL_STATEMENT.captures(line.trim()) else {
            continue;
        };
        if async_functions.contains(&captures[1]) {
            add_finding(
                disabled,
                findings,
                path,
                "py-coroutine-not-awaited",
                index + 1,
                "coroutine call is neither awaited, returned, nor scheduled",
            );
        }
    }
}

fn report_unclosed_resources(
    path: &str,
    lines: &[&str],
    sanitized: &[String],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in sanitized.iter().enumerate() {
        let Some(captures) = RESOURCE_ASSIGNMENT.captures(line) else {
            continue;
        };
        let variable = &captures[1];
        let constructor = &captures[2];
        if constructor == "Session" && !imports_closeable_session(sanitized) {
            continue;
        }
        let constructor_open = captures.get(0).unwrap().end() - 1;
        if resource_constructor_is_chained(lines, index, constructor_open) {
            continue;
        }
        let indent = leading_indent(lines[index]);
        let Some(end) = enclosing_function_end(lines, sanitized, index, indent) else {
            continue;
        };
        let function_lines = &sanitized[index + 1..end];
        if resource_is_released_or_transferred(function_lines, variable)
            || resource_owner_is_closed(function_lines, constructor)
        {
            continue;
        }
        add_finding(
            disabled,
            findings,
            path,
            "py-resource-not-closed",
            index + 1,
            "locally created resource has no visible close or ownership transfer",
        );
    }
}

fn imports_closeable_session(lines: &[String]) -> bool {
    lines
        .iter()
        .any(|line| CLOSEABLE_SESSION_IMPORT.is_match(line))
}

fn resource_constructor_is_chained(lines: &[&str], index: usize, open: usize) -> bool {
    let call = continued_call(lines, index);
    suffix_after_matching_parenthesis(&call, open)
        .is_some_and(|suffix| suffix.trim_start().starts_with('.'))
}

fn suffix_after_matching_parenthesis(source: &str, open: usize) -> Option<&str> {
    let masked = mask_strings(source);
    let mut depth = 0;
    for (relative, character) in masked[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return source.get(open + relative + 1..);
                }
            }
            _ => {}
        }
    }
    None
}

fn enclosing_function_end(
    lines: &[&str],
    sanitized: &[String],
    index: usize,
    indent: usize,
) -> Option<usize> {
    let (function_index, function_indent) = (0..index).rev().find_map(|candidate| {
        let candidate_line = sanitized[candidate].trim();
        let candidate_indent = leading_indent(lines[candidate]);
        (candidate_indent < indent && is_python_function_header(candidate_line))
            .then_some((candidate, candidate_indent))
    })?;
    let end = sanitized
        .iter()
        .enumerate()
        .skip(function_index + 1)
        .find(|(candidate, line)| {
            !line.trim().is_empty() && leading_indent(lines[*candidate]) <= function_indent
        })
        .map_or(sanitized.len(), |(candidate, _)| candidate);
    (index < end).then_some(end)
}

fn resource_is_released_or_transferred(lines: &[String], variable: &str) -> bool {
    let contained_markers = [
        format!("{variable}.close("),
        format!("closing({variable})"),
        format!(".append({variable})"),
        format!(".add({variable})"),
    ];
    let exact_markers = [format!("return {variable}"), format!("yield {variable}")];
    let prefix_markers = [
        format!("with {variable}"),
        format!("async with {variable}"),
        format!("return {variable},"),
        format!("yield {variable},"),
    ];

    lines.iter().any(|line| {
        let line = line.trim();
        contained_markers
            .iter()
            .any(|marker| line.contains(marker.as_str()))
            || exact_markers.iter().any(|marker| line == marker)
            || prefix_markers.iter().any(|marker| line.starts_with(marker))
            || transfers_to_attribute(line, variable)
    })
}

fn resource_owner_is_closed(lines: &[String], constructor: &str) -> bool {
    constructor.strip_suffix(".cursor").is_some_and(|owner| {
        let close_call = format!("{owner}.close(");
        lines.iter().any(|line| line.contains(&close_call))
    })
}

fn transfers_to_attribute(line: &str, variable: &str) -> bool {
    let Some((target, value)) = line.split_once('=') else {
        return false;
    };
    target.trim().contains('.') && value.trim() == variable
}

fn report_finally_control_flow(
    path: &str,
    lines: &[&str],
    sanitized: &[String],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    for index in 0..sanitized.len() {
        if let Some(line) = finally_control_flow_line(lines, sanitized, index) {
            add_finally_control_flow_finding(path, line, disabled, findings);
        }
    }
}

fn finally_control_flow_line(lines: &[&str], sanitized: &[String], index: usize) -> Option<usize> {
    let header = sanitized[index].trim();
    if !header.starts_with("finally:") {
        return None;
    }
    if inline_suite(header).is_some_and(is_finally_control_flow) {
        return Some(index + 1);
    }
    let header_indent = leading_indent(lines[index]);
    let end = indented_block_end(lines, sanitized, index, header_indent);
    let mut state = FinallySuiteState::default();
    sanitized
        .iter()
        .enumerate()
        .take(end)
        .skip(index + 1)
        .find_map(|(candidate, line)| {
            state
                .suppresses_exception(line.trim(), leading_indent(lines[candidate]))
                .then_some(candidate + 1)
        })
}

#[derive(Default)]
struct FinallySuiteState {
    nested_definition_indent: Option<usize>,
    nested_loop_indents: Vec<usize>,
}

impl FinallySuiteState {
    fn suppresses_exception(&mut self, line: &str, indent: usize) -> bool {
        if line.is_empty() {
            return false;
        }
        if self
            .nested_definition_indent
            .is_some_and(|nested| indent <= nested)
        {
            self.nested_definition_indent = None;
        }
        if self.nested_definition_indent.is_some() {
            return false;
        }
        if is_python_function_header(line) || line.starts_with("class ") {
            self.nested_definition_indent = Some(indent);
            return false;
        }
        while self
            .nested_loop_indents
            .last()
            .is_some_and(|loop_indent| indent <= *loop_indent)
        {
            self.nested_loop_indents.pop();
        }
        let keyword = line.split_whitespace().next();
        let suppresses = keyword == Some("return")
            || (matches!(keyword, Some("break" | "continue"))
                && self.nested_loop_indents.is_empty());
        if is_python_loop_header(line) {
            self.nested_loop_indents.push(indent);
        }
        suppresses
    }
}

fn add_finally_control_flow_finding(
    path: &str,
    line: usize,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    add_finding(
        disabled,
        findings,
        path,
        "py-finally-control-flow",
        line,
        "control flow in finally can suppress an active exception",
    );
}

fn is_finally_control_flow(line: &str) -> bool {
    matches!(
        line.split_whitespace().next(),
        Some("return" | "break" | "continue")
    )
}

fn report_unbounded_retry_loops(
    path: &str,
    lines: &[&str],
    sanitized: &[String],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in sanitized.iter().enumerate() {
        if !matches!(line.trim(), "while True:" | "while 1:") {
            continue;
        }
        let indent = leading_indent(lines[index]);
        let end = indented_block_end(lines, sanitized, index, indent);
        let body = &sanitized[index + 1..end];
        let has_try = body.iter().any(|line| line.trim() == "try:");
        let retries_without_exit =
            exception_handler_retries_without_exit(lines, sanitized, index + 1, end);
        if has_try
            && retries_without_exit
            && !retry_loop_has_guarded_exit(lines, sanitized, index + 1, end)
        {
            add_finding(
                disabled,
                findings,
                path,
                "py-unbounded-retry-loop",
                index + 1,
                "retry handler can repeat without a visible attempt limit, deadline, or cancellation guard",
            );
        }
    }
}

fn retry_loop_has_guarded_exit(
    lines: &[&str],
    sanitized: &[String],
    start: usize,
    end: usize,
) -> bool {
    (start..end).any(|guard| {
        let header = sanitized[guard].trim();
        if !header.starts_with("if ") || !RETRY_BOUND_GUARD.is_match(header) {
            return false;
        }
        let guard_indent = leading_indent(lines[guard]);
        let guard_end = indented_block_end(lines, sanitized, guard, guard_indent).min(end);
        let direct_indent = (guard + 1..guard_end)
            .find(|candidate| !sanitized[*candidate].trim().is_empty())
            .map(|candidate| leading_indent(lines[candidate]));
        (guard + 1..guard_end).any(|candidate| {
            direct_indent.is_some_and(|indent| leading_indent(lines[candidate]) == indent)
                && matches!(
                    sanitized[candidate].split_whitespace().next(),
                    Some("break" | "return" | "raise")
                )
        })
    })
}

fn exception_handler_retries_without_exit(
    lines: &[&str],
    sanitized: &[String],
    start: usize,
    end: usize,
) -> bool {
    (start..end).any(|handler| {
        let line = sanitized[handler].trim();
        if !line.starts_with("except")
            || is_interactive_validation_handler(lines, sanitized, start, handler)
        {
            return false;
        }
        if let Some(suite) = inline_suite(line) {
            return suite == "continue";
        }
        handler_body_retries_without_exit(lines, sanitized, handler, end)
    })
}

fn handler_body_retries_without_exit(
    lines: &[&str],
    sanitized: &[String],
    handler: usize,
    end: usize,
) -> bool {
    let handler_indent = leading_indent(lines[handler]);
    let handler_end = indented_block_end(lines, sanitized, handler, handler_indent).min(end);
    let mut direct_indent = None;
    let mut retries = false;
    let mut exits = false;
    for candidate in handler + 1..handler_end {
        let statement = sanitized[candidate].trim();
        if statement.is_empty() {
            continue;
        }
        let indent = leading_indent(lines[candidate]);
        if indent != *direct_indent.get_or_insert(indent) {
            continue;
        }
        match statement.split_whitespace().next() {
            Some("continue") => retries = true,
            Some("break" | "return" | "raise") => exits = true,
            _ => {}
        }
    }
    retries && !exits
}

fn is_interactive_validation_handler(
    lines: &[&str],
    sanitized: &[String],
    start: usize,
    handler: usize,
) -> bool {
    let Some(error) = INTERACTIVE_VALIDATION_ERROR.captures(sanitized[handler].trim()) else {
        return false;
    };
    let indent = leading_indent(lines[handler]);
    let Some(try_index) = (start..handler).rev().find(|index| {
        leading_indent(lines[*index]) == indent && sanitized[*index].trim() == "try:"
    }) else {
        return false;
    };
    let Some(prompt_index) = (start..try_index)
        .rev()
        .find(|index| !sanitized[*index].trim().is_empty())
    else {
        return false;
    };
    if leading_indent(lines[prompt_index]) != indent {
        return false;
    }
    let Some(prompt) = INTERACTIVE_INPUT_ASSIGNMENT.captures(sanitized[prompt_index].trim()) else {
        return false;
    };
    let body = sanitized[try_index + 1..handler].join("\n");
    let body = body.trim();
    let Some(validation) = INTERACTIVE_VALIDATION_CALL.captures(body) else {
        return false;
    };
    if &error[1] == "ValueError" && !matches!(&validation[1], "int" | "float" | "complex") {
        return false;
    }
    let Some(matched) = validation.get(0) else {
        return false;
    };
    let open = matched.end() - 1;
    if parenthesized_body(body, open).map(|argument| argument.trim().trim_end_matches(',').trim())
        != Some(&prompt[1])
    {
        return false;
    }
    suffix_after_matching_delimiter(body, open).is_some_and(|suffix| {
        let suffix = suffix.trim();
        suffix.is_empty()
            || suffix
                .strip_prefix("if ")
                .and_then(|condition| condition.split_once(" else "))
                .is_some_and(|(condition, fallback)| condition == &prompt[1] && fallback == "None")
    })
}

fn report_destroyed_tracebacks(
    path: &str,
    lines: &[&str],
    sanitized: &[String],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in sanitized.iter().enumerate() {
        let Some(captures) = EXCEPTION_ALIAS.captures(line.trim()) else {
            continue;
        };
        let alias = &captures[1];
        let indent = leading_indent(lines[index]);
        let end = indented_block_end(lines, sanitized, index, indent);
        let destructive_raise = format!("raise {alias}");
        for (candidate, line) in sanitized.iter().enumerate().take(end).skip(index + 1) {
            if line.trim() == destructive_raise {
                add_finding(
                    disabled,
                    findings,
                    path,
                    "py-raise-destroys-traceback",
                    candidate + 1,
                    "raising the caught exception by name resets traceback context",
                );
            }
        }
    }
}

fn indented_block_end(
    lines: &[&str],
    sanitized: &[String],
    header: usize,
    header_indent: usize,
) -> usize {
    sanitized
        .iter()
        .enumerate()
        .skip(header + 1)
        .find(|(index, line)| {
            !line.trim().is_empty() && leading_indent(lines[*index]) <= header_indent
        })
        .map_or(sanitized.len(), |(index, _)| index)
}

fn inline_suite(line: &str) -> Option<&str> {
    line.split_once(':')
        .map(|(_, suite)| suite.trim())
        .filter(|suite| !suite.is_empty())
}

fn catches_broad_exception(line: &str) -> bool {
    if line == "except:" || line.starts_with("except:") {
        return true;
    }
    ["except Exception", "except BaseException"]
        .iter()
        .any(|prefix| {
            line.strip_prefix(prefix).is_some_and(|rest| {
                rest.starts_with(':')
                    || rest
                        .strip_prefix(" as ")
                        .is_some_and(|alias| alias.contains(':'))
            })
        })
}

fn exception_handler_is_swallowed(lines: &[&str], current: &PythonLine<'_>) -> bool {
    if let Some(suite) = inline_suite(current.line()) {
        return matches!(suite, "pass" | "continue");
    }
    let mut body_indent = None;
    let mut saw_statement = false;
    for raw in lines.iter().skip(current.index + 1) {
        let code = strip_quoted_strings(code_before_comment(raw));
        let line = code.trim();
        if line.is_empty() {
            continue;
        }
        let indent = leading_indent(raw);
        if indent <= current.indent {
            break;
        }
        let direct_indent = *body_indent.get_or_insert(indent);
        if indent != direct_indent {
            continue;
        }
        saw_statement = true;
        if !matches!(line, "pass" | "continue") {
            return false;
        }
    }
    saw_statement
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PythonArchiveKind {
    Tar,
    Zip,
}

fn archive_receiver_kind(lines: &[String], receiver: &str) -> Option<PythonArchiveKind> {
    for line in lines.iter().rev().map(|line| line.trim()) {
        if let Some(kind) = archive_binding_kind(line, receiver) {
            return Some(kind);
        }
        if line
            .split_once('=')
            .is_some_and(|(target, _)| target.trim() == receiver)
            || is_python_function_header(line)
            || line.starts_with("class ")
        {
            return None;
        }
    }
    None
}

fn archive_binding_kind(line: &str, receiver: &str) -> Option<PythonArchiveKind> {
    for (constructor, kind) in [
        ("tarfile.open(", PythonArchiveKind::Tar),
        ("zipfile.ZipFile(", PythonArchiveKind::Zip),
    ] {
        if let Some((target, value)) = line.split_once('=')
            && target.trim() == receiver
            && value.trim_start().starts_with(constructor)
        {
            return Some(kind);
        }
        if (line.starts_with("with ") || line.starts_with("async with "))
            && line.contains(constructor)
            && line
                .rsplit_once(" as ")
                .is_some_and(|(_, binding)| binding.trim_end_matches(':').trim() == receiver)
        {
            return Some(kind);
        }
    }
    None
}

struct ImportedPythonSymbol {
    consumer_path: String,
    provider: String,
    symbol: String,
}

struct TestPythonImport {
    module_file: String,
    module_init: String,
    symbol: String,
}

fn analyze_mock_targets(
    sources: &BTreeMap<String, String>,
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let test_sources = sources
        .iter()
        .filter(|(path, _)| path.ends_with(".py") && is_test_path(path))
        .collect::<Vec<_>>();
    if test_sources.is_empty() {
        return;
    }
    let imported_symbols = collect_imported_python_symbols(sources);
    if imported_symbols.is_empty() {
        return;
    }
    for (path, source) in test_sources {
        analyze_test_mock_targets(path, source, &imported_symbols, disabled, findings);
    }
}

fn collect_imported_python_symbols(
    sources: &BTreeMap<String, String>,
) -> Vec<ImportedPythonSymbol> {
    let mut imported_symbols = Vec::new();
    for (path, source) in sources
        .iter()
        .filter(|(path, _)| path.ends_with(".py") && !is_test_path(path))
    {
        let (code, stripped) = masked_python_sources(source);
        for captures in FROM_IMPORT.captures_iter(&code) {
            if contains_python_call(&stripped, &captures[2]) {
                imported_symbols.push(ImportedPythonSymbol {
                    consumer_path: path.clone(),
                    provider: captures[1].to_owned(),
                    symbol: captures[2].to_owned(),
                });
            }
        }
    }
    imported_symbols
}

fn analyze_test_mock_targets(
    path: &str,
    source: &str,
    imported_symbols: &[ImportedPythonSymbol],
    disabled: &BTreeSet<&'static str>,
    findings: &mut Vec<Finding>,
) {
    let (code, stripped) = masked_python_sources(source);
    if !PATCH_TARGET.is_match(&code) {
        return;
    }
    let test_imports = test_python_imports(&code);
    for patch in PATCH_TARGET.captures_iter(&code) {
        if !patch_targets_provider(&patch[1], &stripped, imported_symbols, &test_imports) {
            continue;
        }
        let offset = patch.get(0).map_or(0, |matched| matched.start());
        add_finding(
            disabled,
            findings,
            path,
            "py-test-mocked-target-wrong",
            code[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1,
            "mock patches the provider instead of the importing consumer",
        );
    }
}

fn test_python_imports(code: &str) -> Vec<TestPythonImport> {
    FROM_IMPORT
        .captures_iter(code)
        .map(|captures| {
            let module_path = captures[1].replace('.', "/");
            TestPythonImport {
                module_file: format!("{module_path}.py"),
                module_init: format!("{module_path}/__init__.py"),
                symbol: captures[2].to_owned(),
            }
        })
        .collect()
}

fn patch_targets_provider(
    target: &str,
    stripped_test_source: &str,
    imported_symbols: &[ImportedPythonSymbol],
    test_imports: &[TestPythonImport],
) -> bool {
    imported_symbols.iter().any(|imported| {
        target_is_python_symbol(target, &imported.provider, &imported.symbol)
            && test_imports.iter().any(|test_import| {
                python_path_matches_module(
                    &imported.consumer_path,
                    &test_import.module_file,
                    &test_import.module_init,
                ) && contains_python_call(stripped_test_source, &test_import.symbol)
            })
    })
}

fn contains_python_call(source: &str, symbol: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim();
        if FUNCTION
            .captures(trimmed)
            .is_some_and(|captures| &captures[1] == symbol)
        {
            return false;
        }
        line.match_indices(symbol).any(|(start, _)| {
            let separated_before = start == 0
                || line.as_bytes().get(start - 1).is_some_and(|byte| {
                    !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'.')
                });
            let after = &line[start + symbol.len()..];
            separated_before
                && after
                    .chars()
                    .next()
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
                && after.trim_start().starts_with('(')
        })
    })
}

fn target_is_python_symbol(target: &str, module: &str, symbol: &str) -> bool {
    target
        .strip_prefix(module)
        .and_then(|suffix| suffix.strip_prefix('.'))
        == Some(symbol)
}

fn python_path_matches_module(path: &str, module_file: &str, module_init: &str) -> bool {
    [module_file, module_init].into_iter().any(|module_path| {
        path == module_path
            || (path.ends_with(module_path)
                && path
                    .as_bytes()
                    .get(path.len() - module_path.len() - 1)
                    .is_some_and(|separator| matches!(separator, b'/' | b'\\')))
    })
}

fn masked_python_sources(source: &str) -> (String, String) {
    let mut state = PythonScanState::default();
    let mut code = String::with_capacity(source.len());
    let mut stripped = String::with_capacity(source.len());
    for (index, raw) in source.split('\n').enumerate() {
        let current = state.scan(index, raw);
        code.push_str(&current.code);
        code.push('\n');
        stripped.push_str(&current.stripped);
        stripped.push('\n');
        state.finish(&current);
    }
    (code, stripped)
}

#[derive(Default)]
struct PythonProjectPolicy {
    disabled: BTreeSet<&'static str>,
    tar_data_filter_default: bool,
}

fn python_project_policy(context: &SourceAnalysisContext<'_>) -> PythonProjectPolicy {
    let Some(source) = context.auxiliary_files().get("pyproject.toml") else {
        return PythonProjectPolicy::default();
    };
    let Ok(document) = toml::from_str::<Value>(source) else {
        return PythonProjectPolicy::default();
    };
    let tar_data_filter_default = document
        .get("project")
        .and_then(|value| value.get("requires-python"))
        .and_then(Value::as_str)
        .is_some_and(requires_python_3_14_or_newer);
    let pylint = document
        .get("tool")
        .and_then(|value| value.get("pylint"))
        .and_then(|value| {
            value
                .get("messages_control")
                .or_else(|| value.get("MESSAGES CONTROL"))
        })
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
    if pylint.contains("broad-exception-caught") || pylint.contains("broad-except") {
        disabled.insert("py-broad-except");
    }
    if ruff.contains("E402") {
        disabled.insert("py-import-not-top");
    }
    if ruff.contains("E722") {
        disabled.insert("py-bare-except");
    }
    PythonProjectPolicy {
        disabled,
        tar_data_filter_default,
    }
}

fn requires_python_3_14_or_newer(specifier: &str) -> bool {
    specifier
        .split(',')
        .filter_map(|constraint| constraint.trim().strip_prefix(">="))
        .filter_map(parse_python_version)
        .any(|(major, minor)| major > 3 || (major == 3 && minor >= 14))
}

fn parse_python_version(version: &str) -> Option<(u32, u32)> {
    let version = version.trim_start();
    let (major, minor) = version.split_once('.').unwrap_or((version, "0"));
    Some((major.parse().ok()?, numeric_prefix(minor)?))
}

fn numeric_prefix(value: &str) -> Option<u32> {
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    (digits > 0).then(|| value[..digits].parse().ok()).flatten()
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
        let code = code_before_comment(line);
        if !call.is_empty() {
            call.push('\n');
        }
        call.push_str(code);
        depth += bracket_delta(&mask_strings(code));
        if depth <= 0 {
            break;
        }
    }
    call
}

fn has_inline_compound_body(line: &str) -> bool {
    if !COMPOUND_HEADER.is_match(line) {
        return false;
    }
    let mut depth = 0_isize;
    for (index, character) in line.char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = (depth - 1).max(0),
            ':' if depth == 0 && line.as_bytes().get(index + 1) != Some(&b'=') => {
                return !line[index + 1..].trim().is_empty();
            }
            _ => {}
        }
    }
    false
}

fn defines_function_named(line: &str, expected: &str) -> bool {
    FUNCTION.captures(line).is_some_and(|captures| {
        captures
            .get(1)
            .is_some_and(|name| name.as_str() == expected)
    })
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

fn uses_literal_sql_identifier_choice(lines: &[&str], current: &PythonLine<'_>) -> bool {
    let fields = PYTHON_F_STRING_IDENTIFIER_FIELD
        .captures_iter(&current.code)
        .map(|captures| captures[1].to_owned())
        .collect::<BTreeSet<_>>();
    !fields.is_empty()
        && fields.iter().all(|field| {
            lines[..current.index]
                .iter()
                .rev()
                .take(12)
                .find(|line| {
                    PYTHON_SIMPLE_ASSIGNMENT
                        .captures(line)
                        .is_some_and(|captures| &captures[1] == field)
                })
                .is_some_and(|line| is_literal_sql_identifier_choice(line, field))
        })
}

fn is_literal_sql_identifier_choice(line: &str, field: &str) -> bool {
    let Some((name, value)) = code_before_comment(line).split_once('=') else {
        return false;
    };
    if name.trim() != field {
        return false;
    }
    let Some((when_true, condition_and_false)) = value.split_once(" if ") else {
        return false;
    };
    let Some((_condition, when_false)) = condition_and_false.rsplit_once(" else ") else {
        return false;
    };
    is_sql_identifier_literal(when_true) && is_sql_identifier_literal(when_false)
}

fn is_sql_identifier_literal(expression: &str) -> bool {
    let expression = expression.trim();
    let Some(captures) = SECRET_STRING_LITERAL.captures(expression) else {
        return false;
    };
    let Some(whole) = captures.get(0) else {
        return false;
    };
    let literal = captures
        .get(1)
        .or_else(|| captures.get(2))
        .map_or("", |capture| capture.as_str());
    whole.start() == 0
        && whole.end() == expression.len()
        && literal.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphanumeric()
                    && (index > 0 || character.is_ascii_alphabetic())
        })
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

fn has_naming_contract_decorator(
    lines: &PythonSourceLines<'_>,
    method_indent: usize,
    method_name: &str,
) -> bool {
    let mut end = lines.sanitized.len();
    while let Some((index, decorator)) = preceding_decorator(lines, end, method_indent) {
        match naming_contract_decorator(decorator, method_name) {
            Some(true) => return true,
            None => return false,
            Some(false) => {}
        }
        end = index;
    }
    false
}

fn preceding_decorator<'a>(
    lines: &'a PythonSourceLines<'_>,
    end: usize,
    method_indent: usize,
) -> Option<(usize, &'a str)> {
    let mut continuation_depth = 0;
    for (index, code) in lines.sanitized[..end].iter().enumerate().rev() {
        let raw = lines.raw[index];
        let candidate = code.trim();
        if candidate.is_empty() {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') || continuation_depth > 0
            {
                continue;
            }
            return None;
        }
        continuation_depth -= bracket_delta(candidate);
        if continuation_depth > 0 {
            continue;
        }
        if continuation_depth < 0
            || leading_indent(raw) != method_indent
            || !candidate.starts_with('@')
        {
            return None;
        }
        return Some((index, &candidate[1..]));
    }
    None
}

fn naming_contract_decorator(decorator: &str, method_name: &str) -> Option<bool> {
    let decorator = decorator.trim();
    let (target, configured) = decorator
        .split_once('(')
        .map_or((decorator, false), |(target, _)| (target.trim(), true));
    if !QUALIFIED_PYTHON_IDENTIFIER.is_match(target) {
        return None;
    }
    let name = target.rsplit('.').next().unwrap_or(target);
    let direct_override = !configured && matches!(target, "override" | "typing.override");
    let descriptor = matches!(name, "property" | "classproperty" | "cached_property");
    let accessor = !configured
        && matches!(name, "getter" | "setter" | "deleter")
        && target
            .rsplit_once('.')
            .and_then(|(attribute, _)| attribute.rsplit('.').next())
            == Some(method_name);
    Some(direct_override || descriptor || accessor)
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

fn broad_handler_unconditionally_raises(lines: &[&str], current: &PythonLine<'_>) -> bool {
    if let Some(suite) = inline_suite(current.line()) {
        return is_raise_statement(suite);
    }
    let mut body_indent = None;
    for raw in lines.iter().skip(current.index + 1) {
        let line = code_before_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let indent = leading_indent(raw);
        if indent <= current.indent {
            break;
        }
        let direct_indent = *body_indent.get_or_insert(indent);
        if is_early_exit_statement(line) {
            return false;
        }
        if indent == direct_indent && is_raise_statement(line) {
            return true;
        }
    }
    false
}

fn is_early_exit_statement(line: &str) -> bool {
    line == "return" || line.starts_with("return ") || matches!(line, "break" | "continue")
}

fn is_raise_statement(line: &str) -> bool {
    line == "raise" || line.starts_with("raise ")
}

fn expression_has_noqa(lines: &[&str], current: &PythonLine<'_>, code: &str) -> bool {
    let start = current.expression_start.unwrap_or(current.index);
    lines[start..=current.index].iter().any(|raw| {
        let source = code_before_comment(raw);
        has_noqa_for(&raw[source.len()..], code)
    })
}

fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    PYTHON_TEST_DIRECTORY.is_match(&normalized)
        || name.starts_with("test_")
        || name.ends_with("_test.py")
}

fn is_package_init(path: &str) -> bool {
    path == "__init__.py" || path.ends_with("/__init__.py")
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

fn has_pylint_disable(comment: &str, codes: &[&str]) -> bool {
    let normalized = comment.to_ascii_lowercase();
    normalized
        .split("pylint:")
        .skip(1)
        .filter_map(|directive| directive.trim_start().strip_prefix("disable"))
        .map(|directive| {
            directive
                .trim_start()
                .strip_prefix('=')
                .unwrap_or(directive)
        })
        .flat_map(|directive| {
            directive.split(|character: char| character.is_whitespace() || character == ',')
        })
        .any(|listed| codes.contains(&listed))
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

fn has_hardcoded_secret(code: &str, path: &str, in_expression_continuation: bool) -> bool {
    let secret = HARDCODED_SECRET_MAP_ENTRY
        .find(code)
        .filter(|matched| !is_inside_quoted_string(code, matched.start()))
        .or_else(|| {
            (!in_expression_continuation)
                .then(|| HARDCODED_SECRET_ASSIGNMENT.find(code))
                .flatten()
        });
    let Some(secret) = secret else {
        return false;
    };
    let text = secret.as_str();
    if REPEATED_FILLER_SECRET.is_match(code)
        || EMPTY_HARDCODED_SECRET.is_match(code)
        || is_symbolic_secret_value(text)
        || is_secret_metadata_label(text)
        || is_placeholder_secret(text, path)
        || is_non_alphanumeric_secret_marker(text)
    {
        return false;
    }
    true
}

fn is_inside_quoted_string(code: &str, offset: usize) -> bool {
    QUOTED_STRING
        .find_iter(code)
        .any(|literal| literal.start() < offset && offset < literal.end())
}

fn is_secret_form_metadata(lines: &[&str], current: &PythonLine<'_>) -> bool {
    if !HARDCODED_SECRET_MAP_ENTRY.is_match(&current.code) {
        return false;
    }
    if is_secret_form_metadata_container(&current.code) {
        return true;
    }

    let mut outer_indent = current.indent;
    for raw in lines[..current.index].iter().rev() {
        let code = code_before_comment(raw).trim();
        if code.is_empty() {
            continue;
        }
        let indent = leading_indent(raw);
        if indent >= outer_indent {
            continue;
        }
        outer_indent = indent;
        if is_secret_form_metadata_container(code) {
            return true;
        }
        if !(code.ends_with('{') || code.ends_with('[')) {
            return false;
        }
    }
    false
}

fn is_secret_form_metadata_container(code: &str) -> bool {
    [
        "\"relabeling\"",
        "'relabeling'",
        "\"placeholders\"",
        "'placeholders'",
    ]
    .iter()
    .any(|name| code.contains(name))
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

fn is_secret_metadata_label(text: &str) -> bool {
    let Some(literal) = SECRET_STRING_LITERAL.captures_iter(text).last() else {
        return false;
    };
    let value = literal
        .get(1)
        .or_else(|| literal.get(2))
        .map_or("", |value| value.as_str())
        .trim();
    SECRET_METADATA_LABEL.is_match(value)
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

fn is_non_alphanumeric_secret_marker(text: &str) -> bool {
    let Some(literal) = SECRET_STRING_LITERAL.captures_iter(text).last() else {
        return false;
    };
    let value = literal
        .get(1)
        .or_else(|| literal.get(2))
        .map_or("", |value| value.as_str());
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_ascii_alphanumeric())
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

static ASYNC_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*async\s+def\s+([A-Za-z_]\w*)\s*\(").unwrap());
static DIRECT_CALL_STATEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_]\w*)\s*\(").unwrap());
static RESOURCE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*([A-Za-z_]\w*)\s*=\s*(open|socket\.(?:socket|create_connection)|requests\.Session|httpx\.(?:Client|AsyncClient)|aiohttp\.ClientSession|[A-Za-z_]\w*\.cursor|Session|SessionLocal|AsyncSession)\s*\(",
    )
    .unwrap()
});
static CLOSEABLE_SESSION_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*from\s+(?:requests|sqlalchemy(?:\.[A-Za-z_]\w*)*|sqlmodel)\s+import\b.*\bSession\b",
    )
    .unwrap()
});
static EXCEPTION_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*except\s+[^:]+\s+as\s+([A-Za-z_]\w*)\s*:\s*$").unwrap());
static ARCHIVE_EXTRACTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*extract(?:all)?\s*\(").unwrap());
static ARCHIVE_DATA_FILTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bfilter\s*=\s*["']data["']"#).unwrap());
static INSECURE_RANDOM_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:password|passwd|secret|client_secret|api_?key|token|nonce|otp|session_?id|(?:access|refresh|reset|csrf|verification|auth)_token)\s*=.*\brandom\.(?:choice|choices|randint|randrange|getrandbits)\s*\(",
    )
    .unwrap()
});
static SENSITIVE_LOGGING_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:[A-Za-z_]\w*_logger|log|logger|logging)\.(?:debug|info|warning|error|exception|critical)\s*\([^)]*\b(?:password|passwd|secret|client_secret|api_?key|token|nonce|otp|(?:access|refresh|reset|csrf|verification|auth)_token|authorization|cookie)\b",
    )
    .unwrap()
});
static SENSITIVE_FSTRING_LOGGING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:[A-Za-z_]\w*_logger|log|logger|logging)\.(?:debug|info|warning|error|exception|critical)\s*\([^)]*(?:f[r]?|rf)["'][^"'\n]*\{[^}\n]*\b(?:password|passwd|secret|client_secret|api_?key|token|nonce|otp|(?:access|refresh|reset|csrf|verification|auth)_token|authorization|cookie)\b[^}\n]*\}"#,
    )
    .unwrap()
});
static PYTHON_LOOP_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[A-Za-z_]\w*\s*=\s*)?(?:await\s+)?(?:[A-Za-z_]\w*\.)*(?:\w*(?:cursor|cur|connection|conn|database|db|session|engine|repository|repo|store)\.(?:execute|query|scalar|scalars)\s*\(|\w*session\.get\s*\(\s*(?:[A-Za-z_]\w*\.)*[A-Z]\w*\s*,)",
    )
    .unwrap()
});
static PYTHON_SESSION_GET_OPEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\w*session\.get\s*\(").unwrap());
static RETRY_BOUND_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b\w*(?:attempts?|retries|retry_count|deadline|timeout|shutdown|stop|cancel|max_retries|max_attempts)\b",
    )
    .unwrap()
});
static INTERACTIVE_VALIDATION_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^except\s+(SyntaxError|ValueError)(?:\s+as\s+[A-Za-z_]\w*)?\s*:").unwrap()
});
static INTERACTIVE_INPUT_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_]\w*)\s*=\s*input\s*\([^;]*\)\s*$").unwrap());
static INTERACTIVE_VALIDATION_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:return\s+|[A-Za-z_]\w*\s*=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(")
        .unwrap()
});
static FROM_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+([A-Za-z_]\w*)\b").unwrap()
});
static PATCH_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:mock\.)?patch\s*\(\s*["']([A-Za-z_][\w.]*\.[A-Za-z_]\w*)["']"#).unwrap()
});
static PYTHON_LIST_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z_]\w*)\s*(?::\s*(?:list|List)\s*\[[^\]\n]+\](?:\s*=\s*[^#]+)?|=\s*(?:\[[^\]\n]*\]|list\s*\())",
    )
    .unwrap()
});
static PYTHON_STRING_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b([A-Za-z_]\w*)\s*(?::\s*str\b(?:\s*=\s*[^#]+)?|=\s*[rRuUbB]{0,2}(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'))"#,
    )
    .unwrap()
});
static PYTHON_IMMUTABLE_SEQUENCE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b([A-Za-z_]\w*)\s*(?::\s*(?:tuple(?:\[[^\]\n]+\])?|bytes)\b(?:\s*=\s*[^#]+)?|=\s*(?:tuple\s*\(|bytes\s*\(|[bB](?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\(\s*\)|\([^()\n]*,[^()\n]*\)))"#,
    )
    .unwrap()
});
static NUMPY_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*import\s+numpy(?:\s+as\s+([A-Za-z_]\w*))?\s*$").unwrap());
static EAGER_ANY_ALL_OPEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^\w.])(?:any|all)\s*\(").unwrap());
static EAGER_EVALUATION_RATIONALE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:\bensure(?:s)?\b[^\n]{0,80}\b(?:called|evaluated|run)\b[^\n]{0,40}\b(?:all|every)\b|\b(?:does\s+not|do\s+not|don't|without)\s+short[- ]?circuit)",
    )
    .unwrap()
});
static SUM_CALL_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bsum\s*\(").unwrap());
static EMPTY_LIST_SUM_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:start\s*=\s*)?\[\s*\]\s*,?$").unwrap());
static EAGER_LOGGING_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\.(?:debug|info)\s*\(").unwrap()
});
static STANDARD_LOGGING_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^import\s+logging(?:\s+as\s+([A-Za-z_]\w*))?\s*$").unwrap());
static LOGGING_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^((?:self\.)?[A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.*)$").unwrap());
static STANDARD_LOGGER_FACTORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([A-Za-z_]\w*)\.(?:getLogger|Logger|LoggerAdapter)\s*\(").unwrap()
});
static EAGER_FSTRING_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)^(?:f|fr|rf)\s*(?:"|')"#).unwrap());
static STRING_FORMAT_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)^[rub]{0,2}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*\.format\s*\("#)
        .unwrap()
});
static PYTHON_LIST_SEARCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^\w.])([A-Za-z_]\w*)\s*\.\s*(?:count|index)\s*\(").unwrap()
});
static PYTHON_SEQUENCE_REBUILD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+").unwrap());
static PYTHON_SIMPLE_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([A-Za-z_]\w*)\s*=").unwrap());
static PYTHON_NUMPY_GROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.(?:append|concatenate|vstack|hstack)\s*\(",
    )
    .unwrap()
});
static PYTHON_CONSTANT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bre\.compile\s*\(\s*[rRuUbB]{0,2}(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"#)
        .unwrap()
});
static PYTHON_MEMBERSHIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\s+(?:not\s+)?in\s+([A-Za-z_]\w*)\b").unwrap());
static PYTHON_LIST_FRONT_REMOVAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*pop\s*\(\s*0\s*\)").unwrap());
static PYTHON_IN_PLACE_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\+=").unwrap());
static PYTHON_IN_PLACE_SEQUENCE_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([A-Za-z_]\w*)\s*\+=").unwrap());
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
static NONE_TIMEOUT_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btimeout\s*=\s*None\b").unwrap());
static SUBPROCESS_CHECK_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcheck\s*=").unwrap());
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
static DEBUG_ENABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^\s*debug\s*=\s*true\b|\b(?:app|application)\.run\s*\([^#]*\bdebug\s*=\s*true\b|["']debug["']\s*:\s*true\b)"#,
    )
    .unwrap()
});
static OPEN_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[^\w.])open\s*\(").unwrap());
static BINARY_OPEN_MODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)["'][rwa+x]*b[rwa+x]*["']"#).unwrap());
static STDERR_PRINT_TARGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*file\s*=\s*sys\.stderr\s*$").unwrap());
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
    Regex::new(
        r#"(?i)^["']\s*(?:select\s+\S+[^\n]*\s+from\b|insert\s+into\b|update\s+[A-Za-z_][\w.]*\s+set\b|delete\s+from\b)"#,
    )
    .unwrap()
});
static PYTHON_F_STRING_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[^\w])(?:f[r]?|r[f])$").unwrap());
static PYTHON_F_STRING_IDENTIFIER_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([A-Za-z_]\w*)\}").unwrap());
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
static QUALIFIED_PYTHON_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$").unwrap());
static PYTHON_TEST_DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|/)(?:test|tests|__tests__)(?:/|$)").unwrap());
static NOQA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)#\s*noqa\b(?:\s*:\s*([A-Z0-9_,\s]+))?").unwrap());
static HTTP_REQUEST_HANDLER_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^do_(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)$").unwrap()
});
static PYTHON_TEST_LIFECYCLE_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:setUp|tearDown)(?:Class|Module)?$").unwrap());
static PYTHON_VISITOR_METHOD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:visit|leave)_[A-Z]").unwrap());
static EXPECTED_OPEN_FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:with\s+)?(?:(?:self\.)?assertRaises|pytest\.raises)\(\s*(?:FileNotFoundError|PermissionError|IsADirectoryError)\s*\)\s*:\s*$").unwrap()
});
static QUOTED_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"#).unwrap()
});
static HARDCODED_SECRET_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^\s*(?:[A-Za-z_]\w*\.)*(?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)\s*=\s*[rRuUbB]{0,2}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*(?:[,}\])]|$)"#).unwrap()
});
static HARDCODED_SECRET_MAP_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)["'](?:password|passwd|secret|api_?key|token|access_token|refresh_token|auth_token|bearer_token|client_secret|secret_key)["']\s*:\s*[rRuUbB]{0,2}(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*(?:[,}\])]|$)"#).unwrap()
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
    Regex::new(r"(?i)^(?:none|null|undefined|incorrect|invalid|wrong(?:[-_][a-z0-9]+)?|\[%key:[^]]+%\])$|(?:^|[-_])your(?:[-_])(?:[a-z0-9]+[-_])*(?:key|token|secret|password|credential)(?:$|[-_])|(?:^|[-_])replace[-_]?me(?:$|[-_])").unwrap()
});
static SECRET_METADATA_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:secrets? backend|(?:client )?(?:secret|password|token|api key) (?:field|label|name|identifier|id|endpoint|url))$").unwrap()
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
                ("py-exception-swallowed", 23),
                ("py-pickle", 25),
                ("py-weak-hash", 26),
                ("py-debug-enabled", 27),
                ("py-subprocess-shell", 28),
                ("py-subprocess-run-unchecked", 28),
            ]
        );
    }

    #[test]
    fn distinguishes_multiline_stderr_diagnostics_from_stdout_exception_prints() {
        let cases = [
            (
                "stderr.py",
                "try:\n    run()\nexcept ValueError as error:\n    print(\n        f'Invalid value: {error}',\n        file=sys.stderr,\n    )\n",
            ),
            (
                "stderr_single.py",
                "try:\n    run()\nexcept ValueError as error:\n    print(error, file = sys.stderr)\n",
            ),
            (
                "stdout.py",
                "try:\n    run()\nexcept ValueError as error:\n    print(\n        error,\n        file=sys.stdout,\n    )\n",
            ),
            (
                "nested.py",
                "try:\n    run()\nexcept ValueError as error:\n    print(render(error, file=sys.stderr))\n",
            ),
            (
                "string.py",
                "try:\n    run()\nexcept ValueError as error:\n    print('file=sys.stderr', error)\n",
            ),
            (
                "neighbor.py",
                "try:\n    run()\nexcept ValueError as error:\n    print(error)\n    print('diagnostic', file=sys.stderr)\n",
            ),
        ];
        let sources = cases
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect::<BTreeMap<_, _>>();
        let selected = analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "py-logging-exception")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![
                ("neighbor.py".to_owned(), 4),
                ("nested.py".to_owned(), 4),
                ("stdout.py".to_owned(), 4),
                ("string.py".to_owned(), 4),
            ],
        );
    }

    #[test]
    fn groups_runtime_assertions_per_file() {
        let sources = BTreeMap::from([(
            "service.py".to_owned(),
            "assert configured\nassert handler is not None\n".to_owned(),
        )]);

        assert_eq!(
            analyze(&SourceAnalysisContext::unchanged(&sources))
                .into_iter()
                .filter(|finding| finding.code == "py-assert-runtime")
                .map(|finding| (finding.path, finding.line))
                .collect::<Vec<_>>(),
            [("service.py".to_owned(), 1)]
        );
    }

    #[test]
    fn accepts_package_facades_and_explicit_wildcard_suppressions() {
        let sources = BTreeMap::from([
            (
                "package/__init__.py".to_owned(),
                "from .api import *\nfrom package.models import *\n__all__ = [\"run\"]\n"
                    .to_owned(),
            ),
            (
                "module.py".to_owned(),
                "from package import *\nfrom generated import *  # noqa: F403\n".to_owned(),
            ),
            (
                "unbounded/__init__.py".to_owned(),
                "from .api import *\n".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "py-wildcard-import")
                .map(|finding| (finding.path, finding.line))
                .collect::<Vec<_>>(),
            vec![("module.py".to_owned(), 1)]
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
    fn honors_inline_function_naming_suppressions() {
        let sources = BTreeMap::from([(
            "api.py".to_owned(),
            "def Path(  # noqa: N802\n\
    value: str,\n\
):\n\
    return value\n\
def Legacy():  # pylint: disable=invalid-name\n\
    return None\n\
def ReportMe():\n\
    return None\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| finding.code == "py-function-naming")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![7]);
    }

    #[test]
    fn accepts_descriptor_attributes_and_attached_override_contracts() {
        let sources = BTreeMap::from([(
            "attributes.py".to_owned(),
            r#"class Attributes:
    @classproperty
    def IE_NAME(cls):
        return cls.__name__

    @classproperty(cache=True)
    def FormatSort(cls):
        return Sorter

    @helpers.classproperty(
        cache=True,
        options={"brackets": ("(", ")")},
    )
    # The decorator still belongs to this definition.
    def _VALID_URL(
        cls,
    ):
        return cls.pattern

    @property
    def API_URL(self):
        return self.url

    @API_URL.setter
    def API_URL(self, value):
        self.url = value

    @API_URL.deleter
    def API_URL(self):
        del self.url

    @Base.API_URL.getter
    def API_URL(self):
        return self.url

    @cached_property
    def DEVICE_ID(self):
        return generate_id()

    @functools.cached_property
    def CLIENT_ID(self):
        return load_id()

    @builtins.property
    def DISPLAY_NAME(self):
        return self.name

    @descriptors.cached_property(
        ttl=60,
    )
    def CACHE_KEY(self):
        return self.key

    @typing.override
    @instrument(
        label="property",
        options={
            "nested": (1, 2),
        },
    )
    def shouldRollover(self, record):
        return False
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(
            analyze(&context)
                .iter()
                .all(|finding| finding.code != "py-function-naming")
        );
    }

    #[test]
    fn reports_ordinary_names_without_borrowing_descriptor_decorators() {
        let cases = [
            (
                "ordinary.py",
                "def OrdinaryBadName():\n    return None\n",
                1,
            ),
            (
                "unrelated.py",
                "@instrument\ndef OrdinaryBadName():\n    return None\n",
                2,
            ),
            (
                "configured.py",
                "@instrument(\n    property=True,\n    label='@cached_property',\n)\ndef OrdinaryBadName():\n    return None\n",
                5,
            ),
            (
                "lookalike.py",
                "@cached_property_wrapper\ndef OrdinaryBadName():\n    return None\n",
                2,
            ),
            (
                "member.py",
                "@property.instrument\ndef OrdinaryBadName():\n    return None\n",
                2,
            ),
            (
                "accessor.py",
                "class Attributes:\n    @Base.VALUE.getter\n    def OtherName(self):\n        return None\n",
                3,
            ),
            (
                "neighbor.py",
                "class Attributes:\n    @property\n    def VALUE(self):\n        return None\n\n    @instrument\n    def OrdinaryBadName(self):\n        return None\n",
                7,
            ),
            (
                "nested.py",
                "class Attributes:\n    @property\n    def VALUE(self):\n        def OrdinaryBadName():\n            return None\n        return OrdinaryBadName()\n",
                4,
            ),
            (
                "comment.py",
                "# @property\ndef OrdinaryBadName():\n    return None\n",
                2,
            ),
            (
                "string.py",
                "\"\"\"\n@property\n\"\"\"\ndef OrdinaryBadName():\n    return None\n",
                4,
            ),
            (
                "wrapped.py",
                "@instrument(property)\ndef OrdinaryBadName():\n    return None\n",
                2,
            ),
        ];
        for (path, source, line) in cases {
            let sources = BTreeMap::from([(path.to_owned(), source.to_owned())]);
            let context = SourceAnalysisContext::unchanged(&sources);
            let selected = analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "py-function-naming")
                .map(|finding| (finding.path, finding.line, finding.confidence))
                .collect::<Vec<_>>();

            assert_eq!(
                selected,
                [(path.to_owned(), line, "medium".to_owned())],
                "{path}"
            );
        }
    }

    #[test]
    fn honors_inline_and_legacy_broad_exception_suppressions() {
        let inline_sources = BTreeMap::from([
            (
                "inline.py".to_owned(),
                "try:\n    run()\nexcept Exception:  # noqa: BLE001\n    recover()\n"
                    .to_owned(),
            ),
            (
                "pylint_inline.py".to_owned(),
                "try:\n    run()\nexcept Exception:  # pylint: disable=broad-except\n    recover()\n"
                    .to_owned(),
            ),
        ]);
        let inline_context = SourceAnalysisContext::unchanged(&inline_sources);
        assert!(
            analyze(&inline_context)
                .iter()
                .all(|finding| finding.code != "py-broad-except")
        );

        let policy_sources = BTreeMap::from([(
            "policy.py".to_owned(),
            "try:\n    run()\nexcept Exception:\n    recover()\n".to_owned(),
        )]);
        let auxiliary = BTreeMap::from([(
            "pyproject.toml".to_owned(),
            "[tool.pylint.\"MESSAGES CONTROL\"]\ndisable = [\"broad-except\"]\n".to_owned(),
        )]);
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let policy_context = SourceAnalysisContext::with_auxiliary(
            &policy_sources,
            &base,
            &changed,
            false,
            &auxiliary,
        );
        assert!(
            analyze(&policy_context)
                .iter()
                .all(|finding| finding.code != "py-broad-except")
        );
    }

    #[test]
    fn groups_broad_exception_evidence_per_file() {
        let sources = BTreeMap::from([(
            "worker.py".to_owned(),
            "try:\n    first()\nexcept Exception:\n    recover_first()\n\
             try:\n    second()\nexcept BaseException:\n    recover_second()\n"
                .to_owned(),
        )]);

        let findings = analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "py-broad-except")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn accepts_broad_exception_observation_before_unconditional_rethrow() {
        let sources = BTreeMap::from([(
            "telemetry.py".to_owned(),
            "try:\n    run()\nexcept Exception as error:\n    record(error)\n    mark_failed()\n    raise\n\
try:\n    run()\nexcept:  # noqa: E722\n    clean_up()\n    raise\n"
                .to_owned(),
        )]);

        assert!(
            analyze(&SourceAnalysisContext::unchanged(&sources))
                .iter()
                .all(|finding| !matches!(
                    finding.code.as_str(),
                    "py-bare-except" | "py-broad-except"
                ))
        );
    }
    #[test]
    fn accepts_reviewed_security_and_exception_boundaries() {
        let sources = BTreeMap::from([(
            "boundaries.py".to_owned(),
            r#"try:
    parse(value)
except Exception as error:
    raise DomainError("invalid value") from error

ConsoleMessage(
    "details",
    debug=True,
)
query = text(
    f"SELECT * FROM {table}"  # noqa: S608
    f" WHERE id = {column}"
)

try:
    parse(other)
except Exception:
    recover()

raise ValueError(f"Task {task} is unsupported. Select task from {available_tasks}.")
prompt = f"Select from your existing {kind} credential blocks"

debug = True
unsafe_query = f"SELECT * FROM users WHERE id = {user_id}"
secure_column = "is_secure" if "is_secure" in columns else "secure"
cursor.execute(f"SELECT {secure_column} FROM cookies")
app.run(debug=True)
"#
            .to_owned(),
        )]);

        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "py-broad-except")
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "py-debug-enabled")
                .count(),
            2
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "py-sql-string-build")
                .count(),
            1
        );
    }

    #[test]
    fn accepts_python_protocols_and_multiline_headers() {
        let sources = BTreeMap::from([(
            "protocols.py".to_owned(),
            r#"from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from package import Model
from runtime import value

class Handler:
    @override
    def shouldRollover(self, record):
        return False

    def visit_FunctionDef(self, node):
        return node

    def open(self):
        return None

if (loaded := load(
    value
)):
    consume(loaded)
items = [item for item in values if (selected := choose(item))]
handle = open("data.txt")
if ready: run()
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "py-import-not-top"
                        | "py-function-naming"
                        | "py-open-no-encoding"
                        | "py-compound-statement"
                )
            })
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                "py-open-no-encoding".to_owned(),
                "py-compound-statement".to_owned()
            ]
        );
    }

    #[test]
    fn reports_only_literal_secret_assignments_and_map_entries() {
        let sources = BTreeMap::from([(
            "secrets.py".to_owned(),
            r#"API_KEY = "actual-static-api-key"
client = Client(api_key="responseFieldName")
other_client = Client(
    api_key="anotherResponseField",
)
token = f"{secrets.token_urlsafe(16)}.{extension}"
password = "*"
labels = {"password": "[%key:common::password%]"}
credentials = {"token": "actual-static-token"}
connection_form = {
    "relabeling": {"password": "Client Secret"},
    "placeholders": {
        "password": "secret",
    },
}
metadata = {"secret": "secrets backend"}
examples = {"example": '{"password": "password_for_server"}'}
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "py-hardcoded-secret")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1, 9]
        );
    }
    #[test]
    fn reports_python_loop_performance_patterns() {
        let sources = BTreeMap::from([(
            "performance.py".to_owned(),
            "def scan(blocked: list[str], values: list[str]):\n\
+    output: str = \"\"\n\
+    for value in values:\n\
+        matcher = re.compile(r\"^[a-z]+$\")\n\
+        if value in blocked:\n\
+            output += value\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code.starts_with("py-") && finding.code.contains("loop"))
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("py-regex-compile-in-loop".to_owned(), 4),
                ("py-linear-membership-in-loop".to_owned(), 5),
                ("py-string-concat-in-loop".to_owned(), 6),
            ]
        );
    }

    #[test]
    fn membership_advice_requires_a_list_reused_by_the_repeating_loop() {
        let source = r#"def scan(items, blocked: list[str]):
    for item in items:
        labels = [entry.name for entry in item.labels]
        if "hold" in labels:
            continue
        for candidate in item.candidates:
            if candidate in labels:
                consume(candidate)
        if item.name in blocked:
            consume(item)
    # if "hold" in labels:
    example = 'if "hold" in labels:'
"#;
        let sources = BTreeMap::from([("membership.py".to_owned(), source.to_owned())]);
        let selected = analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "py-linear-membership-in-loop")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![
                ("membership.py".to_owned(), 7),
                ("membership.py".to_owned(), 9),
            ],
        );
    }

    #[test]
    fn reports_front_removal_only_for_proven_lists_inside_loops() {
        let sources = BTreeMap::from([(
            "queue.py".to_owned(),
            "def drain(queue: list[str], custom):\n\
+    while queue:\n\
+        consume(queue.pop(0))\n\
+        custom.pop(0)\n\
+    queue.pop(0)\n\
+    # queue.pop(0)\n\
+    example = 'queue.pop(0)'\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "py-list-front-removal-in-loop")
                .map(|finding| (finding.path, finding.line))
                .collect::<Vec<_>>(),
            vec![("queue.py".to_owned(), 3)]
        );
    }

    #[test]
    fn accepts_python_loop_performance_safe_variants() {
        let sources = BTreeMap::from([(
            "safe_performance.py".to_owned(),
            "def scan(pattern: str, allowed: set[str], values: list[str]):\n\
+    matcher = re.compile(r\"^[a-z]+$\")\n\
+    output = []\n\
+    for value in values:\n\
+        dynamic = re.compile(pattern)\n\
+        message: str = \"\"\n\
+        message += value\n\
+        if value in allowed:\n\
+            output.append(value)\n\
+        copied = [item for item in values]\n\
+        def deferred():\n\
+            return re.compile(r\"deferred\")\n\
+    return \"\".join(output)\n\
+\n\
+def first_match(values: list[str]):\n\
+    message: str = \"\"\n\
+    for value in values:\n\
+        message += value\n\
+        break\n\
+    return message\n\
+# re.compile(\"commented\")\n\
+example = 're.compile(\"literal\")'\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "py-regex-compile-in-loop"
                        | "py-linear-membership-in-loop"
                        | "py-string-concat-in-loop"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn reports_conservative_python_efficiency_patterns() {
        let sources = BTreeMap::from([(
            "efficiency.py".to_owned(),
            r#"import numpy as np
import logging
def inefficient(values: list[int], groups, batches):
    result = []
    payload: bytes = b""
    coordinates: tuple[int, ...] = ()
    array = np.array([])
    if any(
        [
            validate(value)
            for value in values
        ]
    ):
        consume()
    flattened = sum(
        groups,
        [],
    )
    logging.debug(f"flattened={len(flattened)}")
    logging.info("count={}".format(len(flattened)))
    logging.debug("count=" + str(len(flattened)))
    for value in values:
        duplicates = values.count(value)
        position = values.index(value)
        result = result + [value]
        payload += bytes(value)
        coordinates += (value,)
        array = np.concatenate(
            (array, batches[value]),
        )
    return result, payload, coordinates, array
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "py-eager-any-all-comprehension"
                        | "py-list-search-in-loop"
                        | "py-sequence-rebuild-in-loop"
                        | "py-quadratic-list-flattening"
                        | "py-numpy-grow-in-loop"
                        | "py-logging-eager-format"
                )
            })
            .map(|finding| (finding.code, finding.path, finding.line, finding.confidence))
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![
                (
                    "py-eager-any-all-comprehension".to_owned(),
                    "efficiency.py".to_owned(),
                    8,
                    "medium".to_owned(),
                ),
                (
                    "py-quadratic-list-flattening".to_owned(),
                    "efficiency.py".to_owned(),
                    15,
                    "medium".to_owned(),
                ),
                (
                    "py-logging-eager-format".to_owned(),
                    "efficiency.py".to_owned(),
                    19,
                    "medium".to_owned(),
                ),
                (
                    "py-list-search-in-loop".to_owned(),
                    "efficiency.py".to_owned(),
                    23,
                    "medium".to_owned(),
                ),
                (
                    "py-list-search-in-loop".to_owned(),
                    "efficiency.py".to_owned(),
                    24,
                    "medium".to_owned(),
                ),
                (
                    "py-sequence-rebuild-in-loop".to_owned(),
                    "efficiency.py".to_owned(),
                    25,
                    "medium".to_owned(),
                ),
                (
                    "py-sequence-rebuild-in-loop".to_owned(),
                    "efficiency.py".to_owned(),
                    26,
                    "medium".to_owned(),
                ),
                (
                    "py-sequence-rebuild-in-loop".to_owned(),
                    "efficiency.py".to_owned(),
                    27,
                    "medium".to_owned(),
                ),
                (
                    "py-numpy-grow-in-loop".to_owned(),
                    "efficiency.py".to_owned(),
                    28,
                    "medium".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn accepts_python_efficiency_safe_variants() {
        let sources = BTreeMap::from([(
            "efficient.py".to_owned(),
            r#"import numpy as np
from itertools import chain

def efficient(values: list[int], groups, batches, custom):
    ready = any(validate(value) for value in values)
    flags = all([True, False])
    nested = any([validate(value) for value in group] for group in groups)
    numpy_all = np.all([validate(value) for value in values])
    flattened = list(chain.from_iterable(groups))
    total = sum(values, 0)
    logger.debug("values=%s", values)
    logger.warning(f"values={values}")
    metrics.debug(f"values={values}")
    result = []
    array = np.array([])
    for value in values:
        result += [value]
        custom.count(value)
        chunk = np.concatenate((array, batches[value]))
        refreshed = batches[value].copy()
        refreshed = np.concatenate((refreshed, batches[value]))
        local = []
        local = local + [value]
    payload: bytes = b""
    payload += b"suffix"
    return ready, flags, nested, numpy_all, flattened, total, result, chunk, payload

def concatenate_fresh_batches(batches):
    for batch in batches:
        array = batch.copy()
        array = np.concatenate((array, batch))
    return array

def first_match(values: list[int]):
    for value in values:
        position = values.index(value)
        break
    return position

async def await_everything(coros):
    return any([await coro for coro in coros])

def validate_everything(forms):
    # List comprehension ensures validate() is called for all forms.
    return all([form.validate() for form in forms])

# any([check(value) for value in values])
example = 'sum(groups, [])'
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "py-eager-any-all-comprehension"
                        | "py-list-search-in-loop"
                        | "py-sequence-rebuild-in-loop"
                        | "py-quadratic-list-flattening"
                        | "py-numpy-grow-in-loop"
                        | "py-logging-eager-format"
                )
            })
            .collect::<Vec<_>>();

        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn reports_dangling_tasks_and_discarded_unchecked_subprocesses() {
        let sources = BTreeMap::from([(
            "async_work.py".to_owned(),
            r#"async def run():
    asyncio.create_task(save())
    asyncio.ensure_future(cleanup())
    retained = asyncio.create_task(index())
    await asyncio.create_task(refresh())
    subprocess.run(["formatter"])
    subprocess.run(["checked"], check=True)
    result = subprocess.run(["inspected"])
    return subprocess.run(["returned"])
    asyncio.create_task(documented())  # noqa: RUF006
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "py-asyncio-dangling-task" | "py-subprocess-run-unchecked"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("py-asyncio-dangling-task".to_owned(), 2),
                ("py-asyncio-dangling-task".to_owned(), 3),
                ("py-subprocess-run-unchecked".to_owned(), 6),
            ]
        );
    }

    #[test]
    fn accepts_tasks_retained_by_multiline_expressions_and_nested_sync_work() {
        let sources = BTreeMap::from([(
            "retained.py".to_owned(),
            r#"async def run(values):
    def blocking_request():
        return requests.get(url)
    tasks = []
    tasks.append(
        asyncio.create_task(save())
    )
    pending = [
        asyncio.create_task(process(value))
        for value in values
    ]
    asyncio.create_task(discarded())
"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "py-asyncio-dangling-task" | "py-async-blocking-call"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![("py-asyncio-dangling-task".to_owned(), 12)]);
    }

    #[test]
    fn reports_structured_python_correctness_and_reliability_rules() {
        let sources = BTreeMap::from([(
            "structured.py".to_owned(),
            r#"async def save():
    return 1

async def run():
    save()
    await save()
    return save()

def leak():
    handle = open("data.txt", encoding="utf-8")
    consume(handle)

def swallowed():
    try:
        perform()
    except Exception:
        pass

def cleanup():
    try:
        return work()
    finally:
        return fallback()

def retry():
    while True:
        try:
            connect()
            break
        except OSError:
            record_failure()
            continue

def rereraise():
    try:
        parse()
    except ValueError as error:
        raise error
"#
            .to_owned(),
        )]);

        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert!(
            findings
                .iter()
                .filter(|finding| is_added_python_rule(&finding.code))
                .all(|finding| {
                    finding.path == "structured.py"
                        && finding.end_line == finding.line
                        && finding.confidence == "medium"
                })
        );
        let mut selected = findings
            .into_iter()
            .filter(|finding| is_added_python_rule(&finding.code))
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        selected.sort();

        assert_eq!(
            selected,
            vec![
                ("py-coroutine-not-awaited".to_owned(), 5),
                ("py-exception-swallowed".to_owned(), 16),
                ("py-finally-control-flow".to_owned(), 23),
                ("py-raise-destroys-traceback".to_owned(), 38),
                ("py-resource-not-closed".to_owned(), 10),
                ("py-unbounded-retry-loop".to_owned(), 26),
            ]
        );
    }

    #[test]
    fn distinguishes_interactive_validation_from_autonomous_retry() {
        let sources = BTreeMap::from(
            [
                (
                    "interactive.py",
                    r#"def choose():
    while True:
        if interactive:
            value = input()
            try:
                selected = parse_selector(value) if value else None
            except SyntaxError:
                continue
        break

def choose_number():
    while True:
        value = input("Number: ")
        try:
            selected = int(
                value,
            )
        except ValueError:
            continue
        return selected
"#,
                ),
                (
                    "network.py",
                    r#"def connect_forever():
    while True:
        value = input()
        try:
            return connect(value)
        except ValueError:
            continue
"#,
                ),
                (
                    "mixed.py",
                    r#"def choose_and_send():
    while True:
        value = input()
        try:
            selected = parse_selector(value)
            send_request(selected)
        except SyntaxError:
            continue
"#,
                ),
                (
                    "future.py",
                    r#"def wait(future):
    while True:
        try:
            return future.result(0.1)
        except TimeoutError:
            continue
"#,
                ),
                (
                    "success.py",
                    r#"def retry():
    while True:
        try:
            return connect()
        except OSError:
            continue
"#,
                ),
                (
                    "other_handler.py",
                    r#"def choose():
    while True:
        value = input()
        try:
            selected = parse_selector(value)
        except SyntaxError:
            continue
        except Exception:
            continue
        return selected
"#,
                ),
                (
                    "unrelated.py",
                    r#"def run():
    while True:
        value = input()
        try:
            selected = parse_selector(cached)
        except SyntaxError:
            continue
"#,
                ),
            ]
            .map(|(path, source)| (path.to_owned(), source.to_owned())),
        );
        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "py-unbounded-retry-loop")
                .map(|finding| finding.path.as_str())
                .collect::<Vec<_>>(),
            [
                "future.py",
                "mixed.py",
                "network.py",
                "other_handler.py",
                "success.py",
                "unrelated.py",
            ]
        );
    }

    #[test]
    fn reports_python_security_database_and_subprocess_rules_without_duplicates() {
        let sources = BTreeMap::from([(
            "boundaries.py".to_owned(),
            r#"import random
import subprocess
import tarfile
import zipfile

def unpack_tar(path, destination):
    archive = tarfile.open(path)
    archive.extractall(destination)  # filter="data"

def unpack_zip(path, destination):
    with zipfile.ZipFile(path) as archive:
        archive.extract(destination)

reset_token = random.choice(characters)
logger.info("issued token %s", reset_token)
audit_logger.warning(f"credential={access_token}")

async def load(items):
    for item in items:
        result = await session.execute(item)
    checked = subprocess.run(
        ["worker"],
        check=True,
    )
    subprocess.run(["formatter"])
    commented = subprocess.run(["worker"], check=True)  # timeout=10
    unbounded = subprocess.run(["worker"], check=True, timeout=None)
"#
            .to_owned(),
        )]);

        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert!(
            findings
                .iter()
                .filter(|finding| {
                    is_added_python_rule(&finding.code)
                        || finding.code == "py-subprocess-run-unchecked"
                })
                .all(|finding| {
                    finding.path == "boundaries.py"
                        && finding.end_line == finding.line
                        && finding.confidence == "medium"
                })
        );
        let mut selected = findings
            .into_iter()
            .filter(|finding| {
                is_added_python_rule(&finding.code) || finding.code == "py-subprocess-run-unchecked"
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        selected.sort();

        assert_eq!(
            selected,
            vec![
                ("py-insecure-random-token".to_owned(), 14),
                ("py-query-in-loop".to_owned(), 20),
                ("py-sensitive-data-logging".to_owned(), 15),
                ("py-sensitive-data-logging".to_owned(), 16),
                ("py-subprocess-no-timeout".to_owned(), 21),
                ("py-subprocess-run-unchecked".to_owned(), 25),
                ("py-unsafe-archive-extract".to_owned(), 8),
                ("py-unsafe-archive-extract".to_owned(), 12),
            ]
        );
    }

    #[test]
    fn distinguishes_mapping_lookups_from_database_work_in_loops() {
        let sources = BTreeMap::from([(
            "lookups.py".to_owned(),
            r#"def scan(connections, session, cursor, store):
    for connection in connections:
        href = connection.get('href')
        kind = connection.get('kind', 'video')
        cached = store.get('key')
        model = session.get(User, key)
        result = cursor.execute(query)
        # session.get(User, key)
        example = "cursor.execute(query)"
        model = session.get(
            models.User,
            key,
        )
        cached = session.get(
            'setting',
            fallback,
        )
    return session.get(User, key)
"#
            .to_owned(),
        )]);
        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "py-query-in-loop")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [6, 7, 10]
        );
    }

    #[test]
    fn requires_standard_logging_provenance_for_deferred_formatting_advice() {
        let sources = BTreeMap::from([
            (
                "bound.py".to_owned(),
                "import logging as log\nlogger = log.getLogger(__name__)\nlogger.debug(f'value={value}')\n"
                    .to_owned(),
            ),
            (
                "module.py".to_owned(),
                "import logging\nlogging.info(\n    f'value={value}',\n)\n".to_owned(),
            ),
            (
                "custom.py".to_owned(),
                "logger = CustomLogger()\nlogger.debug(f'value={value}')\nself.logger.info(f'value={value}')\n"
                    .to_owned(),
            ),
            (
                "shadow.py".to_owned(),
                "import logging\nlogging = CustomLogger()\nlogging.info(f'value={value}')\n"
                    .to_owned(),
            ),
            (
                "parameter.py".to_owned(),
                "import logging\ndef run(logging):\n    logging.debug(f'value={value}')\n"
                    .to_owned(),
            ),
            (
                "safe.py".to_owned(),
                "import logging\nlogging.debug('value=%s', value)\n# logging.info(f'value={value}')\nexample = \"logging.info(f'value={value}')\"\n"
                    .to_owned(),
            ),
        ]);
        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "py-logging-eager-format")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            [("bound.py", 3), ("module.py", 2)]
        );
    }

    #[test]
    fn accepts_safe_variants_of_added_python_rules() {
        let sources = BTreeMap::from([(
            "safe.py".to_owned(),
            r#"from device_api import Session

async def save():
    return 1

async def run():
    await save()
    returned = save()
    task = asyncio.create_task(save())
    return returned, task

async def collision():
    return 1

def collision():
    return 2

def call_sync_collision():
    collision()

def close_resource():
    handle = open("data.txt", encoding="utf-8")
    with handle:
        consume(handle)

def transfer_resource(self):
    client = httpx.Client()
    self.client = client
    return client

def cleanup():
    try:
        run_work()
    finally:
        def deferred():
            return "nested control flow"
        for item in pending:
            break
        finish_cleanup()

def bounded_retry():
    while True:
        try:
            connect()
        except OSError:
            record_failure()
            break

def limited_retry():
    attempts = 0
    while True:
        attempts += 1
        if attempts >= MAX_ATTEMPTS:
            raise TimeoutError
        try:
            connect()
        except OSError:
            continue

def stoppable_retry():
    while True:
        if self._shutdown:
            return
        try:
            connect()
        except OSError:
            continue

def event_loop():
    while True:
        try:
            receive_event()
        except OSError:
            pass

def terminating_retry():
    while True:
        try:
            connect()
        except ConnectionError:
            return unavailable()

def rereraise():
    try:
        parse()
    except ValueError:
        raise

def translate():
    try:
        parse()
    except TypeError as error:
        raise DomainError() from error

with tarfile.open(path) as archive:
    archive.extractall(destination, filter="data")
    archive.extract(member, filter="data")

token = secrets.choice(characters)
sample = random.choice(characters)
logger.info("request headers: %s", request.headers)
logger.info("processed item %s", item)
logger.info("created session %s", session_id)
session.execute(statement)
for label in labels:
    labels_by_name.get(label)
completed = subprocess.run(["worker"], check=True, timeout = 10)
returned = subprocess.run(["worker"], timeout=10)

def use_domain_session():
    session = Session()
    session.refresh()

def chained_session():
    response = requests.Session().send(request)
    return response

example = "subprocess.run(command); logger.info(token); archive.extractall(path)"
# token = random.choice(characters)
# while True: subprocess.run(command)
"#
            .to_owned(),
        )]);

        let selected = analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| is_added_python_rule(&finding.code))
            .collect::<Vec<_>>();

        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn accepts_consumed_multiline_coroutines_and_specific_exception_sentinels() {
        let sources = BTreeMap::from([(
            "safe_boundaries.py".to_owned(),
            r#"async def save():
    return 1

async def run():
    await asyncio.gather(
        save()
    )

def optional_attribute(value):
    try:
        return value.name
    except AttributeError:
        pass
    return None
"#
            .to_owned(),
        )]);

        let selected = analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "py-coroutine-not-awaited" | "py-exception-swallowed"
                )
            })
            .collect::<Vec<_>>();

        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn accepts_python_3_14_tar_data_filter_default() {
        let sources = BTreeMap::from([(
            "archive.py".to_owned(),
            r#"def unpack(path, destination):
    archive = tarfile.open(path)
    archive.extractall(destination)
"#
            .to_owned(),
        )]);
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let python_314 = BTreeMap::from([(
            "pyproject.toml".to_owned(),
            "[project]\nrequires-python = \">=3.14\"\n".to_owned(),
        )]);
        let python_313 = BTreeMap::from([(
            "pyproject.toml".to_owned(),
            "[project]\nrequires-python = \">=3.13\"\n".to_owned(),
        )]);

        let supported =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &python_314);
        assert!(
            analyze(&supported)
                .iter()
                .all(|finding| finding.code != "py-unsafe-archive-extract")
        );

        let legacy =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &python_313);
        assert_eq!(
            analyze(&legacy)
                .iter()
                .filter(|finding| finding.code == "py-unsafe-archive-extract")
                .count(),
            1
        );
    }

    #[test]
    fn reports_mock_targets_patched_at_the_provider() {
        let sources = BTreeMap::from([
            (
                "src/app/service.py".to_owned(),
                "from deps.client import fetch\n\ndef handle():\n    return fetch()\n".to_owned(),
            ),
            (
                "src/app/unused.py".to_owned(),
                "from deps.client import remove\n\ndef handle():\n    return 1\n".to_owned(),
            ),
            (
                "tests/test_unused.py".to_owned(),
                r#"from app.unused import handle
from unittest.mock import patch

def test_unused_dependency():
    with patch("deps.client.remove"):
        handle()
"#
                .to_owned(),
            ),
            (
                "tests/test_service.py".to_owned(),
                r#"from app.service import handle
from unittest.mock import patch

def test_wrong_target():
    with patch("deps.client.fetch"):
        handle()

def test_consumer_target():
    with patch("app.service.fetch"):
        handle()

EXAMPLE = """with patch("deps.client.fetch"):
    handle()
"""
# with patch("deps.client.fetch"): handle()
"#
                .to_owned(),
            ),
        ]);

        assert_eq!(
            analyze(&SourceAnalysisContext::unchanged(&sources))
                .into_iter()
                .filter(|finding| finding.code == "py-test-mocked-target-wrong")
                .map(|finding| {
                    (
                        finding.path,
                        finding.line,
                        finding.end_line,
                        finding.confidence,
                    )
                })
                .collect::<Vec<_>>(),
            vec![(
                "tests/test_service.py".to_owned(),
                5,
                5,
                "medium".to_owned()
            )]
        );
    }

    fn is_added_python_rule(code: &str) -> bool {
        matches!(
            code,
            "py-coroutine-not-awaited"
                | "py-exception-swallowed"
                | "py-resource-not-closed"
                | "py-finally-control-flow"
                | "py-unsafe-archive-extract"
                | "py-insecure-random-token"
                | "py-query-in-loop"
                | "py-subprocess-no-timeout"
                | "py-unbounded-retry-loop"
                | "py-raise-destroys-traceback"
                | "py-sensitive-data-logging"
                | "py-test-mocked-target-wrong"
        )
    }

    #[test]
    fn scans_unicode_before_python_string_literals() {
        assert_eq!(
            code_outside_triple_quoted_strings("label = \"Øresund\"", None),
            ("label = \"Øresund\"".to_owned(), None)
        );
    }
}
