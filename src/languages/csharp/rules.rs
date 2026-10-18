use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    let prefers_file_scoped_namespaces = fs::read_to_string(config.root.join(".editorconfig"))
        .ok()
        .is_some_and(|source| FILE_SCOPED_PREFERENCE.is_match(&source));
    let mut findings = Vec::new();
    for (path, source) in sources.iter().filter(|(path, _)| path.ends_with(".cs")) {
        findings.extend(analyze_source(path, source, prefers_file_scoped_namespaces));
    }
    findings
}

struct State<'a> {
    path: &'a str,
    lines: Vec<&'a str>,
    comment_free: Vec<String>,
    structural: Vec<String>,
    findings: Vec<Finding>,
    readonly_http_client_fields: BTreeSet<String>,
    archive_path_variables: BTreeSet<String>,
    validated_archive_path_variables: BTreeSet<String>,
    archive_extraction_wrappers: BTreeSet<String>,
    reported_once: BTreeSet<String>,
    namespace_depth: i32,
    loop_starts: Vec<usize>,
    prefers_file_scoped_namespaces: bool,
}

fn analyze_source(path: &str, source: &str, prefers_file_scoped_namespaces: bool) -> Vec<Finding> {
    let lines = source.split('\n').collect::<Vec<_>>();
    let comment_free_source = without_comments(source);
    let comment_free = comment_free_source
        .split('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let structural = comment_free
        .iter()
        .map(|line| strip_strings(line))
        .collect::<Vec<_>>();
    let archive_extraction_wrappers = find_archive_extraction_wrappers(&lines);
    let mut state = State {
        path,
        lines,
        comment_free,
        structural,
        findings: Vec::new(),
        readonly_http_client_fields: BTreeSet::new(),
        archive_path_variables: BTreeSet::new(),
        validated_archive_path_variables: BTreeSet::new(),
        archive_extraction_wrappers,
        reported_once: BTreeSet::new(),
        namespace_depth: 0,
        loop_starts: Vec::new(),
        prefers_file_scoped_namespaces,
    };
    for index in 0..state.lines.len() {
        let line = state.line(index);
        let legacy_line = state.legacy_line(index);
        analyze_structure(&mut state, index, &line, &legacy_line);
        analyze_runtime(&mut state, index, &line, &legacy_line);
        analyze_legacy_apis(&mut state, index, &line, &legacy_line);
        track_archive_paths(&mut state, index, &legacy_line);
        analyze_security(&mut state, index, &line);
    }
    state.findings
}

impl State<'_> {
    fn raw(&self, index: usize) -> &str {
        self.lines[index]
    }

    fn line(&self, index: usize) -> String {
        strip_strings(self.raw(index)).trim().to_owned()
    }

    fn legacy_line(&self, index: usize) -> String {
        self.structural[index].trim().to_owned()
    }

    fn add(&mut self, code: &str, index: usize, message: &str, once_per_file: bool) {
        if once_per_file && !self.reported_once.insert(code.to_owned()) {
            return;
        }
        let metadata = rule_catalog::metadata(code).expect("C# rule metadata must exist");
        self.findings.push(Finding {
            code: code.to_owned(),
            severity: Severity::parse(metadata.default_severity)
                .expect("catalog severity must be valid"),
            path: self.path.to_owned(),
            line: index + 1,
            end_line: index + 1,
            message: message.to_owned(),
            confidence: "medium".to_owned(),
            why: metadata.why.to_owned(),
            suggestion: metadata.suggestion.to_owned(),
            related_files: Vec::new(),
            snippet: String::new(),
            code_flow: Vec::new(),
        });
    }
}

// code-buster-ignore complex-function: a single line scan deliberately dispatches independent structure rules.
fn analyze_structure(state: &mut State<'_>, index: usize, line: &str, legacy_line: &str) {
    if line.starts_with("namespace ") && !line.ends_with(';') {
        state.namespace_depth = 1;
        if state.prefers_file_scoped_namespaces {
            state.add(
                "cs-file-scoped-namespace",
                index,
                "block-scoped namespace used in C# file",
                false,
            );
        }
    } else if state.namespace_depth > 0 {
        state.namespace_depth += state.raw(index).matches('{').count() as i32
            - state.raw(index).matches('}').count() as i32;
        if state.namespace_depth > 0 && is_using_directive(line) {
            state.add(
                "cs-using-inside-namespace",
                index,
                "using directive appears inside a namespace",
                false,
            );
        }
    }
    if line.starts_with("catch (Exception") || line.starts_with("catch (System.Exception") {
        state.add(
            "cs-catch-system-exception",
            index,
            "catch block catches System.Exception",
            false,
        );
    }
    if RUNTIME_TYPE.is_match(legacy_line) {
        state.add(
            "cs-runtime-type-alias",
            index,
            "runtime type name used instead of C# keyword",
            false,
        );
    }
    if uses_non_short_circuit_boolean(line) {
        state.add(
            "cs-non-short-circuit-bool",
            index,
            "boolean condition uses non-short-circuit operator",
            false,
        );
    }
    if line.starts_with("catch") && empty_block(&state.lines, index) {
        state.add("cs-empty-catch", index, "catch block is empty", false);
    }
    if weak_lock_target(state, index, &state.comment_free[index]) {
        state.add(
            "cs-lock-weak-identity",
            index,
            "lock target has weak identity and can be shared outside this synchronization boundary",
            false,
        );
    }
    analyze_loop(state, index, line);
}

fn weak_lock_target(state: &State<'_>, index: usize, source: &str) -> bool {
    if WEAK_LOCK_LITERAL_OR_TYPE.is_match(source) {
        return true;
    }
    WEAK_LOCK_VARIABLE
        .captures(source)
        .and_then(|capture| csharp_variable_declaration_before(state, index, &capture[1]))
        .is_some_and(|(_, variable_type)| {
            matches!(
                variable_type.trim().trim_end_matches('?'),
                "string" | "String" | "System.String"
            )
        })
}

fn is_using_directive(line: &str) -> bool {
    if !line.starts_with("using ") || !line.ends_with(';') || line.starts_with("using (") {
        return false;
    }
    let Some(equals) = line.find('=') else {
        return true;
    };
    IDENTIFIER.is_match(line["using ".len()..equals].trim())
}

fn analyze_loop(state: &mut State<'_>, index: usize, line: &str) {
    let starts_loop = LOOP_START.is_match(line);
    if starts_loop {
        state.loop_starts.push(index);
    }
    if concatenates_in_loop(state, index, line) {
        state.add(
            "cs-string-concat-loop",
            index,
            "possible string concatenation inside loop",
            false,
        );
    }
    if !state.loop_starts.is_empty()
        && !starts_loop
        && CSHARP_CONSTANT_REGEX.is_match(&state.comment_free[index])
    {
        state.add(
            "cs-regex-created-in-loop",
            index,
            "constant regular expression is compiled inside a loop",
            false,
        );
    }
    if !state.loop_starts.is_empty()
        && CSHARP_LINEAR_MEMBERSHIP
            .captures_iter(line)
            .any(|capture| csharp_linear_collection_in_scope(state, index, &capture[1]))
    {
        state.add(
            "cs-linear-membership-in-loop",
            index,
            "linear list membership is checked inside a loop",
            false,
        );
    }
    if !state.loop_starts.is_empty() && line == "}" {
        state.loop_starts.pop();
    }
}

fn concatenates_in_loop(state: &State<'_>, index: usize, line: &str) -> bool {
    if state.loop_starts.is_empty() || (!line.contains(" + ") && !line.contains(" += ")) {
        return false;
    }
    let target = if let Some(plus_equals) = line.find(" += ") {
        let candidate = line[..plus_equals].trim();
        IDENTIFIER.is_match(candidate).then_some(candidate)
    } else {
        SELF_CONCAT.captures(line).and_then(|capture| {
            let left = capture.get(1)?;
            let right = capture.get(2)?;
            (left.as_str() == right.as_str()).then_some(left.as_str())
        })
    };
    let Some(target) = target else {
        return false;
    };
    let Some(loop_start) = state.loop_starts.last() else {
        return false;
    };
    csharp_variable_declaration_before(state, index, target).is_some_and(
        |(declaration, variable_type)| {
            declaration < *loop_start
                && matches!(variable_type, "string" | "String" | "System.String")
        },
    )
}

fn csharp_linear_collection_in_scope(state: &State<'_>, index: usize, target: &str) -> bool {
    let Some(loop_start) = state.loop_starts.last() else {
        return false;
    };
    csharp_variable_declaration_before(state, index, target).is_some_and(
        |(declaration, variable_type)| {
            declaration < *loop_start
                && variable_type
                    .split('<')
                    .next()
                    .and_then(|base| base.trim().rsplit('.').next())
                    .is_some_and(|base| {
                        matches!(base, "List" | "IList" | "IReadOnlyList" | "ArrayList")
                    })
        },
    )
}

fn csharp_variable_declaration_before<'state>(
    state: &'state State<'_>,
    index: usize,
    target: &str,
) -> Option<(usize, &'state str)> {
    state.structural[..=index]
        .iter()
        .enumerate()
        .rev()
        .find_map(|(line, source)| {
            CSHARP_VARIABLE_DECLARATION
                .captures_iter(source)
                .find(|capture| &capture[2] == target)
                .and_then(|capture| {
                    capture
                        .get(1)
                        .map(|variable_type| (line, variable_type.as_str().trim()))
                })
        })
}

// code-buster-ignore complex-function: a single line scan deliberately dispatches independent runtime rules.
fn analyze_runtime(state: &mut State<'_>, index: usize, line: &str, legacy_line: &str) {
    if let Some(field) = READONLY_HTTP_CLIENT.captures(legacy_line) {
        state
            .readonly_http_client_fields
            .insert(field[1].to_owned());
    }
    if line.contains(" = new ") && line.contains("delegate") {
        state.add(
            "cs-explicit-delegate-new",
            index,
            "explicit delegate construction can use concise syntax",
            false,
        );
    }
    if legacy_line.contains("async void ")
        && !ASYNC_VOID_HANDLER.is_match(legacy_line)
        && !ASYNC_VOID_OVERRIDE.is_match(legacy_line)
    {
        state.add("cs-async-void", index, "async void method used", false);
    }
    if synchronously_waits(state, index, line) {
        state.add(
            "cs-sync-over-async",
            index,
            "synchronous wait on async work",
            false,
        );
    }
    if line.contains("Thread.Sleep(") {
        state.add("cs-thread-sleep", index, "Thread.Sleep used", false);
    }
    if legacy_line.contains("DateTime.Now") {
        state.add(
            "cs-datetime-now",
            index,
            "local wall-clock time used",
            false,
        );
    }
    if line.contains("new HttpClient(") && !constructs_shared_http_client(state, line) {
        state.add(
            "cs-new-httpclient",
            index,
            "HttpClient constructed directly",
            false,
        );
    }
}

fn synchronously_waits(state: &State<'_>, index: usize, line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    if SYNC_EVENT_WAIT.is_match(code) {
        return false;
    }
    if code.contains(".GetAwaiter().GetResult()") {
        return true;
    }
    if TASK_WAIT_CALL
        .captures_iter(code)
        .any(|capture| csharp_task_variable(state, index, &capture[1]))
    {
        return true;
    }
    TASK_RESULT_MEMBER.captures_iter(code).any(|capture| {
        let matched = capture.get(0).unwrap();
        let suffix = &code[matched.end()..];
        (!suffix.trim_start().starts_with('=') || suffix.trim_start().starts_with("=="))
            && csharp_task_variable(state, index, &capture[1])
            && !guarded_completed_result(state, index, &capture[1])
    })
}

fn csharp_task_variable(state: &State<'_>, index: usize, target: &str) -> bool {
    csharp_variable_declaration_before(state, index, target).is_some_and(
        |(declaration, variable_type)| {
            let base = variable_type
                .split('<')
                .next()
                .and_then(|kind| kind.trim().rsplit('.').next());
            matches!(base, Some("Task" | "ValueTask"))
                || (base == Some("var")
                    && state.structural[declaration].contains("Async(")
                    && !state.structural[declaration].contains("await "))
        },
    )
}

fn guarded_completed_result(state: &State<'_>, index: usize, target: &str) -> bool {
    let guard = format!("{target}.IsCompleted");
    state.structural[index.saturating_sub(4)..=index]
        .iter()
        .any(|line| line.contains(&guard))
}

fn constructs_shared_http_client(state: &State<'_>, line: &str) -> bool {
    if static_http_client_member(line) {
        return true;
    }
    HTTP_CLIENT_ASSIGNMENT
        .captures(line)
        .is_some_and(|capture| state.readonly_http_client_fields.contains(&capture[1]))
}

fn static_http_client_member(line: &str) -> bool {
    let Some(equals) = line.find('=') else {
        return false;
    };
    line[..equals]
        .split_whitespace()
        .any(|word| word == "static")
        && HTTP_CLIENT_MEMBER.is_match(line)
}

// code-buster-ignore complex-function: a single line scan deliberately dispatches independent legacy API rules.
fn analyze_legacy_apis(state: &mut State<'_>, index: usize, line: &str, legacy_line: &str) {
    if legacy_line.contains("BinaryFormatter")
        || legacy_line.contains("System.Runtime.Serialization.Formatters.Binary")
    {
        state.add(
            "cs-binaryformatter",
            index,
            "BinaryFormatter API referenced",
            false,
        );
    }
    if legacy_line.contains("System.Runtime.Remoting")
        || legacy_line.contains("RemotingConfiguration")
        || legacy_line.contains("MarshalByRefObject")
    {
        state.add(
            "cs-remoting-api",
            index,
            ".NET Remoting API referenced",
            false,
        );
    }
    if legacy_line.contains("System.EnterpriseServices")
        || legacy_line.contains("ServicedComponent")
        || legacy_line.contains("[ComImport")
        || legacy_line.contains("CoCreateInstance")
    {
        state.add(
            "cs-dcom-api",
            index,
            "COM/DCOM interop surface referenced",
            true,
        );
    }
    if line.contains("AllowPartiallyTrustedCallers") {
        state.add(
            "cs-aptca-attribute",
            index,
            "AllowPartiallyTrustedCallers attribute used",
            false,
        );
    }
    if !line.starts_with("//") && CAS_API.is_match(line) {
        state.add(
            "cs-cas-api",
            index,
            "Code Access Security API referenced",
            true,
        );
    }
    if public_pinvoke(state, index, line) {
        state.add(
            "cs-public-pinvoke",
            index,
            "public native interop entry point exposed",
            true,
        );
    }
}

fn public_pinvoke(state: &State<'_>, index: usize, line: &str) -> bool {
    (line.contains("[DllImport") || line.contains("[LibraryImport"))
        && next_non_blank(&state.lines, index + 1)
            .trim()
            .starts_with("public")
        && in_externally_visible_type(&state.lines, index)
}

#[derive(Clone, Copy)]
enum TypeVisibility {
    External,
    Restricted,
}

impl TypeVisibility {
    fn is_external(self) -> bool {
        matches!(self, Self::External)
    }
}

struct ContainingType {
    depth: i32,
    visibility: TypeVisibility,
}

#[derive(Default)]
struct ContainingTypeState {
    scopes: Vec<ContainingType>,
    pending_visibility: Option<TypeVisibility>,
    depth: i32,
}

impl ContainingTypeState {
    fn propagate_line(&mut self, code: &str, declared_type: Option<TypeVisibility>) {
        if let Some(visibility) = declared_type {
            self.pending_visibility = Some(visibility);
        }
        let mut has_semicolon = false;
        for character in code.chars() {
            has_semicolon |= character == ';';
            self.propagate_brace(character);
        }
        if has_semicolon {
            self.pending_visibility = None;
        }
    }

    fn propagate_brace(&mut self, character: char) {
        match character {
            '{' => self.enter_scope(),
            '}' => self.leave_scope(),
            _ => {}
        }
    }

    fn enter_scope(&mut self) {
        self.depth += 1;
        if let Some(visibility) = self.pending_visibility.take() {
            self.scopes.push(ContainingType {
                depth: self.depth,
                visibility,
            });
        }
    }

    fn leave_scope(&mut self) {
        if self
            .scopes
            .last()
            .is_some_and(|scope| scope.depth == self.depth)
        {
            self.scopes.pop();
        }
        self.depth -= 1;
    }

    fn is_externally_visible(&self) -> bool {
        !self.scopes.is_empty()
            && self
                .scopes
                .iter()
                .all(|scope| scope.visibility.is_external())
    }
}

fn in_externally_visible_type(lines: &[&str], end: usize) -> bool {
    let mut containing_types = ContainingTypeState::default();
    for line in lines.iter().take(end + 1) {
        let uncommented = line.split("//").next().unwrap_or("");
        let stripped = strip_strings(uncommented);
        let code = stripped.trim();
        let declared_type = discover_type_visibility(code);
        containing_types.propagate_line(code, declared_type);
    }
    containing_types.is_externally_visible()
}

fn discover_type_visibility(code: &str) -> Option<TypeVisibility> {
    let declaration = TYPE_DECLARATION.captures(code)?;
    let modifiers = declaration.get(1).map_or("", |matched| matched.as_str());
    Some(classify_type_modifiers(modifiers))
}

fn classify_type_modifiers(modifiers: &str) -> TypeVisibility {
    let restricted = ["private", "internal", "file"]
        .iter()
        .any(|modifier| contains_identifier(modifiers, modifier));
    let exported = ["public", "protected"]
        .iter()
        .any(|modifier| contains_identifier(modifiers, modifier));
    if exported && !restricted {
        TypeVisibility::External
    } else {
        TypeVisibility::Restricted
    }
}

// code-buster-ignore complex-function: archive taint tracking must retain assignment, guard, and extraction state together.
fn track_archive_paths(state: &mut State<'_>, index: usize, code: &str) {
    if let Some(assignment) = ARCHIVE_ASSIGNMENT.captures(code) {
        let variable = assignment[1].to_owned();
        let expression = &assignment[2];
        if contains_archive_entry_path(expression)
            || state
                .archive_path_variables
                .iter()
                .any(|name| contains_identifier(expression, name))
        {
            state.archive_path_variables.insert(variable);
        }
    }
    for variable in state.archive_path_variables.clone() {
        if !code.contains(&format!("{variable}.StartsWith")) {
            continue;
        }
        let end = state.lines.len().min(index + 5);
        let guard = state.lines[index..end].join("\n");
        if RETURN_OR_THROW.is_match(&guard) {
            state.validated_archive_path_variables.insert(variable);
        }
    }
    let extraction = ARCHIVE_EXTRACTION.captures(code);
    let Some(extraction) = extraction else {
        return;
    };
    let Some(whole) = extraction.get(0) else {
        return;
    };
    let direct = code.contains(".ExtractToFile");
    let wrapper = extraction.get(1).map(|matched| matched.as_str());
    if !direct && wrapper.is_none_or(|wrapper| !state.archive_extraction_wrappers.contains(wrapper))
    {
        return;
    }
    let destination = &code[whole.end()..];
    let direct_entry_path = contains_archive_entry_path(destination);
    let tainted = state
        .archive_path_variables
        .iter()
        .find(|name| contains_identifier(destination, name))
        .cloned();
    if !direct_entry_path && tainted.is_none() {
        return;
    }
    if tainted
        .as_ref()
        .is_some_and(|name| state.validated_archive_path_variables.contains(name))
    {
        return;
    }
    state.add(
        "cs-archive-path-traversal",
        index,
        "archive entry path reaches extraction without a containment check",
        false,
    );
}

fn contains_archive_entry_path(expression: &str) -> bool {
    ARCHIVE_ENTRY_PATH.is_match(expression)
}

fn find_archive_extraction_wrappers(lines: &[&str]) -> BTreeSet<String> {
    let mut wrappers = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(declaration) = ARCHIVE_WRAPPER_DECLARATION.captures(line) else {
            continue;
        };
        if line.trim().ends_with(';') {
            continue;
        }
        if lines[index..lines.len().min(index + 40)]
            .iter()
            .any(|line| line.contains(".ExtractToFile("))
        {
            wrappers.insert(declaration[1].to_owned());
        }
    }
    wrappers
}

// code-buster-ignore complex-function: a single line scan deliberately dispatches independent security rules.
fn analyze_security(state: &mut State<'_>, index: usize, line: &str) {
    if line.contains("Process.Start")
        && (line.contains("Request.")
            || line.contains("Console.ReadLine")
            || line.contains("args["))
    {
        state.add(
            "cs-process-start-input",
            index,
            "external process is started with apparent user-controlled input",
            false,
        );
    }
    if contains_hardcoded_secret(state, index) {
        state.add(
            "cs-hardcoded-secret",
            index,
            "possible hardcoded secret",
            false,
        );
    }
    if uses_weak_crypto(state, index, line) {
        state.add(
            "cs-weak-crypto",
            index,
            "weak cryptography API referenced",
            false,
        );
    }
    if (line.contains("new Random(") || line.contains("Random.Shared"))
        && SECRET_IDENTIFIER.is_match(state.raw(index))
    {
        state.add(
            "cs-random-security",
            index,
            "System.Random appears used for security-sensitive value",
            false,
        );
    }
    if builds_sql_string(state, index) {
        state.add(
            "cs-sql-string-build",
            index,
            "SQL appears to be built with interpolation/concatenation",
            false,
        );
    }
}

// code-buster-ignore complex-function: the explicit guard chain is the auditable secret-classification policy.
fn contains_hardcoded_secret(state: &State<'_>, index: usize) -> bool {
    let Some(assignment) = LITERAL_ASSIGNMENT.captures(state.raw(index)) else {
        return false;
    };
    let identifier = &assignment[1];
    let literal = &assignment[2];
    let normalized_identifier = alphanumeric(identifier).to_ascii_lowercase();
    let normalized_literal = alphanumeric(literal).to_ascii_lowercase();
    !literal.trim().is_empty()
        && (normalized_literal.len() >= 8
            || !normalized_literal.chars().all(|c| c.is_ascii_digit()))
        && SECRET_IDENTIFIER.is_match(identifier)
        && normalized_literal != normalized_identifier
        && !is_placeholder_secret(&normalized_literal)
        && !is_lexical_token_literal(
            identifier,
            literal,
            &normalized_identifier,
            &normalized_literal,
        )
        && !NON_CREDENTIAL_KEY.is_match(identifier)
        && !URI_LITERAL.is_match(literal)
        && !SYMBOLIC_SECRET_LITERAL.is_match(literal)
        && !state
            .raw(index)
            .to_ascii_lowercase()
            .contains("environment.getenvironmentvariable")
        && !state
            .raw(index)
            .to_ascii_lowercase()
            .contains("configuration[")
}

fn alphanumeric(value: &str) -> String {
    value.chars().filter(char::is_ascii_alphanumeric).collect()
}

fn is_placeholder_secret(normalized: &str) -> bool {
    matches!(
        normalized,
        "password"
            | "changeme"
            | "yoursecret"
            | "yourapikey"
            | "placeholder"
            | "example"
            | "test"
            | "asdf"
    ) || PLACEHOLDER_SECRET.is_match(normalized)
}

fn is_lexical_token_literal(
    identifier: &str,
    literal: &str,
    normalized_identifier: &str,
    normalized_literal: &str,
) -> bool {
    if literal.contains('-') && normalized_literal.ends_with(normalized_identifier) {
        return true;
    }
    if !identifier.to_ascii_lowercase().ends_with("token") {
        return false;
    }
    let prefix = &normalized_identifier[..normalized_identifier.len() - "token".len()];
    (!prefix.is_empty() && (prefix == normalized_literal || prefix.ends_with(normalized_literal)))
        || PASCAL_LITERAL.is_match(literal)
        || FORMAT_PLACEHOLDER.is_match(literal)
        || (literal.starts_with('<') && literal.ends_with('>'))
}

fn uses_weak_crypto(state: &State<'_>, index: usize, line: &str) -> bool {
    if OBSOLETE_CIPHER.is_match(line) {
        return true;
    }
    if !LEGACY_DIGEST.is_match(line) {
        return false;
    }
    let mut surrounding = state.raw(index).to_ascii_lowercase();
    for candidate in state.lines[index.saturating_sub(12)..index].iter().rev() {
        if METHOD_SIGNATURE.is_match(candidate) {
            surrounding.push(' ');
            surrounding.push_str(&candidate.to_ascii_lowercase());
            break;
        }
    }
    SECURITY_CONTEXT.is_match(&surrounding)
}

fn builds_sql_string(state: &State<'_>, index: usize) -> bool {
    let raw = state.raw(index);
    if !SQL_ASSIGNMENT.is_match(raw) || is_management_query(state, index) {
        return false;
    }
    if (raw.contains("$\"") || raw.contains("$@\"") || raw.contains("@$\""))
        && !interpolation_expressions(raw).is_empty()
    {
        return !only_safe_numeric_sql_interpolation(state, index, raw);
    }
    if !raw.contains('+') {
        return false;
    }
    let expression = strip_strings(raw)
        .split('=')
        .skip(1)
        .collect::<Vec<_>>()
        .join("=");
    DYNAMIC_CONCAT.is_match(&expression)
}

fn is_management_query(state: &State<'_>, index: usize) -> bool {
    let Some(assignment) = ANY_ASSIGNMENT.captures(state.raw(index)) else {
        return false;
    };
    let variable = &assignment[1];
    let lower = variable.to_ascii_lowercase();
    if lower.contains("wmi") || lower.contains("cim") {
        return true;
    }
    let use_pattern = Regex::new(&format!(
        r"\b(?:ManagementObjectSearcher|QueryInstances)\s*\([^;]*\b{}\b",
        regex::escape(variable)
    ))
    .expect("escaped management query regex must compile");
    state.lines[index + 1..state.lines.len().min(index + 25)]
        .iter()
        .any(|line| use_pattern.is_match(line))
}

fn interpolation_expressions(raw: &str) -> Vec<&str> {
    let bytes = raw.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'{' || (index > 0 && bytes[index - 1] == b'{') {
            index += 1;
            continue;
        }
        let Some(relative_close) = raw[index + 1..].find('}') else {
            break;
        };
        let close = index + 1 + relative_close;
        if close + 1 < bytes.len() && bytes[close + 1] == b'}' {
            index = close + 2;
            continue;
        }
        let expression = &raw[index + 1..close];
        if !expression.contains('{') && !expression.contains('}') {
            result.push(expression);
        }
        index = close + 1;
    }
    result
}

fn only_safe_numeric_sql_interpolation(state: &State<'_>, index: usize, raw: &str) -> bool {
    let expressions = interpolation_expressions(raw);
    !expressions.is_empty()
        && expressions.into_iter().all(|expression| {
            let expression = expression.trim();
            if NUMERIC_CAST.is_match(expression) {
                return true;
            }
            if !IDENTIFIER.is_match(expression) {
                return false;
            }
            for declaration in state.lines[index.saturating_sub(80)..index].iter().rev() {
                if NUMERIC_DECLARATION
                    .captures_iter(declaration)
                    .any(|capture| {
                        capture
                            .get(1)
                            .is_some_and(|name| name.as_str() == expression)
                    })
                {
                    return true;
                }
                if let Some(value) = INFERRED_DECLARATION
                    .captures_iter(declaration)
                    .find(|capture| {
                        capture
                            .get(1)
                            .is_some_and(|name| name.as_str() == expression)
                    })
                    .and_then(|capture| capture.get(2))
                {
                    let value = value.as_str().trim();
                    return NUMERIC_LITERAL.is_match(value) || value.contains(".Ticks");
                }
            }
            false
        })
}

fn uses_non_short_circuit_boolean(line: &str) -> bool {
    if !IF_OR_WHILE.is_match(line) || !has_top_level_non_short_circuit_operator(line) {
        return false;
    }
    !NUMERIC_BITWISE_OPERAND.is_match(line) && !bitwise_result_comparison(line)
}

#[derive(Clone, Copy)]
struct OperatorContext {
    character: char,
    previous: Option<char>,
    depth: i32,
}

struct TopLevelExpressionState {
    depth: i32,
    previous: Option<char>,
}

impl TopLevelExpressionState {
    fn after_opening_parenthesis() -> Self {
        Self {
            depth: 1,
            previous: Some('('),
        }
    }

    fn advance(&mut self, character: char) -> OperatorContext {
        match character {
            '(' => self.depth += 1,
            ')' => self.depth -= 1,
            _ => {}
        }
        let context = OperatorContext {
            character,
            previous: self.previous,
            depth: self.depth,
        };
        self.previous = Some(character);
        context
    }
}

fn is_top_level_non_short_circuit_operator(context: OperatorContext, next: Option<char>) -> bool {
    context.depth == 1
        && matches!(context.character, '&' | '|')
        && context.previous != Some(context.character)
        && next != Some(context.character)
}

fn has_top_level_non_short_circuit_operator(line: &str) -> bool {
    let mut characters = CodeCharacters::new(line).peekable();
    if !characters.any(|character| character == '(') {
        return false;
    }

    let mut state = TopLevelExpressionState::after_opening_parenthesis();
    while let Some(character) = characters.next() {
        let context = state.advance(character);
        if is_top_level_non_short_circuit_operator(context, characters.peek().copied()) {
            return true;
        }
    }
    false
}

fn bitwise_result_comparison(line: &str) -> bool {
    let Some(single_operator) = line.find(" & ").or_else(|| line.find(" | ")) else {
        return false;
    };
    let Some(close) = line[single_operator..]
        .find(')')
        .map(|offset| single_operator + offset)
    else {
        return false;
    };
    let suffix = line[close + 1..].trim_start();
    let Some(comparison) = ["==", "!=", "<=", ">=", "<", ">"]
        .iter()
        .find(|operator| suffix.starts_with(**operator))
    else {
        return false;
    };
    let value = suffix[comparison.len()..].trim_start();
    !value.starts_with("true") && !value.starts_with("false")
}

fn empty_block(lines: &[&str], start: usize) -> bool {
    let mut index = start + 1;
    while index < lines.len() && (lines[index].trim().is_empty() || lines[index].trim() == "{") {
        index += 1;
    }
    index < lines.len() && lines[index].trim() == "}"
}

fn next_non_blank<'a>(lines: &'a [&str], start: usize) -> &'a str {
    lines[start..]
        .iter()
        .find(|line| !line.trim().is_empty())
        .copied()
        .unwrap_or("")
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(offset, _)| {
        !is_identifier_byte(
            offset
                .checked_sub(1)
                .and_then(|i| source.as_bytes().get(i).copied()),
        ) && !is_identifier_byte(source.as_bytes().get(offset + identifier.len()).copied())
    })
}

fn is_identifier_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Clone, Copy)]
enum StringScanState {
    Code,
    Regular { delimiter: char, escaped: bool },
    Verbatim,
}

enum StringScanAction {
    Keep,
    Mask,
    MaskPair,
}

impl StringScanState {
    fn advance(
        &mut self,
        character: char,
        next: Option<char>,
        previous: Option<char>,
    ) -> StringScanAction {
        match *self {
            Self::Code => self.advance_code(character, previous),
            Self::Regular { delimiter, escaped } => {
                self.advance_regular(character, delimiter, escaped)
            }
            Self::Verbatim => self.advance_verbatim(character, next),
        }
    }

    fn advance_code(&mut self, character: char, previous: Option<char>) -> StringScanAction {
        if character != '"' && character != '\'' {
            return StringScanAction::Keep;
        }
        *self = if character == '"' && previous == Some('@') {
            Self::Verbatim
        } else {
            Self::Regular {
                delimiter: character,
                escaped: false,
            }
        };
        StringScanAction::Mask
    }

    fn advance_regular(
        &mut self,
        character: char,
        delimiter: char,
        escaped: bool,
    ) -> StringScanAction {
        if escaped {
            *self = Self::Regular {
                delimiter,
                escaped: false,
            };
        } else if character == '\\' {
            *self = Self::Regular {
                delimiter,
                escaped: true,
            };
        } else if character == delimiter {
            *self = Self::Code;
        }
        StringScanAction::Mask
    }

    fn advance_verbatim(&mut self, character: char, next: Option<char>) -> StringScanAction {
        if character != '"' {
            return StringScanAction::Mask;
        }
        if next == Some('"') {
            return StringScanAction::MaskPair;
        }
        *self = Self::Code;
        StringScanAction::Mask
    }
}

struct CodeCharacters<'a> {
    characters: std::iter::Peekable<std::str::Chars<'a>>,
    state: StringScanState,
    previous: Option<char>,
}

impl<'a> CodeCharacters<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            characters: source.chars().peekable(),
            state: StringScanState::Code,
            previous: None,
        }
    }
}

impl Iterator for CodeCharacters<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let character = self.characters.next()?;
            let action =
                self.state
                    .advance(character, self.characters.peek().copied(), self.previous);
            self.previous = Some(character);
            match action {
                StringScanAction::Keep => return Some(character),
                StringScanAction::Mask => {}
                StringScanAction::MaskPair => self.previous = self.characters.next(),
            }
        }
    }
}

fn strip_strings(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    result.extend(CodeCharacters::new(line));
    result
}

fn without_comments(source: &str) -> String {
    CommentScanner::new(source).scan()
}

#[derive(Clone, Copy)]
enum CommentScanState {
    Code,
    BlockComment,
    LineComment,
    Quoted { delimiter: char, verbatim: bool },
}

struct CommentScanner {
    characters: Vec<char>,
    result: String,
    state: CommentScanState,
    index: usize,
}

impl CommentScanner {
    fn new(source: &str) -> Self {
        Self {
            characters: source.chars().collect(),
            result: String::with_capacity(source.len()),
            state: CommentScanState::Code,
            index: 0,
        }
    }

    fn scan(mut self) -> String {
        while self.index < self.characters.len() {
            let character = self.characters[self.index];
            let next = self.characters.get(self.index + 1).copied();
            match self.state {
                CommentScanState::Code => self.scan_code(character, next),
                CommentScanState::BlockComment => self.scan_block_comment(character, next),
                CommentScanState::LineComment => self.scan_line_comment(character),
                CommentScanState::Quoted {
                    delimiter,
                    verbatim,
                } => self.scan_quoted(character, next, delimiter, verbatim),
            }
            self.index += 1;
        }
        self.result
    }

    fn scan_block_comment(&mut self, character: char, next: Option<char>) {
        if character == '*' && next == Some('/') {
            self.state = CommentScanState::Code;
            self.index += 1;
        } else if character == '\n' {
            self.result.push('\n');
        }
    }

    fn scan_line_comment(&mut self, character: char) {
        if character == '\n' {
            self.state = CommentScanState::Code;
            self.result.push('\n');
        }
    }

    fn scan_quoted(
        &mut self,
        character: char,
        next: Option<char>,
        delimiter: char,
        verbatim: bool,
    ) {
        self.result.push(character);
        if !verbatim && character == '\\' {
            if let Some(escaped) = next {
                self.result.push(escaped);
                self.index += 1;
            }
        } else if character == delimiter {
            if verbatim && next == Some(delimiter) {
                self.result.push(delimiter);
                self.index += 1;
            } else {
                self.state = CommentScanState::Code;
            }
        }
    }

    fn scan_code(&mut self, character: char, next: Option<char>) {
        if character == '/' && next == Some('/') {
            self.state = CommentScanState::LineComment;
            self.index += 1;
            return;
        }
        if character == '/' && next == Some('*') {
            self.state = CommentScanState::BlockComment;
            self.index += 1;
            return;
        }
        if character == '"' {
            self.scan_double_quote();
        } else if character == '\'' {
            self.state = CommentScanState::Quoted {
                delimiter: character,
                verbatim: false,
            };
        }
        self.result.push(character);
    }

    fn scan_double_quote(&mut self) {
        let width = self.characters[self.index..]
            .iter()
            .take_while(|candidate| **candidate == '"')
            .count();
        if width >= 3 {
            for _ in 1..width {
                self.result.push('"');
            }
            self.index += width - 1;
        } else {
            self.state = CommentScanState::Quoted {
                delimiter: '"',
                verbatim: self.index > 0 && self.characters[self.index - 1] == '@',
            };
        }
    }
}

static FILE_SCOPED_PREFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\s*csharp_style_namespace_declarations\s*=\s*file_scoped\b").unwrap()
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());
static LOOP_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:for|foreach|while|do)\b").unwrap());
static SELF_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+").unwrap());
static CSHARP_VARIABLE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z_][\w.]*(?:\s*<[^;(){}=>\n]+>)?(?:\s*\[\])?)\s+([A-Za-z_]\w*)\s*(?:=|,|\)|;)",
    )
    .unwrap()
});
static CSHARP_LINEAR_MEMBERSHIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*Contains\s*\(").unwrap());
static CSHARP_CONSTANT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bnew\s+(?:System\.Text\.RegularExpressions\.)?Regex\s*\(\s*@?\""#).unwrap()
});
static READONLY_HTTP_CLIENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\breadonly\s+(?:System\.Net\.Http\.)?HttpClient\??\s+([A-Za-z_]\w*)\s*;").unwrap()
});
static ASYNC_VOID_HANDLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\basync\s+void\s+[A-Za-z_]\w*\s*\(\s*object\??\s+sender\s*,\s*(?:[A-Za-z_]\w*\.)*(?:[A-Za-z_]\w*)?EventArgs\??\s+[A-Za-z_]\w*\s*\)").unwrap()
});
static ASYNC_VOID_OVERRIDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\boverride\s+async\s+void\b").unwrap());
static SYNC_EVENT_WAIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\b|\.)[A-Za-z_]\w*Event\.Wait\s*\(\s*\)").unwrap());
static TASK_WAIT_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\.Wait\s*\(").unwrap());
static TASK_RESULT_MEMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\.Result\b").unwrap());
static WEAK_LOCK_LITERAL_OR_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*lock\s*\(\s*(?:this\b|typeof\s*\(|(?:@|\$|@\$|\$@)?"|(?:System\.)?String\.Intern\s*\()"#,
    )
    .unwrap()
});
static WEAK_LOCK_VARIABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*lock\s*\(\s*([A-Za-z_]\w*)\s*\)").unwrap());
static HTTP_CLIENT_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:this\.)?([A-Za-z_]\w*)\s*=\s*new\s+HttpClient\s*\(").unwrap()
});
static HTTP_CLIENT_MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:System\.Net\.Http\.)?HttpClient\??\s+[A-Za-z_]\w*\s*(?:\{[^}]*\}\s*)?=\s*new\s+HttpClient\s*\(").unwrap()
});
static RUNTIME_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bSystem\.(?:String|Int32|Boolean|Object|Void)\b").unwrap());
static CAS_API: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:CodeAccessPermission|SecurityPermission|PermissionSet)\b").unwrap()
});
static TYPE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\[[^\]]+\]\s*)*((?:(?:public|protected|internal|private|file|new|static|abstract|sealed|partial|readonly|ref)\s+)*)(?:class|struct|interface|record(?:\s+(?:class|struct))?)\s+[A-Za-z_]\w*").unwrap()
});
static ARCHIVE_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:var|string)\s+([A-Za-z_]\w*)\s*=\s*(.+?);?$").unwrap());
static ARCHIVE_ENTRY_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\.FullName\b").unwrap());
static RETURN_OR_THROW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:throw|return)\b").unwrap());
static ARCHIVE_WRAPPER_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:(?:public|protected|internal|private|static|async)\s+)+[A-Za-z_][\w<>\[\]?,.]*\s+([A-Za-z_]\w*)\s*\(",
    )
    .unwrap()
});
static ARCHIVE_EXTRACTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.ExtractToFile\s*\(|\b([A-Za-z_]\w*)\s*\(").unwrap());
static LITERAL_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\b([A-Za-z_]\w*)\s*=\s*(?:@|\$@|@\$)?\"([^\"]*)\""#).unwrap());
static SECRET_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|_)(?:token|secret|password|passwd|api_?key|nonce|salt)(?:$|_)|(?:access|auth|bearer|refresh|session|jwt|api|client|identity|security|oauth)token$|(?:secret|password|passwd|apikey|nonce|salt)$").unwrap()
});
static NON_CREDENTIAL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:Map|Preference|Package|Action|Type|Path|Error|Width|Height|Quality|Configuration|Setting|Name|Id|Url|Uri|File|Directory|Certificate)(?:Key|Token|Secret|Password)?$|^HeaderName\w*$").unwrap()
});
static URI_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://").unwrap());
static SYMBOLIC_SECRET_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Z][A-Z0-9_]*|[a-z0-9]+(?:_[a-z0-9]+)+|[a-z]+-\d+(?:-[a-z0-9]+)*|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+|<[A-Za-z0-9_:-]+>|\[[A-Za-z0-9_:-]+\])$").unwrap()
});
static PLACEHOLDER_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?:fake|mock|dummy|test)[a-z0-9]*(?:key|token|secret|password|passwd)|(?:asdf){2,})$",
    )
    .unwrap()
});
static PASCAL_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Za-z0-9]*$").unwrap());
static FORMAT_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\d+\}").unwrap());
static OBSOLETE_CIPHER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:DES|TripleDES|RC2|RijndaelManaged)\b\s*(?:\(|\.Create\b)").unwrap()
});
static LEGACY_DIGEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bHashAlgorithmName\.(?:MD5|SHA1)\b|\b(?:MD5|SHA1)\b\s*(?:\(|\.Create\b)").unwrap()
});
static METHOD_SIGNATURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\s*\([^;]*\)\s*(?:\{|$)").unwrap());
static SECURITY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:auth|credential|password|passwd|secret|token|signature|signing|certificate|encryption|encrypt|decrypt|keyderivation|key derivation)").unwrap()
});
static SQL_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b\w*(?:sql|query|command)\w*\s*=\s*(?:\$@?|@\$?)?\"[^\"]*\b(?:select|insert|update|delete)\s"#).unwrap()
});
static ANY_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*=").unwrap());
static DYNAMIC_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\+\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*\+)").unwrap());
static NUMERIC_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\((?:s?byte|u?short|u?int|u?long|float|double|decimal)\)\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$").unwrap()
});
static NUMERIC_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[+-]?\d[\d_]*(?:\.\d[\d_]*)?[fFdDmMuUlL]*$").unwrap());
static NUMERIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:const\s+)?(?:s?byte|u?short|u?int|u?long|float|double|decimal)\s+([A-Za-z_]\w*)\b",
    )
    .unwrap()
});
static INFERRED_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bvar\s+([A-Za-z_]\w*)\s*=\s*([^;]+)").unwrap());
static IF_OR_WHILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:if|while)\s*\(").unwrap());
static NUMERIC_BITWISE_OPERAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:0[xX][0-9A-Fa-f]+|\b\d+)(?:[uUlL]+)?\s*[&|]|[&|]\s*(?:0[xX][0-9A-Fa-f]+|\d+)(?:[uUlL]+\b)?").unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        analyze, analyze_source, has_top_level_non_short_circuit_operator, without_comments,
    };
    use crate::config::Config;

    #[test]
    fn masks_comments_without_changing_strings_or_line_positions() {
        let source = concat!(
            r#"var interpolated = $"https://{host}/*path*/"; // trailing"#,
            "\n",
            r#"var verbatim = @"// ""quoted"" /* text */"; /* block"#,
            "\n",
            "continues */Call();\n",
            "var character = '/';\n",
        );
        let expected = concat!(
            r#"var interpolated = $"https://{host}/*path*/"; "#,
            "\n",
            r#"var verbatim = @"// ""quoted"" /* text */"; "#,
            "\n",
            "Call();\n",
            "var character = '/';\n",
        );

        assert_eq!(without_comments(source), expected);
    }

    #[test]
    fn identifies_only_unquoted_operators_at_the_condition_depth() {
        assert!(has_top_level_non_short_circuit_operator(
            "if ((ready) & enabled) {}"
        ));
        assert!(has_top_level_non_short_circuit_operator(
            "if (ready | enabled"
        ));
        assert!(!has_top_level_non_short_circuit_operator(
            "if ((ready & enabled)) {}"
        ));
        assert!(!has_top_level_non_short_circuit_operator(
            r#"if (text == "&" && ready) {}"#
        ));
        assert!(!has_top_level_non_short_circuit_operator(
            r#"if (left &"quoted"& right) {}"#
        ));
        assert!(!has_top_level_non_short_circuit_operator(
            r#"if ("unterminated & enabled"#
        ));
    }

    #[test]
    fn reports_complete_csharp_source_family() {
        let sources = BTreeMap::from([(
            "All.cs".to_owned(),
            "namespace Demo {\n\
using System.Text;\n\
public class All {\n\
[AllowPartiallyTrustedCallers]\n\
[DllImport(\"native\")]\n\
public static extern void Native();\n\
async void Run(Task<int> task) {\n\
string text = \"\";\n\
for (;;) {\n\
text = text + value;\n\
}\n\
try {}\n\
catch (System.Exception error)\n\
{\n\
}\n\
var formatter = new BinaryFormatter();\n\
PermissionSet permission = Load();\n\
System.Int32 count = 0;\n\
if (ready & enabled) {}\n\
var callback = new delegate();\n\
var result = task.Result;\n\
Thread.Sleep(1);\n\
var now = DateTime.Now;\n\
using var client = new HttpClient();\n\
Process.Start(Request.Path);\n\
var password = \"literal-secret\";\n\
var random_password_value = new Random();\n\
var userQuery = $\"SELECT * FROM Users WHERE Name = '{userName}'\";\n\
var cipher = DES.Create();\n\
var remote = RemotingConfiguration.ApplicationName;\n\
var com = new ServicedComponent();\n\
}\n\
}\n"
            .to_owned(),
        )]);
        let config = Config::defaults(std::env::temp_dir().join("cbr-csharp-unit"));

        let findings = analyze(&sources, &config);
        let codes = findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert!(codes.contains("cs-aptca-attribute"));
        assert!(codes.contains("cs-async-void"));
        assert!(codes.contains("cs-binaryformatter"));
        assert!(codes.contains("cs-cas-api"));
        assert!(codes.contains("cs-catch-system-exception"));
        assert!(codes.contains("cs-datetime-now"));
        assert!(codes.contains("cs-dcom-api"));
        assert!(codes.contains("cs-empty-catch"));
        assert!(codes.contains("cs-explicit-delegate-new"));
        assert!(codes.contains("cs-hardcoded-secret"));
        assert!(codes.contains("cs-new-httpclient"));
        assert!(codes.contains("cs-non-short-circuit-bool"));
        assert!(codes.contains("cs-process-start-input"));
        assert!(codes.contains("cs-public-pinvoke"));
        assert!(codes.contains("cs-random-security"));
        assert!(codes.contains("cs-remoting-api"));
        assert!(codes.contains("cs-runtime-type-alias"));
        assert!(codes.contains("cs-sql-string-build"));
        assert!(codes.contains("cs-string-concat-loop"));
        assert!(codes.contains("cs-sync-over-async"));
        assert!(codes.contains("cs-thread-sleep"));
        assert!(codes.contains("cs-using-inside-namespace"));
        assert!(codes.contains("cs-weak-crypto"));
    }

    #[test]
    fn accepts_unambiguous_datetime_offset_now() {
        let sources = BTreeMap::from([(
            "Clock.cs".to_owned(),
            "/// <example>Log.Debug(\"Started {At}\", DateTime.Now);</example>\nvar localInstant = DateTimeOffset.Now;".to_owned(),
        )]);
        let config = Config::defaults(std::env::temp_dir().join("cbr-csharp-clock-unit"));

        assert!(
            analyze(&sources, &config)
                .into_iter()
                .all(|finding| finding.code != "cs-datetime-now")
        );
    }

    #[test]
    fn applies_csharp_handler_resource_legacy_and_bitmask_exclusions() {
        let sources = BTreeMap::from([(
            "Safe.cs".to_owned(),
            "class Safe {\n\
private async void Click(object sender, EventArgs e) {}\n\
protected override async void OnClose(EventArgs e) {}\n\
private async void Refresh() {}\n\
public static HttpClient Shared { get; } = new HttpClient();\n\
private readonly HttpClient Cached;\n\
Safe() {\n\
Cached = new HttpClient();\n\
}\n\
void Work() {\n\
using var local = new HttpClient();\n\
if ((mask & Flag.Read) == Flag.Read) {}\n\
if (ready & enabled) {}\n\
var example = \"BinaryFormatter\";\n\
// BinaryFormatter\n\
var formatter = new BinaryFormatter();\n\
}\n\
}\n"
            .to_owned(),
        )]);
        let config = Config::defaults(std::env::temp_dir().join("cbr-csharp-safe-unit"));

        let findings = analyze(&sources, &config)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("cs-async-void".to_owned(), 4),
                ("cs-new-httpclient".to_owned(), 11),
                ("cs-non-short-circuit-bool".to_owned(), 13),
                ("cs-binaryformatter".to_owned(), 16),
            ]
        );
    }
    #[test]
    fn ignores_comments_inside_multiline_raw_strings() {
        let sources = BTreeMap::from([(
            "Generator.cs".to_owned(),
            concat!(
                "class Generator {\n",
                "private string Generated = $$\"\"\"\n",
                "/// generated P:Example.Item(System.Int32)\n",
                "// generated source with { braces }\n",
                "\"\"\";\n",
                "System.Int32 Parse(System.Int32 value) => value;\n",
                "}\n",
            )
            .to_owned(),
        )]);
        let config = Config::defaults(std::env::temp_dir().join("cbr-csharp-raw-string-unit"));

        let runtime_alias_lines = analyze(&sources, &config)
            .into_iter()
            .filter(|finding| finding.code == "cs-runtime-type-alias")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();

        assert_eq!(runtime_alias_lines, vec![6]);
    }

    #[test]
    fn follows_archive_paths_through_extraction_wrappers() {
        let sources = BTreeMap::from([(
            "Archive.cs".to_owned(),
            "class Archive {\n\
private static void Save(ZipArchiveEntry entry, string destination) {\n\
entry.ExtractToFile(destination);\n\
}\n\
void Extract(ZipArchiveEntry entry) {\n\
var output = entry.FullName;\n\
Save(entry, output);\n\
}\n\
}\n"
            .to_owned(),
        )]);
        let config = Config::defaults(std::env::temp_dir().join("cbr-csharp-archive-unit"));

        let findings = analyze(&sources, &config)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(findings, vec![("cs-archive-path-traversal".to_owned(), 7)]);
    }

    #[test]
    fn tolerates_incomplete_concat_and_archive_extraction_expressions() {
        let sources = BTreeMap::from([(
            "Incomplete.cs".to_owned(),
            "class Incomplete {\n\
private static void Save(ZipArchiveEntry entry, string destination) {\n\
entry.ExtractToFile(destination);\n\
}\n\
void Run(ZipArchiveEntry entry) {\n\
string text = \"\";\n\
for (;;) {\n\
text = + value;\n\
text = text + value;\n\
}\n\
var output = entry.FullName;\n\
Save(\n\
Save(entry, output);\n\
}\n\
}\n"
            .to_owned(),
        )]);
        let config = Config::defaults(std::env::temp_dir().join("cbr-csharp-incomplete-unit"));

        let findings = analyze(&sources, &config)
            .into_iter()
            .filter(|finding| {
                finding.code == "cs-string-concat-loop"
                    || finding.code == "cs-archive-path-traversal"
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("cs-string-concat-loop".to_owned(), 9),
                ("cs-archive-path-traversal".to_owned(), 13),
            ]
        );
    }
    #[test]
    fn reports_csharp_loop_performance_patterns() {
        let source = "class Scan {\n\
+  void Run(List<string> blocked, List<string> values) {\n\
+    string output = \"\";\n\
+    foreach (var value in values) {\n\
+      var matcher = new Regex(\"^[a-z]+$\");\n\
+      if (blocked.Contains(value)) {\n\
+        output += value;\n\
+      }\n\
+    }\n\
+  }\n\
+}\n"
            .replace("\n+", "\n");

        assert_eq!(
            analyze_source("Scan.cs", &source, false)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "cs-regex-created-in-loop"
                            | "cs-linear-membership-in-loop"
                            | "cs-string-concat-loop"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("cs-regex-created-in-loop".to_owned(), 5),
                ("cs-linear-membership-in-loop".to_owned(), 6),
                ("cs-string-concat-loop".to_owned(), 7),
            ]
        );
    }

    #[test]
    fn accepts_csharp_loop_performance_safe_variants() {
        let source = "class SafeScan {\n\
+  void Run(string pattern, HashSet<string> allowed, List<string> values) {\n\
+    var stable = new Regex(\"^[a-z]+$\");\n\
+    var output = new StringBuilder();\n\
+    foreach (var value in values) {\n\
+      var dynamic = new Regex(pattern);\n\
+      string perIteration = \"\";\n\
+      perIteration += value;\n\
+      if (allowed.Contains(value)) output.Append(value);\n\
+      // new Regex(\"commented\");\n\
+      var example = \"new Regex(\\\"literal\\\")\";\n\
+    }\n\
+  }\n\
+}\n"
            .replace("\n+", "\n");

        let selected = analyze_source("SafeScan.cs", &source, false)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "cs-regex-created-in-loop"
                        | "cs-linear-membership-in-loop"
                        | "cs-string-concat-loop"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn accepts_non_task_result_members_and_completed_value_tasks() {
        let source = "class SafeResult {\n\
+  int Read(Outcome outcome, ValueTask<int> task) {\n\
+    if (task.IsCompleted) {\n\
+      return task.Result;\n\
+    }\n\
+    return outcome.Result;\n\
+  }\n\
+  async Task<int> ReadOutcome() {\n\
+    var outcome = await LoadOutcomeAsync();\n\
+    return outcome.Result;\n\
+  }\n\
+}\n"
            .replace("\n+", "\n");

        let selected = analyze_source("SafeResult.cs", &source, false)
            .into_iter()
            .filter(|finding| finding.code == "cs-sync-over-async")
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn reports_weak_identity_lock_targets() {
        let source = r#"class Locks {
  private string gate = "shared";
  private readonly object safeGate = new();
  void Run() {
    lock ("literal") {}
    lock (typeof(Locks)) {}
    lock (this) {}
    lock (gate) {}
    lock (safeGate) {}
  }
}"#;

        assert_eq!(
            analyze_source("Locks.cs", source, false)
                .into_iter()
                .filter(|finding| finding.code == "cs-lock-weak-identity")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![5, 6, 7, 8]
        );
    }
}
