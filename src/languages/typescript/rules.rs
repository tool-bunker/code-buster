use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::languages::functions::mask_javascript_strings_and_comments;
use crate::languages::strip_quoted_literals as strip_literals;
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| is_javascript(path))
    {
        findings.extend(node_fs_constant_imports(path, source));
        findings.extend(source_findings(path, source));
    }
    findings
}

struct SourceLine<'a> {
    path: &'a str,
    raw: &'a str,
    line: &'a str,
    syntax_line: &'a str,
    sink_line: &'a str,
    uncommented_line: &'a str,
    code_line: &'a str,
    uncommented_lines: &'a [&'a str],
    code_lines: &'a [&'a str],
    sink_lines: &'a [&'a str],
    index: usize,
    inside_loop: bool,
    tooling: bool,
    command_line: bool,
    typescript: bool,
    inside_async: bool,
}

#[derive(Default)]
struct PerformanceFacts {
    arrays: BTreeSet<String>,
    outer_arrays: BTreeSet<String>,
    strings: BTreeSet<String>,
    direct_sync_fs: BTreeSet<String>,
    fs_namespaces: BTreeSet<String>,
}

impl PerformanceFacts {
    fn from_source(source: &str, inside_loop: &[bool]) -> Self {
        let mut arrays = BTreeSet::new();
        let mut outer_arrays = BTreeSet::new();
        for capture in ARRAY_DECLARATION.captures_iter(source) {
            let name = capture[1].to_owned();
            arrays.insert(name.clone());
            if capture.get(0).is_some_and(|whole| {
                let line = line_number(source, whole.start());
                !inside_loop.get(line - 1).copied().unwrap_or(false)
            }) {
                outer_arrays.insert(name);
            }
        }
        let strings = STRING_DECLARATION
            .captures_iter(source)
            .map(|capture| capture[1].to_owned())
            .collect();
        let mut direct_sync_fs = BTreeSet::new();
        for capture in NODE_FS_IMPORT.captures_iter(source) {
            collect_sync_fs_names(&capture[1], &mut direct_sync_fs);
        }
        for capture in NODE_FS_REQUIRE_DESTRUCTURE.captures_iter(source) {
            collect_sync_fs_names(&capture[1], &mut direct_sync_fs);
        }
        let mut fs_namespaces = NODE_FS_NAMESPACE_IMPORT
            .captures_iter(source)
            .map(|capture| capture[1].to_owned())
            .collect::<BTreeSet<_>>();
        fs_namespaces.extend(
            NODE_FS_REQUIRE_NAMESPACE
                .captures_iter(source)
                .map(|capture| capture[1].to_owned()),
        );
        Self {
            arrays,
            outer_arrays,
            strings,
            direct_sync_fs,
            fs_namespaces,
        }
    }

    fn calls_sync_fs(&self, line: &str) -> bool {
        CALL_EXPRESSION.captures_iter(line).any(|capture| {
            let root = &capture[1];
            capture.get(2).map_or_else(
                || self.direct_sync_fs.contains(root),
                |method| self.fs_namespaces.contains(root) && method.as_str().ends_with("Sync"),
            )
        })
    }
}

fn collect_sync_fs_names(imports: &str, output: &mut BTreeSet<String>) {
    for item in imports.split(',') {
        let mut names = AS_ALIAS.split(item.trim());
        let imported = names.next().unwrap_or("").trim();
        let local = names.next().unwrap_or(imported).trim();
        if imported.ends_with("Sync") && !local.is_empty() {
            output.insert(local.to_owned());
        }
    }
}

impl SourceLine<'_> {
    fn add(&self, findings: &mut Vec<Finding>, code: &str, message: &str) {
        findings.push(finding(
            code,
            self.path,
            self.index + 1,
            self.index + 1,
            message,
            "medium",
        ));
    }
}

fn source_findings(path: &str, source: &str) -> Vec<Finding> {
    let tooling = is_tooling_source(path);
    let command_line = is_node_command_line(source);
    let typescript = is_typescript(path);
    let raw_lines = source.split('\n').collect::<Vec<_>>();
    let uncommented_source = without_comments(source);
    let uncommented_lines = uncommented_source.split('\n').collect::<Vec<_>>();
    let code_source = without_template_literals(&uncommented_source);
    let code_lines = code_source.split('\n').collect::<Vec<_>>();
    let sink_source = without_string_literal_text(&uncommented_source);
    let sink_lines = sink_source.split('\n').collect::<Vec<_>>();
    let syntax_source = mask_javascript_strings_and_comments(source);
    let syntax_lines = syntax_source.split('\n').collect::<Vec<_>>();
    let (inside_loop, inside_async) = scopes_by_line(&code_lines);
    let performance = PerformanceFacts::from_source(&uncommented_source, &inside_loop);
    let mut findings = Vec::new();
    findings.extend(async_foreach_findings(path, &sink_source));
    findings.extend(child_process_shell_findings(path, &uncommented_source));
    findings.extend(accumulating_spread_findings(path, &sink_source));
    findings.extend(filtered_first_match_findings(
        path,
        &sink_source,
        &performance,
    ));
    findings.extend(buffer_concat_findings(path, &sink_source, &inside_loop));
    findings.extend(intl_formatter_findings(
        path,
        &uncommented_source,
        &inside_loop,
    ));
    findings.extend(locale_format_findings(
        path,
        &uncommented_source,
        &inside_loop,
    ));

    for index in 0..raw_lines.len() {
        let stripped_code = strip_literals(code_lines[index]);
        let stripped_sink = strip_literals(sink_lines[index]);
        let line = SourceLine {
            path,
            raw: raw_lines[index],
            line: stripped_code.trim(),
            syntax_line: syntax_lines[index].trim(),
            sink_line: stripped_sink.trim(),
            uncommented_line: uncommented_lines[index],
            code_line: code_lines[index],
            uncommented_lines: &uncommented_lines,
            code_lines: &code_lines,
            sink_lines: &sink_lines,
            index,
            inside_loop: inside_loop[index],
            inside_async: inside_async[index],
            tooling,
            command_line,
            typescript,
        };
        analyze_style(&line, &mut findings);
        analyze_execution_sinks(&line, &mut findings);
        analyze_async_usage(&line, &mut findings);
        analyze_hardcoded_secret(&line, &mut findings);
        analyze_json_parsing(&line, &mut findings);
        analyze_performance(&line, &performance, &mut findings);
    }
    findings
}

fn async_foreach_findings(path: &str, source: &str) -> Vec<Finding> {
    ASYNC_FOREACH
        .find_iter(source)
        .map(|matched| {
            let line = line_number(source, matched.start());
            finding(
                "js-async-foreach",
                path,
                line,
                line,
                "async forEach callback does not make the caller await its work",
                "high",
            )
        })
        .collect()
}

fn accumulating_spread_findings(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for reducer in REDUCE_CALL.find_iter(source) {
        let open = reducer.end() - 1;
        let Some(call_close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        let Some((accumulator, body_start, body_end)) =
            reducer_callback(source, open + 1, call_close)
        else {
            continue;
        };
        for spread in SPREAD_IDENTIFIER.captures_iter(&source[body_start..body_end]) {
            if spread
                .get(1)
                .is_none_or(|name| name.as_str() != accumulator)
            {
                continue;
            }
            let Some(whole) = spread.get(0) else {
                continue;
            };
            let line = line_number(source, body_start + whole.start());
            findings.push(finding(
                "js-accumulating-spread",
                path,
                line,
                line,
                "spreading the reducer accumulator copies all accumulated values on every iteration",
                "high",
            ));
        }
    }
    findings
}

fn reducer_callback(
    source: &str,
    start: usize,
    call_close: usize,
) -> Option<(String, usize, usize)> {
    let mut cursor = skip_ascii_whitespace(source, start);
    let accumulator = if source.as_bytes().get(cursor) == Some(&b'(') {
        let parameters_end = matching_delimiter(source, cursor, b'(', b')')?;
        if parameters_end >= call_close {
            return None;
        }
        let first = source[cursor + 1..parameters_end].split(',').next()?.trim();
        if !JAVASCRIPT_IDENTIFIER.is_match(first) {
            return None;
        }
        cursor = skip_ascii_whitespace(source, parameters_end + 1);
        first.to_owned()
    } else {
        let identifier = JAVASCRIPT_IDENTIFIER_PREFIX.find(&source[cursor..])?;
        if identifier.start() != 0 {
            return None;
        }
        cursor += identifier.end();
        cursor = skip_ascii_whitespace(source, cursor);
        identifier.as_str().to_owned()
    };
    if source.as_bytes().get(cursor..cursor + 2) != Some(b"=>") {
        return None;
    }
    let body_start = skip_ascii_whitespace(source, cursor + 2);
    let opening = *source.as_bytes().get(body_start)?;
    let body_end = match opening {
        b'{' => matching_delimiter(source, body_start, b'{', b'}')? + 1,
        b'[' => matching_delimiter(source, body_start, b'[', b']')? + 1,
        b'(' => matching_delimiter(source, body_start, b'(', b')')? + 1,
        _ => source[body_start..call_close]
            .find(',')
            .map_or(call_close, |offset| body_start + offset),
    };
    (body_end <= call_close).then_some((accumulator, body_start, body_end))
}

fn filtered_first_match_findings(
    path: &str,
    source: &str,
    facts: &PerformanceFacts,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for filtered in FILTER_CALL.captures_iter(source) {
        let (Some(whole), Some(receiver)) = (filtered.get(0), filtered.get(1)) else {
            continue;
        };
        if !facts.arrays.contains(receiver.as_str()) {
            continue;
        }
        let open = whole.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        if !FILTER_FIRST_ACCESS.is_match(&source[close + 1..]) {
            continue;
        }
        let line = line_number(source, whole.start());
        findings.push(finding(
            "js-filter-first-match",
            path,
            line,
            line,
            "filter traverses the full array before selecting one match",
            "high",
        ));
    }
    findings
}
fn buffer_concat_findings(path: &str, source: &str, inside_loop: &[bool]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for assignment in BUFFER_CONCAT_ASSIGNMENT.captures_iter(source) {
        let (Some(whole), Some(destination)) = (assignment.get(0), assignment.get(1)) else {
            continue;
        };
        let array_open = whole.end() - 1;
        let Some(array_close) = matching_delimiter(source, array_open, b'[', b']') else {
            continue;
        };
        let Some(elements) = split_top_level(&source[array_open + 1..array_close]) else {
            continue;
        };
        if elements.len() < 2
            || !elements
                .iter()
                .any(|element| *element == destination.as_str())
        {
            continue;
        }
        let line = line_number(source, whole.start());
        if !inside_loop.get(line - 1).copied().unwrap_or(false) {
            continue;
        }
        findings.push(finding(
            "js-buffer-concat-in-loop",
            path,
            line,
            line,
            "Buffer.concat repeatedly copies the accumulated buffer inside a loop",
            "high",
        ));
    }
    findings
}

fn intl_formatter_findings(path: &str, source: &str, inside_loop: &[bool]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for constructor in INTL_FORMATTER_CONSTRUCTOR.find_iter(source) {
        if !is_code_offset(source, constructor.start()) {
            continue;
        }
        let open = constructor.end() - 1;
        let Some(arguments) = call_arguments(source, open) else {
            continue;
        };
        if !static_intl_configuration(&arguments) {
            continue;
        }
        let line = line_number(source, constructor.start());
        if !inside_loop.get(line - 1).copied().unwrap_or(false) {
            continue;
        }
        findings.push(finding(
            "js-intl-formatter-in-loop",
            path,
            line,
            line,
            "constant Intl formatter is constructed inside a loop",
            "high",
        ));
    }
    findings
}

fn locale_format_findings(path: &str, source: &str, inside_loop: &[bool]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for formatter in LOCALE_FORMAT_CALL.find_iter(source) {
        if !is_code_offset(source, formatter.start()) {
            continue;
        }
        let open = formatter.end() - 1;
        let Some(arguments) = call_arguments(source, open) else {
            continue;
        };
        if !static_intl_configuration(&arguments) {
            continue;
        }
        let line = line_number(source, formatter.start());
        if !inside_loop.get(line - 1).copied().unwrap_or(false) {
            continue;
        }
        findings.push(finding(
            "js-locale-format-in-loop",
            path,
            line,
            line,
            "locale formatting repeatedly resolves the same formatter inside a loop",
            "high",
        ));
    }
    findings
}

fn static_intl_configuration(arguments: &[&str]) -> bool {
    match arguments {
        [] => true,
        [locale] => static_intl_locale(locale),
        [locale, options] => static_intl_locale(locale) && static_intl_options(options),
        _ => false,
    }
}

fn static_intl_locale(source: &str) -> bool {
    let source = source.trim();
    if matches!(source, "undefined" | "null") || is_static_string_literal(source) {
        return true;
    }
    if !(source.starts_with('[') && source.ends_with(']')) {
        return false;
    }
    split_top_level(&source[1..source.len() - 1]).is_some_and(|items| {
        !items.is_empty() && items.iter().all(|item| is_static_string_literal(item))
    })
}

fn static_intl_options(source: &str) -> bool {
    let source = source.trim();
    if matches!(source, "undefined" | "null") {
        return true;
    }
    if !(source.starts_with('{') && source.ends_with('}')) {
        return false;
    }
    split_top_level(&source[1..source.len() - 1]).is_some_and(|properties| {
        properties.iter().all(|property| {
            property
                .split_once(':')
                .is_some_and(|(_, value)| static_intl_option_value(value))
        })
    })
}

fn static_intl_option_value(source: &str) -> bool {
    let source = source.trim();
    is_static_string_literal(source)
        || matches!(source, "true" | "false" | "null" | "undefined")
        || source.parse::<f64>().is_ok()
}

fn skip_ascii_whitespace(source: &str, mut offset: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    offset
}

#[derive(Clone, Copy)]
enum ChildProcessApi {
    Exec,
    Spawn,
}

#[derive(Default)]
struct ChildProcessBindings {
    exec: BTreeSet<String>,
    spawn: BTreeSet<String>,
    namespaces: BTreeSet<String>,
}

fn child_process_shell_findings(path: &str, source: &str) -> Vec<Finding> {
    let static_commands = static_command_bindings(source);
    let bindings = child_process_bindings(source);
    let mut calls = Vec::new();
    for name in &bindings.exec {
        calls.extend(call_openings(source, name).map(|open| (open, ChildProcessApi::Exec)));
    }
    for name in &bindings.spawn {
        calls.extend(call_openings(source, name).map(|open| (open, ChildProcessApi::Spawn)));
    }
    for namespace in &bindings.namespaces {
        for api in ["exec", "execSync"] {
            let callable = format!("{namespace}.{api}");
            calls
                .extend(call_openings(source, &callable).map(|open| (open, ChildProcessApi::Exec)));
        }
        for api in ["spawn", "spawnSync"] {
            let callable = format!("{namespace}.{api}");
            calls.extend(
                call_openings(source, &callable).map(|open| (open, ChildProcessApi::Spawn)),
            );
        }
    }
    calls.sort_by_key(|(open, _)| *open);
    calls.dedup_by_key(|(open, _)| *open);
    calls
        .into_iter()
        .filter_map(|(open, api)| {
            let arguments = call_arguments(source, open)?;
            let risky = match api {
                ChildProcessApi::Exec => arguments.first().is_some_and(|command| {
                    !is_static_command_expression(command)
                        && !static_commands.contains(command.trim())
                        && !is_allowlist_guarded_command(source, open, command)
                }),
                ChildProcessApi::Spawn => spawn_uses_dynamic_shell_input(&arguments),
            };
            risky.then(|| {
                let line = line_number(source, open);
                finding(
                    "js-child-process-shell-interpolation",
                    path,
                    line,
                    line,
                    "dynamic data reaches a child-process shell command",
                    "high",
                )
            })
        })
        .collect()
}

fn child_process_bindings(source: &str) -> ChildProcessBindings {
    let mut bindings = ChildProcessBindings::default();
    for captures in CHILD_PROCESS_IMPORT.captures_iter(source) {
        if let Some(list) = captures.get(1) {
            collect_child_process_names(list.as_str(), false, &mut bindings);
        }
    }
    for captures in CHILD_PROCESS_REQUIRE_DESTRUCTURE.captures_iter(source) {
        if let Some(list) = captures.get(1) {
            collect_child_process_names(list.as_str(), true, &mut bindings);
        }
    }
    for captures in CHILD_PROCESS_NAMESPACE.captures_iter(source) {
        if let Some(namespace) = captures.get(1) {
            bindings.namespaces.insert(namespace.as_str().to_owned());
        }
    }
    for captures in CHILD_PROCESS_REQUIRE_NAMESPACE.captures_iter(source) {
        if let Some(namespace) = captures.get(1) {
            bindings.namespaces.insert(namespace.as_str().to_owned());
        }
    }
    bindings
}

fn static_command_bindings(source: &str) -> BTreeSet<String> {
    STATIC_COMMAND_BINDING
        .captures_iter(source)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str();
            let expression = captures.get(2)?.as_str().trim();
            is_static_command_expression(expression).then(|| name.to_owned())
        })
        .collect()
}

fn collect_child_process_names(list: &str, common_js: bool, bindings: &mut ChildProcessBindings) {
    for entry in list
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (imported, local) = if common_js {
            entry
                .split_once(':')
                .map_or((entry, entry), |(imported, alias)| {
                    (imported.trim(), alias.trim())
                })
        } else {
            let mut parts = entry.split_whitespace();
            let Some(imported) = parts.next() else {
                continue;
            };
            let local = match (parts.next(), parts.next()) {
                (Some("as"), Some(alias)) => alias,
                _ => imported,
            };
            (imported, local)
        };
        match imported {
            "exec" | "execSync" => {
                bindings.exec.insert(local.to_owned());
            }
            "spawn" | "spawnSync" => {
                bindings.spawn.insert(local.to_owned());
            }
            _ => {}
        }
    }
}

fn call_openings<'a>(source: &'a str, callable: &'a str) -> impl Iterator<Item = usize> + 'a {
    source
        .match_indices(callable)
        .filter_map(move |(start, _)| {
            let before = source[..start].chars().next_back();
            let after_name = start + callable.len();
            let boundary = before.is_none_or(|character| {
                !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$' | '.')
            });
            if !boundary || !is_code_offset(source, start) {
                return None;
            }
            let whitespace = source[after_name..]
                .len()
                .saturating_sub(source[after_name..].trim_start().len());
            source[after_name + whitespace..]
                .starts_with('(')
                .then_some(after_name + whitespace)
        })
}

// code-buster-ignore complex-function: the single-pass quote scan keeps delimiter and escape state local.
fn is_code_offset(source: &str, target: usize) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for character in source[..target].chars() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
        } else if matches!(character, '"' | '\'' | '`') {
            quote = Some(character);
        }
    }
    quote.is_none()
}

// code-buster-ignore complex-function: the argument parser keeps quote and three delimiter depths local.
fn call_arguments(source: &str, open: usize) -> Option<Vec<&str>> {
    let mut arguments = Vec::new();
    let body_start = open + 1;
    let mut argument_start = body_start;
    let mut quote = None;
    let mut escaped = false;
    let mut parentheses = 1_i32;
    let mut brackets = 0_i32;
    let mut braces = 0_i32;
    for (relative, character) in source[body_start..].char_indices() {
        let offset = body_start + relative;
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '"' | '\'' | '`' => quote = Some(character),
            '(' => parentheses += 1,
            ')' => {
                parentheses -= 1;
                if parentheses == 0 {
                    let argument = source[argument_start..offset].trim();
                    if !argument.is_empty() {
                        arguments.push(argument);
                    }
                    return Some(arguments);
                }
            }
            '[' => brackets += 1,
            ']' => brackets -= 1,
            '{' => braces += 1,
            '}' => braces -= 1,
            ',' if parentheses == 1 && brackets == 0 && braces == 0 => {
                arguments.push(source[argument_start..offset].trim());
                argument_start = offset + character.len_utf8();
            }
            _ => {}
        }
    }
    None
}

fn spawn_uses_dynamic_shell_input(arguments: &[&str]) -> bool {
    let Some(options) = arguments
        .iter()
        .find(|argument| CHILD_PROCESS_SHELL_TRUE.is_match(argument))
    else {
        return false;
    };
    arguments
        .iter()
        .take_while(|argument| *argument != options)
        .any(|argument| !is_static_spawn_input(argument))
}

fn is_static_spawn_input(expression: &str) -> bool {
    if is_static_command_expression(expression) {
        return true;
    }
    let expression = expression.trim();
    if !(expression.starts_with('[') && expression.ends_with(']')) {
        return false;
    }
    split_top_level(&expression[1..expression.len() - 1])
        .is_some_and(|items| items.iter().all(|item| is_static_command_expression(item)))
}

// code-buster-ignore complex-function: the top-level splitter keeps quote and three delimiter depths local.
fn split_top_level(source: &str) -> Option<Vec<&str>> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut parentheses = 0_i32;
    let mut brackets = 0_i32;
    let mut braces = 0_i32;
    for (offset, character) in source.char_indices() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '"' | '\'' | '`' => quote = Some(character),
            '(' => parentheses += 1,
            ')' => parentheses -= 1,
            '[' => brackets += 1,
            ']' => brackets -= 1,
            '{' => braces += 1,
            '}' => braces -= 1,
            ',' if parentheses == 0 && brackets == 0 && braces == 0 => {
                items.push(source[start..offset].trim());
                start = offset + character.len_utf8();
            }
            _ => {}
        }
        if parentheses < 0 || brackets < 0 || braces < 0 {
            return None;
        }
    }
    if quote.is_some() || parentheses != 0 || brackets != 0 || braces != 0 {
        return None;
    }
    let final_item = source[start..].trim();
    if !final_item.is_empty() {
        items.push(final_item);
    }
    Some(items)
}

fn is_static_command_expression(source: &str) -> bool {
    let source = unwrapped_static_expression(source);
    if is_static_string_literal(source) {
        return true;
    }
    let operators = top_level_static_operators(source);
    let pluses = operators
        .into_iter()
        .filter(|offset| source.as_bytes()[*offset] == b'+')
        .collect::<Vec<_>>();
    if pluses.is_empty() {
        return false;
    }
    let mut start = 0;
    for plus in pluses {
        if !is_static_string_literal(source[start..plus].trim()) {
            return false;
        }
        start = plus + 1;
    }
    is_static_string_literal(source[start..].trim())
}

fn is_allowlist_guarded_command(source: &str, open: usize, command: &str) -> bool {
    let roots = SHELL_TEMPLATE_ROOT
        .captures_iter(command)
        .filter_map(|capture| capture.get(1).map(|name| name.as_str()))
        .collect::<BTreeSet<_>>();
    if roots.is_empty() {
        return false;
    }
    let prefix = &source[..open];
    let scope = prefix
        .rfind("function ")
        .map_or(prefix, |start| &prefix[start..]);
    let guarded = SHELL_ALLOWLIST_GUARD
        .captures_iter(scope)
        .filter_map(|capture| capture.get(1).map(|name| name.as_str()))
        .collect::<BTreeSet<_>>();
    roots.is_subset(&guarded)
}

fn line_number(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn analyze_style(line: &SourceLine<'_>, findings: &mut Vec<Finding>) {
    if line.typescript && uses_explicit_any(line.syntax_line) {
        line.add(findings, "ts-any", "explicit any type used");
    }
    if line.typescript && uses_non_null_assertion(line.syntax_line) {
        line.add(findings, "ts-non-null-assertion", "non-null assertion used");
    }
    if leaves_console_logging(line) {
        line.add(findings, "ts-console", "console logging left in code");
    }
    if line.line == "debugger;" {
        line.add(findings, "ts-debugger", "debugger statement left in code");
    }
}

fn uses_explicit_any(line: &str) -> bool {
    line.contains(": any") || line.contains("<any>") || line.contains(" as any")
}

fn uses_non_null_assertion(line: &str) -> bool {
    line.contains('!') && NON_NULL_ASSERTION.is_match(line) && !line.starts_with("if ")
}

fn leaves_console_logging(line: &SourceLine<'_>) -> bool {
    !line.tooling
        && !line.command_line
        && (line.line.contains("console.log(") || line.line.contains("console.debug("))
}

fn analyze_execution_sinks(line: &SourceLine<'_>, findings: &mut Vec<Finding>) {
    if uses_direct_eval(line) || uses_dynamic_function_constructor(line) {
        line.add(findings, "ts-eval", "dynamic JavaScript execution used");
    }
    if uses_string_timer(line) {
        line.add(
            findings,
            "ts-string-timer-code-execution",
            "timer executes source text as code",
        );
    }
    if uses_unsafe_inner_html(line) {
        line.add(findings, "ts-inner-html", "raw HTML injection sink used");
    }
}

fn uses_direct_eval(line: &SourceLine<'_>) -> bool {
    line.sink_line.contains("eval")
        && (DIRECT_EVAL_CALL.is_match(line.sink_line) || GLOBAL_EVAL_CALL.is_match(line.sink_line))
        && !EVAL_FUNCTION_DECLARATION.is_match(line.sink_line)
        && !EVAL_METHOD_DECLARATION.is_match(line.sink_line)
}

fn uses_dynamic_function_constructor(line: &SourceLine<'_>) -> bool {
    line.sink_line.contains("Function")
        && NEW_FUNCTION.is_match(line.sink_line)
        && !is_static_function_constructor(line.uncommented_lines, line.index)
}

fn uses_string_timer(line: &SourceLine<'_>) -> bool {
    (line.sink_line.contains("setTimeout") || line.sink_line.contains("setInterval"))
        && has_string_timer_execution(line.uncommented_lines, line.sink_line, line.index)
}

fn uses_unsafe_inner_html(line: &SourceLine<'_>) -> bool {
    (line.sink_line.contains("innerHTML") || line.sink_line.contains("dangerouslySetInnerHTML"))
        && has_unsafe_inner_html_sink(line.uncommented_lines, line.sink_lines, line.index)
}

fn analyze_async_usage(line: &SourceLine<'_>, findings: &mut Vec<Finding>) {
    let starts_promise = (line.line.starts_with("fetch") || line.line.starts_with("axios"))
        && STARTS_PROMISE_CALL.is_match(line.line);
    if starts_promise
        && !FUNCTION_BIND_CALL.is_match(line.line)
        && !is_inside_awaited_wrapper(line.code_lines, line.index)
        && !is_implicit_arrow_return(line.code_lines, line.index)
        && !HANDLED_PROMISE.is_match(&continued_expression(line.code_lines, line.index))
    {
        line.add(
            findings,
            "ts-floating-promise",
            "promise-returning call is not awaited or returned",
        );
    }
    if line.line.starts_with("await ") && line.inside_loop {
        line.add(findings, "ts-await-in-loop", "await inside loop");
    }
}

fn analyze_hardcoded_secret(line: &SourceLine<'_>, findings: &mut Vec<Finding>) {
    let lower = line.raw.to_ascii_lowercase();
    let Some((identifier, literal, assignment_offset)) = secret_assignment(line, &lower) else {
        return;
    };
    if SECRET_IDENTIFIER.is_match(&identifier)
        && !literal.trim().is_empty()
        && !is_explicit_empty_sentinel(&identifier, &literal)
        && !is_placeholder_secret(&identifier, &literal)
        && !is_enum_member(line.code_lines, line.index, assignment_offset)
    {
        line.add(findings, "ts-hardcoded-secret", "possible hardcoded secret");
    }
}

fn secret_assignment(line: &SourceLine<'_>, lower: &str) -> Option<(String, String, usize)> {
    if !might_contain_secret_identifier(lower)
        || !line.code_line.contains('=')
        || !(line.uncommented_line.contains('"')
            || line.uncommented_line.contains('\'')
            || line.uncommented_line.contains('`'))
        || lower.contains("process.env")
        || lower.contains("import.meta.env")
    {
        return None;
    }
    hardcoded_secret_assignment(line.uncommented_line, line.code_line)
}

fn analyze_json_parsing(line: &SourceLine<'_>, findings: &mut Vec<Finding>) {
    if !line.tooling
        && line.line.contains("JSON.parse(")
        && !EMBEDDED_JSON_PARSE.is_match(line.line)
        && !JSON_ROUND_TRIP.is_match(line.line)
        && !is_parse_of_immediately_stringified_value(line.code_lines, line.index)
        && !is_inside_handled_try(line.code_lines, line.index)
        && !SAFE_JSON_NAME.is_match(line.line)
    {
        line.add(
            findings,
            "ts-json-parse-unsafe",
            "JSON.parse without obvious validation or handling",
        );
    }
    if line.line.contains("localStorage.") && line.line.contains("JSON.parse(") {
        line.add(
            findings,
            "ts-localstorage-json",
            "localStorage JSON parsed directly",
        );
    }
}

fn analyze_performance(
    line: &SourceLine<'_>,
    facts: &PerformanceFacts,
    findings: &mut Vec<Finding>,
) {
    if line.inside_loop {
        analyze_repeated_performance(line, facts, findings);
    }
    if line.inside_async
        && !SYNC_FUNCTION_DECLARATION.is_match(line.sink_line)
        && facts.calls_sync_fs(line.sink_line)
    {
        line.add(
            findings,
            "js-sync-io-in-async",
            "synchronous filesystem API is called inside async code",
        );
    }
}

fn analyze_repeated_performance(
    line: &SourceLine<'_>,
    facts: &PerformanceFacts,
    findings: &mut Vec<Finding>,
) {
    if REGEXP_CONSTRUCTOR.is_match(line.sink_line)
        && CONSTANT_REGEXP.is_match(line.uncommented_line)
    {
        line.add(
            findings,
            "js-regexp-created-in-loop",
            "constant regular expression is compiled inside a loop",
        );
    }
    if ARRAY_MEMBERSHIP
        .captures_iter(line.line)
        .any(|capture| facts.arrays.contains(&capture[1]))
    {
        line.add(
            findings,
            "js-linear-membership-in-loop",
            "linear array membership is checked inside a loop",
        );
    }
    if IN_PLACE_CONCAT
        .captures(line.sink_line)
        .is_some_and(|capture| facts.strings.contains(&capture[1]))
    {
        line.add(
            findings,
            "js-string-concat-in-loop",
            "immutable string is concatenated inside a loop",
        );
    }
    if repeatedly_copies_growing_array(line.sink_line, facts) {
        line.add(
            findings,
            "js-growing-array-copy-in-loop",
            "rebuilding an array from its previous value repeatedly copies accumulated elements",
        );
    }
    if ARRAY_SHIFT
        .captures_iter(line.line)
        .any(|capture| facts.arrays.contains(&capture[1]))
    {
        line.add(
            findings,
            "js-array-shift-in-loop",
            "removing the first array element repeatedly shifts the remaining elements",
        );
    }
    if ARRAY_UNSHIFT
        .captures_iter(line.line)
        .any(|capture| facts.arrays.contains(&capture[1]))
    {
        line.add(
            findings,
            "js-array-unshift-in-loop",
            "inserting at the front of an array repeatedly shifts existing elements",
        );
    }
}

fn repeatedly_copies_growing_array(line: &str, facts: &PerformanceFacts) -> bool {
    GROWING_ARRAY_SPREAD
        .captures_iter(line)
        .any(|capture| capture[1] == capture[2] && facts.outer_arrays.contains(&capture[1]))
        || GROWING_ARRAY_CONCAT
            .captures_iter(line)
            .any(|capture| capture[1] == capture[2] && facts.outer_arrays.contains(&capture[1]))
}

fn node_fs_constant_imports(path: &str, source: &str) -> Vec<Finding> {
    NODE_FS_IMPORT
        .captures_iter(source)
        .filter_map(|capture| {
            let imports = capture.get(1)?.as_str();
            let mut invalid = imports
                .split(',')
                .filter_map(|item| {
                    let imported = AS_ALIAS.split(item.trim()).next().unwrap_or("").trim();
                    matches!(imported, "F_OK" | "R_OK" | "W_OK" | "X_OK")
                        .then(|| imported.to_owned())
                })
                .collect::<Vec<_>>();
            invalid.sort();
            invalid.dedup();
            if invalid.is_empty() {
                return None;
            }
            let matched = capture.get(0)?;
            let line = source[..matched.start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            Some(finding(
                "js-node-fs-constant-import",
                path,
                line,
                0,
                &format!(
                    "Node file-access constants must use fs.constants: {}",
                    invalid.join(", ")
                ),
                "high",
            ))
        })
        .collect()
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    end_line: usize,
    message: &str,
    confidence: &str,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("TypeScript rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

fn is_javascript(path: &str) -> bool {
    [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn is_typescript(path: &str) -> bool {
    [".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn is_tooling_source(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized == "gulpfile.js" || TOOLING_PATH.is_match(&normalized)
}

fn is_node_command_line(source: &str) -> bool {
    source
        .split('\n')
        .next()
        .is_some_and(|line| NODE_SHEBANG.is_match(line.trim()))
}

fn might_contain_secret_identifier(line: &str) -> bool {
    [
        "token", "secret", "password", "passwd", "api_key", "apikey", "nonce", "salt",
    ]
    .iter()
    .any(|candidate| line.contains(candidate))
}

fn hardcoded_secret_assignment(uncommented: &str, code: &str) -> Option<(String, String, usize)> {
    if let Some(capture) = LITERAL_ASSIGNMENT.captures(code) {
        let whole = capture.get(0)?;
        let identifier = capture.get(1)?.as_str();
        let literal = capture.get(2)?.as_str();
        if assignment_has_valid_end(&code[whole.end()..]) {
            return Some((identifier.to_owned(), literal.to_owned(), whole.start() + 1));
        }
    }
    let capture = TEMPLATE_ASSIGNMENT.captures(uncommented)?;
    let whole = capture.get(0)?;
    let identifier = capture.get(1)?.as_str();
    let literal = capture.get(2)?.as_str();
    if !assignment_has_valid_end(&uncommented[whole.end()..]) || has_template_interpolation(literal)
    {
        return None;
    }
    let masked = MASKED_TEMPLATE_ASSIGNMENT.captures(code)?;
    let masked_identifier = masked.get(1)?.as_str();
    (masked_identifier == identifier)
        .then(|| (identifier.to_owned(), literal.to_owned(), whole.start() + 1))
}

fn assignment_has_valid_end(suffix: &str) -> bool {
    suffix.trim_start().is_empty() || suffix.trim_start().starts_with([';', ','])
}

fn has_template_interpolation(literal: &str) -> bool {
    let mut escaped = false;
    let characters = literal.chars().collect::<Vec<_>>();
    for index in 0..characters.len().saturating_sub(1) {
        if escaped {
            escaped = false;
        } else if characters[index] == '\\' {
            escaped = true;
        } else if characters[index] == '$' && characters[index + 1] == '{' {
            return true;
        }
    }
    false
}

fn is_placeholder_secret(identifier: &str, literal: &str) -> bool {
    let normalized = literal
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "test" | "example" | "placeholder" | "changeme"
    ) || PLACEHOLDER_SECRET.is_match(&normalized)
        || (identifier.to_ascii_lowercase().starts_with("test") && normalized == "test")
}

fn is_explicit_empty_sentinel(identifier: &str, literal: &str) -> bool {
    identifier.to_ascii_lowercase().starts_with("empty")
        && matches!(
            literal.trim().to_ascii_lowercase().as_str(),
            "empty" | "_empty" | "empty_" | "_empty_"
        )
}

struct EnumContext {
    open_blocks: Vec<bool>,
}

impl EnumContext {
    fn new() -> Self {
        Self {
            open_blocks: Vec::new(),
        }
    }

    fn consume_line(&mut self, code: &str, previous_line: Option<&str>, limit: usize) {
        for (offset, character) in code[..limit].char_indices() {
            match character {
                '}' => {
                    self.open_blocks.pop();
                }
                '{' => self
                    .open_blocks
                    .push(opening_block_is_enum(code, offset, previous_line)),
                _ => {}
            }
        }
    }

    fn is_inside_enum(&self) -> bool {
        self.open_blocks.iter().any(|is_enum| *is_enum)
    }
}

fn opening_block_is_enum(code: &str, offset: usize, previous_line: Option<&str>) -> bool {
    let prefix = code[..offset].trim_end();
    if !prefix.is_empty() {
        return ENUM_PREFIX.is_match(prefix);
    }
    previous_line.is_some_and(|line| ENUM_PREFIX.is_match(strip_literals(line).trim_end()))
}

fn is_enum_member(lines: &[&str], index: usize, assignment_offset: usize) -> bool {
    let mut context = EnumContext::new();
    for (line_index, line) in lines.iter().enumerate().take(index + 1) {
        let code = strip_literals(line);
        let limit = if line_index == index {
            assignment_offset.min(code.len())
        } else {
            code.len()
        };
        context.consume_line(
            &code,
            line_index
                .checked_sub(1)
                .and_then(|previous| lines.get(previous).copied()),
            limit,
        );
    }
    context.is_inside_enum()
}

fn is_implicit_arrow_return(lines: &[&str], index: usize) -> bool {
    lines[..index]
        .iter()
        .rev()
        .map(|line| strip_literals(line))
        .map(|line| line.trim().to_owned())
        .find(|line| !line.is_empty())
        .is_some_and(|line| line.ends_with("=>"))
}

fn is_inside_awaited_wrapper(lines: &[&str], index: usize) -> bool {
    for line in lines[..index].iter().rev() {
        let previous = strip_literals(line).trim().to_owned();
        if previous.is_empty() {
            continue;
        }
        if previous.ends_with(';') || previous == "}" {
            return false;
        }
        if AWAITED_WRAPPER.is_match(&previous) {
            return true;
        }
    }
    false
}

fn continued_expression(lines: &[&str], start: usize) -> String {
    let mut expression = String::new();
    let mut depth = 0_i32;
    for (index, line) in lines.iter().enumerate().skip(start) {
        let code = strip_literals(line);
        if !expression.is_empty() {
            expression.push('\n');
        }
        expression.push_str(&code);
        for character in code.chars() {
            match character {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
        }
        if depth > 0 {
            continue;
        }
        if code.trim_end().ends_with(';') {
            break;
        }
        let next = lines[index + 1..]
            .iter()
            .map(|line| strip_literals(line))
            .map(|line| line.trim().to_owned())
            .find(|line| !line.is_empty());
        if next.as_deref().is_none_or(|line| !line.starts_with('.')) {
            break;
        }
    }
    expression
}

#[derive(Clone, Copy)]
struct Block {
    function: bool,
    loop_block: bool,
    async_function: bool,
}

impl Block {
    fn from_prefix(prefix: &str) -> Self {
        let async_function = ASYNC_FUNCTION_PREFIX.is_match(prefix);
        Self {
            function: FUNCTION_PREFIX.is_match(prefix) || async_function,
            loop_block: LOOP_PREFIX.is_match(prefix) || DO_PREFIX.is_match(prefix),
            async_function,
        }
    }
}

#[derive(Default)]
struct LoopLineState {
    blocks: Vec<Block>,
}

impl LoopLineState {
    fn is_inside_loop(&self) -> bool {
        self.blocks
            .iter()
            .rev()
            .take_while(|block| !block.function)
            .any(|block| block.loop_block)
    }

    fn is_inside_async(&self) -> bool {
        self.blocks
            .iter()
            .rev()
            .find(|block| block.function)
            .is_some_and(|block| block.async_function)
    }

    fn consume_line(&mut self, line: &str, previous_line: Option<&str>) {
        let code = strip_literals(line);
        for (offset, character) in code.char_indices() {
            match character {
                '}' => {
                    self.blocks.pop();
                }
                '{' => self
                    .blocks
                    .push(block_for_opening_brace(&code, offset, previous_line)),
                _ => {}
            }
        }
    }
}

fn block_for_opening_brace(code: &str, offset: usize, previous_line: Option<&str>) -> Block {
    let prefix = code[..offset].trim_end();
    if !prefix.is_empty() {
        return Block::from_prefix(prefix);
    }
    let previous = previous_line.map(strip_literals);
    Block::from_prefix(previous.as_deref().map(str::trim_end).unwrap_or(prefix))
}

fn scopes_by_line(lines: &[&str]) -> (Vec<bool>, Vec<bool>) {
    let mut state = LoopLineState::default();
    let mut loops = Vec::with_capacity(lines.len());
    let mut async_scopes = Vec::with_capacity(lines.len());
    for (line_index, line) in lines.iter().enumerate() {
        loops.push(state.is_inside_loop());
        async_scopes.push(state.is_inside_async());
        let previous_line = line_index
            .checked_sub(1)
            .and_then(|index| lines.get(index))
            .copied();
        state.consume_line(line, previous_line);
    }
    (loops, async_scopes)
}

fn is_inside_handled_try(lines: &[&str], index: usize) -> bool {
    let structural = lines
        .iter()
        .map(|line| strip_literals(line))
        .collect::<Vec<_>>();
    let Some(offset_in_line) = structural[index].find("JSON.parse(") else {
        return false;
    };
    let parse_offset = structural[..index]
        .iter()
        .map(|line| line.len() + 1)
        .sum::<usize>()
        + offset_in_line;
    let source = without_comments(&structural.join("\n"));
    let bytes = source.as_bytes();
    let mut opens = Vec::new();
    for (offset, byte) in bytes.iter().enumerate().take(parse_offset) {
        if *byte == b'{' {
            opens.push(offset);
        } else if *byte == b'}' {
            opens.pop();
        }
    }
    for open in opens.into_iter().rev() {
        if !TRY_PREFIX.is_match(&source[..open]) {
            continue;
        }
        let Some(close) = matching_block_close(&source, open) else {
            continue;
        };
        if CATCH_SUFFIX.is_match(&source[close + 1..]) {
            return true;
        }
    }
    false
}

fn matching_block_close(source: &str, open: usize) -> Option<usize> {
    matching_delimiter(source, open, b'{', b'}')
}

fn matching_delimiter(source: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    if source.as_bytes().get(open) != Some(&opening) {
        return None;
    }
    let mut depth = 0;
    for (offset, byte) in source.bytes().enumerate().skip(open) {
        if byte == opening {
            depth += 1;
        } else if byte == closing {
            depth -= 1;
            if depth == 0 {
                return Some(offset);
            }
        }
    }
    None
}

fn is_parse_of_immediately_stringified_value(lines: &[&str], index: usize) -> bool {
    let Some(line) = lines.get(index) else {
        return false;
    };
    let Some(capture) = JSON_PARSE_VARIABLE.captures(line) else {
        return false;
    };
    let Some(target) = capture
        .get(1)
        .map(|matched| regex::escape(matched.as_str()))
    else {
        return false;
    };
    let Ok(pattern) = Regex::new(&format!(
        r"(?:^|[;{{])\s*{target}\s*=\s*JSON\.stringify\s*\("
    )) else {
        return false;
    };
    lines[..index]
        .iter()
        .rev()
        .map(|line| line.trim())
        .find(|line| !line.is_empty())
        .is_some_and(|line| pattern.is_match(line))
}

fn has_string_timer_execution(lines: &[&str], code_line: &str, index: usize) -> bool {
    let Some(matched) = TIMER_CALL.find(code_line) else {
        return false;
    };
    let Some(raw_match) = TIMER_CALL.find(lines[index]) else {
        return false;
    };
    if matched.start() > 0 && code_line.as_bytes()[matched.start() - 1] == b'.' {
        return false;
    }
    if raw_match.start() > 0 && lines[index].as_bytes()[raw_match.start() - 1] == b'.' {
        return false;
    }
    let source = lines[index..lines.len().min(index + 20)].join("\n");
    source[raw_match.end()..]
        .trim_start()
        .starts_with(['"', '\'', '`'])
}

#[derive(Clone, Copy)]
enum DelimiterPolicy {
    Parentheses,
    Grouping,
}

impl DelimiterPolicy {
    fn is_opening(self, character: char) -> bool {
        match self {
            Self::Parentheses => character == '(',
            Self::Grouping => matches!(character, '(' | '[' | '{'),
        }
    }

    fn is_closing(self, character: char) -> bool {
        match self {
            Self::Parentheses => character == ')',
            Self::Grouping => matches!(character, ')' | ']' | '}'),
        }
    }
}

#[derive(Default)]
struct DelimiterState {
    quote: Option<char>,
    escaped: bool,
    depth: i32,
}

impl DelimiterState {
    fn inside(depth: i32) -> Self {
        Self {
            depth,
            ..Self::default()
        }
    }

    fn is_code(&self) -> bool {
        self.quote.is_none()
    }

    fn consume(&mut self, character: char, policy: DelimiterPolicy) -> bool {
        if self.consume_quoted(character) {
            return false;
        }
        if matches!(character, '"' | '\'' | '`') {
            self.quote = Some(character);
        } else if policy.is_opening(character) {
            self.depth += 1;
        } else if policy.is_closing(character) {
            self.depth -= 1;
            return self.depth == 0;
        }
        false
    }

    fn consume_quoted(&mut self, character: char) -> bool {
        let Some(delimiter) = self.quote else {
            return false;
        };
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == delimiter {
            self.quote = None;
        }
        true
    }
}

#[derive(Clone, Copy, Default)]
enum StaticLiteralState {
    #[default]
    LeadingWhitespace,
    Quoted {
        delimiter: char,
        escaped: bool,
        previous_dollar: bool,
    },
    TrailingWhitespace,
    Invalid,
}

impl StaticLiteralState {
    fn consume(&mut self, character: char) {
        *self = match *self {
            Self::LeadingWhitespace => Self::start(character),
            Self::Quoted {
                delimiter,
                escaped,
                previous_dollar,
            } => Self::continue_quoted(character, delimiter, escaped, previous_dollar),
            Self::TrailingWhitespace if character.is_whitespace() => Self::TrailingWhitespace,
            Self::TrailingWhitespace | Self::Invalid => Self::Invalid,
        };
    }

    fn start(character: char) -> Self {
        match character {
            character if character.is_whitespace() => Self::LeadingWhitespace,
            delimiter @ ('"' | '\'' | '`') => Self::Quoted {
                delimiter,
                escaped: false,
                previous_dollar: false,
            },
            _ => Self::Invalid,
        }
    }

    fn continue_quoted(
        character: char,
        delimiter: char,
        escaped: bool,
        previous_dollar: bool,
    ) -> Self {
        if escaped {
            return Self::quoted(delimiter, false, false);
        }
        if character == '\\' {
            return Self::quoted(delimiter, true, false);
        }
        if delimiter == '`' && previous_dollar && character == '{' {
            return Self::Invalid;
        }
        if character == delimiter {
            return Self::TrailingWhitespace;
        }
        Self::quoted(delimiter, false, character == '$')
    }

    fn quoted(delimiter: char, escaped: bool, previous_dollar: bool) -> Self {
        Self::Quoted {
            delimiter,
            escaped,
            previous_dollar,
        }
    }

    fn is_empty(self) -> bool {
        matches!(self, Self::LeadingWhitespace)
    }

    fn is_complete(self) -> bool {
        matches!(self, Self::TrailingWhitespace)
    }
}

#[derive(Default)]
struct StaticArgumentState {
    current: StaticLiteralState,
    has_separator: bool,
}

impl StaticArgumentState {
    fn consume(&mut self, character: char) {
        self.current.consume(character);
    }

    fn separate(&mut self) -> bool {
        if !self.current.is_complete() {
            return false;
        }
        self.current = StaticLiteralState::default();
        self.has_separator = true;
        true
    }

    fn is_complete(&self) -> bool {
        (!self.has_separator && self.current.is_empty()) || self.current.is_complete()
    }
}

fn is_static_function_constructor(lines: &[&str], index: usize) -> bool {
    let source = lines[index..lines.len().min(index + 20)].join("\n");
    let Some(start) = NEW_FUNCTION.find(&source) else {
        return false;
    };
    has_only_static_function_arguments(&source[start.end()..])
}

fn has_only_static_function_arguments(source: &str) -> bool {
    let mut delimiters = DelimiterState::inside(1);
    let mut arguments = StaticArgumentState::default();
    for character in source.chars() {
        let separates_arguments = delimiters.is_code() && character == ',';
        if delimiters.consume(character, DelimiterPolicy::Grouping) {
            return arguments.is_complete();
        }
        if separates_arguments {
            if !arguments.separate() {
                return false;
            }
        } else {
            arguments.consume(character);
        }
    }
    false
}

fn has_unsafe_inner_html_sink(raw_lines: &[&str], code_lines: &[&str], index: usize) -> bool {
    let code = code_lines[index];
    if code.contains("dangerouslySetInnerHTML") || INNER_HTML_UPDATE.is_match(code) {
        return true;
    }
    let Some(assignment) = INNER_HTML_ASSIGNMENT.find(code) else {
        return false;
    };
    let right_hand_side = inner_html_right_hand_side(raw_lines, index, assignment.end());
    !is_static_inner_html_expression(&right_hand_side)
}

struct InnerHtmlExpression {
    result: String,
    quote: Option<char>,
    escaped: bool,
    parentheses: i32,
    brackets: i32,
    braces: i32,
    ternaries: i32,
}

impl InnerHtmlExpression {
    fn new() -> Self {
        Self {
            result: String::new(),
            quote: None,
            escaped: false,
            parentheses: 0,
            brackets: 0,
            braces: 0,
            ternaries: 0,
        }
    }

    fn consume_line(&mut self, line: &str, start: usize) -> bool {
        for character in line[start..].chars() {
            if self.consume_character(character) {
                return true;
            }
        }
        false
    }

    fn consume_character(&mut self, character: char) -> bool {
        if let Some(delimiter) = self.quote {
            self.consume_quoted(character, delimiter);
            return false;
        }
        match character {
            '"' | '\'' | '`' => self.quote = Some(character),
            '(' => self.parentheses += 1,
            ')' => self.parentheses -= 1,
            '[' => self.brackets += 1,
            ']' => self.brackets -= 1,
            '{' => self.braces += 1,
            '}' => self.braces -= 1,
            ';' if self.at_top_level() => return true,
            '?' if self.at_top_level() => self.ternaries += 1,
            ':' if self.at_top_level() && self.ternaries > 0 => self.ternaries -= 1,
            _ => {}
        }
        self.result.push(character);
        false
    }

    fn consume_quoted(&mut self, character: char, delimiter: char) {
        self.result.push(character);
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == delimiter {
            self.quote = None;
        }
    }

    fn at_top_level(&self) -> bool {
        self.parentheses == 0 && self.brackets == 0 && self.braces == 0
    }

    fn completed_expression(&self) -> Option<String> {
        let collected = self.result.trim_end();
        (self.quote.is_none()
            && self.at_top_level()
            && self.ternaries == 0
            && !collected.is_empty()
            && !STATIC_EXPRESSION_CONTINUATION.is_match(collected))
        .then(|| collected.to_owned())
    }
}

fn inner_html_right_hand_side(
    lines: &[&str],
    assignment_line: usize,
    assignment_end: usize,
) -> String {
    let mut expression = InnerHtmlExpression::new();
    for (line_index, line) in lines.iter().enumerate().skip(assignment_line) {
        let start = if line_index == assignment_line {
            assignment_end
        } else {
            0
        };
        if expression.consume_line(line, start) {
            return expression.result;
        }
        if let Some(completed) = expression.completed_expression() {
            return completed;
        }
        expression.result.push('\n');
    }
    expression.result
}

fn is_static_inner_html_expression(source: &str) -> bool {
    let expression = unwrapped_static_expression(source);
    if is_directly_static_inner_html_expression(expression) {
        return true;
    }
    if is_static_trusted_html_expression(expression) {
        return true;
    }
    let operators = top_level_static_operators(expression);
    static_ternary_expression(expression, &operators)
        .unwrap_or_else(|| is_static_concatenation(expression, &operators))
}

fn unwrapped_static_expression(source: &str) -> &str {
    let mut expression = source.trim();
    while has_wrapping_parentheses(expression) {
        expression = expression[1..expression.len() - 1].trim();
    }
    expression
}

fn is_directly_static_inner_html_expression(expression: &str) -> bool {
    !expression.is_empty()
        && (is_static_string_literal(expression)
            || STATIC_PRIMITIVE.is_match(expression)
            || STATIC_STRING_TERNARY.is_match(expression))
}

fn is_static_trusted_html_expression(expression: &str) -> bool {
    TRUSTED_HTML
        .captures(expression)
        .is_some_and(|capture| is_static_inner_html_expression(&capture[1]))
}

fn static_ternary_expression(expression: &str, operators: &[usize]) -> Option<bool> {
    let question_index = operators
        .iter()
        .position(|offset| expression.as_bytes()[*offset] == b'?')?;
    let question = operators[question_index];
    let Some(colon) = matching_ternary_colon(expression, &operators[question_index + 1..]) else {
        return Some(false);
    };
    Some(
        !expression[..question].trim().is_empty()
            && is_static_inner_html_expression(&expression[question + 1..colon])
            && is_static_inner_html_expression(&expression[colon + 1..]),
    )
}

fn matching_ternary_colon(expression: &str, operators: &[usize]) -> Option<usize> {
    let mut nested = 0;
    for offset in operators.iter().copied() {
        match expression.as_bytes()[offset] {
            b'?' => nested += 1,
            b':' if nested > 0 => nested -= 1,
            b':' => return Some(offset),
            _ => {}
        }
    }
    None
}

fn is_static_concatenation(expression: &str, operators: &[usize]) -> bool {
    let mut start = 0;
    let mut found_plus = false;
    for plus in operators
        .iter()
        .copied()
        .filter(|offset| expression.as_bytes()[*offset] == b'+')
    {
        found_plus = true;
        if !is_static_inner_html_expression(&expression[start..plus]) {
            return false;
        }
        start = plus + 1;
    }
    found_plus && is_static_inner_html_expression(&expression[start..])
}

#[derive(Default)]
struct StaticOperatorScanner {
    operators: Vec<usize>,
    quote: Option<char>,
    escaped: bool,
    depth: i32,
}

impl StaticOperatorScanner {
    fn scan(source: &str) -> Vec<usize> {
        let bytes = source.as_bytes();
        let mut scanner = Self::default();
        for (index, character) in source.char_indices() {
            scanner.consume(index, character, bytes);
        }
        scanner.operators
    }

    fn consume(&mut self, index: usize, character: char, bytes: &[u8]) {
        if let Some(delimiter) = self.quote {
            self.consume_quoted(character, delimiter);
            return;
        }
        match character {
            '"' | '\'' | '`' => self.quote = Some(character),
            '(' | '[' | '{' => self.depth += 1,
            ')' | ']' | '}' => self.depth -= 1,
            '+' | ':' | '?' if self.depth == 0 && is_static_operator(index, character, bytes) => {
                self.operators.push(index);
            }
            _ => {}
        }
    }

    fn consume_quoted(&mut self, character: char, delimiter: char) {
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == delimiter {
            self.quote = None;
        }
    }
}

fn is_static_operator(index: usize, character: char, bytes: &[u8]) -> bool {
    character != '?'
        || index + 1 >= bytes.len()
        || (bytes[index + 1] != b'?' && bytes[index + 1] != b'.')
}

fn top_level_static_operators(source: &str) -> Vec<usize> {
    StaticOperatorScanner::scan(source)
}

fn has_wrapping_parentheses(source: &str) -> bool {
    if source.len() < 2 || !source.starts_with('(') || !source.ends_with(')') {
        return false;
    }
    let mut delimiters = DelimiterState::default();
    for (index, character) in source.char_indices() {
        if delimiters.consume(character, DelimiterPolicy::Parentheses) {
            return index == source.len() - 1;
        }
    }
    false
}

fn is_static_string_literal(source: &str) -> bool {
    let mut literal = StaticLiteralState::default();
    for character in source.chars() {
        literal.consume(character);
    }
    literal.is_complete()
}

#[derive(Clone, Copy)]
enum CommentMaskState {
    Code,
    Quoted { delimiter: char, escaped: bool },
    LineComment,
    BlockComment,
}

impl CommentMaskState {
    fn consume(self, character: char, next: Option<char>, result: &mut String) -> (Self, bool) {
        match self {
            Self::Code => Self::consume_code(character, next, result),
            Self::Quoted { delimiter, escaped } => {
                result.push(character);
                (Self::quoted_state(delimiter, escaped, character), false)
            }
            Self::LineComment => {
                Self::consume_line_comment(character, result);
                (
                    if character == '\n' {
                        Self::Code
                    } else {
                        Self::LineComment
                    },
                    false,
                )
            }
            Self::BlockComment => Self::consume_block_comment(character, next, result),
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
            (delimiter @ ('"' | '\'' | '`'), _) => {
                result.push(character);
                (
                    Self::Quoted {
                        delimiter,
                        escaped: false,
                    },
                    false,
                )
            }
            _ => {
                result.push(character);
                (Self::Code, false)
            }
        }
    }

    fn quoted_state(delimiter: char, escaped: bool, character: char) -> Self {
        if escaped {
            Self::Quoted {
                delimiter,
                escaped: false,
            }
        } else if character == '\\' {
            Self::Quoted {
                delimiter,
                escaped: true,
            }
        } else if character == delimiter {
            Self::Code
        } else {
            Self::Quoted {
                delimiter,
                escaped: false,
            }
        }
    }

    fn consume_line_comment(character: char, result: &mut String) {
        if character == '\n' {
            result.push('\n');
        } else {
            Self::push_mask(character, result);
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
            Self::consume_line_comment(character, result);
            (Self::BlockComment, false)
        }
    }

    fn push_mask(character: char, result: &mut String) {
        for _ in 0..character.len_utf8() {
            result.push(' ');
        }
    }
}

fn without_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut state = CommentMaskState::Code;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        let (next_state, consume_next) =
            state.consume(character, characters.peek().copied(), &mut result);
        state = next_state;
        if consume_next {
            characters.next();
        }
    }
    result
}

#[derive(Clone, Copy)]
struct TemplateLiteralMaskState {
    in_template: bool,
    escaped: bool,
}

impl TemplateLiteralMaskState {
    fn new() -> Self {
        Self {
            in_template: false,
            escaped: false,
        }
    }

    fn consume(&mut self, character: char, result: &mut String) {
        if self.in_template {
            self.consume_template(character, result);
        } else {
            self.consume_code(character, result);
        }
    }

    fn consume_code(&mut self, character: char, result: &mut String) {
        if character == '`' {
            self.in_template = true;
            result.push(' ');
        } else {
            result.push(character);
        }
    }

    fn consume_template(&mut self, character: char, result: &mut String) {
        if character == '\n' {
            result.push('\n');
            self.escaped = false;
            return;
        }
        result.push(' ');
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == '`' {
            self.in_template = false;
        }
    }
}

fn without_template_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut state = TemplateLiteralMaskState::new();
    for character in source.chars() {
        state.consume(character, &mut result);
    }
    result
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LiteralMaskMode {
    Code,
    SingleQuoted,
    DoubleQuoted,
    Template,
}

struct LiteralMaskState {
    mode: LiteralMaskMode,
    template_return_depths: Vec<usize>,
    interpolation_depth: usize,
    escaped: bool,
}

impl LiteralMaskState {
    fn new() -> Self {
        Self {
            mode: LiteralMaskMode::Code,
            template_return_depths: Vec::new(),
            interpolation_depth: 0,
            escaped: false,
        }
    }

    fn consume(&mut self, characters: &[char], index: usize, result: &mut String) -> usize {
        match self.mode {
            LiteralMaskMode::Code => self.consume_code(characters[index], result),
            LiteralMaskMode::SingleQuoted => {
                self.consume_quoted(characters[index], '\'', result);
                1
            }
            LiteralMaskMode::DoubleQuoted => {
                self.consume_quoted(characters[index], '"', result);
                1
            }
            LiteralMaskMode::Template => self.consume_template(characters, index, result),
        }
    }

    fn consume_code(&mut self, character: char, result: &mut String) -> usize {
        match character {
            '\'' => {
                self.mode = LiteralMaskMode::SingleQuoted;
                result.push(' ');
            }
            '"' => {
                self.mode = LiteralMaskMode::DoubleQuoted;
                result.push(' ');
            }
            '`' => {
                self.template_return_depths.push(self.interpolation_depth);
                self.mode = LiteralMaskMode::Template;
                result.push(' ');
            }
            '{' if self.interpolation_depth > 0 => {
                self.interpolation_depth += 1;
                result.push(character);
            }
            '}' if self.interpolation_depth > 0 => {
                self.interpolation_depth -= 1;
                if self.interpolation_depth == 0 {
                    self.mode = LiteralMaskMode::Template;
                    result.push(' ');
                } else {
                    result.push(character);
                }
            }
            _ => result.push(character),
        }
        1
    }

    fn consume_quoted(&mut self, character: char, delimiter: char, result: &mut String) {
        if character == '\n' {
            result.push('\n');
            self.escaped = false;
            return;
        }
        result.push(' ');
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == delimiter {
            self.mode = LiteralMaskMode::Code;
        }
    }

    fn consume_template(
        &mut self,
        characters: &[char],
        index: usize,
        result: &mut String,
    ) -> usize {
        let character = characters[index];
        if character == '\n' {
            result.push('\n');
            self.escaped = false;
            return 1;
        }
        if !self.escaped && character == '$' && characters.get(index + 1).copied() == Some('{') {
            result.push_str("  ");
            self.mode = LiteralMaskMode::Code;
            self.interpolation_depth = 1;
            return 2;
        }
        result.push(' ');
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == '`' {
            self.mode = LiteralMaskMode::Code;
            self.interpolation_depth = self.template_return_depths.pop().unwrap_or(0);
        }
        1
    }
}

fn without_string_literal_text(source: &str) -> String {
    let characters = source.chars().collect::<Vec<_>>();
    let mut result = String::with_capacity(source.len());
    let mut state = LiteralMaskState::new();
    let mut index = 0;
    while index < characters.len() {
        index += state.consume(&characters, index, &mut result);
    }
    result
}

static ARRAY_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z_$][\w$]*)\s*(?::\s*(?:(?:readonly\s+)?[A-Za-z_$][\w$]*\s*\[\]|(?:Readonly)?Array\s*<[^>\n]+>)\s*(?:=[^;\n,)]+)?|=\s*\[)",
    )
    .unwrap()
});
static STRING_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\b(?:\s*=[^;\n]+)?|=\s*(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'))"#,
    )
    .unwrap()
});
static CONSTANT_REGEXP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bnew\s+RegExp\s*\(\s*[\"']"#).unwrap());
static REGEXP_CONSTRUCTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+RegExp\s*\(").unwrap());
static ARRAY_MEMBERSHIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(?:includes|indexOf)\s*\(").unwrap());
static ARRAY_SHIFT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\.\s*shift\s*\(\s*\)").unwrap());
static ARRAY_UNSHIFT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\.\s*unshift\s*\(").unwrap());
static REDUCE_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.\s*reduce\s*\(").unwrap());
static BUFFER_CONCAT_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*Buffer\s*\.\s*concat\s*\(\s*\[").unwrap()
});
static INTL_FORMATTER_CONSTRUCTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bnew\s+Intl\s*\.\s*(?:DateTimeFormat|NumberFormat|Collator)\s*\(").unwrap()
});
static LOCALE_FORMAT_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\s*toLocale(?:String|DateString|TimeString)\s*\(").unwrap());
static FILTER_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\.\s*filter\s*\(").unwrap());
static FILTER_FIRST_ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:\[\s*0\s*\]|\.\s*(?:shift|pop)\s*\(\s*\)|\.\s*at\s*\(\s*(?:0|-1)\s*\))")
        .unwrap()
});
static SPREAD_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\.\.\s*([A-Za-z_$][\w$]*)").unwrap());
static JAVASCRIPT_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*$").unwrap());
static JAVASCRIPT_IDENTIFIER_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*").unwrap());
static IN_PLACE_CONCAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\+=").unwrap());
static GROWING_ARRAY_SPREAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*\[\s*\.\.\.\s*([A-Za-z_$][\w$]*)\b").unwrap()
});
static GROWING_ARRAY_CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*concat\s*\(").unwrap()
});
static CALL_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?\s*\(").unwrap()
});
static NODE_FS_NAMESPACE_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*[\"'](?:node:)?fs[\"']"#)
        .unwrap()
});
static NODE_FS_REQUIRE_DESTRUCTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*[\"'](?:node:)?fs[\"']\s*\)"#,
    )
    .unwrap()
});
static NODE_FS_REQUIRE_NAMESPACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*[\"'](?:node:)?fs[\"']\s*\)"#,
    )
    .unwrap()
});
static ASYNC_FUNCTION_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\basync\b(?:\s+function\b[^{}]*|\s+[A-Za-z_$][\w$]*\s*\([^{}]*\)|[^{}]*=>)\s*$")
        .unwrap()
});
static SYNC_FUNCTION_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*function(?:\s*\*)?\s+[A-Za-z_$][\w$]*\s*\(").unwrap());
static NON_NULL_ASSERTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_$)\]}]!\s*(?:\.|\)|;|,|\])").unwrap());
static DIRECT_EVAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^\w$?.])eval\s*\(").unwrap());
static GLOBAL_EVAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:globalThis|window)\s*\.\s*eval\s*\(").unwrap());
static EVAL_FUNCTION_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfunction\s*\*?\s+eval\s*\(").unwrap());
static EVAL_METHOD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:public|private|protected|static|abstract|async|override)\s+)*eval\s*\([^)]*\)\s*(?:(?::[^\{]+)?\{|:[^;]+;)").unwrap()
});
static NEW_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+Function\s*\(").unwrap());
static STARTS_PROMISE_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:fetch\s*\(|axios(?:\.[A-Za-z_$][\w$]*)*\s*\()").unwrap());
static FUNCTION_BIND_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.bind\s*\(").unwrap());
static HANDLED_PROMISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:await|return|void)\b|\.(?:then|catch|subscribe)\s*\(").unwrap()
});
static TIMER_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:window|globalThis)\s*\.\s*)?(?:setTimeout|setInterval)\s*\(").unwrap()
});
static EMBEDDED_JSON_PARSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"JSON\.parse\(\s*document\.(?:querySelector|getElementById)\([^)]*\)\.(?:innerText|textContent)\s*\)").unwrap()
});
static JSON_ROUND_TRIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"JSON\.parse\s*\(\s*JSON\.stringify\s*\(").unwrap());
static SAFE_JSON_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:safe|schema|zod|validate)\b").unwrap());
static JSON_PARSE_VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bJSON\.parse\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\)").unwrap()
});
static INNER_HTML_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\binnerHTML\s*(?:\?\?=|&&=|\|\|=|\*\*=|>>>=|<<=|>>=|[+\-*/%&|^]=|=(?:[^=>]|$))")
        .unwrap()
});
static INNER_HTML_UPDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\+\+|--)\s*[\w$.\[\]]*\.innerHTML\b|\binnerHTML\s*(?:\+\+|--)").unwrap()
});
static STATIC_EXPRESSION_CONTINUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\+|&&|\|\||\?\?|[?:])\s*$").unwrap());
static STATIC_PRIMITIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:true|false|null|-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$").unwrap()
});
static STATIC_STRING_TERNARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^[A-Za-z_$][\w$.\[\]]*\s*\?\s*(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\$]|\$(?:[^\{]|$))*`)\s*:\s*(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\$]|\$(?:[^\{]|$))*`)$"#).unwrap()
});
static TRUSTED_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:create_trusted_html|createTrustedHTML|[A-Za-z_$][\w$.\[\]]*\.createHTML)\s*\(([\s\S]*)\)$").unwrap()
});
static LITERAL_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[;{])\s*(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*=\s*[\"']([^\"']*)[\"']"#).unwrap()
});
static TEMPLATE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;{])\s*(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*=\s*`((?:\\.|[^`])*)`").unwrap()
});
static MASKED_TEMPLATE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;{])\s*(?:(?:const|let|var)\s+)?(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*=\s*(?:[;,]|$)").unwrap()
});
static SECRET_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|_)(?:token|secret|password|passwd|api_?key|nonce|salt)$|(?:Token|Secret|Password|Passwd|ApiKey|Nonce|Salt)$").unwrap()
});
static PLACEHOLDER_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?:fake|mock|dummy|test)[a-z0-9]*(?:key|token|secret|password|passwd)|(?:asdf){2,})$",
    )
    .unwrap()
});
static ENUM_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)(?:const\s+)?enum\s+[\w$]+\s*$").unwrap());
static AWAITED_WRAPPER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bawait\b.*(?:\(|\[|\{)\s*$").unwrap());
static FUNCTION_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:=>|\bfunction(?:\s*\*)?(?:\s+[\w$]+)?\s*\([^)]*\))\s*$").unwrap()
});
static LOOP_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:for\s*(?:await\s*)?|while\s*)\(").unwrap());
static DO_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdo\s*$").unwrap());
static TRY_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btry\s*$").unwrap());
static CATCH_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*catch\b").unwrap());
static ASYNC_FOREACH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\.\s*forEach\s*\(\s*async(?:\s+function\b)?")
        .expect("async forEach regex must compile")
});
static CHILD_PROCESS_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\bimport\s*\{([^}]*)\}\s*from\s*["'](?:node:)?child_process["']"#)
        .expect("child process import regex must compile")
});
static CHILD_PROCESS_REQUIRE_DESTRUCTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)"#,
    )
    .expect("child process destructuring regex must compile")
});
static CHILD_PROCESS_NAMESPACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*["'](?:node:)?child_process["']"#,
    )
    .expect("child process namespace regex must compile")
});
static CHILD_PROCESS_REQUIRE_NAMESPACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)"#,
    )
    .expect("child process require regex must compile")
});
static STATIC_COMMAND_BINDING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\r\n]+)")
        .expect("static command binding regex must compile")
});
static SHELL_TEMPLATE_ROOT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{\s*([A-Za-z_$][\w$]*)")
        .expect("shell template interpolation regex must compile")
});
static SHELL_ALLOWLIST_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)if\s*\(\s*!\s*/\^[^/\r\n]+\$/[a-z]*\.test\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\)\s*\{[^{}]*\b(?:throw|return)\b"#,
    )
    .expect("shell allowlist guard regex must compile")
});
static CHILD_PROCESS_SHELL_TRUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)(?:^|[,{])\s*shell\s*:\s*true\b")
        .expect("child process shell option regex must compile")
});
static TOOLING_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|/)(?:extra|scripts|tasks|bin|sandbox|playgrounds?|benchmarks?|benchmarking|dev)/",
    )
    .unwrap()
});
static NODE_SHEBANG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^#!\s*(?:/usr/bin/env(?:\s+-S)?\s+|/(?:usr/)?bin/)(?:node|nodejs)(?:\s|$)")
        .unwrap()
});
static NODE_FS_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)import\s*\{([^}]*)\}\s*from\s*[\"'](?:node:)?fs[\"']"#).unwrap()
});
static AS_ALIAS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+as\s+").unwrap());

#[cfg(test)]
mod tests {
    use super::{
        analyze, is_parse_of_immediately_stringified_value, is_static_string_literal,
        without_string_literal_text,
    };
    use crate::source_analysis_context::SourceAnalysisContext;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn reports_all_javascript_and_typescript_source_rules() {
        let sources = BTreeMap::from([(
            "main.ts".to_owned(),
            "import { R_OK, W_OK } from 'node:fs';\n\
const value: any = JSON.parse(input);\n\
console.log(value);\n\
debugger;\n\
eval(input);\n\
element.innerHTML = input;\n\
fetch('/api');\n\
const password = \"secret\";\n\
for (const item of items) {\n\
  await save(item);\n\
}\n\
const definite = value!.name;\n\
const cached = JSON.parse(localStorage.value);\n\
setTimeout(\"runTask()\", 10);\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "js-node-fs-constant-import".to_owned(),
                "ts-any".to_owned(),
                "ts-await-in-loop".to_owned(),
                "ts-console".to_owned(),
                "ts-debugger".to_owned(),
                "ts-eval".to_owned(),
                "ts-floating-promise".to_owned(),
                "ts-hardcoded-secret".to_owned(),
                "ts-inner-html".to_owned(),
                "ts-json-parse-unsafe".to_owned(),
                "ts-localstorage-json".to_owned(),
                "ts-non-null-assertion".to_owned(),
                "ts-string-timer-code-execution".to_owned(),
            ])
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line, finding.end_line))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("js-node-fs-constant-import", 1, 0),
                ("ts-any", 2, 2),
                ("ts-json-parse-unsafe", 2, 2),
                ("ts-console", 3, 3),
                ("ts-debugger", 4, 4),
                ("ts-eval", 5, 5),
                ("ts-inner-html", 6, 6),
                ("ts-floating-promise", 7, 7),
                ("ts-hardcoded-secret", 8, 8),
                ("ts-await-in-loop", 10, 10),
                ("ts-non-null-assertion", 12, 12),
                ("ts-json-parse-unsafe", 13, 13),
                ("ts-localstorage-json", 13, 13),
                ("ts-string-timer-code-execution", 14, 14),
            ])
        );
    }

    #[test]
    fn applies_javascript_source_and_sink_exclusions() {
        let sources = BTreeMap::from([
            (
                "scripts/release.js".to_owned(),
                "console.log('released');\nJSON.parse(metadata);".to_owned(),
            ),
            (
                "src/cli.ts".to_owned(),
                "#!/usr/bin/env node\nconsole.log('ready');".to_owned(),
            ),
            (
                "src/app.ts".to_owned(),
                "console.log('unexpected');\n\
element.innerHTML = '<strong>safe</strong>';\n\
element.innerHTML = renderedHtml;\n\
const token = `${session.id}`;\n\
const apiToken = `literal-token`;\n\
setTimeout(runTask, 10);\n\
scheduler.setTimeout(\"not a global timer\", 10);\n\
service.eval(input);\n\
function eval(input: string) { return input; }\n\
JSON.parse(JSON.stringify(value));\n\
try { JSON.parse(payload); } catch (error) { recover(error); }\n"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .map(|finding| (finding.code, finding.path, finding.line))
            .collect::<BTreeSet<_>>();

        assert_eq!(
            findings,
            BTreeSet::from([
                ("ts-console".to_owned(), "src/app.ts".to_owned(), 1,),
                ("ts-inner-html".to_owned(), "src/app.ts".to_owned(), 3,),
                ("ts-hardcoded-secret".to_owned(), "src/app.ts".to_owned(), 5,),
            ])
        );
    }

    #[test]
    fn limits_typescript_syntax_rules_and_ignores_regex_literals() {
        let sources = BTreeMap::from([
            (
                "src/rules.js".to_owned(),
                "const lookbehind = /(?<!,)/u;\nconst punctuation = /[~!]/u;".to_owned(),
            ),
            (
                "src/rules.ts".to_owned(),
                "const shebang = /^#!.*/;\n\
const punctuation = /[~!]/u;\n\
const safe = !/^(?:https?:)?\\/\\//.test(filename);\n\
const value: any = load();\n\
const definite = value!.name;\n"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| matches!(
                    finding.code.as_str(),
                    "ts-any" | "ts-non-null-assertion"
                ))
                .map(|finding| (finding.code, finding.path, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("ts-any".to_owned(), "src/rules.ts".to_owned(), 4),
                (
                    "ts-non-null-assertion".to_owned(),
                    "src/rules.ts".to_owned(),
                    5
                ),
            ]
        );
    }

    #[test]
    fn string_masking_preserves_nested_template_expressions() {
        let source = "const hidden = \"eval(secret)\";\n\
const nested = `ignored ${eval(input) + `inner ${danger}`} tail`;\n";
        let masked = without_string_literal_text(source);

        assert_eq!(masked.len(), source.len());
        assert_eq!(masked.matches("eval(").count(), 1);
        assert!(masked.contains("eval(input)"));
        assert!(masked.contains("danger"));
        for hidden in ["secret", "ignored", "inner", "tail"] {
            assert!(!masked.contains(hidden), "literal text leaked: {hidden}");
        }
    }
    #[test]
    fn parses_multiline_inner_html_expressions_to_their_boundary() {
        let sources = BTreeMap::from([(
            "src/render.ts".to_owned(),
            "safe.innerHTML =\n\
enabled ? '<b>yes</b>' : '<i>no</i>';\n\
unsafe.innerHTML =\n\
enabled ? render(user) : '<i>no</i>';\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "ts-inner-html")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [3]
        );
    }

    #[test]
    fn reports_dynamic_child_process_shell_commands() {
        let sources = BTreeMap::from([(
            "src/commands.ts".to_owned(),
            "import { exec, spawn as run } from 'node:child_process';\n\
exec(`git show ${revision}`);\n\
exec('git status');\n\
run('convert', [input], { shell: true });\n\
run('convert', ['input.png'], { shell: true });\n\
const child = require('child_process');\n\
child.exec(command);\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "js-child-process-shell-interpolation")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [2, 4, 7]
        );
    }

    #[test]
    fn accepts_non_shell_child_process_calls_and_unrelated_functions() {
        let sources = BTreeMap::from([
            (
                "src/safe.ts".to_owned(),
                "import { exec, execFile, spawn } from 'child_process';\n\
const staticCommand = 'git status';\n\
exec('git ' + 'status');\n\
exec(staticCommand);\n\
execFile('git', ['show', revision]);\n\
spawn(command, args);\n\
spawn('git', ['show'], { shell: false });\n\
function inspectDrive(drive: string) {\n\
  if (!/^[a-z]:$/i.test(drive)) { throw new Error('invalid drive') }\n\
  exec(`powershell ${drive.replace(':', '')}`);\n\
}\n\
// exec(command);\n\
const sample = 'exec(command)';\n"
                    .to_owned(),
            ),
            (
                "src/unrelated.ts".to_owned(),
                "function exec(command: string) { return command; }\nexec(command);\n".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(
            analyze(&context)
                .iter()
                .all(|finding| finding.code != "js-child-process-shell-interpolation")
        );
    }

    #[test]
    fn reports_async_foreach_callbacks_across_lines() {
        let sources = BTreeMap::from([(
            "src/tasks.ts".to_owned(),
            "items.forEach(async (item) => save(item));\n\
items.forEach(\n\
  async function (item) { await save(item); }\n\
);\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "js-async-foreach")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn accepts_awaitable_async_iteration_patterns_and_masked_examples() {
        let sources = BTreeMap::from([(
            "src/iteration.ts".to_owned(),
            "items.forEach((item) => save(item));\n\
for (const item of items) { await save(item); }\n\
await Promise.all(items.map(async (item) => save(item)));\n\
// items.forEach(async (item) => save(item));\n\
const example = 'items.forEach(async () => work())';\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(
            analyze(&context)
                .iter()
                .all(|finding| finding.code != "js-async-foreach")
        );
    }
    #[test]
    fn reports_accumulating_buffers_and_constant_intl_formatters_inside_loops() {
        let sources = BTreeMap::from([(
            "src/format.ts".to_owned(),
            r#"function format(chunks: Buffer[]) {
  let buffer = Buffer.alloc(0);
  for (const chunk of chunks) {
    buffer = Buffer.concat([
      buffer,
      chunk,
    ]);
    const date = new Intl.DateTimeFormat(
      "en-US",
      { dateStyle: "medium" },
    );
    const number = new Intl.NumberFormat();
    consume(date, number);
  }
  return buffer;
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
                        "js-buffer-concat-in-loop" | "js-intl-formatter-in-loop"
                    )
                })
                .map(|finding| (finding.code, finding.path, finding.line, finding.confidence))
                .collect::<Vec<_>>(),
            vec![
                (
                    "js-buffer-concat-in-loop".to_owned(),
                    "src/format.ts".to_owned(),
                    4,
                    "high".to_owned(),
                ),
                (
                    "js-intl-formatter-in-loop".to_owned(),
                    "src/format.ts".to_owned(),
                    8,
                    "high".to_owned(),
                ),
                (
                    "js-intl-formatter-in-loop".to_owned(),
                    "src/format.ts".to_owned(),
                    12,
                    "high".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn accepts_non_accumulating_buffers_and_dynamic_or_reused_intl_formatters() {
        let sources = BTreeMap::from([(
            "src/safe-format.ts".to_owned(),
            r#"const stable = new Intl.DateTimeFormat("en-US");
function format(chunks: Buffer[], locale: string, options: Intl.NumberFormatOptions) {
  let buffer = Buffer.alloc(0);
  for (const chunk of chunks) {
    consume(Buffer.concat([chunk]));
    buffer = Buffer.concat([chunk]);
    const localized = new Intl.DateTimeFormat(locale);
    const configured = new Intl.NumberFormat("en-US", options);
    // buffer = Buffer.concat([buffer, chunk]);
    const example = 'new Intl.Collator()';
    consume(localized, configured);
  }
  buffer = Buffer.concat([buffer, Buffer.from("done")]);
  return buffer;
}"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "js-buffer-concat-in-loop" | "js-intl-formatter-in-loop"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn reports_javascript_loop_and_async_performance_patterns() {
        let sources = BTreeMap::from([(
            "src/performance.ts".to_owned(),
            "import { readFileSync as readNow } from 'node:fs';\n\
+import * as fs from 'node:fs';\n\
+async function scan(blocked: string[], values: string[]) {\n\
+  let output: string = '';\n\
+  for (const value of values) {\n\
+    const matcher = new RegExp('^[a-z]+$');\n\
+    if (blocked.includes(value)) output += value;\n\
+    readNow(value);\n\
+    fs.statSync(value);\n\
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
                        "js-regexp-created-in-loop"
                            | "js-linear-membership-in-loop"
                            | "js-string-concat-in-loop"
                            | "js-sync-io-in-async"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("js-regexp-created-in-loop".to_owned(), 6),
                ("js-linear-membership-in-loop".to_owned(), 7),
                ("js-string-concat-in-loop".to_owned(), 7),
                ("js-sync-io-in-async".to_owned(), 8),
                ("js-sync-io-in-async".to_owned(), 9),
            ]
        );
    }

    #[test]
    fn accepts_javascript_performance_safe_variants() {
        let sources = BTreeMap::from([(
            "src/safe-performance.ts".to_owned(),
            "import { readFileSync, promises as fs } from 'node:fs';\n\
+const stable = new RegExp('^[a-z]+$');\n\
+async function scan(pattern: string, allowed: Set<string>, values: string[]) {\n\
+  const output: string[] = [];\n\
+  for (const value of values) {\n\
+    const dynamic = new RegExp(pattern);\n\
+    if (allowed.has(value)) output.push(value);\n\
+    await fs.readFile(value);\n\
+    function deferred() { return readFileSync(value); }\n\
+  }\n\
+  return output.join('');\n\
+}\n\
+// new RegExp('commented')\n\
+const example = \"new RegExp('literal')\";\n"
                .replace("\n+", "\n"),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "js-regexp-created-in-loop"
                        | "js-linear-membership-in-loop"
                        | "js-string-concat-in-loop"
                        | "js-sync-io-in-async"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn reports_array_shift_used_as_a_loop_queue() {
        let sources = BTreeMap::from([(
            "src/queue.ts".to_owned(),
            r#"function drain(queue: string[]) {
  while (queue.length > 0) {
    consume(queue.shift());
  }
}

function once(queue: string[]) {
  consume(queue.shift());
}"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| finding.code == "js-array-shift-in-loop")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn reports_accumulating_spread_front_insertion_and_filtered_first_match() {
        let sources = BTreeMap::from([(
            "src/performance.ts".to_owned(),
            r#"function index(values: string[], queue: string[]) {
  const byValue = values.reduce((acc, value) => ({ ...acc, [value]: true }), {});
  const copied = values.reduce(
    (acc, value) => {
      return [...acc, value];
    },
    [],
  );
  const first = values.filter((value) => value.length > 2)[0];
  const last = values.filter(Boolean).at(-1);
  for (const value of values) {
    queue.unshift(value);
  }
  queue.unshift("once");
  return { byValue, copied, first, last };
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
                        "js-accumulating-spread"
                            | "js-array-unshift-in-loop"
                            | "js-filter-first-match"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("js-accumulating-spread".to_owned(), 2),
                ("js-accumulating-spread".to_owned(), 5),
                ("js-filter-first-match".to_owned(), 9),
                ("js-filter-first-match".to_owned(), 10),
                ("js-array-unshift-in-loop".to_owned(), 12),
            ]
        );
    }

    #[test]
    fn accepts_non_accumulating_reducers_non_arrays_and_one_off_unshift() {
        let sources = BTreeMap::from([(
            "src/safe-performance.ts".to_owned(),
            r#"function summarize(values: string[], custom: Filterable) {
  const count = values.reduce((acc, value) => acc + value.length, 0);
  const copied = values.reduce((acc, value) => [...value, acc], []);
  const selected = custom.filter(Boolean)[0];
  values.unshift("once");
  return { count, copied, selected };
}"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "js-accumulating-spread" | "js-array-unshift-in-loop" | "js-filter-first-match"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn reports_growing_array_copies_and_repeated_locale_formatting() {
        let sources = BTreeMap::from([(
            "src/render.ts".to_owned(),
            r#"function render(values: string[], dates: Date[]) {
  let spreadOutput: string[] = [];
  let concatOutput: string[] = [];
  for (const value of values) {
    spreadOutput = [...spreadOutput, value];
    concatOutput = concatOutput.concat(value);
  }
  for (const date of dates) {
    labels.push(date.toLocaleDateString("en-US", { year: "numeric" }));
  }
  return { spreadOutput, concatOutput };
}"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert_eq!(
            analyze(&context)
                .into_iter()
                .filter(|finding| matches!(
                    finding.code.as_str(),
                    "js-growing-array-copy-in-loop" | "js-locale-format-in-loop"
                ))
                .map(|finding| (finding.code, finding.line))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("js-growing-array-copy-in-loop".to_owned(), 5),
                ("js-growing-array-copy-in-loop".to_owned(), 6),
                ("js-locale-format-in-loop".to_owned(), 9),
            ])
        );
    }

    #[test]
    fn accepts_local_arrays_pushes_cached_formatters_and_dynamic_locales() {
        let sources = BTreeMap::from([(
            "src/render.ts".to_owned(),
            r#"function render(values: string[], dates: Date[], locale: string, options: object) {
  const output: string[] = [];
  const formatter = new Intl.DateTimeFormat("en-US", { year: "numeric" });
  for (const value of values) {
    output.push(value);
    let local: string[] = [];
    local = [...local, value];
  }
  for (const date of dates) {
    labels.push(formatter.format(date));
    labels.push(date.toLocaleDateString(locale, options));
  }
  return [...output];
}"#
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let selected = analyze(&context)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "js-growing-array-copy-in-loop" | "js-locale-format-in-loop"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn malformed_source_and_capture_candidates_fail_closed() {
        let sources = BTreeMap::from([(
            "src/malformed.ts".to_owned(),
            "import { R_OK from 'node:fs';\n\
const password = \"unterminated;\n\
const token = `unterminated;\n\
JSON.parse();\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(analyze(&context).into_iter().all(|finding| {
            !matches!(
                finding.code.as_str(),
                "js-node-fs-constant-import" | "ts-hardcoded-secret" | "ts-json-parse-unsafe"
            )
        }));
        assert!(!is_parse_of_immediately_stringified_value(&[], 0));
        assert!(!is_parse_of_immediately_stringified_value(
            &["JSON.parse(payload)"],
            1
        ));
        assert!(!is_static_string_literal(""));
        assert!(!is_static_string_literal("\""));
    }
}
