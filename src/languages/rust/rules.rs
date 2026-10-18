use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
#[cfg(test)]
use crate::function_sources;
use crate::function_sources::FunctionSource;
use crate::object_soup_rules;
use crate::rule_catalog;

use super::panic_guards;
use super::regex_contracts::RegexContracts;
use super::test_scopes;

#[cfg(test)]
pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let functions = function_sources::extract(sources);
    analyze_with_functions(sources, &functions)
}

pub fn analyze_with_functions(
    sources: &BTreeMap<String, String>,
    functions: &[FunctionSource],
) -> Vec<Finding> {
    let mut findings = object_soup_rules::rust(functions);
    for (path, source) in sources.iter().filter(|(path, _)| path.ends_with(".rs")) {
        let file = RustFile::new(source);
        analyze_simple_rules(path, &file, &mut findings);
        analyze_hardcoded_secrets(path, &file, &mut findings);
        analyze_unsafe_blocks(path, &file, &mut findings);
        analyze_static_mut(path, &file, &mut findings);
        analyze_raw_ownership(path, &file, &mut findings);
        analyze_impl_into(path, &file, &mut findings);
        analyze_manual_send_sync(path, &file, &mut findings);
        analyze_shell_commands(path, &file, &mut findings);
        analyze_ffi_panics(path, &file, &mut findings);
        analyze_async_blocking(path, &file, &mut findings);
        analyze_sync_lock_across_await(path, &file, &mut findings);
        analyze_loop_performance(path, &file, functions, &mut findings);
        analyze_map_double_lookup(path, &file, functions, &mut findings);
        analyze_format_allocations(path, &file, functions, &mut findings);
        analyze_unbounded_channels(path, &file, &mut findings);
    }
    findings
}

struct SimpleRule {
    code: &'static str,
    pattern: Regex,
    message: &'static str,
    allowed_lints: &'static [&'static str],
}

fn analyze_simple_rules(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for rule in SIMPLE_RULES.iter() {
        if file_allows_rule(file.source, rule.allowed_lints) {
            continue;
        }
        let allowed_lines = attributed_allowed_lines(&file.masked, rule.allowed_lints);
        let mut source_offset = 0usize;
        for (index, line) in file.masked.split('\n').enumerate() {
            if reportable_simple_match(file, rule, &allowed_lines, index, line, source_offset)
                .is_some()
            {
                findings.push(finding(rule.code, path, index + 1, rule.message));
            }
            source_offset += line.len() + 1;
        }
    }
}

fn reportable_simple_match(
    file: &RustFile<'_>,
    rule: &SimpleRule,
    allowed_lines: &BTreeSet<usize>,
    index: usize,
    line: &str,
    source_offset: usize,
) -> Option<usize> {
    if file.test_lines.contains(&index) || allowed_lines.contains(&index) {
        return None;
    }
    rule.pattern
        .find_iter(line)
        .find(|matched| {
            !is_proven_panic_invariant(rule.code, file, source_offset + matched.start())
        })
        .map(|matched| matched.start())
}

fn is_proven_panic_invariant(code: &str, file: &RustFile<'_>, call_offset: usize) -> bool {
    if !matches!(code, "rust-unwrap" | "rust-expect") {
        return false;
    }
    if file
        .regex_contracts
        .capture_access_is_invariant(file.source, &file.masked, call_offset)
        || panic_guards::locally_proven_invariant(file.source, &file.masked, call_offset)
    {
        return true;
    }
    let statement_start = file.masked[..call_offset]
        .rfind(';')
        .map_or(0, |offset| offset + 1);
    let statement_end = file.masked[call_offset..]
        .find(';')
        .map_or(file.source.len(), |offset| call_offset + offset + 1);
    let statement = &file.source[statement_start..statement_end];
    if expect_statement_documents_invariant(code, statement, &file.source[call_offset..]) {
        return true;
    }
    regex_constructor_is_invariant(file.source, &file.masked, statement_start, call_offset)
}

fn expect_statement_documents_invariant(code: &str, statement: &str, call: &str) -> bool {
    code == "rust-expect"
        && (expect_message_documents_invariant(call)
            || [
                "rule_catalog::metadata(",
                "rule_catalog::descriptor(",
                "Severity::parse(metadata.default_severity)",
            ]
            .iter()
            .any(|invariant| statement.contains(invariant))
            || statement.contains("String::from_utf8(") && statement.contains("UTF-8"))
}

fn expect_message_documents_invariant(call: &str) -> bool {
    EXPECT_INVARIANT_MESSAGE.is_match(call)
}

fn regex_constructor_is_invariant(
    source: &str,
    masked: &str,
    statement_start: usize,
    call_offset: usize,
) -> bool {
    let statement = &source[statement_start..call_offset];
    let Some(constructor) = ["Regex::new", "regex::Regex::new"]
        .into_iter()
        .filter_map(|name| statement.rfind(name).map(|offset| (offset, name.len())))
        .max_by_key(|(offset, _)| *offset)
    else {
        return false;
    };
    let Some(open) = statement[constructor.0 + constructor.1..]
        .find('(')
        .map(|offset| statement_start + constructor.0 + constructor.1 + offset)
    else {
        return false;
    };
    let Some(close) = matching_delimiter(masked, open, b'(', b')') else {
        return false;
    };
    if close >= call_offset || !source[close + 1..call_offset].trim().is_empty() {
        return false;
    }
    let mut argument = open + 1;
    let argument_end = close;
    argument += source[argument..argument_end]
        .len()
        .saturating_sub(source[argument..argument_end].trim_start().len());
    if source.as_bytes().get(argument) == Some(&b'&') {
        argument += 1;
        while source
            .as_bytes()
            .get(argument)
            .is_some_and(u8::is_ascii_whitespace)
        {
            argument += 1;
        }
    }
    if rust_literal_end(source.as_bytes(), argument).is_some_and(|end| {
        let trailing = source[end..argument_end].trim();
        trailing.is_empty() || trailing == ","
    }) {
        return true;
    }
    escaped_format_arguments(source, masked, argument, argument_end)
}

fn escaped_format_arguments(
    source: &str,
    masked: &str,
    argument: usize,
    call_offset: usize,
) -> bool {
    if !source[argument..call_offset].starts_with("format!") {
        return false;
    }
    let Some(open) = masked[argument..call_offset]
        .find('(')
        .map(|offset| argument + offset)
    else {
        return false;
    };
    let Some(close) = matching_delimiter(masked, open, b'(', b')') else {
        return false;
    };
    let arguments = top_level_ranges(masked, open + 1, close);
    let Some((format_start, format_end)) = arguments.first().copied() else {
        return false;
    };
    let format_start = format_start
        + source[format_start..format_end]
            .len()
            .saturating_sub(source[format_start..format_end].trim_start().len());
    if rust_literal_end(source.as_bytes(), format_start).is_none() || arguments.len() < 2 {
        return false;
    }
    arguments[1..].iter().all(|(start, end)| {
        let argument = source[*start..*end].trim();
        let value = argument
            .split_once('=')
            .map_or(argument, |(_, value)| value.trim());
        value.starts_with("regex::escape(")
    })
}

fn top_level_ranges(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut range_start = start;
    let mut delimiters = Vec::new();
    for (offset, byte) in bytes[start..end].iter().enumerate() {
        match byte {
            b'(' => delimiters.push(b')'),
            b'[' => delimiters.push(b']'),
            b'{' => delimiters.push(b'}'),
            byte if delimiters.last() == Some(byte) => {
                delimiters.pop();
            }
            b',' if delimiters.is_empty() => {
                let comma = start + offset;
                ranges.push((range_start, comma));
                range_start = comma + 1;
            }
            _ => {}
        }
    }
    ranges.push((range_start, end));
    ranges
}

fn matching_delimiter(source: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open) != Some(&opening) {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if *byte == opening {
            depth += 1;
        } else if *byte == closing {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn file_allows_rule(source: &str, allowed_lints: &[&str]) -> bool {
    if allowed_lints.is_empty() {
        return false;
    }
    CRATE_ALLOW.captures_iter(source).any(|capture| {
        allowed_lints
            .iter()
            .any(|lint| lint_list_contains(&capture[1], lint))
    })
}

fn attributed_allowed_lines(masked: &str, allowed_lints: &[&str]) -> BTreeSet<usize> {
    if allowed_lints.is_empty() {
        return BTreeSet::new();
    }
    attributed_lines(masked, |line| {
        ITEM_ALLOW.captures(line).is_some_and(|capture| {
            allowed_lints
                .iter()
                .any(|lint| lint_list_contains(&capture[1], lint))
        })
    })
}

fn lint_list_contains(list: &str, lint: &str) -> bool {
    list.split(|character: char| character == ',' || character.is_whitespace())
        .any(|candidate| candidate == lint)
}

fn attributed_lines(masked: &str, matches_attribute: impl Fn(&str) -> bool) -> BTreeSet<usize> {
    let mut result = BTreeSet::new();
    let mut pending = false;
    let mut depth = 0isize;
    for (index, line) in masked.split('\n').enumerate() {
        if depth > 0 {
            result.insert(index);
            depth += brace_delta(line);
            continue;
        }
        if matches_attribute(line) {
            pending = true;
            result.insert(index);
            continue;
        }
        if pending && line.trim_start().starts_with("#[") {
            result.insert(index);
            continue;
        }
        if pending && !line.trim().is_empty() {
            result.insert(index);
            depth = brace_delta(line);
            pending = false;
        }
    }
    result
}

fn brace_delta(line: &str) -> isize {
    line.bytes().filter(|byte| *byte == b'{').count() as isize
        - line.bytes().filter(|byte| *byte == b'}').count() as isize
}

fn analyze_hardcoded_secrets(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for declaration in SECRET_DECLARATION.captures_iter(&file.masked) {
        let (Some(matched), Some(name)) = (declaration.get(0), declaration.get(1)) else {
            continue;
        };
        if file.excluded(matched.start()) {
            continue;
        }
        let mut literal_start = skip_ascii_whitespace(file.source, matched.end());
        if file.source.as_bytes().get(literal_start) == Some(&b'&') {
            literal_start = skip_ascii_whitespace(file.source, literal_start + 1);
        }
        let Some(literal_end) = rust_literal_end(file.source.as_bytes(), literal_start) else {
            continue;
        };
        let literal = &file.source[literal_start..literal_end];
        if !looks_like_hardcoded_secret(name.as_str(), literal) {
            continue;
        }
        findings.push(finding(
            "rust-hardcoded-secret",
            path,
            file.line_at(matched.start()),
            &format!(
                "hardcoded string assigned to credential-like `{}`",
                name.as_str()
            ),
        ));
    }
}

fn looks_like_hardcoded_secret(name: &str, literal: &str) -> bool {
    let Some(value) = rust_string_body(literal).map(str::trim) else {
        return false;
    };
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----") {
        return true;
    }
    let Some(kind) = secret_name_kind(name) else {
        return false;
    };
    if value.is_empty() || value.contains("://") || is_secret_placeholder(name, value) {
        return false;
    }
    match kind {
        SecretNameKind::Direct => {
            value.len() >= 6 && value.bytes().any(|byte| byte.is_ascii_alphanumeric())
        }
        SecretNameKind::Token => looks_like_token_secret(value),
    }
}

enum SecretNameKind {
    Direct,
    Token,
}

fn secret_name_kind(name: &str) -> Option<SecretNameKind> {
    if [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "client_secret",
        "clientsecret",
        "private_key",
        "privatekey",
        "signing_key",
        "signingkey",
    ]
    .into_iter()
    .any(|candidate| ascii_name_ends_with(name, candidate))
    {
        return Some(SecretNameKind::Direct);
    }
    [
        "token",
        "access_token",
        "accesstoken",
        "auth_token",
        "authtoken",
        "bearer_token",
        "bearertoken",
        "refresh_token",
        "refreshtoken",
        "session_token",
        "sessiontoken",
        "jwt_token",
        "jwttoken",
    ]
    .into_iter()
    .any(|candidate| ascii_name_ends_with(name, candidate))
    .then_some(SecretNameKind::Token)
}

fn looks_like_token_secret(value: &str) -> bool {
    if value.len() < 16 || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    let symbolic = value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte));
    !symbolic || value.bytes().any(|byte| byte.is_ascii_digit())
}

fn ascii_name_ends_with(name: &str, candidate: &str) -> bool {
    name.get(name.len().saturating_sub(candidate.len())..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(candidate))
}

fn is_secret_placeholder(name: &str, value: &str) -> bool {
    normalized_ascii_eq(value, name)
        || [
            "password",
            "changeme",
            "yoursecret",
            "yourapikey",
            "placeholder",
            "example",
            "redacted",
            "test",
        ]
        .into_iter()
        .any(|placeholder| normalized_ascii_eq(value, placeholder))
        || ["fake", "mock", "dummy", "test"]
            .into_iter()
            .any(|prefix| normalized_ascii_starts_with(value, prefix))
}

fn normalized_ascii_eq(left: &str, right: &str) -> bool {
    normalized_ascii(left).eq(normalized_ascii(right))
}

fn normalized_ascii_starts_with(value: &str, prefix: &str) -> bool {
    let mut value = normalized_ascii(value);
    normalized_ascii(prefix).all(|expected| value.next() == Some(expected))
}

fn normalized_ascii(value: &str) -> impl Iterator<Item = u8> + '_ {
    value
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
}

fn rust_string_body(literal: &str) -> Option<&str> {
    let first_quote = literal.find('"')?;
    let last_quote = literal.rfind('"')?;
    (last_quote > first_quote).then_some(&literal[first_quote + 1..last_quote])
}

fn analyze_unsafe_blocks(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for matched in UNSAFE_BLOCK.find_iter(&file.masked) {
        let Some(open) = file.masked[matched.start()..]
            .find('{')
            .map(|offset| matched.start() + offset)
        else {
            continue;
        };
        if file.excluded(matched.start()) || file.has_safety_rationale(matched.start(), open) {
            continue;
        }
        findings.push(finding(
            "rust-undocumented-unsafe-block",
            path,
            file.line_at(matched.start()),
            "unsafe block has no attached SAFETY rationale",
        ));
    }
}

fn analyze_static_mut(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for matched in STATIC_MUT.find_iter(&file.masked) {
        if matched.start() > 0 && file.masked.as_bytes()[matched.start() - 1] == b'\'' {
            continue;
        }
        if !file.excluded(matched.start()) {
            findings.push(finding(
                "rust-static-mut",
                path,
                file.line_at(matched.start()),
                "mutable static requires unsafe synchronization discipline",
            ));
        }
    }
}

fn analyze_raw_ownership(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for matched in RAW_OWNERSHIP.find_iter(&file.masked) {
        if !file.excluded(matched.start()) {
            findings.push(finding(
                "rust-raw-ownership-reconstruction",
                path,
                file.line_at(matched.start()),
                "raw pointer is converted back into an owning Rust value",
            ));
        }
    }
}

fn analyze_impl_into(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    const ALLOWED_LINTS: &[&str] = &["clippy::from_over_into", "from_over_into"];

    if file_allows_rule(&file.masked, ALLOWED_LINTS) {
        return;
    }
    let allowed_lines = attributed_allowed_lines(&file.masked, ALLOWED_LINTS);
    for matched in IMPL_KEYWORD.find_iter(&file.masked) {
        let line = file.line_at(matched.start());
        if file.excluded(matched.start())
            || allowed_lines.contains(&(line - 1))
            || !implements_into(&file.masked, matched.end())
        {
            continue;
        }
        findings.push(finding(
            "rust-impl-into-instead-of-from",
            path,
            line,
            "implement From instead; Rust supplies Into automatically",
        ));
    }
}

fn implements_into(source: &str, impl_end: usize) -> bool {
    let mut cursor = skip_ascii_whitespace(source, impl_end);
    if source.as_bytes().get(cursor) == Some(&b'<') {
        let Some(end) = matching_angle_bracket(source, cursor) else {
            return false;
        };
        cursor = skip_ascii_whitespace(source, end + 1);
    }

    if token_at(source, cursor, "std") {
        cursor = skip_ascii_whitespace(source, cursor + 3);
        if !source[cursor..].starts_with("::") {
            return false;
        }
        cursor = skip_ascii_whitespace(source, cursor + 2);
        if !token_at(source, cursor, "convert") {
            return false;
        }
        cursor = skip_ascii_whitespace(source, cursor + 7);
        if !source[cursor..].starts_with("::") {
            return false;
        }
        cursor = skip_ascii_whitespace(source, cursor + 2);
    }

    if !token_at(source, cursor, "Into") {
        return false;
    }
    cursor = skip_ascii_whitespace(source, cursor + 4);
    if source.as_bytes().get(cursor) != Some(&b'<') {
        return false;
    }
    let Some(end) = matching_angle_bracket(source, cursor) else {
        return false;
    };
    cursor = skip_ascii_whitespace(source, end + 1);
    token_at(source, cursor, "for") && impl_header_has_body(source, cursor + 3)
}

fn impl_header_has_body(source: &str, start: usize) -> bool {
    let header = &source[start..];
    let Some(boundary) = header.find(['{', '}', ';']) else {
        return false;
    };
    header.as_bytes()[boundary] == b'{' && !header[..boundary].trim().is_empty()
}

fn skip_ascii_whitespace(source: &str, mut cursor: usize) -> usize {
    while source
        .as_bytes()
        .get(cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        cursor += 1;
    }
    cursor
}

fn token_at(source: &str, start: usize, token: &str) -> bool {
    source[start..].starts_with(token)
        && source
            .as_bytes()
            .get(start + token.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn matching_angle_bracket(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open) != Some(&b'<') {
        return None;
    }
    let mut depth = 0usize;
    for index in open..bytes.len() {
        match bytes[index] {
            b'<' => depth += 1,
            b'>' if index == 0 || bytes[index - 1] != b'-' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn analyze_manual_send_sync(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    let mut reported = BTreeSet::new();
    for capture in MANUAL_SEND_SYNC.captures_iter(&file.masked) {
        let (Some(matched), Some(safety_trait), Some(type_name)) =
            (capture.get(0), capture.get(1), capture.get(2))
        else {
            continue;
        };
        if file.excluded(matched.start()) {
            continue;
        }
        let open = file.masked[matched.end()..]
            .find('{')
            .map_or(file.masked.len(), |offset| matched.end() + offset);
        if file.has_safety_rationale(matched.start(), open) {
            continue;
        }
        let type_name = type_name.as_str();
        if !reported.insert(type_name.to_owned()) {
            continue;
        }
        findings.push(finding(
            "rust-manual-send-sync-impl",
            path,
            file.line_at(matched.start()),
            &format!(
                "manual {} implementation has no attached SAFETY rationale",
                safety_trait.as_str()
            ),
        ));
    }
}

fn analyze_shell_commands(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for capture in SHELL_COMMAND.captures_iter(&file.comments_masked) {
        let (Some(matched), Some(shell)) = (capture.get(0), capture.get(1)) else {
            continue;
        };
        if file.excluded(matched.start()) {
            continue;
        }
        let stop = file.comments_masked[matched.end()..].find(';').map_or_else(
            || {
                matched
                    .end()
                    .saturating_add(600)
                    .min(file.comments_masked.len())
            },
            |offset| matched.end() + offset + 1,
        );
        let builder = &file.comments_masked[matched.start()..stop];
        let shell = shell.as_str().to_ascii_lowercase();
        let has_switch = match shell.as_str() {
            "sh" | "bash" | "zsh" => POSIX_COMMAND_SWITCH.is_match(builder),
            "cmd" | "cmd.exe" => CMD_COMMAND_SWITCH.is_match(builder),
            _ => POWERSHELL_COMMAND_SWITCH.is_match(builder),
        };
        if has_switch {
            findings.push(finding(
                "rust-command-shell",
                path,
                file.line_at(matched.start()),
                "shell interpreter executes a command string",
            ));
        }
    }
}

fn analyze_ffi_panics(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for capture in FFI_FUNCTION.captures_iter(&file.comments_masked) {
        let (Some(function), Some(abi), Some(name)) =
            (capture.get(0), capture.get(1), capture.get(2))
        else {
            continue;
        };
        if file.excluded(function.start()) {
            continue;
        }
        let header = function.as_str();
        if !EXPORT_ATTRIBUTE.is_match(header) && !PUBLIC_EXTERN.is_match(header) {
            continue;
        }
        let Some(open) = file.masked[function.start()..]
            .find('{')
            .map(|offset| function.start() + offset)
        else {
            continue;
        };
        let Some(close) = file.matching(open, b'{', b'}') else {
            continue;
        };
        let body_start = open + 1;
        let body = &file.masked[body_start..close];
        let panic = PANIC_SITE.find_iter(body).find(|candidate| {
            !inside_catch_unwind(file, body_start, body_start + candidate.start())
        });
        let Some(panic) = panic else {
            continue;
        };
        findings.push(finding(
            "rust-panic-across-ffi-boundary",
            path,
            file.line_at(body_start + panic.start()),
            &format!(
                "exported {} ABI function {} contains an explicit panic path",
                abi.as_str(),
                name.as_str()
            ),
        ));
    }
}

fn inside_catch_unwind(file: &RustFile<'_>, body_start: usize, panic_offset: usize) -> bool {
    for matched in CATCH_UNWIND.find_iter(&file.masked[body_start..]) {
        let start = body_start + matched.start();
        if start >= panic_offset {
            break;
        }
        let Some(open) = file.masked[start..].find('(').map(|offset| start + offset) else {
            continue;
        };
        if open < panic_offset
            && file
                .matching(open, b'(', b')')
                .is_some_and(|close| close >= panic_offset)
        {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy)]
struct RustLoop {
    body_start: usize,
    body_end: usize,
}

struct NamedScope {
    start_line: usize,
    end_line: usize,
    names: BTreeSet<String>,
}

fn analyze_loop_performance(
    path: &str,
    file: &RustFile<'_>,
    functions: &[FunctionSource],
    findings: &mut Vec<Finding>,
) {
    let loops = rust_loops(file);
    analyze_loop_regex(path, file, &loops, findings);
    let scopes = named_scopes(path, functions, &LINEAR_COLLECTION_DECLARATION);
    analyze_loop_membership(path, file, &loops, &scopes, findings);
    analyze_loop_front_removal(path, file, &loops, &scopes, findings);
    analyze_loop_front_insertion(path, file, &loops, &scopes, findings);
}

fn analyze_loop_regex(
    path: &str,
    file: &RustFile<'_>,
    loops: &[RustLoop],
    findings: &mut Vec<Finding>,
) {
    let mut reported = BTreeSet::new();
    for current in loops {
        let repeated = &file.comments_masked[current.body_start..current.body_end];
        for constructor in REGEX_CONSTRUCTOR.find_iter(repeated) {
            let absolute = current.body_start + constructor.start();
            let argument =
                skip_ascii_whitespace(file.source, current.body_start + constructor.end());
            let Some(end) = rust_literal_end(file.source.as_bytes(), argument) else {
                continue;
            };
            if end > current.body_end
                || rust_string_body(&file.source[argument..end]).is_none()
                || file
                    .masked
                    .as_bytes()
                    .get(absolute)
                    .is_none_or(u8::is_ascii_whitespace)
                || file.excluded(absolute)
                || line_prefix(file.source, absolute).contains("static ")
                || !reported.insert(absolute)
            {
                continue;
            }
            findings.push(finding(
                "rust-regex-created-in-loop",
                path,
                file.line_at(absolute),
                "constant regular expression is compiled during each loop iteration",
            ));
        }
    }
}

fn analyze_loop_membership(
    path: &str,
    file: &RustFile<'_>,
    loops: &[RustLoop],
    scopes: &[NamedScope],
    findings: &mut Vec<Finding>,
) {
    let mut reported = BTreeSet::new();
    for current in loops {
        let repeated = &file.masked[current.body_start..current.body_end];
        for membership in LINEAR_MEMBERSHIP_CALL.captures_iter(repeated) {
            let whole = membership.get(0).unwrap();
            let absolute = current.body_start + whole.start();
            let line = file.line_at(absolute);
            if !scopes.iter().any(|scope| {
                scope.start_line <= line
                    && line <= scope.end_line
                    && scope.names.contains(&membership[1])
            }) || file.excluded(absolute)
                || !reported.insert(absolute)
            {
                continue;
            }
            findings.push(finding(
                "rust-linear-membership-in-loop",
                path,
                line,
                "linear collection membership is checked inside a loop",
            ));
        }
    }
}

fn analyze_loop_front_removal(
    path: &str,
    file: &RustFile<'_>,
    loops: &[RustLoop],
    scopes: &[NamedScope],
    findings: &mut Vec<Finding>,
) {
    let mut reported = BTreeSet::new();
    for current in loops {
        let repeated = &file.masked[current.body_start..current.body_end];
        for removal in VEC_FRONT_REMOVAL.captures_iter(repeated) {
            let whole = removal.get(0).unwrap();
            let absolute = current.body_start + whole.start();
            let line = file.line_at(absolute);
            if !scopes.iter().any(|scope| {
                scope.start_line <= line
                    && line <= scope.end_line
                    && scope.names.contains(&removal[1])
            }) || file.excluded(absolute)
                || !reported.insert(absolute)
            {
                continue;
            }
            findings.push(finding(
                "rust-vec-front-removal-in-loop",
                path,
                line,
                "removing the first Vec element repeatedly shifts the remaining elements",
            ));
        }
    }
}

fn analyze_loop_front_insertion(
    path: &str,
    file: &RustFile<'_>,
    loops: &[RustLoop],
    scopes: &[NamedScope],
    findings: &mut Vec<Finding>,
) {
    let mut reported = BTreeSet::new();
    for current in loops {
        let repeated = &file.masked[current.body_start..current.body_end];
        for insertion in VEC_FRONT_INSERTION.captures_iter(repeated) {
            let whole = insertion.get(0).unwrap();
            let absolute = current.body_start + whole.start();
            let line = file.line_at(absolute);
            if !scope_contains(scopes, &insertion[1], line)
                || file.excluded(absolute)
                || !reported.insert(absolute)
            {
                continue;
            }
            findings.push(finding(
                "rust-vec-front-insertion-in-loop",
                path,
                line,
                "inserting at the front of a Vec repeatedly shifts existing elements",
            ));
        }
    }
}

fn analyze_map_double_lookup(
    path: &str,
    file: &RustFile<'_>,
    functions: &[FunctionSource],
    findings: &mut Vec<Finding>,
) {
    let scopes = named_scopes(path, functions, &MAP_DECLARATION);
    for guard in MAP_CONTAINS_GUARD.captures_iter(&file.masked) {
        let (Some(whole), Some(map), Some(key)) = (guard.get(0), guard.get(1), guard.get(2)) else {
            continue;
        };
        let line = file.line_at(whole.start());
        if !scope_contains(&scopes, map.as_str(), line) || file.excluded(whole.start()) {
            continue;
        }
        let open = whole.end() - 1;
        let Some(close) = file.matching(open, b'{', b'}') else {
            continue;
        };
        let repeated_lookup = MAP_INSERT_CALL
            .captures_iter(&file.masked[open + 1..close])
            .any(|insert| {
                insert
                    .get(1)
                    .is_some_and(|name| name.as_str() == map.as_str())
                    && insert
                        .get(2)
                        .is_some_and(|name| name.as_str() == key.as_str())
            });
        if repeated_lookup {
            findings.push(finding(
                "rust-map-double-lookup",
                path,
                line,
                "contains_key followed by insert repeats the map lookup",
            ));
        }
    }
}

fn analyze_format_allocations(
    path: &str,
    file: &RustFile<'_>,
    functions: &[FunctionSource],
    findings: &mut Vec<Finding>,
) {
    let scopes = named_scopes(path, functions, &STRING_DECLARATION);
    for append in FORMAT_APPEND.captures_iter(&file.masked) {
        let (Some(whole), Some(name)) = (append.get(0), append.get(1).or_else(|| append.get(2)))
        else {
            continue;
        };
        let line = file.line_at(whole.start());
        if scope_contains(&scopes, name.as_str(), line) && !file.excluded(whole.start()) {
            findings.push(finding(
                "rust-format-append",
                path,
                line,
                "format! allocates a temporary String before appending it",
            ));
        }
    }
    for mapped in ITERATOR_MAP.find_iter(&file.masked) {
        let open = mapped.end() - 1;
        let Some(close) = file.matching(open, b'(', b')') else {
            continue;
        };
        if file.excluded(mapped.start())
            || !FORMAT_MACRO.is_match(&file.masked[open + 1..close])
            || !COLLECT_STRING.is_match(&file.masked[close + 1..])
        {
            continue;
        }
        findings.push(finding(
            "rust-format-collect",
            path,
            file.line_at(mapped.start()),
            "format! allocates a temporary String for every collected element",
        ));
    }
}

fn scope_contains(scopes: &[NamedScope], name: &str, line: usize) -> bool {
    scopes.iter().any(|scope| {
        scope.start_line <= line && line <= scope.end_line && scope.names.contains(name)
    })
}

fn named_scopes(path: &str, functions: &[FunctionSource], declaration: &Regex) -> Vec<NamedScope> {
    functions
        .iter()
        .filter(|function| function.path == path)
        .filter_map(|function| {
            let masked = RustFile::new(&function.source).masked;
            let names = declaration
                .captures_iter(&masked)
                .filter_map(|capture| capture.get(1).or_else(|| capture.get(2)))
                .map(|name| name.as_str().to_owned())
                .collect::<BTreeSet<_>>();
            (!names.is_empty()).then_some(NamedScope {
                start_line: function.line,
                end_line: function.end_line,
                names,
            })
        })
        .collect()
}

fn rust_loops(file: &RustFile<'_>) -> Vec<RustLoop> {
    RUST_LOOP
        .find_iter(&file.masked)
        .filter_map(|matched| {
            let open = matched.end() - 1;
            let close = file.matching(open, b'{', b'}')?;
            Some(RustLoop {
                body_start: open + 1,
                body_end: close,
            })
        })
        .collect()
}

fn line_prefix(source: &str, offset: usize) -> &str {
    let start = source[..offset].rfind('\n').map_or(0, |line| line + 1);
    &source[start..offset]
}

fn analyze_async_blocking(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for scope in ASYNC_SCOPE.find_iter(&file.masked) {
        if file.excluded(scope.start()) {
            continue;
        }
        let Some(open) = file.masked[scope.start()..]
            .find('{')
            .map(|offset| scope.start() + offset)
        else {
            continue;
        };
        let Some(close) = file.matching(open, b'{', b'}') else {
            continue;
        };
        let body_start = open + 1;
        for call in BLOCKING_CALL.find_iter(&file.masked[body_start..close]) {
            let absolute = body_start + call.start();
            if !inside_offload(file, body_start, absolute) {
                findings.push(finding(
                    "rust-blocking-call-in-async",
                    path,
                    file.line_at(absolute),
                    "known blocking API is called directly from async code",
                ));
            }
        }
    }
}

fn inside_offload(file: &RustFile<'_>, scope_start: usize, call_offset: usize) -> bool {
    for matched in OFFLOAD.find_iter(&file.masked[scope_start..]) {
        let start = scope_start + matched.start();
        if start >= call_offset {
            break;
        }
        let Some(open) = file.masked[start..].find('(').map(|offset| start + offset) else {
            continue;
        };
        if file
            .matching(open, b'(', b')')
            .is_some_and(|close| close >= call_offset)
        {
            return true;
        }
    }
    false
}

fn analyze_sync_lock_across_await(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    let parking_lot = PARKING_LOT_MUTEX.is_match(&file.masked);
    let mut reported = BTreeSet::new();
    for scope in ASYNC_SCOPE.find_iter(&file.masked) {
        let Some(open) = file.masked[scope.start()..]
            .find('{')
            .map(|offset| scope.start() + offset)
        else {
            continue;
        };
        let Some(close) = file.matching(open, b'{', b'}') else {
            continue;
        };
        for lock in SYNC_LOCK_GUARD.captures_iter(&file.masked[open + 1..close]) {
            let whole = lock.get(0).unwrap();
            let absolute = open + 1 + whole.start();
            if file.excluded(absolute)
                || (!parking_lot
                    && !whole.as_str().contains(".unwrap")
                    && !whole.as_str().contains(".expect"))
            {
                continue;
            }
            let Some(block_end) = enclosing_rust_block_end(file, open, absolute) else {
                continue;
            };
            let search_start = open + 1 + whole.end();
            let Some(awaited) = AWAIT_POINT.find(&file.masked[search_start..block_end]) else {
                continue;
            };
            let await_offset = search_start + awaited.start();
            let guard = &lock["guard"];
            let explicit_drop = Regex::new(&format!(
                r"\b(?:std::mem::)?drop\s*\(\s*{}\s*\)",
                regex::escape(guard)
            ))
            .expect("Rust guard-drop regex must compile");
            if explicit_drop.is_match(&file.masked[search_start..await_offset])
                || !reported.insert(absolute)
            {
                continue;
            }
            findings.push(finding(
                "rust-sync-lock-across-await",
                path,
                file.line_at(absolute),
                &format!("synchronous lock guard `{guard}` remains in scope across await"),
            ));
        }
    }
}

fn enclosing_rust_block_end(
    file: &RustFile<'_>,
    scope_open: usize,
    offset: usize,
) -> Option<usize> {
    let mut depth = 0usize;
    for index in (scope_open..offset).rev() {
        match file.masked.as_bytes()[index] {
            b'}' => depth += 1,
            b'{' if depth == 0 => return file.matching(index, b'{', b'}'),
            b'{' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn analyze_unbounded_channels(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    for matched in UNBOUNDED_CHANNEL.find_iter(&file.masked) {
        if !file.excluded(matched.start()) {
            findings.push(finding(
                "rust-unbounded-channel",
                path,
                file.line_at(matched.start()),
                "unbounded channel permits unlimited queued messages",
            ));
        }
    }
}

#[derive(Clone, Copy)]
struct CommentRange {
    start: usize,
    end: usize,
}

struct RustFile<'a> {
    source: &'a str,
    masked: String,
    comments_masked: String,
    comments: Vec<CommentRange>,
    test_lines: BTreeSet<usize>,
    regex_contracts: RegexContracts,
}

impl<'a> RustFile<'a> {
    fn new(source: &'a str) -> Self {
        let (masked, comments_masked, comments) = scan_rust(source);
        let test_lines = test_scopes::test_lines(source, &masked);
        let regex_contracts = RegexContracts::new(source, &masked);
        Self {
            source,
            masked,
            comments_masked,
            comments,
            test_lines,
            regex_contracts,
        }
    }

    fn line_at(&self, offset: usize) -> usize {
        self.source.as_bytes()[..offset.min(self.source.len())]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1
    }

    fn excluded(&self, offset: usize) -> bool {
        self.test_lines.contains(&(self.line_at(offset) - 1))
    }

    fn matching(&self, open: usize, opening: u8, closing: u8) -> Option<usize> {
        let bytes = self.masked.as_bytes();
        if bytes.get(open) != Some(&opening) {
            return None;
        }
        let mut depth = 0usize;
        for (index, byte) in bytes.iter().enumerate().skip(open) {
            if *byte == opening {
                depth += 1;
            } else if *byte == closing {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
        }
        None
    }

    fn has_safety_rationale(&self, unsafe_offset: usize, open_brace: usize) -> bool {
        let line_start = self.source[..unsafe_offset]
            .rfind('\n')
            .map_or(0, |offset| offset + 1);
        let preceding = self
            .comments
            .iter()
            .take_while(|comment| comment.end <= line_start)
            .copied()
            .collect::<Vec<_>>();
        if let Some(last) = preceding.last()
            && self.source[last.end..line_start].trim().is_empty()
        {
            let mut first = preceding.len() - 1;
            while first > 0
                && self.source[preceding[first - 1].end..preceding[first].start]
                    .trim()
                    .is_empty()
            {
                first -= 1;
            }
            let rationale = preceding[first..]
                .iter()
                .map(|comment| &self.source[comment.start..comment.end])
                .collect::<Vec<_>>()
                .join("\n");
            if SAFETY_COMMENT.is_match(&rationale) {
                return true;
            }
        }
        self.comments
            .iter()
            .find(|comment| {
                comment.start > open_brace
                    && self.source[open_brace + 1..comment.start].trim().is_empty()
            })
            .is_some_and(|comment| {
                SAFETY_COMMENT.is_match(&self.source[comment.start..comment.end])
            })
    }
}

pub(crate) fn function_lexical_facts(source: &str) -> (String, BTreeSet<usize>) {
    let (masked, _, _) = scan_rust(source);
    let test_lines = test_scopes::test_lines(source, &masked);
    (masked, test_lines)
}

enum RustScanTransition {
    Advance,
    Comment(usize),
    Literal(usize),
}

fn scan_rust(source: &str) -> (String, String, Vec<CommentRange>) {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut comments_masked = bytes.to_vec();
    let mut comments = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        match rust_scan_transition(bytes, index) {
            RustScanTransition::Advance => index += 1,
            RustScanTransition::Comment(end) => {
                mask_range(&mut masked, index, end);
                mask_range(&mut comments_masked, index, end);
                comments.push(CommentRange { start: index, end });
                index = end;
            }
            RustScanTransition::Literal(end) => {
                mask_range(&mut masked, index, end);
                index = end;
            }
        }
    }
    (
        String::from_utf8(masked).expect("masked Rust must remain UTF-8"),
        String::from_utf8(comments_masked).expect("comment-masked Rust must remain UTF-8"),
        comments,
    )
}

fn rust_scan_transition(source: &[u8], index: usize) -> RustScanTransition {
    if starts_with(source, index, b"//") {
        let end = source[index..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(source.len(), |offset| index + offset);
        return RustScanTransition::Comment(end);
    }
    if starts_with(source, index, b"/*") {
        return RustScanTransition::Comment(rust_block_comment_end(source, index));
    }
    rust_literal_end(source, index).map_or(RustScanTransition::Advance, RustScanTransition::Literal)
}

fn rust_block_comment_end(source: &[u8], mut index: usize) -> usize {
    let mut depth = 0usize;
    while index < source.len() {
        if starts_with(source, index, b"/*") {
            depth += 1;
            index += 2;
        } else if starts_with(source, index, b"*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                break;
            }
        } else {
            index += 1;
        }
    }
    index
}

fn mask_range(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

enum RustLiteralKind {
    Raw { body_start: usize, hashes: usize },
    Quoted { body_start: usize },
    Character { body_start: usize },
}

fn rust_literal_end(source: &[u8], start: usize) -> Option<usize> {
    match rust_literal_kind(source, start)? {
        RustLiteralKind::Raw { body_start, hashes } => {
            Some(rust_raw_literal_end(source, body_start, hashes))
        }
        RustLiteralKind::Quoted { body_start } => Some(rust_quoted_literal_end(source, body_start)),
        RustLiteralKind::Character { body_start } => rust_character_literal_end(source, body_start),
    }
}

fn rust_literal_kind(source: &[u8], start: usize) -> Option<RustLiteralKind> {
    let mut prefix = start;
    let raw_prefix = if starts_with(source, start, b"br") || starts_with(source, start, b"rb") {
        prefix += 2;
        true
    } else if source.get(start).is_some_and(|byte| b"rbc".contains(byte)) {
        prefix += 1;
        source[start] == b'r'
    } else {
        false
    };
    if source.get(prefix) == Some(&b'#') {
        let mut hashes = 0usize;
        while source.get(prefix + hashes) == Some(&b'#') {
            hashes += 1;
        }
        let quote = prefix + hashes;
        return (source.get(quote) == Some(&b'"') && raw_prefix).then_some(RustLiteralKind::Raw {
            body_start: quote + 1,
            hashes,
        });
    }
    if source.get(prefix) == Some(&b'"') {
        return Some(RustLiteralKind::Quoted {
            body_start: prefix + 1,
        });
    }
    (source.get(start) == Some(&b'\'')).then_some(RustLiteralKind::Character {
        body_start: start + 1,
    })
}

fn rust_raw_literal_end(source: &[u8], body_start: usize, hashes: usize) -> usize {
    let mut index = body_start;
    while index < source.len() {
        if source[index] == b'"'
            && (0..hashes).all(|hash| source.get(index + 1 + hash) == Some(&b'#'))
        {
            return (index + 1 + hashes).min(source.len());
        }
        index += 1;
    }
    source.len()
}

fn rust_quoted_literal_end(source: &[u8], body_start: usize) -> usize {
    let mut index = body_start;
    while index < source.len() {
        if source[index] == b'\\' {
            index = (index + 2).min(source.len());
            continue;
        }
        let closes = source[index] == b'"';
        index += 1;
        if closes {
            break;
        }
    }
    index.min(source.len())
}

fn rust_character_literal_end(source: &[u8], body_start: usize) -> Option<usize> {
    let mut index = body_start;
    if source.get(index) == Some(&b'\\') {
        index += 2;
    }
    if source.get(index).is_some_and(|byte| *byte != b'\n') && source.get(index + 1) == Some(&b'\'')
    {
        return Some(index + 2);
    }
    None
}

fn starts_with(source: &[u8], start: usize, pattern: &[u8]) -> bool {
    source.get(start..start + pattern.len()) == Some(pattern)
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Rust rule metadata must exist");
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

static SIMPLE_RULES: LazyLock<Vec<SimpleRule>> = LazyLock::new(|| {
    vec![
        SimpleRule {
            code: "rust-unwrap",
            pattern: Regex::new(r"\.unwrap\s*\(").unwrap(),
            message: "unwrap can panic on a recoverable value",
            allowed_lints: &["clippy::unwrap_used", "unwrap_used"],
        },
        SimpleRule {
            code: "rust-expect",
            pattern: Regex::new(r"\.expect\s*\(").unwrap(),
            message: "expect can panic when its assumed invariant fails",
            allowed_lints: &["clippy::expect_used", "expect_used"],
        },
        SimpleRule {
            code: "rust-panic-macro",
            pattern: Regex::new(r"\bpanic!\s*\(").unwrap(),
            message: "explicit panic in production source",
            allowed_lints: &["clippy::panic", "panic"],
        },
        SimpleRule {
            code: "rust-mem-forget",
            pattern: Regex::new(r"\b(?:std::)?mem::forget\s*\(").unwrap(),
            message: "mem::forget deliberately skips destruction",
            allowed_lints: &[],
        },
        SimpleRule {
            code: "rust-dbg-macro",
            pattern: Regex::new(r"\bdbg!\s*\(").unwrap(),
            message: "dbg! output remains in production source",
            allowed_lints: &[],
        },
        SimpleRule {
            code: "rust-todo-macro",
            pattern: Regex::new(r"\btodo!\s*\(").unwrap(),
            message: "todo! leaves an executable panic path",
            allowed_lints: &[],
        },
    ]
});

static CRATE_ALLOW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)#!\s*\[\s*allow\s*\(([^)]*)\)\s*\]").unwrap());
static ITEM_ALLOW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\s*\[\s*allow\s*\(([^)]*)\)\s*\]").unwrap());
static SAFETY_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bSAFETY\s*:\s*\S").unwrap());
static SECRET_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\b(?:const|static|let)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=\n;]+)?=").unwrap()
});
static EXPECT_INVARIANT_MESSAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)^\.expect\s*\(\s*(?:r#*)?"[^"\r\n]*(?:\b(?:always|never|invariant|impossible|guaranteed)\b|by construction|cannot fail|can't fail|static[- ]shape|writ(?:e|ing) to (?:a )?string)[^"\r\n]*""#,
    )
    .expect("expect invariant message regex must compile")
});
static UNSAFE_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bunsafe\s*\{").unwrap());
static STATIC_MUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bstatic\s+mut\s+[A-Za-z_]\w*").unwrap());
static RAW_OWNERSHIP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:std|alloc)::(?:boxed::Box|vec::Vec|string::String|ffi::CString|rc::Rc|sync::Arc)|Box|Vec|String|CString|Rc|Arc)::from_raw(?:_parts)?\s*\(").unwrap()
});
static IMPL_KEYWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bimpl\b").unwrap());
static MANUAL_SEND_SYNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\bunsafe\s+impl(?:\s*<[^>{}]*>)?[^{};]*?\b(Send|Sync)\s+for\s+([A-Za-z_]\w*)")
        .unwrap()
});
static SHELL_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bCommand::new\s*\(\s*["'](?:/bin/|/usr/bin/)?(sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)["']\s*\)"#).unwrap()
});
static POSIX_COMMAND_SWITCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.arg\s*\(\s*["']-c["']\s*\)"#).unwrap());
static CMD_COMMAND_SWITCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.arg\s*\(\s*["']/[cC]["']\s*\)"#).unwrap());
static POWERSHELL_COMMAND_SWITCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.arg\s*\(\s*["']-(?:Command|EncodedCommand)["']\s*\)"#).unwrap()
});
static FFI_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)(?:(?:#\s*\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name)[^\]]*\]\s*)+)?(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?extern\s+"(C|system|cdecl|stdcall|fastcall)"\s+fn\s+([A-Za-z_]\w*)[^;{]*\{"#).unwrap()
});
static EXPORT_ATTRIBUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\s*\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name)").unwrap());
static PUBLIC_EXTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpub(?:\([^)]*\))?\s+(?:unsafe\s+)?extern\b").unwrap());
static PANIC_SITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:panic|todo|unimplemented|unreachable|assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)!\s*\(|\.(?:unwrap|expect)\s*\(").unwrap()
});
static CATCH_UNWIND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcatch_unwind\s*\(").unwrap());
static RUST_LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:(?:for|while)\b[^;{}]*|loop)\s*\{").unwrap());
static REGEX_CONSTRUCTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:regex(?:::bytes)?::)?(?:Regex|RegexBuilder))::new\s*\(").unwrap()
});
static LINEAR_COLLECTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:([A-Za-z_]\w*)\s*:\s*(?:&\s*(?:mut\s*)?)?Vec\s*<|let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*(?:Vec(?:::[A-Za-z_]\w*)?\s*::|vec!\s*\[))",
    )
    .unwrap()
});
static LINEAR_MEMBERSHIP_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*contains\s*\(").unwrap());
static VEC_FRONT_REMOVAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*remove\s*\(\s*0\s*\)").unwrap());
static VEC_FRONT_INSERTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*insert\s*\(\s*0\s*,").unwrap());
static MAP_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:([A-Za-z_]\w*)\s*:\s*(?:&\s*(?:mut\s*)?)?(?:(?:std::collections::)?(?:HashMap|BTreeMap))\s*<|let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*(?:(?:std::collections::)?(?:HashMap|BTreeMap))(?:::[A-Za-z_]\w*)?\s*::)",
    )
    .unwrap()
});
static MAP_CONTAINS_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bif\s+!\s*([A-Za-z_]\w*)\s*\.\s*contains_key\s*\(\s*&?\s*([A-Za-z_]\w*)\s*\)\s*\{",
    )
    .unwrap()
});
static MAP_INSERT_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*insert\s*\(\s*([A-Za-z_]\w*)\s*,").unwrap()
});
static STRING_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:([A-Za-z_]\w*)\s*:\s*(?:&\s*mut\s*)?String\b|let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*String(?:::[A-Za-z_]\w*)?\s*::)",
    )
    .unwrap()
});
static FORMAT_APPEND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:([A-Za-z_]\w*)\s*\.\s*push_str\s*\(\s*&\s*format!|([A-Za-z_]\w*)\s*\+=\s*&\s*format!)\s*\(",
    )
    .unwrap()
});
static ITERATOR_MAP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.\s*map\s*\(").unwrap());
static FORMAT_MACRO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bformat!\s*\(").unwrap());
static COLLECT_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\.\s*collect\s*::\s*<\s*String\s*>\s*\(\s*\)").unwrap());
static ASYNC_SCOPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\basync\s+(?:move\s+)?(?:fn\s+[A-Za-z_]\w*[^;{]*|)\{").unwrap()
});
static BLOCKING_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:std::thread::sleep|reqwest::blocking(?:::[A-Za-z_]\w*)?|std::fs::(?:read|read_to_string|write|copy|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename)|std::process::Command::new)\s*\(").unwrap()
});
static OFFLOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:tokio::task::spawn_blocking|async_std::task::spawn_blocking|smol::unblock|(?:[A-Za-z_]\w*::)*asyncify)\s*\(",
    )
    .unwrap()
});
static SYNC_LOCK_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\blet\s+(?:mut\s+)?(?P<guard>[A-Za-z_]\w*)\s*=\s*[^;\n]*?\.lock\s*\(\s*\)\s*(?:\.\s*(?:unwrap|expect)\s*\([^;\n]*\))?\s*;",
    )
    .unwrap()
});
static PARKING_LOT_MUTEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:use\s+)?parking_lot(?:::|\b)").unwrap());
static AWAIT_POINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.await\b").unwrap());
static UNBOUNDED_CHANNEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:tokio::sync::mpsc::unbounded_channel|async_channel::unbounded|crossbeam_channel::unbounded|std::sync::mpsc::channel)\s*(?:::<[^;{}()]*>)?\s*\(").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(source: &str) -> Vec<Finding> {
        analyze(&BTreeMap::from([(
            "src/lib.rs".to_owned(),
            source.to_owned(),
        )]))
    }

    #[test]
    fn reports_complete_rust_rule_family() {
        let source = r#"use std::process::Command;
fn run() {
    value.unwrap();
    value.expect("required");
    panic!("failed");
    unsafe { touch_raw(); }
    static mut CACHE: usize = 0;
    let owner = Box::from_raw(pointer);
    unsafe impl Send for Handle {}
    std::mem::forget(resource);
    dbg!(value);
    todo!("finish this");
    Command::new("sh").arg("-c").arg(input);
    let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
}
impl Into<Target> for Source {
    fn into(self) -> Target { Target }
}
#[no_mangle]
pub extern "C" fn decode(pointer: *const u8) -> i32 {
    parse(pointer).unwrap()
}
async fn refresh() {
    std::thread::sleep(delay);
}
"#;
        let reported = findings(source);
        let codes = reported
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            codes,
            BTreeSet::from([
                "rust-blocking-call-in-async",
                "rust-command-shell",
                "rust-dbg-macro",
                "rust-expect",
                "rust-impl-into-instead-of-from",
                "rust-manual-send-sync-impl",
                "rust-mem-forget",
                "rust-panic-across-ffi-boundary",
                "rust-panic-macro",
                "rust-raw-ownership-reconstruction",
                "rust-static-mut",
                "rust-todo-macro",
                "rust-unbounded-channel",
                "rust-undocumented-unsafe-block",
                "rust-unwrap",
            ])
        );
    }

    #[test]
    fn excludes_tests_allowed_lints_comments_and_literals() {
        let source = r##"#![allow(clippy::unwrap_used)]
fn production() {
    value.expect("required");
    value.expect("value is always present by construction");
    let borrowed: &'static mut Value = source;
    use_value(borrowed);
    // panic!("comment");
    let sample = r#"static mut FAKE: usize = 0; value.expect("fake")"#;
}
#[test]
fn fixture() {
    value.expect("fixture");
    panic!("fixture");
}
#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    fn nested() { value.expect("fixture"); }
}
#[allow(clippy::expect_used)]
fn allowed() { value.expect("allowed"); }
"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-expect" | "rust-panic-macro" | "rust-static-mut"
                )
            })
            .map(|finding| format!("{}:{}", finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(selected, vec!["rust-expect:3"]);
    }

    #[test]
    fn distinguishes_mutable_static_items_from_static_lifetimes() {
        let selected = findings(
            "static mut GLOBAL: usize = 0;\nfn borrow(value: &'static mut usize) -> &'static mut usize { value }\n",
        )
        .into_iter()
        .filter(|finding| finding.code == "rust-static-mut")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();

        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn reports_production_hardcoded_rust_secrets() {
        let source = r####"const API_KEY: &str = "sk-live-0123456789abcdef";
static CLIENT_SECRET: &str = r#"correct horse battery staple"#;
fn connect() {
    let password = "hunter2";
}
"####;

        assert_eq!(
            findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-hardcoded-secret")
                .map(|finding| (finding.line, finding.message))
                .collect::<Vec<_>>(),
            vec![
                (
                    1,
                    "hardcoded string assigned to credential-like `API_KEY`".to_owned(),
                ),
                (
                    2,
                    "hardcoded string assigned to credential-like `CLIENT_SECRET`".to_owned(),
                ),
                (
                    4,
                    "hardcoded string assigned to credential-like `password`".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn ignores_non_credentials_placeholders_literals_and_test_secrets() {
        let source = r####"const TOKEN_GROUP: &str = "md.comp.assist-chip";
const CALLBACK_URL: &str = "https://example.test/token";
const API_KEY: &str = "your_api_key";
const SAMPLE: &str = r#"const PASSWORD: &str = "actual-secret";"#;
fn cancel() {
    let cancellation_token = "cancel-operation-token";
}
#[test]
fn fixture() {
    let password = "fixture-password";
}
"####;

        assert!(
            findings(source)
                .into_iter()
                .all(|finding| finding.code != "rust-hardcoded-secret")
        );
    }

    #[test]
    fn accepts_documented_and_contained_boundaries() {
        let source = r#"fn boundaries() {
    // SAFETY: pointer is non-null and uniquely owned.
    unsafe { touch_raw(); }
    Command::new("sh").arg("script.sh");
}
// SAFETY: Handle contains a thread-safe operating-system token.
unsafe impl Send for Handle {}
#[no_mangle]
pub extern "C" fn guarded() -> i32 {
    std::panic::catch_unwind(|| parse().unwrap()).unwrap_or(-1)
}
async fn refresh() {
    tokio::task::spawn_blocking(|| {
        std::fs::read_to_string(path)
    }).await.unwrap();
    asyncify(|| std::fs::copy(from, to)).await;
}
"#;
        let codes = findings(source)
            .into_iter()
            .map(|finding| finding.code)
            .filter(|code| {
                matches!(
                    code.as_str(),
                    "rust-undocumented-unsafe-block"
                        | "rust-manual-send-sync-impl"
                        | "rust-command-shell"
                        | "rust-panic-across-ffi-boundary"
                        | "rust-blocking-call-in-async"
                )
            })
            .collect::<Vec<_>>();
        assert!(codes.is_empty(), "unexpected findings: {codes:?}");
    }

    #[test]
    fn ignores_proven_invariants_but_reports_dynamic_failures() {
        let source = r##"fn patterns(input: &str, suffix: &str, bytes: Vec<u8>, code: &str) {
    let first = Regex::new(r"^[a-z]+$").unwrap();
    let second = Regex::new(
        "^value$",
    ).expect("literal pattern must compile");
    let dynamic = Regex::new(input).unwrap();
    let escaped = Regex::new(&format!(r"^{}$", regex::escape(input))).unwrap();
    let partial = Regex::new(&format!(r"^{}{}", regex::escape(input), suffix)).unwrap();
    let metadata = rule_catalog::metadata(code).expect("rule metadata must exist");
    let severity = Severity::parse(metadata.default_severity).expect("catalog severity must be valid");
    let masked = String::from_utf8(bytes).expect("masking preserves UTF-8");
    let capture = pattern.captures(input).unwrap();
    let whole = captures.get(0).unwrap();
    let first = values.get(0).unwrap();
}"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| format!("{}:{}", finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![
                "rust-unwrap:6",
                "rust-unwrap:8",
                "rust-unwrap:12",
                "rust-unwrap:13",
                "rust-unwrap:14",
            ]
        );
    }

    #[test]
    fn checks_every_panic_call_on_a_line() {
        let source = r#"fn patterns(input: &str) {
    let mixed = (Regex::new("literal").unwrap(), Regex::new(input).unwrap());
    let reversed = (Regex::new(input).unwrap(), Regex::new("literal").unwrap());
    let safe = (Regex::new("first").unwrap(), Regex::new("second").unwrap());
}"#;

        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| format!("{}:{}", finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["rust-unwrap:2", "rust-unwrap:3"]);
    }

    #[test]
    fn reports_into_implementations_in_source_order() {
        let source = r#"struct Wrapper<T>(T);
impl Into<u8> for Wrapper<u8> {
    fn into(self) -> u8 { self.0 }
}
impl<T>
    std::convert::Into<Vec<T>>
    for Wrapper<T>
{
    fn into(self) -> Vec<T> { vec![self.0] }
}"#;

        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-impl-into-instead-of-from")
            .map(|finding| (finding.path, finding.line, finding.message))
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![
                (
                    "src/lib.rs".to_owned(),
                    2,
                    "implement From instead; Rust supplies Into automatically".to_owned(),
                ),
                (
                    "src/lib.rs".to_owned(),
                    5,
                    "implement From instead; Rust supplies Into automatically".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn ignores_nearby_traits_bounds_masked_text_tests_and_item_allows() {
        let source = r##"impl From<Input> for Output {}
impl TryFrom<Input> for Output {}
impl TryInto<Output> for Input {}
impl IntoIterator for Input {}
impl<T: Into<Output>> Marker for T {}
impl crate::Into<Output> for Input {}
// impl Into<Output> for Commented {}
const EXAMPLE: &str = "impl Into<Output> for Literal {}";
#[allow(clippy::from_over_into)]
impl Into<Output> for Allowed {}
#[allow(from_over_into)]
impl
    Into<Output>
    for AlsoAllowed {}
#[cfg(test)]
mod tests {
    impl Into<Output> for Fixture {}
}
#[test]
fn conversion_works() {
    impl Into<Output> for LocalFixture {}
}"##;

        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-impl-into-instead-of-from")
            .collect::<Vec<_>>();

        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }

    #[test]
    fn honors_crate_level_from_over_into_allow() {
        let source = r#"#![allow(from_over_into)]
impl Into<Output> for Input {}"#;

        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-impl-into-instead-of-from")
            .collect::<Vec<_>>();

        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn reports_constant_regex_and_linear_membership_inside_loops() {
        let source = r#"fn scan(blocked: Vec<String>, values: Vec<String>) {
    for value in values {
        let matcher = Regex::new(r"^[a-z]+$").unwrap();
        if blocked.contains(&value) && matcher.is_match(&value) {}
    }
}"#;

        assert_eq!(
            findings(source)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "rust-regex-created-in-loop" | "rust-linear-membership-in-loop"
                    )
                })
                .map(|finding| (finding.code, finding.line, finding.confidence))
                .collect::<Vec<_>>(),
            vec![
                (
                    "rust-regex-created-in-loop".to_owned(),
                    3,
                    "high".to_owned(),
                ),
                (
                    "rust-linear-membership-in-loop".to_owned(),
                    4,
                    "high".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn accepts_dynamic_regex_sets_and_non_repeated_construction() {
        let source = r####"fn scan(pattern: &str, allowed: HashSet<String>, values: Vec<String>) {
    let stable = Regex::new(r"^[a-z]+$").unwrap();
    for value in values {
        let dynamic = Regex::new(pattern).unwrap();
        if allowed.contains(&value) && dynamic.is_match(&value) && stable.is_match(&value) {}
        // Regex::new("commented")
        let example = r#"Regex::new("literal")"#;
    }
}"####;

        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-regex-created-in-loop" | "rust-linear-membership-in-loop"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
    #[test]
    fn reports_front_removal_and_sync_locks_across_await() {
        let source = r#"use parking_lot::Mutex;

async fn process(values: &Mutex<Vec<u8>>, mut queue: Vec<u8>) {
    let guard = values.lock();
    consume(&guard).await;
    while ready() {
        queue.remove(0);
    }
}

async fn safe(values: &Mutex<Vec<u8>>, mut queue: Vec<u8>) {
    {
        let guard = values.lock();
        consume(&guard);
    }
    consume(&queue).await;
    if ready() {
        queue.remove(0);
    }
}"#;

        assert_eq!(
            findings(source)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "rust-sync-lock-across-await" | "rust-vec-front-removal-in-loop"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("rust-sync-lock-across-await".to_owned(), 4),
                ("rust-vec-front-removal-in-loop".to_owned(), 7),
            ]
        );
    }

    #[test]
    fn reports_map_format_and_front_insertion_performance_issues() {
        let source = r#"use std::collections::HashMap;

fn render(values: Vec<u8>, mut queue: Vec<u8>, key: String, mut labels: HashMap<String, String>) -> String {
    let mut output = String::new();
    if !labels.contains_key(&key) {
        labels.insert(key, "new".to_owned());
    }
    for value in values {
        output.push_str(&format!("{value:02x}"));
        queue.insert(0, value);
    }
    (0..4).map(|value| format!("{value:x}")).collect::<String>()
}"#;

        assert_eq!(
            findings(source)
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "rust-map-double-lookup"
                            | "rust-format-append"
                            | "rust-vec-front-insertion-in-loop"
                            | "rust-format-collect"
                    )
                })
                .map(|finding| (finding.code, finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("rust-vec-front-insertion-in-loop".to_owned(), 10),
                ("rust-map-double-lookup".to_owned(), 5),
                ("rust-format-append".to_owned(), 9),
                ("rust-format-collect".to_owned(), 12),
            ]
        );
    }

    #[test]
    fn accepts_single_lookups_direct_formatting_and_non_loop_front_insertion() {
        let source = r#"use std::collections::HashMap;
use std::fmt::Write as _;

fn render(mut values: Vec<u8>, key: String, mut labels: HashMap<String, String>) -> String {
    let mut output = String::new();
    labels.insert(key, "new".to_owned());
    values.insert(0, 1);
    let _ = write!(output, "{:02x}", values.len());
    (0..4).map(|value| value.to_string()).collect::<String>()
}"#;

        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-map-double-lookup"
                        | "rust-format-append"
                        | "rust-vec-front-insertion-in-loop"
                        | "rust-format-collect"
                )
            })
            .collect::<Vec<_>>();
        assert!(selected.is_empty(), "unexpected findings: {selected:?}");
    }
}
