use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Instant;

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

pub struct RustAnalysisOutput {
    pub findings: Vec<Finding>,
    pub shared_durations_microseconds: BTreeMap<String, u128>,
    pub rule_durations_microseconds: BTreeMap<String, u128>,
}

#[cfg(test)]
pub fn analyze_with_functions(
    sources: &BTreeMap<String, String>,
    functions: &[FunctionSource],
) -> Vec<Finding> {
    analyze_profiled(sources, functions, false).findings
}

pub fn analyze_profiled(
    sources: &BTreeMap<String, String>,
    functions: &[FunctionSource],
    collect_timings: bool,
) -> RustAnalysisOutput {
    let mut findings = Vec::new();
    let mut shared_durations = BTreeMap::new();
    let mut rule_durations = BTreeMap::new();
    macro_rules! run {
        ($name:literal, $analysis:expr) => {{
            if collect_timings {
                let started = Instant::now();
                $analysis;
                record_duration(&mut rule_durations, $name, started);
            } else {
                $analysis;
            }
        }};
    }
    let started = collect_timings.then(Instant::now);
    let scope_index = RustScopeIndex::new(functions);
    let inherited_unsafe_policy = inherited_unsafe_policy_files(sources);
    if let Some(started) = started {
        record_duration(&mut shared_durations, "rust-scope-index", started);
    }
    run!("rust-object-soup", {
        findings.extend(object_soup_rules::rust(functions))
    });
    for (path, source) in sources.iter().filter(|(path, _)| path.ends_with(".rs")) {
        let started = collect_timings.then(Instant::now);
        let file = RustFile::new(source);
        if let Some(started) = started {
            record_duration(&mut shared_durations, "rust-file-index", started);
        }
        analyze_simple_rules(
            path,
            &file,
            &mut findings,
            collect_timings,
            &mut rule_durations,
        );
        run!("rust-hardcoded-secrets", {
            analyze_hardcoded_secrets(path, &file, &mut findings)
        });
        run!("rust-unsafe-blocks", {
            analyze_unsafe_blocks(
                path,
                &file,
                inherited_unsafe_policy.contains(path),
                &mut findings,
            )
        });
        run!("rust-static-mut", {
            analyze_static_mut(path, &file, &mut findings)
        });
        run!("rust-raw-ownership", {
            analyze_raw_ownership(path, &file, &mut findings)
        });
        run!("rust-impl-into", {
            analyze_impl_into(path, &file, &mut findings)
        });
        run!("rust-manual-send-sync", {
            analyze_manual_send_sync(path, &file, &mut findings)
        });
        run!("rust-shell-command", {
            analyze_shell_commands(path, &file, &mut findings)
        });
        run!("rust-ffi-panic", {
            analyze_ffi_panics(path, &file, &mut findings)
        });
        run!("rust-async-blocking", {
            analyze_async_blocking(path, &file, &mut findings)
        });
        run!("rust-lock-across-await", {
            analyze_sync_lock_across_await(path, &file, &mut findings)
        });
        run!("rust-loop-performance", {
            analyze_loop_performance(path, &file, scope_index.linear(path), &mut findings)
        });
        run!("rust-map-double-lookup", {
            analyze_map_double_lookup(path, &file, scope_index.maps(path), &mut findings)
        });
        run!("rust-format-allocation", {
            analyze_format_allocations(path, &file, scope_index.strings(path), &mut findings)
        });
        run!("rust-unbounded-channel", {
            analyze_unbounded_channels(path, &file, &mut findings)
        });
    }
    RustAnalysisOutput {
        findings,
        shared_durations_microseconds: shared_durations,
        rule_durations_microseconds: rule_durations,
    }
}

fn record_duration(durations: &mut BTreeMap<String, u128>, name: &str, started: Instant) {
    *durations.entry(name.to_owned()).or_default() += started.elapsed().as_micros();
}

struct SimpleRule {
    code: &'static str,
    pattern: Regex,
    message: &'static str,
    allowed_lints: &'static [&'static str],
}

fn analyze_simple_rules(
    path: &str,
    file: &RustFile<'_>,
    findings: &mut Vec<Finding>,
    collect_timings: bool,
    durations: &mut BTreeMap<String, u128>,
) {
    for rule in SIMPLE_RULES.iter() {
        let started = collect_timings.then(Instant::now);
        if !file_allows_rule(&file.masked, rule.allowed_lints) {
            let allowed_ranges = attributed_allowed_ranges(&file.masked, rule.allowed_lints);
            let mut source_offset = 0usize;
            for (index, line) in file.masked.split('\n').enumerate() {
                if reportable_simple_match(file, rule, &allowed_ranges, index, line, source_offset)
                    .is_some()
                {
                    findings.push(finding(rule.code, path, index + 1, rule.message));
                }
                source_offset += line.len() + 1;
            }
        }
        if let Some(started) = started {
            record_duration(durations, rule.code, started);
        }
    }
}

fn reportable_simple_match(
    file: &RustFile<'_>,
    rule: &SimpleRule,
    allowed_ranges: &[(usize, usize)],
    index: usize,
    line: &str,
    source_offset: usize,
) -> Option<usize> {
    if file.test_lines.contains(&index) {
        return None;
    }
    rule.pattern
        .find_iter(line)
        .find(|matched| {
            let offset = source_offset + matched.start();
            !allowed_ranges
                .iter()
                .any(|(start, end)| *start <= offset && offset < *end)
                && !is_proven_panic_invariant(rule.code, file, offset)
        })
        .map(|matched| matched.start())
}

fn is_proven_panic_invariant(code: &str, file: &RustFile<'_>, call_offset: usize) -> bool {
    match code {
        "rust-panic-macro" => panic_macro_is_invariant(file, call_offset),
        "rust-unwrap" | "rust-expect" => recoverable_panic_is_invariant(code, file, call_offset),
        _ => false,
    }
}

fn panic_macro_is_invariant(file: &RustFile<'_>, call_offset: usize) -> bool {
    let source = file.source;
    let line_end = source[call_offset..]
        .find('\n')
        .map_or(source.len(), |offset| call_offset + offset);
    PANIC_INVARIANT_MESSAGE.is_match(&source[call_offset..line_end])
        || containing_function_documents_panic(file, call_offset)
}

fn recoverable_panic_is_invariant(code: &str, file: &RustFile<'_>, call_offset: usize) -> bool {
    if local_panic_invariant(file, call_offset)
        || containing_function_documents_panic(file, call_offset)
        || expect_call_is_proven_custom(code, file, call_offset)
    {
        return true;
    }
    let statement_start = file.masked[..call_offset]
        .rfind(';')
        .map_or(0, |offset| offset + 1);
    if code == "rust-expect"
        && documented_utf8_reconstruction(
            &file.source[statement_start..call_offset],
            &file.source[call_offset..],
        )
    {
        return true;
    }
    let statement_end = file.masked[call_offset..]
        .find(';')
        .map_or(file.source.len(), |offset| call_offset + offset + 1);
    let statement = &file.source[statement_start..statement_end];
    if statement_documents_panic_invariant(code, file, statement_start, statement) {
        return true;
    }
    regex_constructor_is_invariant(file.source, &file.masked, statement_start, call_offset)
}

fn expect_call_is_proven_custom(code: &str, file: &RustFile<'_>, call_offset: usize) -> bool {
    if code != "rust-expect" {
        return false;
    }
    if receiver_has_explicit_nonstandard_type(file.source, call_offset) {
        return true;
    }
    let Some(open) = file.masked[call_offset..]
        .find('(')
        .map(|offset| call_offset + offset)
    else {
        return false;
    };
    let Some(close) = matching_delimiter(&file.masked, open, b'(', b')') else {
        return false;
    };
    ASSOCIATED_VALUE_ARGUMENT.is_match(file.source[open + 1..close].trim())
}

fn receiver_has_explicit_nonstandard_type(source: &str, call_offset: usize) -> bool {
    let prefix = &source[..call_offset];
    let Some((receiver_start, receiver)) = receiver_before_call(prefix) else {
        return false;
    };
    declared_receiver_type(prefix, receiver_start, receiver).is_some_and(|type_name| {
        let leaf = type_name.rsplit("::").next().unwrap_or(type_name);
        !matches!(leaf, "Option" | "Result")
    })
}

fn receiver_before_call(prefix: &str) -> Option<(usize, &str)> {
    let receiver_end = prefix.len();
    let receiver_start = prefix
        .as_bytes()
        .iter()
        .rposition(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        .map_or(0, |offset| offset + 1);
    (receiver_start != receiver_end)
        .then(|| (receiver_start, &prefix[receiver_start..receiver_end]))
}

fn declared_receiver_type<'a>(
    prefix: &'a str,
    receiver_start: usize,
    receiver: &str,
) -> Option<&'a str> {
    for (offset, _) in prefix[..receiver_start].rmatch_indices(receiver) {
        if offset > 0 {
            let previous = prefix.as_bytes()[offset - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                continue;
            }
        }
        let after_receiver = &prefix[offset + receiver.len()..];
        let Some(declaration) = after_receiver.trim_start().strip_prefix(':') else {
            continue;
        };
        if let Some(type_name) = declared_type_name(declaration) {
            return Some(type_name);
        }
    }
    None
}

fn declared_type_name(mut declaration: &str) -> Option<&str> {
    declaration = declaration.trim_start();
    if let Some(borrowed) = declaration.strip_prefix('&') {
        declaration = borrowed.trim_start();
        if declaration.starts_with('\'') {
            declaration = declaration
                .find(char::is_whitespace)
                .map_or("", |end| declaration[end..].trim_start());
        }
        declaration = declaration
            .strip_prefix("mut ")
            .unwrap_or(declaration)
            .trim_start();
    }
    let type_end = declaration
        .find(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == ':')
        })
        .unwrap_or(declaration.len());
    let type_name = &declaration[..type_end];
    (!type_name.is_empty()).then_some(type_name)
}

fn local_panic_invariant(file: &RustFile<'_>, call_offset: usize) -> bool {
    file.regex_contracts
        .capture_access_is_invariant(file.source, &file.masked, call_offset)
        || panic_guards::locally_proven_invariant(file.source, &file.masked, call_offset)
        || preceding_comment_documents_invariant(file, call_offset)
}

fn statement_documents_panic_invariant(
    code: &str,
    file: &RustFile<'_>,
    statement_start: usize,
    statement: &str,
) -> bool {
    expect_statement_documents_invariant(code, statement)
        || string_format_write_is_invariant(file.source, statement_start, statement)
        || literal_parse_is_invariant(statement)
        || static_infallible_construction_is_invariant(statement)
}

fn preceding_comment_documents_invariant(file: &RustFile<'_>, call_offset: usize) -> bool {
    let source = file.source;
    if let Some(index) = file
        .comments
        .iter()
        .rposition(|comment| comment.end <= call_offset)
        && is_safety_expression_prefix(&file.masked[file.comments[index].end..call_offset])
        && RUST_INVARIANT_COMMENT.is_match(file.comment_block_ending_at(index))
    {
        return true;
    }
    let line_start = source[..call_offset]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let mut crossed_macro_declaration = false;
    for line in source[..line_start].lines().rev().take(5) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("//") {
            if RUST_INVARIANT_COMMENT.is_match(trimmed) {
                return true;
            }
            continue;
        }
        if !crossed_macro_declaration && trimmed.starts_with("macro_rules!") {
            crossed_macro_declaration = true;
            continue;
        }
        break;
    }
    false
}

fn string_format_write_is_invariant(source: &str, statement_start: usize, statement: &str) -> bool {
    let write_open = statement
        .rfind("write!(")
        .map(|index| index + "write!(".len());
    let writeln_open = statement
        .rfind("writeln!(")
        .map(|index| index + "writeln!(".len());
    let Some(open) = write_open.into_iter().chain(writeln_open).max() else {
        return false;
    };
    let target_end = statement[open..]
        .find([',', ')'])
        .map_or(statement.len(), |offset| open + offset);
    let target = statement[open..target_end]
        .trim()
        .strip_prefix("&mut ")
        .unwrap_or(statement[open..target_end].trim());
    if target.is_empty()
        || !target
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return false;
    }
    source[..statement_start]
        .lines()
        .rev()
        .take(80)
        .take_while(|line| !line.trim_start().starts_with("fn "))
        .any(|line| {
            let line = line.trim();
            line.starts_with("let mut ")
                && line["let mut ".len()..].starts_with(target)
                && line[target.len() + "let mut ".len()..]
                    .trim_start()
                    .starts_with('=')
                && (line.contains("String::new(") || line.contains("String::with_capacity("))
        })
}

fn literal_parse_is_invariant(statement: &str) -> bool {
    STATIC_LITERAL_PARSE.is_match(statement)
}

fn static_infallible_construction_is_invariant(statement: &str) -> bool {
    STATIC_INFALLIBLE_CONSTRUCTION.is_match(statement)
}

fn containing_function_documents_panic(file: &RustFile<'_>, call_offset: usize) -> bool {
    file.panic_contracts
        .iter()
        .rev()
        .find(|(open, close, _)| *open < call_offset && call_offset < *close)
        .is_some_and(|(_, _, documented)| *documented)
}

fn function_panic_contracts(
    source: &str,
    masked: &str,
    comments: &[CommentRange],
) -> Vec<(usize, usize, bool)> {
    if !RUST_PANIC_DOCUMENTATION.is_match(source) {
        return Vec::new();
    }
    let documentation = panic_documentation_ranges(source, masked, comments);
    RUST_FUNCTION_DECLARATION
        .find_iter(masked)
        .filter_map(|declaration| {
            let open = declaration.end() + masked[declaration.end()..].find('{')?;
            if masked[declaration.end()..open].contains(';') {
                return None;
            }
            let close = matching_delimiter(masked, open, b'{', b'}')?;
            let mut cursor = declaration.start();
            let mut documented = false;
            for &(start, end, contract) in documentation.iter().rev() {
                if end > cursor {
                    continue;
                }
                if !RUST_FUNCTION_QUALIFIERS.is_match(&masked[end..cursor]) {
                    break;
                }
                documented |= contract;
                cursor = start;
            }
            Some((open, close, documented))
        })
        .collect()
}

fn panic_documentation_ranges(
    source: &str,
    masked: &str,
    comments: &[CommentRange],
) -> Vec<(usize, usize, bool)> {
    let mut ranges = comments
        .iter()
        .map(|comment| {
            let text = &source[comment.start..comment.end];
            let outer_doc = (text.starts_with("///") && !text.starts_with("////"))
                || (text.starts_with("/**") && !text.starts_with("/***"));
            (
                comment.start,
                comment.end,
                outer_doc && RUST_PANIC_DOCUMENTATION.is_match(text),
            )
        })
        .collect::<Vec<_>>();
    for attribute in RUST_OUTER_ATTRIBUTE.find_iter(masked) {
        let open = attribute.end() - 1;
        let Some(close) = matching_delimiter(masked, open, b'[', b']') else {
            continue;
        };
        let text = source[open + 1..close].trim();
        let contract = text
            .strip_prefix("doc")
            .and_then(|text| text.trim_start().strip_prefix('='))
            .map(str::trim)
            .filter(|literal| literal.starts_with('"') || literal.starts_with('r'))
            .filter(|literal| {
                rust_literal_end(literal.as_bytes(), 0)
                    .is_some_and(|end| literal[end..].trim().is_empty())
            })
            .and_then(rust_string_body)
            .is_some_and(|body| RUST_PANIC_DOCUMENTATION.is_match(body));
        ranges.push((attribute.start(), close + 1, contract));
    }
    ranges.sort_unstable_by_key(|(_, end, _)| *end);
    ranges
}

fn expect_statement_documents_invariant(code: &str, statement: &str) -> bool {
    code == "rust-expect"
        && [
            "rule_catalog::metadata(",
            "rule_catalog::descriptor(",
            "Severity::parse(metadata.default_severity)",
        ]
        .iter()
        .any(|invariant| statement.contains(invariant))
}

fn documented_utf8_reconstruction(receiver: &str, call: &str) -> bool {
    UTF8_RECONSTRUCTION_RECEIVER.is_match(receiver)
        && UTF8_RECONSTRUCTION_MESSAGE
            .captures(call)
            .is_some_and(|capture| {
                let message = &capture["message"];
                UTF8_MASKING_DESCRIPTION.is_match(message)
                    && UTF8_PRESERVATION_DESCRIPTION.is_match(message)
            })
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
        let attribute = capture.get(0).unwrap();
        brace_delta(&source[..attribute.start()]) == 0
            && allowed_lints
                .iter()
                .any(|lint| lint_list_contains(&capture[1], lint))
    })
}

fn attributed_allowed_ranges(masked: &str, allowed_lints: &[&str]) -> Vec<(usize, usize)> {
    attributed_policy_ranges(masked, allowed_lints, &[&ITEM_ALLOW, &CRATE_ALLOW])
}

fn attributed_policy_ranges(
    masked: &str,
    allowed_lints: &[&str],
    patterns: &[&Regex],
) -> Vec<(usize, usize)> {
    let mut result = Vec::new();
    if allowed_lints.is_empty() {
        return result;
    }
    for capture in patterns
        .iter()
        .flat_map(|pattern| pattern.captures_iter(masked))
    {
        if !allowed_lints
            .iter()
            .any(|lint| lint_list_contains(&capture[1], lint))
        {
            continue;
        }
        let attribute = capture.get(0).unwrap();
        let mut cursor = skip_ascii_whitespace(masked, attribute.end());
        while masked[cursor..].starts_with("#[") {
            let Some(close) = matching_delimiter(masked, cursor + 1, b'[', b']') else {
                break;
            };
            cursor = skip_ascii_whitespace(masked, close + 1);
        }
        let end = if attribute.as_str().starts_with("#!") {
            enclosing_block_end(masked, 0, attribute.start()).unwrap_or(masked.len())
        } else if let Some(end) = attributed_item_end(masked, cursor) {
            end
        } else {
            continue;
        };
        result.push((attribute.start(), end));
    }
    result
}

fn lint_list_contains(list: &str, lint: &str) -> bool {
    list.split(|character: char| character == ',' || character.is_whitespace())
        .any(|candidate| candidate == lint)
}

fn attributed_item_end(masked: &str, mut cursor: usize) -> Option<usize> {
    while let Some(byte) = masked.as_bytes().get(cursor) {
        match byte {
            b'(' => cursor = matching_delimiter(masked, cursor, b'(', b')')? + 1,
            b'[' => cursor = matching_delimiter(masked, cursor, b'[', b']')? + 1,
            b'{' => return matching_delimiter(masked, cursor, b'{', b'}').map(|end| end + 1),
            b';' => return Some(cursor + 1),
            _ => cursor += 1,
        }
    }
    None
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
    if value.is_empty()
        || value.contains("://")
        || is_symbolic_secret_label(value)
        || is_secret_placeholder(name, value)
    {
        return false;
    }
    match kind {
        SecretNameKind::Direct => {
            value.len() >= 6 && value.bytes().any(|byte| byte.is_ascii_alphanumeric())
        }
        SecretNameKind::Token => looks_like_token_secret(value),
    }
}

fn is_symbolic_secret_label(value: &str) -> bool {
    (value.starts_with('$') && value.contains("::"))
        || (value.len() > 4
            && value.starts_with("__")
            && value.ends_with("__")
            && value[2..value.len() - 2]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
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
    literal.get(first_quote + 1..last_quote)
}

const UNSAFE_DOCUMENTATION_LINTS: &[&str] = &[
    "clippy::undocumented_unsafe_blocks",
    "undocumented_unsafe_blocks",
];

fn inherited_unsafe_policy_files(sources: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut inherited = BTreeSet::new();
    for (path, source) in sources {
        let (directory, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        if !matches!(name, "lib.rs" | "main.rs") || !source.contains("undocumented_unsafe_blocks") {
            continue;
        }
        let sibling = if name == "lib.rs" {
            "main.rs"
        } else {
            "lib.rs"
        };
        if sources.contains_key(&module_candidate(directory, sibling)) {
            continue;
        }
        let masked = scan_rust(source).0;
        if file_allows_rule(&masked, UNSAFE_DOCUMENTATION_LINTS)
            && !file_denies_unsafe_policy(&masked)
        {
            inherit_unsafe_module_policy(sources, path, &masked, &mut inherited);
        }
    }
    inherited
}

fn inherit_unsafe_module_policy(
    sources: &BTreeMap<String, String>,
    path: &str,
    masked: &str,
    inherited: &mut BTreeSet<String>,
) {
    if CUSTOM_MODULE_PATH.is_match(masked) {
        return;
    }
    let base = rust_module_directory(path);
    let mut previous = 0;
    let mut depth = 0;
    let denied_ranges = denied_unsafe_ranges(masked);
    for capture in OUT_OF_LINE_MODULE.captures_iter(masked) {
        let declaration = capture.get(0).unwrap();
        depth += brace_delta(&masked[previous..declaration.start()]);
        previous = declaration.end();
        if depth != 0
            || denied_ranges
                .iter()
                .any(|(start, end)| *start <= declaration.start() && declaration.start() < *end)
        {
            continue;
        }
        let module = &capture[1];
        let flat = module_candidate(base, &format!("{module}.rs"));
        let nested = module_candidate(base, &format!("{module}/mod.rs"));
        let child = match (sources.contains_key(&flat), sources.contains_key(&nested)) {
            (true, false) => flat,
            (false, true) => nested,
            _ => continue,
        };
        let child_masked = scan_rust(&sources[&child]).0;
        if !file_denies_unsafe_policy(&child_masked) && inherited.insert(child.clone()) {
            inherit_unsafe_module_policy(sources, &child, &child_masked, inherited);
        }
    }
}

fn rust_module_directory(path: &str) -> &str {
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    if matches!(name, "lib.rs" | "main.rs" | "mod.rs") {
        directory
    } else {
        path.strip_suffix(".rs").unwrap_or(directory)
    }
}

fn module_candidate(directory: &str, relative: &str) -> String {
    if directory.is_empty() {
        relative.to_owned()
    } else {
        format!("{directory}/{relative}")
    }
}

fn file_denies_unsafe_policy(masked: &str) -> bool {
    UNSAFE_POLICY_DENY.captures_iter(masked).any(|capture| {
        let attribute = capture.get(0).unwrap();
        attribute.as_str().starts_with("#!")
            && brace_delta(&masked[..attribute.start()]) == 0
            && UNSAFE_DOCUMENTATION_LINTS
                .iter()
                .any(|lint| lint_list_contains(&capture[1], lint))
    })
}

fn denied_unsafe_ranges(masked: &str) -> Vec<(usize, usize)> {
    attributed_policy_ranges(masked, UNSAFE_DOCUMENTATION_LINTS, &[&UNSAFE_POLICY_DENY])
}

struct UnsafeDocumentationPolicy {
    file_allowed: bool,
    allowed: Vec<(usize, usize)>,
    denied: Vec<(usize, usize)>,
}

impl UnsafeDocumentationPolicy {
    fn new(masked: &str, inherited_policy: bool) -> Self {
        let file_allowed = inherited_policy || file_allows_rule(masked, UNSAFE_DOCUMENTATION_LINTS);
        Self {
            file_allowed,
            allowed: if file_allowed {
                Vec::new()
            } else {
                attributed_allowed_ranges(masked, UNSAFE_DOCUMENTATION_LINTS)
            },
            denied: denied_unsafe_ranges(masked),
        }
    }

    fn allows(&self, offset: usize) -> bool {
        if self
            .denied
            .iter()
            .any(|(start, end)| *start <= offset && offset < *end)
        {
            return false;
        }
        self.file_allowed
            || self
                .allowed
                .iter()
                .any(|(start, end)| *start <= offset && offset < *end)
    }
}

fn analyze_unsafe_blocks(
    path: &str,
    file: &RustFile<'_>,
    inherited_policy: bool,
    findings: &mut Vec<Finding>,
) {
    let policy = UnsafeDocumentationPolicy::new(&file.masked, inherited_policy);
    if policy.file_allowed && policy.denied.is_empty() {
        return;
    }
    for matched in UNSAFE_BLOCK.find_iter(&file.masked) {
        let Some(open) = file.masked[matched.start()..]
            .find('{')
            .map(|offset| matched.start() + offset)
        else {
            continue;
        };
        if file.excluded(matched.start())
            || policy.allows(matched.start())
            || file.has_safety_rationale(matched.start(), open)
        {
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
        if !file.excluded(matched.start())
            && standard_ownership_path(&file.masked, matched.start())
            && !ownership_roundtrip_is_invariant(file, matched.start(), matched.end() - 1)
        {
            findings.push(finding(
                "rust-raw-ownership-reconstruction",
                path,
                file.line_at(matched.start()),
                "raw pointer is converted back into an owning Rust value",
            ));
        }
    }
}

fn standard_ownership_path(masked: &str, start: usize) -> bool {
    let prefix = masked[..start].trim_end();
    !prefix.ends_with("::")
        || prefix.strip_suffix("::").is_some_and(|path| {
            path.trim_end()
                .as_bytes()
                .last()
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        })
}

fn ownership_roundtrip_is_invariant(file: &RustFile<'_>, start: usize, open: usize) -> bool {
    let Some(close) = file.matching(open, b'(', b')') else {
        return false;
    };
    let owner = file.masked[start..open].rsplit("::").nth(1).unwrap_or("");
    let argument = &file.masked[open + 1..close];
    let Some(origin) = RAW_ORIGIN.captures(argument) else {
        return false;
    };
    if origin.get(1).unwrap().as_str() != owner {
        return false;
    }
    let origin_open = open + 1 + origin.get(0).unwrap().end() - 1;
    let Some(origin_close) = file.matching(origin_open, b'(', b')') else {
        return false;
    };
    if origin_close >= close {
        return false;
    }
    let conversion = file.masked[origin_close + 1..close].trim();
    if conversion.is_empty() || OWNERSHIP_UNSIZING_CAST.is_match(conversion) {
        // The same owner consumes its own fresh pointer exactly once. A direct
        // trait-object cast is a compiler-checked unsizing coercion, not a
        // reinterpretation of an unrelated concrete allocation layout.
        return true;
    }
    OWNERSHIP_POINTER_CAST.is_match(conversion)
        && enclosing_unsafe_rationale(file, start)
            .is_some_and(|rationale| TRANSPARENT_LAYOUT.is_match(rationale))
}

fn enclosing_unsafe_rationale<'a>(file: &'a RustFile<'_>, offset: usize) -> Option<&'a str> {
    let matched = UNSAFE_BLOCK
        .find_iter(&file.masked[..offset])
        .filter(|matched| {
            file.matching(matched.end() - 1, b'{', b'}')
                .is_some_and(|close| offset < close)
        })
        .last()?;
    file.safety_rationale(matched.start(), matched.end() - 1)
}

fn analyze_impl_into(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    const ALLOWED_LINTS: &[&str] = &["clippy::from_over_into", "from_over_into"];

    if file_allows_rule(&file.masked, ALLOWED_LINTS) {
        return;
    }
    let allowed_ranges = attributed_allowed_ranges(&file.masked, ALLOWED_LINTS);
    for matched in IMPL_KEYWORD.find_iter(&file.masked) {
        let line = file.line_at(matched.start());
        if file.excluded(matched.start())
            || allowed_ranges
                .iter()
                .any(|(start, end)| *start <= matched.start() && matched.start() < *end)
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
    let mut documented_pair = None::<(String, usize)>;
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
        let close = file
            .matching(open, b'{', b'}')
            .map_or(open, |offset| offset + 1);
        let type_name = type_name.as_str();
        if file.has_safety_rationale(matched.start(), open) {
            documented_pair = Some((type_name.to_owned(), close));
            continue;
        }
        let paired = documented_pair.take().is_some_and(|(documented, end)| {
            documented == type_name && file.masked[end..matched.start()].trim().is_empty()
        });
        if paired || !reported.insert(type_name.to_owned()) {
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

struct RustScopeIndex<'a> {
    linear: BTreeMap<&'a str, Vec<NamedScope>>,
    maps: BTreeMap<&'a str, Vec<NamedScope>>,
    strings: BTreeMap<&'a str, Vec<NamedScope>>,
}

impl<'a> RustScopeIndex<'a> {
    fn new(functions: &'a [FunctionSource]) -> Self {
        let mut result = Self {
            linear: BTreeMap::new(),
            maps: BTreeMap::new(),
            strings: BTreeMap::new(),
        };
        for function in functions
            .iter()
            .filter(|function| function.path.ends_with(".rs"))
        {
            let (masked, _, _) = scan_rust(&function.source);
            collect_named_scope(
                &mut result.linear,
                function,
                &masked,
                &LINEAR_COLLECTION_DECLARATION,
            );
            collect_named_scope(&mut result.maps, function, &masked, &MAP_DECLARATION);
            collect_named_scope(&mut result.strings, function, &masked, &STRING_DECLARATION);
        }
        result
    }

    fn linear(&self, path: &str) -> &[NamedScope] {
        self.linear.get(path).map(Vec::as_slice).unwrap_or(&[])
    }

    fn maps(&self, path: &str) -> &[NamedScope] {
        self.maps.get(path).map(Vec::as_slice).unwrap_or(&[])
    }

    fn strings(&self, path: &str) -> &[NamedScope] {
        self.strings.get(path).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn collect_named_scope<'a>(
    scopes: &mut BTreeMap<&'a str, Vec<NamedScope>>,
    function: &'a FunctionSource,
    masked: &str,
    declaration: &Regex,
) {
    let names = declaration
        .captures_iter(masked)
        .filter_map(|capture| capture.get(1).or_else(|| capture.get(2)))
        .map(|name| name.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if names.is_empty() {
        return;
    }
    scopes
        .entry(function.path.as_str())
        .or_default()
        .push(NamedScope {
            start_line: function.line,
            end_line: function.end_line,
            names,
        });
}

fn analyze_loop_performance(
    path: &str,
    file: &RustFile<'_>,
    scopes: &[NamedScope],
    findings: &mut Vec<Finding>,
) {
    let loops = rust_loops(file);
    analyze_loop_regex(path, file, &loops, findings);
    analyze_loop_membership(path, file, &loops, scopes, findings);
    analyze_loop_front_removal(path, file, &loops, scopes, findings);
    analyze_loop_front_insertion(path, file, &loops, scopes, findings);
    analyze_loop_chars_nth(path, file, &loops, findings);
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

fn analyze_loop_chars_nth(
    path: &str,
    file: &RustFile<'_>,
    loops: &[RustLoop],
    findings: &mut Vec<Finding>,
) {
    let mut reported = BTreeSet::new();
    for current in loops {
        let repeated = &file.masked[current.body_start..current.body_end];
        for access in CHARS_NTH_WITH_INDEX.find_iter(repeated) {
            let absolute = current.body_start + access.start();
            if file.excluded(absolute) || !reported.insert(absolute) {
                continue;
            }
            findings.push(finding(
                "rust-chars-nth-in-loop",
                path,
                file.line_at(absolute),
                "chars().nth(index) rescans UTF-8 text from the beginning inside a loop",
            ));
        }
    }
}

fn analyze_map_double_lookup(
    path: &str,
    file: &RustFile<'_>,
    scopes: &[NamedScope],
    findings: &mut Vec<Finding>,
) {
    for guard in MAP_CONTAINS_GUARD.captures_iter(&file.masked) {
        let (Some(whole), Some(map), Some(key)) = (guard.get(0), guard.get(1), guard.get(2)) else {
            continue;
        };
        let line = file.line_at(whole.start());
        if !scope_contains(scopes, map.as_str(), line) || file.excluded(whole.start()) {
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
    scopes: &[NamedScope],
    findings: &mut Vec<Finding>,
) {
    for append in FORMAT_APPEND.captures_iter(&file.masked) {
        let (Some(whole), Some(name)) = (append.get(0), append.get(1).or_else(|| append.get(2)))
        else {
            continue;
        };
        let line = file.line_at(whole.start());
        if scope_contains(scopes, name.as_str(), line) && !file.excluded(whole.start()) {
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
    let mut async_scopes = ASYNC_SCOPE.find_iter(&file.masked);
    let Some(first_scope) = async_scopes.next() else {
        return;
    };
    let mut reported = BTreeSet::new();
    let boundaries = AsyncBlockingBoundaries::new(file);
    for scope in std::iter::once(first_scope).chain(async_scopes) {
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
            if !file.excluded(absolute)
                && !boundaries.excludes_call(body_start, absolute)
                && reported.insert(absolute)
            {
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

struct AsyncBlockingBoundaries {
    functions: Vec<(usize, usize)>,
    offloads: Vec<(usize, usize)>,
}

impl AsyncBlockingBoundaries {
    fn new(file: &RustFile<'_>) -> Self {
        let functions = RUST_FUNCTION_DECLARATION
            .find_iter(&file.masked)
            .filter_map(|declaration| {
                let open = declaration.end() + file.masked[declaration.end()..].find('{')?;
                if file.masked[declaration.end()..open].contains(';') {
                    return None;
                }
                Some((open, file.matching(open, b'{', b'}')?))
            })
            .collect();
        Self {
            functions,
            offloads: blocking_offload_ranges(file),
        }
    }

    fn excludes_call(&self, scope_start: usize, offset: usize) -> bool {
        self.functions
            .iter()
            .any(|(start, end)| scope_start <= *start && *start < offset && offset < *end)
            || self
                .offloads
                .iter()
                .any(|(start, end)| scope_start <= *start && *start <= offset && offset < *end)
    }
}

fn blocking_offload_ranges(file: &RustFile<'_>) -> Vec<(usize, usize)> {
    let mut imported = BTreeSet::new();
    for import in OFFLOAD_IMPORT.captures_iter(&file.masked) {
        let whole = import.get(0).unwrap();
        if brace_delta(&file.masked[..whole.start()]) != 0 {
            continue;
        }
        let name = import
            .get(3)
            .or_else(|| import.get(1))
            .or_else(|| import.get(2))
            .unwrap()
            .as_str();
        if !OFFLOAD_SHADOW_BINDING
            .captures_iter(&file.masked)
            .any(|binding| {
                binding
                    .get(1)
                    .or_else(|| binding.get(2))
                    .is_some_and(|bound| bound.as_str() == name)
            })
        {
            imported.insert(name);
        }
    }
    OFFLOAD
        .captures_iter(&file.masked)
        .filter_map(|call| {
            let whole = call.get(0)?;
            if file.masked[..whole.start()]
                .trim_end()
                .ends_with(['.', ':'])
                || call
                    .get(1)
                    .is_some_and(|name| !imported.contains(name.as_str()))
            {
                return None;
            }
            let open = whole.end() - 1;
            let close = file.matching(open, b'(', b')')?;
            let mut argument = skip_ascii_whitespace(&file.masked, open + 1);
            if token_at(&file.masked, argument, "move") {
                argument = skip_ascii_whitespace(&file.masked, argument + 4);
            }
            if !file.masked[argument..].starts_with("||") {
                return None;
            }
            let body = skip_ascii_whitespace(&file.masked, argument + 2);
            let end = if file.masked.as_bytes().get(body) == Some(&b'{') {
                file.matching(body, b'{', b'}')?
            } else {
                close
            };
            Some((body, end))
        })
        .collect()
}

fn analyze_sync_lock_across_await(path: &str, file: &RustFile<'_>, findings: &mut Vec<Finding>) {
    let parking_lot = PARKING_LOT_MUTEX.is_match(&file.masked);
    let async_bodies = ASYNC_SCOPE
        .find_iter(&file.masked)
        .filter_map(|scope| {
            let open = scope.start() + file.masked[scope.start()..].find('{')?;
            Some((open, file.matching(open, b'{', b'}')?))
        })
        .collect::<Vec<_>>();
    for lock in SYNC_LOCK_GUARD.captures_iter(&file.masked) {
        let whole = lock.get(0).unwrap();
        let absolute = whole.start();
        if file.excluded(absolute) || (!parking_lot && lock.name("poison").is_none()) {
            continue;
        }
        let Some((open, _)) = async_bodies
            .iter()
            .rev()
            .find(|(open, close)| *open < absolute && absolute < *close)
        else {
            continue;
        };
        let guard = &lock["guard"];
        if guard_suspends(file, &async_bodies, *open, absolute, whole.end(), guard) {
            findings.push(finding(
                "rust-sync-lock-across-await",
                path,
                file.line_at(absolute),
                &format!("synchronous lock guard `{guard}` remains in scope across await"),
            ));
        }
    }
}

fn guard_suspends(
    file: &RustFile<'_>,
    async_bodies: &[(usize, usize)],
    scope_open: usize,
    binding: usize,
    search_start: usize,
    guard: &str,
) -> bool {
    let Some(block_end) = enclosing_rust_block_end(file, scope_open, binding) else {
        return false;
    };
    let Some(awaited) = AWAIT_POINT
        .find_iter(&file.masked[search_start..block_end])
        .find(|awaited| {
            let offset = search_start + awaited.start();
            !async_bodies
                .iter()
                .any(|(open, close)| binding < *open && *open < offset && offset < *close)
        })
    else {
        return false;
    };
    let await_offset = search_start + awaited.start();
    !EXPLICIT_GUARD_DROP
        .captures_iter(&file.masked[search_start..await_offset])
        .any(|dropped| &dropped["guard"] == guard)
}

fn enclosing_rust_block_end(
    file: &RustFile<'_>,
    scope_open: usize,
    offset: usize,
) -> Option<usize> {
    enclosing_block_end(&file.masked, scope_open, offset)
}

fn enclosing_block_end(masked: &str, scope_open: usize, offset: usize) -> Option<usize> {
    let mut depth = 0usize;
    for index in (scope_open..offset).rev() {
        match masked.as_bytes()[index] {
            b'}' => depth += 1,
            b'{' if depth == 0 => return matching_delimiter(masked, index, b'{', b'}'),
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
    panic_contracts: Vec<(usize, usize, bool)>,
}

impl<'a> RustFile<'a> {
    fn new(source: &'a str) -> Self {
        let (masked, comments_masked, comments) = scan_rust(source);
        let test_lines = test_scopes::test_lines(source, &masked);
        let regex_contracts = RegexContracts::new(source, &masked);
        let panic_contracts = function_panic_contracts(source, &masked, &comments);
        Self {
            source,
            masked,
            comments_masked,
            comments,
            test_lines,
            regex_contracts,
            panic_contracts,
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

    fn comment_block_ending_at(&self, index: usize) -> &'a str {
        let mut first = index;
        while first > 0
            && self.source[self.comments[first - 1].end..self.comments[first].start]
                .trim()
                .is_empty()
        {
            first -= 1;
        }
        &self.source[self.comments[first].start..self.comments[index].end]
    }

    fn has_safety_rationale(&self, unsafe_offset: usize, open_brace: usize) -> bool {
        self.safety_rationale(unsafe_offset, open_brace).is_some()
    }

    fn safety_rationale(&self, unsafe_offset: usize, open_brace: usize) -> Option<&str> {
        self.preceding_safety_rationale(unsafe_offset).or_else(|| {
            self.comments
                .iter()
                .find(|comment| {
                    comment.start > open_brace
                        && self.source[open_brace + 1..comment.start].trim().is_empty()
                })
                .map(|comment| &self.source[comment.start..comment.end])
                .filter(|rationale| SAFETY_COMMENT.is_match(rationale))
        })
    }

    fn preceding_safety_rationale(&self, unsafe_offset: usize) -> Option<&str> {
        let index = self
            .comments
            .iter()
            .rposition(|comment| comment.end <= unsafe_offset)?;
        let last = self.comments[index];
        let gap = &self.masked[last.end..unsafe_offset];
        if !(is_safety_expression_prefix(gap)
            || is_safety_setup_prelude(gap)
            || STRUCT_UPDATE_PREFIX.is_match(gap)
            || STRUCT_MATCH_ARM_PREFIX.is_match(gap)
            || self.is_containing_macro_prefix(last.end, unsafe_offset))
        {
            return None;
        }
        let rationale = self.comment_block_ending_at(index);
        SAFETY_COMMENT.is_match(rationale).then_some(rationale)
    }

    fn is_containing_macro_prefix(&self, comment_end: usize, unsafe_offset: usize) -> bool {
        let gap = &self.masked[comment_end..unsafe_offset];
        RUST_MACRO_EXPRESSION.find_iter(gap).any(|invocation| {
            let prefix = &gap[..invocation.start()];
            if !is_safety_expression_prefix(prefix) && !STRUCT_MATCH_ARM_PREFIX.is_match(prefix) {
                return false;
            }
            let open = comment_end + invocation.end() - 1;
            let opening = self.masked.as_bytes()[open];
            let closing = match opening {
                b'(' => b')',
                b'[' => b']',
                _ => b'}',
            };
            self.matching(open, opening, closing)
                .is_some_and(|close| unsafe_offset < close)
        })
    }
}

fn is_safety_setup_prelude(masked: &str) -> bool {
    let mut in_let = false;
    masked.lines().count() <= 6
        && masked.lines().all(|line| {
            let line = line.trim();
            if line.is_empty() {
                true
            } else if in_let {
                if line.contains(';') {
                    in_let = false;
                }
                true
            } else if line.starts_with("let ") {
                in_let = !line.contains(';');
                true
            } else {
                line.starts_with("#[") && line.ends_with(']')
            }
        })
}

fn is_safety_expression_prefix(masked: &str) -> bool {
    !masked
        .bytes()
        .any(|byte| matches!(byte, b';' | b'{' | b'}'))
}

pub(crate) fn function_lexical_facts(source: &str) -> (String, BTreeSet<usize>) {
    let masked = source_lexical_mask(source);
    let test_lines = test_scopes::test_lines(source, &masked);
    (masked, test_lines)
}

pub(crate) fn source_lexical_mask(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        match rust_scan_transition(bytes, index) {
            RustScanTransition::Advance => index += 1,
            RustScanTransition::Comment(end) | RustScanTransition::Literal(end) => {
                mask_range(&mut masked, index, end);
                index = end;
            }
        }
    }
    String::from_utf8(masked).expect("masked Rust must remain UTF-8")
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
        return Some(if raw_prefix {
            RustLiteralKind::Raw {
                body_start: prefix + 1,
                hashes: 0,
            }
        } else {
            RustLiteralKind::Quoted {
                body_start: prefix + 1,
            }
        });
    }
    let character_start = if source.get(start) == Some(&b'b') {
        start + 1
    } else {
        start
    };
    (source.get(character_start) == Some(&b'\'')).then_some(RustLiteralKind::Character {
        body_start: character_start + 1,
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
    let first = *source.get(body_start)?;
    let width = match first {
        b'\\' => match source.get(body_start + 1)? {
            b'x' => 4,
            b'u' => {
                let digits = source.get(body_start + 2..)?.strip_prefix(b"{")?;
                digits.iter().position(|byte| *byte == b'}')? + 4
            }
            _ => 2,
        },
        b'\n' | b'\r' | b'\'' => return None,
        byte => usize::from(if byte.is_ascii() {
            1
        } else {
            byte.leading_ones() as u8
        }),
    };
    let close = body_start + width;
    (source.get(close) == Some(&b'\'')).then_some(close + 1)
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
            allowed_lints: &["clippy::mem_forget", "mem_forget"],
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
    LazyLock::new(|| Regex::new(r"(?m)#!\s*\[\s*(?:allow|expect)\s*\(([^)]*)\)\s*\]").unwrap());
static ITEM_ALLOW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\s*\[\s*(?:allow|expect)\s*\(([^)]*)\)\s*\]").unwrap());
static OUT_OF_LINE_MODULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*;").unwrap());
static CUSTOM_MODULE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\s*\[\s*(?:path\b|cfg_attr\s*\([^]]*\bpath\b)").unwrap());
static UNSAFE_POLICY_DENY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#\s*!?\s*\[\s*(?:deny|forbid)\s*\(([^)]*)\)\s*\]").unwrap());
static SAFETY_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:SAFETY\b[ \t]*(?::[ \t]*)?|SAFE[ \t]*:[ \t]*)\S").unwrap()
});
static ASSOCIATED_VALUE_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+$").unwrap());
static SECRET_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\b(?:const|static|let)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=\n;]+)?=").unwrap()
});
static UTF8_RECONSTRUCTION_RECEIVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bString::from_utf8\s*\(\s*[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\)\s*$")
        .unwrap()
});
static UTF8_RECONSTRUCTION_MESSAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\.expect\s*\(\s*"(?P<message>(?:\\.|[^"\\])*)""#).unwrap());
static UTF8_MASKING_DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:mask(?:ed|ing)?|structural|structured|normalized|stripped)\b").unwrap()
});
static UTF8_PRESERVATION_DESCRIPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:preserves?|remain(?:s)?)\s+UTF-8\b").unwrap());
static RUST_INVARIANT_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:invariant|ok because|we know|guaranteed|cannot fail|can't fail|impossible|only write to `?string`?)\b",
    )
    .expect("Rust invariant comment regex must compile")
});
static PANIC_INVARIANT_MESSAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bpanic!\s*\([^;\n]*(?:\b(?:impossible|invariant|unreachable)\b|cannot happen|bug(?:\s+for)?\s*:)"#)
        .expect("panic invariant message regex must compile")
});
static STATIC_LITERAL_PARSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r####"(?s)(?:r#*"[^"]*"#*|"(?:\\.|[^"\\])*")\s*\.parse(?:\s*::\s*<[^>]+>)?\s*\(\s*\)\s*\.(?:unwrap|expect)\s*\("####,
    )
    .expect("static literal parse regex must compile")
});
static STATIC_INFALLIBLE_CONSTRUCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bNonZero(?:U|I)(?:8|16|32|64|128|size)::new\(\s*[1-9][0-9_]*(?:[iu](?:8|16|32|64|128|size))?\s*\)\s*\.(?:unwrap|expect)\s*\(",
    )
    .expect("statically infallible Rust construction regex must compile")
});
static RUST_FUNCTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfn\s+[A-Za-z_]\w*[^(;{]*\(")
        .expect("Rust function declaration regex must compile")
});
static RUST_OUTER_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#\s*\[").unwrap());
static RUST_FUNCTION_QUALIFIERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(?:pub(?:\s*\([^()]*\))?|unsafe|async|const|default|extern)\s+)*$").unwrap()
});
static RUST_PANIC_DOCUMENTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:#\s*panics\b|\bpanics?\s+if\b|\bwill panic\b)")
        .expect("Rust panic documentation regex must compile")
});
static UNSAFE_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bunsafe\s*\{").unwrap());
static STATIC_MUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bstatic\s+mut\s+[A-Za-z_]\w*").unwrap());
static RAW_OWNERSHIP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:std|alloc)::(?:boxed::Box|vec::Vec|string::String|ffi::CString|rc::Rc|sync::Arc)|Box|Vec|String|CString|Rc|Arc)::from_raw(?:_parts)?\s*\(").unwrap()
});
static RAW_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(?:std|alloc)::(?:boxed|rc|sync)::)?(Box|Rc|Arc)::into_raw\s*\(").unwrap()
});
static OWNERSHIP_POINTER_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:as\s+\*(?:mut|const)\s+[A-Za-z_\[\]][A-Za-z0-9_:<>,\[\];\s]*|\.\s*cast\s*(?:::\s*<[^(){}]+>)?\s*\(\s*\))?\s*$").unwrap()
});
static OWNERSHIP_UNSIZING_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^as\s+\*(?:mut|const)\s+(?:dyn\s+[A-Za-z_][A-Za-z0-9_:<>+,'()\s]*|\(\s*dyn\s+[A-Za-z_][A-Za-z0-9_:<>+,'()\s]*\))$").unwrap()
});
static TRANSPARENT_LAYOUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:transparent\s+wrapper|repr\s*\(\s*transparent\s*\))").unwrap()
});
static STRUCT_UPDATE_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*\$?[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*\{\s*\.\.\s*$").unwrap()
});
static STRUCT_MATCH_ARM_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*\{[^{};]*\}\s*=>\s*$").unwrap()
});
static RUST_MACRO_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*!\s*[\(\[{]").unwrap());
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
static RUST_LOOP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:for\b[^;{}]*\bin\b[^;{}]*|while\b[^;{}]*|loop)\s*\{").unwrap()
});
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
static CHARS_NTH_WITH_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z_]\w*\s*\.\s*chars\s*\(\s*\)\s*\.\s*nth\s*\(\s*[A-Za-z_]\w*\s*\)")
        .unwrap()
});
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
        r"\b(?:tokio::task::spawn_blocking|async_std::task::spawn_blocking|smol::unblock|(?:deno_core::unsync|deno_unsync)::spawn_blocking|(?:[A-Za-z_]\w*::)*asyncify|([A-Za-z_]\w*))\s*\(",
    )
    .unwrap()
});
static OFFLOAD_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\buse\s+(?:(?:tokio::task|async_std::task|deno_core::unsync|deno_unsync)::(spawn_blocking)|smol::(unblock))(?:\s+as\s+([A-Za-z_]\w*))?\s*;").unwrap()
});
static OFFLOAD_SHADOW_BINDING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:let\s+(?:mut\s+)?|fn\s+)([A-Za-z_]\w*)\b|\b([A-Za-z_]\w*)\s*:[^:]").unwrap()
});
static EXPLICIT_GUARD_DROP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:std::mem::)?drop\s*\(\s*(?P<guard>[A-Za-z_]\w*)\s*\)").unwrap()
});
static SYNC_LOCK_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\blet\s+(?:mut\s+)?(?P<guard>[A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\.\s*lock\s*\(\s*\)\s*(?:\.\s*(?P<poison>unwrap|expect)\s*\([^;]*?\))?\s*;",
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
    fn preserves_source_positions_while_masking_multiline_literals_and_nested_comments() {
        let source = r##"fn real<'a>(text: &'a str) {
    let message = "header
PRAGMA mmap_size=6000000; é
tail";
    let raw = r#"/* literal */ 7000000"#;
    let byte = b'\n'; /* outer /* inner */ 8000000 */
    let character = '字';
    let byte_escape = b'\x7f';
    let scalar_escape = '\u{1f642}';
    let actual = 9000000;
}
"##;
        let masked = super::source_lexical_mask(source);
        assert_eq!(masked.len(), source.len());
        assert_eq!(
            masked
                .match_indices('\n')
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            source
                .match_indices('\n')
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
        );
        assert!(masked.starts_with("fn real<'a>(text: &'a str) {"));
        assert!(masked.contains("let actual = 9000000;"));
        for literal in [
            "PRAGMA",
            "6000000",
            "7000000",
            "8000000",
            "é",
            "'\\n'",
            "'字'",
            "'\\x7f'",
            "'\\u{1f642}'",
        ] {
            assert!(!masked.contains(literal), "{masked}");
        }
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
        assert_eq!(selected, vec!["rust-expect:3", "rust-expect:4"]);
    }

    #[test]
    fn raw_strings_without_hashes_do_not_break_test_exclusion() {
        let source = r####"fn production() {
    let separator = r"\";
    dynamic.unwrap();
}
#[cfg(test)]
#[test]
fn fixture() {
    first.unwrap();
    let separator = r"\";
    second.unwrap();
}
"####;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-unwrap")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![3]);
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
    fn quote_characters_do_not_hide_later_hardcoded_secrets() {
        let source = r#"const PASSWORD: char = '"';
const API_KEY: u8 = b'"';
const CLIENT_SECRET: char = '\"';
fn connect() {
    let password = "actual-production-password";
}
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-hardcoded-secret")
            .map(|finding| (finding.line, finding.message))
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec![(
                5,
                "hardcoded string assigned to credential-like `password`".to_owned(),
            )],
        );
    }

    #[test]
    fn ignores_non_credentials_placeholders_literals_and_test_secrets() {
        let source = r####"const TOKEN_GROUP: &str = "md.comp.assist-chip";
const CALLBACK_URL: &str = "https://example.test/token";
const API_KEY: &str = "your_api_key";
const SERDE_TOKEN: &str = "$serde_json::private::Number";
const DUNDER_MODEL_PRIVATE_KEY: &str = "__pydantic_private__";
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
    // SAFETY pointer remains valid for this call.
    unsafe { touch_raw_without_colon(); }
    // Safety: setup derives both values from the same allocation.
    let data = pointer.data();
    let metadata = pointer.metadata();
    unsafe { rebuild(data, metadata); }
    // SAFETY: the transmuted field has an equivalent representation.
    #[expect(clippy::missing_transmute_annotations)]
    let callback = unsafe { std::mem::transmute(callback) };
    Command::new("sh").arg("script.sh");
}
// Safety: Handle contains a thread-safe operating-system token.
unsafe impl Sync for Handle {}
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
    fn excludes_expect_calls_that_are_not_option_or_result_methods() {
        let source = r#"fn parse(
    args: &mut Args,
    parser: &mut Parser,
    result: Option<u8>,
    nested: Option<Result<u8, Error>>,
) -> Result<(), Error> {
    let value = args.expect("value")?;
    parser.expect(SyntaxKind::Colon);
    result.expect(message);
    nested.expect("outer result")?;
    Ok(())
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-expect")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();

        assert_eq!(selected, vec![9, 10]);
    }

    #[test]
    fn ignores_statically_infallible_constructors() {
        let source = r#"fn constants(dynamic: u32, input: String) {
    let one = NonZeroU32::new(1).unwrap();
    let typed = NonZeroUsize::new(1024_usize).expect("positive literal");
    let empty = CString::new("").unwrap();
    let maybe = NonZeroU32::new(dynamic).unwrap();
    let text = CString::new(input).unwrap();
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| format!("{}:{}", finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["rust-unwrap:5", "rust-unwrap:6"]);
    }

    #[test]
    fn proves_same_scope_none_guard_return_before_option_unwrap() {
        let source = r#"fn replace_separator<'a>(
    path: &'a OsStr,
    path_separator: Option<&str>,
) -> Cow<'a, OsStr> {
    if path_separator.is_none() {
        return Cow::Borrowed(path);
    }
    let path_separator = path_separator.unwrap();
    dynamic.unwrap();
}
fn borrowed(&mut self) {
    if self.value.is_none() { return; }
    self.other = None;
    self.value.as_ref().expect("required");
}
fn multiline(value: Option<&str>) {
    if
        (value.is_none())
    {
        return fallback();
    }
    let mut value = value.as_deref().unwrap();
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| (finding.code, finding.path, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![("rust-unwrap".to_owned(), "src/lib.rs".to_owned(), 9)]
        );
    }

    #[test]
    fn retains_invalidated_non_dominating_and_non_exiting_none_guards() {
        for source in [
            "fn f() { if other.is_none() { return; } value.unwrap(); }",
            "fn f() { if value.is_none() {} value.unwrap(); }",
            "fn f() { if value.is_none() { if ready { return; } } value.unwrap(); }",
            "fn f() { if ready {} else if value.is_none() { return; } value.unwrap(); }",
            "fn f() { { if value.is_none() { return; } } value.unwrap(); }",
            "fn f() { if value.is_none() { return; } value = None; value.unwrap(); }",
            "fn f() { if value.is_none() { return; } let value = None; let value = value.unwrap(); }",
            "fn f() { if value.is_none() { return; } replace(&mut value, None); value.unwrap(); }",
            "fn f() { if self.value.is_none() { return; } self.reset(); self.value.unwrap(); }",
            "fn f() { if self.value.is_none() { return; } replace(&mut self); self.value.unwrap(); }",
            "fn f() { if value.is_none() && ready { return; } value.unwrap(); }",
            "fn f() { if value.is_none() { let f = || return; f(); } value.unwrap(); }",
            "fn f() { if value.is_none() { return; } run(|| value.unwrap()); }",
            "fn f() { let example = \"if value.is_none() { return; }\"; value.unwrap(); }",
            "fn f() {\n// if value.is_none() { return; }\nvalue.unwrap(); }",
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-unwrap")
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "{source}");
            assert_eq!(selected[0].path, "src/lib.rs", "{source}");
            assert_eq!(selected[0].line, source.lines().count(), "{source}");
        }
    }

    #[test]
    fn retains_fallible_constructors_thread_results_and_shared_batch_state() {
        for source in [
            "fn f() { AhoCorasick::new([\"{{\", \"}}\", \"{}\"]).unwrap(); }",
            "fn f() { self.items.lock().unwrap(); }",
            "fn f() { self.lock().take().unwrap().into_iter(); }",
            "fn f() { if self.needs_flush(batch.as_ref()) { batch = self.batch.lock(); } batch.as_mut().unwrap(); }",
            "fn f() { handles.into_iter().map(|handle| handle.join().unwrap()); }",
            "fn f() { ctrlc::set_handler(move || quit()).unwrap(); }",
            "fn f() { receiver.join().unwrap(); }",
            "fn f() { absolute_path(path.normalize().unwrap().as_path()).unwrap(); }",
            "fn f() { for arg in args { if arg.has_tokens() { path_arg = Some(arg); } } path_arg.unwrap(); }",
            "fn f() { determine_command().map(|cmd| CommandSet::new_batch([cmd]).unwrap()); }",
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-unwrap")
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "{source}");
            assert_eq!(selected[0].path, "src/lib.rs", "{source}");
            assert_eq!(selected[0].line, 1, "{source}");
        }
    }

    #[test]
    fn retains_unsafe_signal_block_with_operation_comment_but_no_safety_rationale() {
        let source = r#"fn exit() {
    // Get rid of the SIGINT handler, if present, and raise SIGINT
    unsafe {
        if signal(SIGINT, SigDfl).is_ok() { let _ = raise(SIGINT); }
    }
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![("src/lib.rs".to_owned(), 3)]);
    }

    #[test]
    fn proves_else_if_option_guard_without_changing_sibling_fields() {
        let source = r#"fn shorten(&mut self) {
    if self.width > limit {
        return;
    } else if self.width == limit && self.shortener.is_some() {
        let has_next = self.chars.clone().next().is_some();
        self.action = Action::Terminate;
        return has_next.then(|| self.shortener.unwrap()).or(Some(ch));
    }
    dynamic.unwrap();
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-unwrap")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![9]);
    }

    #[test]
    fn retains_invalidated_mismatched_and_non_dominating_else_if_guards() {
        let source = r#"fn guarded(&mut self) {
    if ready {} else if self.shortener.is_some() {
        self.shortener = None;
        self.shortener.unwrap();
    }
    if ready {} else if self.shortener.is_some() {
        self.reset();
        self.shortener.unwrap();
    }
    if ready {} else if self.shortener.is_some() {
        self.other.unwrap();
    }
    if ready {} else if self.shortener.is_some() {}
    self.shortener.unwrap();
    if ready {} else if self.shortener.is_some() || ready {
        self.shortener.unwrap();
    }
    if ready {} else if self.shortener.is_some() && self.reset() {
        self.shortener.unwrap();
    }
    if ready {} else if self.shortener.is_some() {
        replace(&mut self);
        self.shortener.unwrap();
    }
    // if self.shortener.is_some() {
    self.shortener.unwrap();
    let example = "if self.shortener.is_some() {";
    self.shortener.unwrap();
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-unwrap")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![4, 8, 11, 14, 16, 19, 23, 26, 28]);
    }

    #[test]
    fn proves_guarded_first_character_and_nonempty_char_case_mapping() {
        let source = r#"fn character(text: &str, shift: bool) {
    if text.chars().count() == 1 {
        let modifier = flags.contains(SHIFT);
        let ch = text
            .chars()
            .next()
            .unwrap();
        let lower = if shift { ch.to_lowercase().next().unwrap() } else { ch };
    }
    if text.chars().count() == 1 {
        let ch = text.chars().next().expect("one character");
        let upper = ch.to_uppercase().next().expect("first mapped character");
    }
    text.chars().next().unwrap();
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![("rust-unwrap".to_owned(), 14)]);
    }

    #[test]
    fn retains_unproven_or_invalidated_character_operations() {
        let source = r#"fn character(text: &mut String, other: &str, custom: Custom) {
    if other.chars().count() == 1 { text.chars().next().unwrap(); }
    if text.chars().count() == 1 {
        text.clear();
        text.chars().next().unwrap();
    }
    if text.chars().count() == 0 { text.chars().next().unwrap(); }
    if text.chars().count() == 1 || ready { text.chars().next().unwrap(); }
    if text.chars().count() == 1 {}
    text.chars().next().unwrap();
    custom.to_lowercase().next().unwrap();
    let ch = custom;
    ch.to_uppercase().next().unwrap();
    let ch = text.chars().next().unwrap();
    let ch = custom;
    ch.to_lowercase().next().unwrap();
    let mut ch = text.chars().next().unwrap();
    ch = custom;
    ch.to_lowercase().next().unwrap();
    // if text.chars().count() == 1 {
    text.chars().next().unwrap();
    let example = "if text.chars().count() == 1 {";
    text.chars().next().unwrap();
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-unwrap")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![2, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 21, 23]
        );
    }

    #[test]
    fn proves_nul_free_cstring_literals_and_unambiguous_root_constants() {
        let source = r##"const FALLBACK_LOCALE: &str = "UTF-8";
const OTHER: &str = r#"plain\0text"#;
fn locale(input: String) {
    CString::new(FALLBACK_LOCALE).unwrap();
    std::ffi::CString::new(OTHER).expect("constant text");
    CString::new("literal").unwrap();
    CString::new(r#"raw literal"#).unwrap();
    CString::new("line\nbreak").unwrap();
    CString::new(input).unwrap();
    CString::new("has\0nul").unwrap();
    CString::new("has\x00nul").unwrap();
    CString::new("has\u{0}nul").unwrap();
    let mixed = (CString::new("safe").unwrap(), CString::new(input).unwrap());
}"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![9, 10, 11, 12, 13]);
    }

    #[test]
    fn retains_unresolved_and_shadowed_cstring_constants() {
        for source in [
            r#"const TEXT: &str = "has\0nul"; fn f() { CString::new(TEXT).unwrap(); }"#,
            r#"const TEXT: &str = input; fn f() { CString::new(TEXT).unwrap(); }"#,
            r#"const OTHER: &str = "safe"; fn f() { CString::new(TEXT).unwrap(); }"#,
            r#"mod inner { const TEXT: &str = "safe"; } fn f() { CString::new(TEXT).unwrap(); }"#,
            r#"const TEXT: &str = "safe"; mod inner { fn f() { CString::new(TEXT).unwrap(); } }"#,
            r#"const TEXT: &str = "safe"; fn f() { const TEXT: &str = input; CString::new(TEXT).unwrap(); }"#,
            r#"const TEXT: &str = "safe"; fn f() { use other::TEXT; CString::new(TEXT).unwrap(); }"#,
            r#"const TEXT: &str = "safe"; fn f() { use other::*; CString::new(TEXT).unwrap(); }"#,
            r#"// const TEXT: &str = "safe";
fn f() { CString::new(TEXT).unwrap(); }"#,
            r#"fn f() { let example = "const TEXT: &str = \"safe\";"; CString::new(TEXT).unwrap(); }"#,
            r#"fn f() { CString::new("safe" + input + "").unwrap(); }"#,
            r##"fn f() { CString::new(r#"safe"# + input + r#""#).unwrap(); }"##,
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-unwrap")
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "{source}");
        }
    }

    #[test]
    fn retains_unconditional_modules_even_with_test_support_documentation() {
        let source = r#"/// Terminal test helpers.
pub mod test {
    pub fn mock_term(content: &str) { dynamic.unwrap(); }
}
mod test_helpers {
    pub fn production() { dynamic.unwrap(); }
}
#[cfg(test)]
mod tests {
    fn test_only() { dynamic.unwrap(); }
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-unwrap")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![3, 6]);
    }

    #[test]
    fn ignores_documented_and_string_formatting_invariants() {
        let source = r#"use std::fmt::Write;
fn render(dynamic: Result<(), Error>) -> String {
    let mut output = String::new();
    writeln!(output, "header").unwrap();
    // OK because `set` returning an error means the value already exists.
    state.get_mut().unwrap();
    dynamic.unwrap();
    output
}
macro_rules! write {
    // We only write to `String`.
    ($($tt:tt)*) => { std::write!($($tt)*).unwrap(); }
}
fn impossible() {
    panic!("BUG for NoError: an impossible error occurred");
    panic!("external input was invalid");
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-expect" | "rust-panic-macro"
                )
            })
            .map(|finding| format!("{}:{}", finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["rust-unwrap:7", "rust-panic-macro:16"]);
    }

    #[test]
    fn ignores_literal_parsing_and_documented_panic_contracts() {
        let source = r#"fn defaults() {
    let color: Color = "red".parse().unwrap();
    let dynamic: Color = input.parse().unwrap();
}
/// # Panics
///
/// Panics if adding the amount would overflow.
fn offset<T: AsRef<Path>>(value: usize, amount: usize) -> usize {
    value.checked_add(amount).unwrap()
}
/// This will panic when the caller violates the root invariant.
fn root_only() {
    panic!("not a root");
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-expect" | "rust-panic-macro"
                )
            })
            .map(|finding| format!("{}:{}", finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["rust-unwrap:3"]);
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
    fn distinguishes_trait_implementations_from_repeated_loop_bodies() {
        let source = r##"impl Render for Window {
    fn once(mut queue: Vec<u8>, text: &str, index: usize) {
        queue.contains(&1);
        queue.remove(0);
        queue.insert(0, 1);
        Regex::new("once");
        text.chars().nth(index);
        let example = "for value in values { queue.contains(&value); }";
        // for value in values { queue.insert(0, value); }
    }
    fn repeated(mut queue: Vec<u8>) {
        for value in 0..10 {
            while ready() {
                queue.contains(&value);
                queue.insert(0, value);
            }
        }
    }
}"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-linear-membership-in-loop"
                        | "rust-vec-front-removal-in-loop"
                        | "rust-vec-front-insertion-in-loop"
                        | "rust-regex-created-in-loop"
                        | "rust-chars-nth-in-loop"
                )
            })
            .map(|finding| (finding.code, finding.path, finding.line, finding.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                (
                    "rust-linear-membership-in-loop".to_owned(),
                    "src/lib.rs".to_owned(),
                    14,
                    "high".to_owned(),
                ),
                (
                    "rust-vec-front-insertion-in-loop".to_owned(),
                    "src/lib.rs".to_owned(),
                    15,
                    "high".to_owned(),
                ),
            ]
        );
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
    fn reports_variable_chars_nth_traversal_only_inside_loops() {
        let source = r#"fn scan(text: &str) {
    for index in 0..text.len() {
        let current = text
            .chars()
            .nth(index);
        consume(current);
    }
    let first = text.chars().nth(0);
    let selected = text.chars().nth(position);
    // text.chars().nth(index)
    let example = "text.chars().nth(index)";
    for character in text.chars() {
        consume(character);
    }
}"#;

        assert_eq!(
            findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-chars-nth-in-loop")
                .map(|finding| (finding.path, finding.line, finding.confidence))
                .collect::<Vec<_>>(),
            vec![("src/lib.rs".to_owned(), 3, "high".to_owned(),)]
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
    #[test]
    fn honors_documented_panic_contracts_without_leaking_to_other_functions() {
        let source = r#"/// # Panics
/// If the caller provides an unknown field or invalid index.
fn new_unchecked(
    field: &str,
) -> Self {
    info.index_of(field).expect("Field name should exist");
    field.parse().expect("Field name should be a valid tuple index");
    values.get(index).unwrap();
    fn nested() { external.unwrap(); }
    value.unwrap();
}
fn external() {
    let documentation = "/// # Panics";
    value.unwrap();
}
/// An ordinary function, not a panic contract.
fn sibling() { value.expect("always present by construction"); }
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 9),
                ("rust-unwrap".to_owned(), 14),
                ("rust-expect".to_owned(), 17),
            ]
        );
    }

    #[test]
    fn honors_literal_doc_attributes_without_leaking_panic_policy() {
        let source = r##"macro_rules! taskpool {
    () => {
        #[doc = concat!("Gets the global instance.")]
        #[doc = ""]
        #[doc = " # Panics"]
        #[doc = " Panics if the global instance has not been initialized yet."]
        #[cfg_attr(
            target_arch = "wasm32",
            expect(unused_mut, reason = "not mutated on this target")
        )]
        pub fn get() {
            value.expect("initialize the pool first");
            value.unwrap();
            panic!("pool not initialized");
            fn nested() { value.expect("required"); }
        }
        fn sibling() { value.unwrap(); panic!("mismatched values"); }
    };
}"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-expect" | "rust-panic-macro"
                )
            })
            .map(|finding| {
                assert_eq!(finding.path, "src/lib.rs");
                (finding.code, finding.line)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 17),
                ("rust-expect".to_owned(), 15),
                ("rust-panic-macro".to_owned(), 17),
            ]
        );
    }

    #[test]
    fn attaches_panic_docs_across_multiline_attributes_and_qualifiers() {
        let source = r##"/// # Panics
/// If the caller supplies a mismatched value.
#[expect(
    clippy::match_same_arms,
    // This comment belongs to the attribute, not a neighboring function.
    reason = "the variants have different semantics"
)]
#[inline]
pub(crate) unsafe fn checked() {
    value.unwrap();
    panic!("mismatched values");
}
/**
 * # Panics
 * If the global instance is not initialized.
 */
pub async fn initialized() { value.expect("initialize first"); }
#[
    doc = r#" # Panics
If the requested value is missing."#
]
fn raw_documented() { value.unwrap(); }
fn sibling() { value.unwrap(); }
"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-expect" | "rust-panic-macro"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![("rust-unwrap".to_owned(), 23)]);
    }

    #[test]
    fn rejects_unattached_quoted_and_nonliteral_panic_documentation() {
        let source = r###"#[doc = "# Panics"]
struct DocumentedType;
fn sibling() { value.unwrap(); }
#[deprecated(note = "Panics if the value is missing")]
fn unrelated_attribute() { value.expect("required"); }
#[doc = concat!("# Panics", " if input is invalid")]
fn unresolved_documentation() { panic!("invalid input"); }
// #[doc = "# Panics"]
fn comment() { value.unwrap(); }
const EXAMPLE: &str = r##"#[doc = "# Panics"]
fn quoted() {}"##;
fn quoted_neighbor() { value.unwrap(); }
//// # Panics
fn ordinary_comment() { value.unwrap(); }
/// # Panics
trait Contract { fn required(); }
fn after_trait() { value.unwrap(); }
"###;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-expect" | "rust-panic-macro"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 3),
                ("rust-unwrap".to_owned(), 9),
                ("rust-unwrap".to_owned(), 12),
                ("rust-unwrap".to_owned(), 14),
                ("rust-unwrap".to_owned(), 17),
                ("rust-expect".to_owned(), 5),
                ("rust-panic-macro".to_owned(), 7),
            ]
        );

        let malformed = "#[doc = \"# Panics\"\nfn runtime() { value.unwrap(); }";
        assert_eq!(
            findings(malformed)
                .into_iter()
                .filter(|finding| finding.code == "rust-unwrap")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn honors_multiline_lint_allowances_on_the_attributed_item_only() {
        let source = r##"fn ffi() {
    #[allow(
        clippy::undocumented_unsafe_blocks,
        reason = "safety comment on the containing block (see docs)"
    )]
    unsafe { invoke(); }
    unsafe { undocumented(); }
}
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "caller contract"
)]
#[inline]
fn unchecked(
    value: Option<u8>,
) -> u8 {
    other.expect("required");
    value.unwrap()
}
fn checked(value: Option<u8>) { value.unwrap(); }
// #![allow(clippy::undocumented_unsafe_blocks)]
const EXAMPLE: &str = "#![allow(clippy::expect_used)]";
fn runtime() { value.expect("required"); }
"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-undocumented-unsafe-block" | "rust-unwrap" | "rust-expect"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 21),
                ("rust-expect".to_owned(), 24),
                ("rust-undocumented-unsafe-block".to_owned(), 7),
            ]
        );
    }

    #[test]
    fn attaches_safety_comments_to_multiline_containing_expressions() {
        let source = r#"fn access() {
    // SAFETY: the row was bounds-checked.
    self.get_column(component_id)
        .map(|column| unsafe { column.get_unchecked(row) });
    /* SAFETY: pointer is valid. */ unsafe { pointer.read(); }
    // SAFETY: applies only to the first call.
    unsafe { first(); }
    unsafe { second(); }
    // SAFETY: an unrelated completed statement is not a rationale.
    consume();
    values.map(|value| unsafe { third(value) });
    let sample = "// SAFETY: not a source comment";
    unsafe { fourth(); }
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![8, 11, 13]);
    }

    #[test]
    fn distinguishes_lock_guards_from_copied_and_extracted_values() {
        let source = r#"use parking_lot::Mutex;
async fn copied() {
    let id = *self.id.lock();
    consume(id).await;
}
async fn extracted() {
    let mut examples =
        std::mem::take(&mut *finished.lock().unwrap());
    consume(&mut examples).await;
}
async fn retained() {
    let guard =
        self.values
            .lock();
    consume(&guard).await;
}
async fn standard() {
    let guard = values.lock().unwrap();
    consume(&guard).await;
}
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-sync-lock-across-await")
            .map(|finding| (finding.line, finding.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![(12, "high".to_owned()), (18, "high".to_owned())]
        );
    }

    #[test]
    fn does_not_count_nested_future_awaits_as_guard_suspension() {
        let source = r#"use parking_lot::Mutex;
async fn spawn_tasks() {
    let mut tasks = self.tasks.lock();
    tasks.push(spawn(async move {
        work().await;
    }));
}
async fn retained() {
    let guard = self.values.lock();
    let task = async { work().await; };
    consume(&guard).await;
}
async fn nested_guard() {
    spawn(async move {
        let guard = self.values.lock();
        work(&guard).await;
    });
}
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-sync-lock-across-await")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![9, 15]);
    }

    #[test]
    fn reports_nested_async_blocking_calls_once_and_keeps_filesystem_risks() {
        let source = r#"async fn work() {
    let nested = async {
        std::fs::read(path);
        std::fs::create_dir_all(path);
    };
    tokio::task::spawn_blocking(|| {
        std::fs::read(other_path);
    }).await;
    smol::unblock(|| std::fs::write(path, bytes)).await;
    let example = "std::thread::sleep(delay)";
    // std::fs::remove_file(path);
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-blocking-call-in-async")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![("src/lib.rs".to_owned(), 3), ("src/lib.rs".to_owned(), 4)]
        );
    }

    #[test]
    fn resolves_imported_offloads_without_hiding_async_tasks_or_eager_arguments() {
        let source = r#"use deno_core::unsync::spawn_blocking;
use tokio::task::spawn_blocking as blocking;
async fn work() {
    spawn_blocking(move || {
        std::fs::read(path);
    });
    blocking(|| std::fs::write(path, bytes));
    tokio::task::spawn_blocking({
        std::fs::remove_file(path);
        || {}
    });
    spawn_blocking(|| async {
        std::fs::create_dir_all(path);
    });
    spawn_subcommand(async {
        std::fs::remove_dir_all(path);
    });
    let example = "spawn_blocking(|| std::fs::read(path))";
    // std::fs::read(path);
}"#;
        let mut selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-blocking-call-in-async")
            .map(|finding| (finding.path, finding.line, finding.confidence))
            .collect::<Vec<_>>();
        selected.sort();
        assert_eq!(
            selected,
            vec![
                ("src/lib.rs".to_owned(), 9, "high".to_owned()),
                ("src/lib.rs".to_owned(), 13, "high".to_owned()),
                ("src/lib.rs".to_owned(), 16, "high".to_owned()),
            ]
        );
    }

    #[test]
    fn keeps_unknown_shadowed_and_out_of_scope_offload_names_reportable() {
        for source in [
            r#"use custom::spawn_blocking;
async fn work() { spawn_blocking(|| std::fs::read(path)); }"#,
            r#"use tokio::task::spawn_blocking;
async fn work(spawn_blocking: Callback) { spawn_blocking(|| std::fs::read(path)); }"#,
            r#"mod other { use tokio::task::spawn_blocking; }
async fn work() { spawn_blocking(|| std::fs::read(path)); }"#,
            r#"const EXAMPLE: &str = "use tokio::task::spawn_blocking;";
async fn work() { spawn_blocking(|| std::fs::read(path)); }"#,
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-blocking-call-in-async")
                .map(|finding| finding.line)
                .collect::<Vec<_>>();
            assert_eq!(selected, vec![2], "{source}");
        }
    }

    #[test]
    fn excludes_nested_function_items_but_not_executing_closures_or_async_functions() {
        let source = r#"async fn compile() {
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_file(path);
        }
    }
    fn helper() { std::fs::read(path); }
    async fn nested() { std::fs::write(path, bytes); }
    let callback = || std::fs::create_dir_all(path);
    callback();
    std::fs::copy(from, to);
}"#;
        let mut selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-blocking-call-in-async")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        selected.sort();
        assert_eq!(selected, vec![9, 10, 12]);
    }

    #[test]
    fn scopes_inner_lint_allowances_and_multiline_conversion_attributes() {
        let source = r#"mod internal {
    #![allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "internal caller contract"
    )]
    fn run() {
        value.unwrap();
        unsafe { invoke(); }
    }
}
fn outside() {
    value.unwrap();
    unsafe { undocumented(); }
}
#[allow(
    clippy::from_over_into,
    reason = "conversion ownership"
)]
impl
    Into<Output>
    for Input
{
    fn into(self) -> Output { Output }
}
impl Into<Other> for Input {}
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap"
                        | "rust-undocumented-unsafe-block"
                        | "rust-impl-into-instead-of-from"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 13),
                ("rust-undocumented-unsafe-block".to_owned(), 14),
                ("rust-impl-into-instead-of-from".to_owned(), 26),
            ]
        );
    }

    #[test]
    fn lint_allowances_do_not_hide_unrelated_calls_on_the_same_line() {
        let source = r#"#[allow(clippy::unwrap_used)] fn allowed() { value.unwrap(); } fn other() { value.unwrap(); }
fn ffi() { #[allow(clippy::undocumented_unsafe_blocks)] unsafe { allowed(); } unsafe { undocumented(); } }
/* SAFETY: all fields are thread-safe. */ unsafe impl Send for Handle {}
unsafe impl Sync for Other {}
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-unwrap" | "rust-undocumented-unsafe-block" | "rust-manual-send-sync-impl"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 1),
                ("rust-undocumented-unsafe-block".to_owned(), 2),
                ("rust-manual-send-sync-impl".to_owned(), 4),
            ]
        );
    }

    #[test]
    fn accepts_documented_utf8_reconstruction_but_not_arbitrary_expect_messages() {
        let source = r#"fn reconstruct(bytes: Vec<u8>) {
    String::from_utf8(bytes).expect("masking preserves UTF-8");
    String::from_utf8(self.masked).expect("masked Rust must remain UTF-8");
    String::from_utf8(normalized).expect("normalized source must remain UTF-8");
    String::from_utf8(structured).expect("structured source must remain UTF-8");
    String::from_utf8(stripped).expect("stripped source must remain UTF-8");
    String::from_utf8(input).expect("input is always valid UTF-8");
    String::from_utf8(input).expect("invalid UTF-8 data");
    read_network().expect("masking preserves UTF-8");
    dynamic.expect("always present by construction");
    (String::from_utf8(mask).expect("mask preserves UTF-8"), dynamic.expect("failure"));
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-expect")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![7, 8, 9, 10, 11]);
    }

    #[test]
    fn attaches_safety_rationales_to_fields_match_arms_and_conditions() {
        let source = r#"fn access() {
    let value = Pair {
        // SAFETY: the referenced cell remains uniquely borrowed.
        field: unsafe { cell.read() },
    };
    match status {
        // SAFETY: the row and pointer satisfy the caller contract.
        (Added, _) => unsafe { initialize(); },
        _ => {}
    }
    // SAFETY: only a borrowed backend handle is retrieved.
    if unsafe { device.raw_handle() }.is_some() {}
    // SAFETY: this applies to the copied field only.
    *unsafe { pointer.field() };
    unsafe { undocumented(); }
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![15]);
    }

    #[test]
    fn accepts_fresh_same_owner_roundtrips_and_trait_object_unsizing_only() {
        let source = r#"fn convert() {
    unsafe { Box::from_raw(Box::into_raw(owner)) };
    unsafe { Rc::from_raw(Rc::into_raw(owner) as *const dyn Service) };
    unsafe {
        Arc::from_raw(
            Arc::into_raw(callback) as *const (dyn Fn() + Send + Sync + 'static)
        )
    };
    unsafe { Box::from_raw(Box::into_raw(owner) as *mut dyn Service) };
    unsafe { Box::from_raw(pointer) };
    unsafe { Arc::from_raw(Rc::into_raw(owner) as *const dyn Service) };
    unsafe { Arc::from_raw(Arc::into_raw(owner) as *const Other) };
    unsafe { Arc::from_raw(Arc::into_raw(owner).add(1) as *const dyn Service) };
    unsafe { Arc::from_raw(custom::Arc::into_raw(owner) as *const dyn Service) };
    unsafe { Arc::from_raw(Arc::into_raw(owner).cast::<Other>()) };
    unsafe { Vec::from_raw_parts(pointer, len, capacity) };
    // Arc::from_raw(Arc::into_raw(owner) as *const dyn Service)
    let example = "Box::from_raw(pointer)";
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-raw-ownership-reconstruction")
            .map(|finding| (finding.path, finding.line, finding.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            (10..=16)
                .map(|line| ("src/lib.rs".to_owned(), line, "high".to_owned()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retains_undocumented_platform_calls_and_quoted_unsafe_review() {
        let source = r#"fn platform(signal: i32) {
    let signame = unsafe { libc::strsignal(signal) };
    if !signame.is_null() {
        let text = unsafe { std::ffi::CStr::from_ptr(signame) };
    }
    quote! { unsafe { emitted_pointer.read() } };
    // SAFETY: returned by the platform API and checked for null above.
    let text = unsafe { std::ffi::CStr::from_ptr(signame) };
    // Perform the platform operation.
    unsafe { windows_call() };
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| (finding.path, finding.line, finding.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            [2, 4, 6, 10].map(|line| ("src/lib.rs".to_owned(), line, "high".to_owned()))
        );
    }

    #[test]
    fn accepts_only_documented_matching_direct_owner_roundtrips() {
        let source = r#"fn convert(owner: Box<Inner>, arc: Arc<Inner>, pointer: *mut Inner) {
    // SAFETY: Wrapper is a transparent wrapper around Inner.
    unsafe { Box::from_raw(Box::into_raw(owner) as *mut Wrapper) };
    // SAFETY: Wrapper is repr(transparent) around Inner.
    unsafe {
        Arc::from_raw(
            Arc::into_raw(arc).cast::<Wrapper>()
        )
    };
    // SAFETY: pointer is valid and ownership is documented elsewhere.
    unsafe { Box::from_raw(pointer) };
    // SAFETY: Wrapper is a transparent wrapper around Inner.
    unsafe { Box::from_raw(Rc::into_raw(rc) as *mut Wrapper) };
    // SAFETY: Wrapper is a transparent wrapper around Inner.
    unsafe { Box::from_raw(Box::into_raw(owner).add(1)) };
    // SAFETY: Wrapper is a transparent wrapper around Inner.
    completed();
    unsafe { Box::from_raw(Box::into_raw(owner).cast()) };
    // SAFETY: Wrapper is a transparent wrapper around Inner.
    unsafe { Vec::from_raw_parts(pointer, len, capacity) };
    unsafe { std::slice::from_raw_parts(pointer, len) };
    custom::Box::from_raw(pointer);
    custom::Arc::from_raw(pointer);
    custom::Slice::from_raw_parts(pointer, len);
    // Box::from_raw(pointer);
    let example = "Box::from_raw(pointer)";
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-raw-ownership-reconstruction")
            .map(|finding| (finding.path, finding.line, finding.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            [11, 13, 15, 18, 20].map(|line| ("src/lib.rs".to_owned(), line, "high".to_owned()))
        );
    }

    #[test]
    fn honors_targeted_expect_policies_without_leaking_to_neighbors() {
        let source = r##"fn transfer() {
    #[expect(
        clippy::mem_forget,
        reason = "the moving pointer must not run its destructor (ownership transfer)"
    )]
    std::mem::forget(
        owner
    );
    std::mem::forget(other);
    #[expect(clippy::borrowed_box)]
    unsafe { undocumented(); }
    #[expect(clippy::undocumented_unsafe_blocks)]
    unsafe { invoke(); }
    unsafe { undocumented_again(); }
    #[expect(clippy::unwrap_used)]
    value.unwrap();
    another.unwrap();
    // #[expect(clippy::mem_forget)]
    let example = "#![expect(clippy::undocumented_unsafe_blocks)]";
    mem::forget(last);
}
mod internal {
    #![expect(clippy::mem_forget)]
    fn leak() { mem::forget(owner); }
}
fn outside() { mem::forget(owner); }
"##;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-mem-forget" | "rust-undocumented-unsafe-block" | "rust-unwrap"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-unwrap".to_owned(), 17),
                ("rust-mem-forget".to_owned(), 9),
                ("rust-mem-forget".to_owned(), 20),
                ("rust-mem-forget".to_owned(), 26),
                ("rust-undocumented-unsafe-block".to_owned(), 11),
                ("rust-undocumented-unsafe-block".to_owned(), 14),
            ]
        );
    }

    #[test]
    fn inherits_unsafe_policy_only_through_unambiguous_declared_modules() {
        let sources = BTreeMap::from([
            ("ffi/lib.rs", r#"#![allow(clippy::undocumented_unsafe_blocks)]
pub mod api;
mod denied;
mod ambiguous;
mod inline { mod unreachable; }
// mod commented;
const EXAMPLE: &str = "mod quoted;";
"#),
            ("ffi/api.rs", "pub mod child;\nfn api() { unsafe { invoke(); } }\n"),
            ("ffi/api/child.rs", "fn child() { unsafe { invoke(); } }\n"),
            ("ffi/denied.rs", "#![deny(clippy::undocumented_unsafe_blocks)]\nmod child;\nfn api() { unsafe { invoke(); } }\n"),
            ("ffi/denied/child.rs", "fn child() { unsafe { invoke(); } }\n"),
            ("ffi/ambiguous.rs", "fn flat() { unsafe { invoke(); } }\n"),
            ("ffi/ambiguous/mod.rs", "fn nested() { unsafe { invoke(); } }\n"),
            ("ffi/unreachable.rs", "fn sibling() { unsafe { invoke(); } }\n"),
            ("ffi/commented.rs", "fn sibling() { unsafe { invoke(); } }\n"),
            ("ffi/quoted.rs", "fn sibling() { unsafe { invoke(); } }\n"),
            ("elsewhere/lib.rs", "fn unrelated() { unsafe { invoke(); } }\n"),
        ]).into_iter().map(|(path, source)| (path.to_owned(), source.to_owned())).collect();
        let selected = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("elsewhere/lib.rs".to_owned(), 1),
                ("ffi/ambiguous.rs".to_owned(), 1),
                ("ffi/ambiguous/mod.rs".to_owned(), 1),
                ("ffi/commented.rs".to_owned(), 1),
                ("ffi/denied.rs".to_owned(), 3),
                ("ffi/denied/child.rs".to_owned(), 1),
                ("ffi/quoted.rs".to_owned(), 1),
                ("ffi/unreachable.rs".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn does_not_inherit_unsafe_policy_across_custom_or_shared_crate_roots() {
        let sources = BTreeMap::from([
            (
                "custom/lib.rs",
                "#![expect(clippy::undocumented_unsafe_blocks)]\n#[path = \"other.rs\"] mod api;\n",
            ),
            ("custom/api.rs", "fn api() { unsafe { invoke(); } }\n"),
            ("custom/other.rs", "fn other() { unsafe { invoke(); } }\n"),
            (
                "shared/lib.rs",
                "#![allow(clippy::undocumented_unsafe_blocks)]\nmod api;\n",
            ),
            ("shared/main.rs", "mod api;\nfn main() {}\n"),
            ("shared/api.rs", "fn api() { unsafe { invoke(); } }\n"),
        ])
        .into_iter()
        .map(|(path, source)| (path.to_owned(), source.to_owned()))
        .collect();
        let selected = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| finding.path)
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec!["custom/api.rs", "custom/other.rs", "shared/api.rs"]
        );
    }

    #[test]
    fn keeps_unsafe_function_contracts_separate_from_block_rationales() {
        let source = r#"/// # Safety
/// The pointer must remain valid for this call.
unsafe fn read(pointer: *mut Value) {
    unsafe { pointer.read(); }
}
fn generated() {
    // SAFE: the generated wrapper has the same representation.
    unsafe { convert(); }
    // SAFETY: this expression is never evaluated.
    Wrapper { ..unsafe { pointer.read() } };
    match state {
        // SAFETY: the caller upholds this operation's requirements.
        State::Ready { value, .. } => unsafe { invoke(value) },
        _ => {}
    }
    // SAFETY: an unrelated completed block must not donate its rationale.
    if ready { prepare(); }
    unsafe { undocumented(); }
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![4, 18]);
    }

    #[test]
    fn honors_expect_for_panic_and_conversion_policy_only_on_its_item() {
        let source = r#"#[expect(clippy::panic, reason = "explicit abort policy")]
fn intentional() { panic!("abort"); }
fn unexpected() { panic!("runtime failure"); }
#[expect(
    clippy::from_over_into,
    reason = "conversion policy is explicit"
)]
impl Into<Target> for Source { fn into(self) -> Target { Target } }
impl Into<Other> for Different { fn into(self) -> Other { Other } }
"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "rust-panic-macro" | "rust-impl-into-instead-of-from"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("rust-panic-macro".to_owned(), 3),
                ("rust-impl-into-instead-of-from".to_owned(), 9),
            ]
        );
    }

    #[test]
    fn does_not_mistake_custom_multiline_or_borrowed_raw_apis_for_owners() {
        let source = r#"fn borrow(pointer: *const u8, len: usize) {
    unsafe { custom ::
        Box::from_raw(pointer) };
    unsafe { custom::Slice::from_raw_parts(pointer, len) };
    unsafe { std::slice::from_raw_parts(pointer, len) };
    // SAFETY: The custom transfer is intentional.
    unsafe { ::std::boxed::Box::from_raw(pointer) };
    // SAFETY: pointer is valid, but provenance is not local.
    unsafe { Box::from_raw(pointer) };
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-raw-ownership-reconstruction")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![7, 9]);
    }

    #[test]
    fn deny_and_forbid_prevent_unsafe_allowance_inheritance() {
        let sources = BTreeMap::from([
            ("ffi/lib.rs", "#![allow(clippy::undocumented_unsafe_blocks)]\nmod denied;\nmod forbidden;\n"),
            ("ffi/denied.rs", "#![expect(clippy::undocumented_unsafe_blocks)]\n#[deny(clippy::undocumented_unsafe_blocks)]\nfn api() { unsafe { invoke(); } }\n"),
            ("ffi/forbidden.rs", "#![forbid(clippy::undocumented_unsafe_blocks)]\nfn api() { unsafe { invoke(); } }\n"),
        ]).into_iter().map(|(path, source)| (path.to_owned(), source.to_owned())).collect();
        let selected = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("ffi/denied.rs".to_owned(), 3),
                ("ffi/forbidden.rs".to_owned(), 2),
            ]
        );
    }

    #[test]
    fn reports_qualified_standard_owner_reconstructions_with_arbitrary_provenance() {
        let source = r#"fn reclaim(pointer: *mut Value) {
    unsafe { std::boxed::Box::from_raw(pointer) };
    unsafe { alloc::boxed::Box::from_raw(pointer) };
    unsafe { ::std::sync::Arc::from_raw(pointer) };
    unsafe { std::vec::Vec::from_raw_parts(pointer, len, capacity) };
    unsafe { alloc::rc::Rc::from_raw(pointer) };
    unsafe { custom::boxed::Box::from_raw(pointer) };
}"#;
        let selected = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "rust-raw-ownership-reconstruction")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![2, 3, 4, 5, 6]);
    }

    #[test]
    fn scopes_declared_module_denials_without_disabling_sibling_policy() {
        let sources = BTreeMap::from([
            ("ffi/lib.rs", "#![allow(clippy::undocumented_unsafe_blocks)]\n#[deny(clippy::undocumented_unsafe_blocks)]\nmod denied;\nmod allowed;\n"),
            ("ffi/denied.rs", "mod child;\nfn api() { unsafe { invoke(); } }\n"),
            ("ffi/denied/child.rs", "fn api() { unsafe { invoke(); } }\n"),
            ("ffi/allowed.rs", "#[forbid(clippy::undocumented_unsafe_blocks)]\nmod forbidden;\nmod child;\nfn api() { unsafe { invoke(); } }\n"),
            ("ffi/allowed/forbidden.rs", "fn api() { unsafe { invoke(); } }\n"),
            ("ffi/allowed/child.rs", "fn api() { unsafe { invoke(); } }\n"),
        ]).into_iter().map(|(path, source)| (path.to_owned(), source.to_owned())).collect();
        let selected = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                ("ffi/allowed/forbidden.rs".to_owned(), 1),
                ("ffi/denied.rs".to_owned(), 2),
                ("ffi/denied/child.rs".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn attaches_invariant_comments_to_multiline_panic_expressions() {
        for source in [
            "fn domain() {\n// The non-emptiness invariant guarantees success.\nInterval::new(0.0, self.length())\n    .expect(\"invalid curve\");\n}",
            "fn domain() {\n/* The constructor guarantees this invariant.\n   The collection cannot be empty. */\nself.values\n    .first()\n    .unwrap();\n}",
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
                .collect::<Vec<_>>();
            assert!(selected.is_empty(), "{source}");
        }
        for source in [
            "fn f() {\n// The invariant covers this operation only.\ncomplete();\nvalue\n    .unwrap();\n}",
            "fn f() {\n// The invariant covers this nested operation only.\nif ready { complete(); }\nvalue\n    .unwrap();\n}",
            "fn f() {\nlet example = \"// The invariant guarantees success.\";\nvalue\n    .unwrap();\n}",
            "fn f() {\n// The call may fail on invalid input.\nvalue\n    .expect(\"value\");\n}",
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| matches!(finding.code.as_str(), "rust-unwrap" | "rust-expect"))
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "{source}");
            assert_eq!(selected[0].path, "src/lib.rs");
            assert_eq!(selected[0].confidence, "high");
            assert!(selected[0].related_files.is_empty());
            let offset = source.rfind('.').unwrap();
            assert_eq!(selected[0].line, source[..offset].lines().count());
        }
    }

    #[test]
    fn attaches_safety_rationales_to_containing_macro_expressions() {
        for source in [
            "fn emit() {\n// SAFETY: generated fields have the declared offsets and types.\nquote! {{\n    let fields = &[#(#fields),*];\n    Kind::Struct(unsafe { Struct::new(fields) })\n}};\n}",
            "fn emit() {\n// SAFETY: layout and vtable are generated from Self.\nOk(quote! {\n    unsafe impl Typed for Target {\n        const TYPE: Type = { unsafe { Type::new() } };\n    }\n})\n}",
            "fn emit() {\nmatch &implementation {\n    // SAFETY (all cases below): caller guarantees a valid pointer.\n    Custom(callback, span) => quote_spanned! {span=>\n        (|ptr| { unsafe { callback(ptr) } })\n    },\n}\n}",
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
                .collect::<Vec<_>>();
            assert!(selected.is_empty(), "{source}");
        }
        for source in [
            "fn emit() {\n// SAFETY: applies to the completed macro only.\nquote! { valid() };\nquote! { unsafe { undocumented() } };\n}",
            "fn emit() {\n// SAFETY: applies to the completed expression only.\ncomplete();\nquote! { unsafe { undocumented() } };\n}",
            "fn emit() {\nlet example = \"// SAFETY: not a real comment\";\nquote! { unsafe { undocumented() } };\n}",
            "/// # Safety\n/// The caller must provide a valid pointer.\nunsafe fn read() {\n    quote! { unsafe { undocumented() } };\n}",
            "fn emit() {\n// SAFETY: a match-level comment is not attached to a nested arm.\nmatch &implementation {\n    Custom(callback, span) => quote_spanned! {span=> unsafe { callback() } },\n}\n}",
        ] {
            let selected = findings(source)
                .into_iter()
                .filter(|finding| finding.code == "rust-undocumented-unsafe-block")
                .collect::<Vec<_>>();
            assert_eq!(selected.len(), 1, "{source}");
            assert_eq!(selected[0].path, "src/lib.rs");
            assert_eq!(selected[0].confidence, "high");
            assert!(selected[0].related_files.is_empty());
            let offset = source.rfind("unsafe {").unwrap();
            assert_eq!(selected[0].line, source[..offset].lines().count());
        }
    }
}
