use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{CodeFlowStep, Finding, Severity};
use crate::function_sources::{self, FunctionSource};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let go_sources = sources
        .iter()
        .filter(|(path, _)| path.ends_with(".go"))
        .map(|(path, source)| (path.clone(), source.clone()))
        .collect::<BTreeMap<_, _>>();
    let functions = function_sources::extract(&go_sources);
    let mut findings = Vec::new();
    findings.extend(defer_in_loop(&go_sources));
    findings.extend(derived_context_cancel(&functions));
    findings.extend(source_pattern(
        &go_sources,
        "go-http-client-no-timeout",
        &HTTP_CLIENT_NO_TIMEOUT,
        "HTTP client has no timeout",
        false,
        None,
    ));
    findings.extend(source_pattern(
        &go_sources,
        "go-insecure-tls",
        &INSECURE_TLS,
        "TLS certificate verification is disabled",
        false,
        Some("TLS verification disabled here"),
    ));
    findings.extend(response_body_not_closed(&go_sources, &functions));
    findings.extend(source_pattern(
        &go_sources,
        "go-shell-command",
        &SHELL_COMMAND,
        "shell command execution with -c expands an injection boundary",
        true,
        Some("shell command execution sink"),
    ));
    findings.extend(sql_rows_error(&functions));
    findings.extend(world_writable(&go_sources));
    findings
}

fn source_pattern(
    sources: &BTreeMap<String, String>,
    code: &str,
    pattern: &Regex,
    message: &str,
    include_comments_and_strings: bool,
    code_flow_message: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let mut in_block_comment = false;
        for (index, line) in source.split('\n').enumerate() {
            let masked = mask_non_code(line, &mut in_block_comment);
            let inspected = if include_comments_and_strings {
                line
            } else {
                &masked
            };
            if pattern.is_match(inspected) {
                let line = index + 1;
                let code_flow = code_flow_message.map_or_else(Vec::new, |message| {
                    vec![CodeFlowStep {
                        path: path.clone(),
                        line,
                        message: message.to_owned(),
                    }]
                });
                findings.push(finding(code, path, line, message.to_owned(), code_flow));
            }
        }
    }
    findings
}

fn defer_in_loop(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let structure = go_structure(source);
        let lines = structure.split('\n').collect::<Vec<_>>();
        scan_loop_defers(path, &lines, &mut findings);
    }
    findings
}

fn scan_loop_defers(path: &str, lines: &[&str], findings: &mut Vec<Finding>) {
    let mut scopes = Vec::<GoScope>::new();
    for (index, line) in lines.iter().enumerate() {
        if defer_accumulates_in_loop(lines, index, line, &scopes) {
            findings.push(finding(
                "go-defer-in-loop",
                path,
                index + 1,
                "defer inside a loop accumulates until the surrounding function returns".to_owned(),
                Vec::new(),
            ));
        }
        update_go_scopes(line, &mut scopes);
    }
}

fn defer_accumulates_in_loop(
    lines: &[&str],
    line_index: usize,
    line: &str,
    scopes: &[GoScope],
) -> bool {
    let Some(first_code) = line.find(|character: char| !character.is_whitespace()) else {
        return false;
    };
    let Some(defer_match) = DEFER_WORD.find(line) else {
        return false;
    };
    if defer_match.start() != first_code {
        return false;
    }
    let Some(loop_index) = scopes.iter().rposition(|scope| *scope == GoScope::Loop) else {
        return false;
    };
    let function_index = scopes.iter().rposition(|scope| *scope == GoScope::Function);
    function_index.is_none_or(|function| loop_index > function)
        && !exits_loop_after(lines, line_index, scopes.len() - loop_index - 1)
}

fn update_go_scopes(line: &str, scopes: &mut Vec<GoScope>) {
    let mut segment_start = 0;
    for (offset, byte) in line.bytes().enumerate() {
        match byte {
            b'}' => {
                scopes.pop();
                segment_start = offset + 1;
            }
            b'{' => {
                let prefix = &line[segment_start..offset];
                scopes.push(if FOR_SCOPE.is_match(prefix) {
                    GoScope::Loop
                } else if ANONYMOUS_FUNCTION.is_match(prefix) {
                    GoScope::Function
                } else {
                    GoScope::Block
                });
                segment_start = offset + 1;
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GoScope {
    Block,
    Function,
    Loop,
}

fn exits_loop_after(lines: &[&str], defer_line: usize, nested_block_depth: usize) -> bool {
    let mut depth = nested_block_depth;
    for (index, line) in lines.iter().enumerate().skip(defer_line) {
        let start = if index == defer_line {
            DEFER_WORD.find(line).map_or(0, |matched| matched.end())
        } else {
            0
        };
        if depth <= nested_block_depth && LOOP_EXIT.is_match(line) {
            return true;
        }
        for byte in line.as_bytes()[start..].iter().copied() {
            match byte {
                b'{' => depth += 1,
                b'}' if depth == 0 => return false,
                b'}' => depth -= 1,
                _ => {}
            }
        }
    }
    false
}

fn derived_context_cancel(functions: &[FunctionSource]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for function in functions {
        for creation in DERIVED_CONTEXT.captures_iter(&function.source) {
            let complete = creation.get(0).unwrap();
            let cancel = creation.name("cancel").unwrap().as_str();
            let tail = &function.source[complete.end()..];
            if cancel != "_" {
                let use_pattern = Regex::new(&format!(r"\b{}\b", regex::escape(cancel))).unwrap();
                if use_pattern.is_match(tail) {
                    continue;
                }
            }
            let line = function.line + newline_count(&function.source[..complete.start()]);
            let message = if cancel == "_" {
                "derived context discards its cancel function".to_owned()
            } else {
                format!("derived context cancel function `{cancel}` is never called")
            };
            findings.push(finding(
                "go-derived-context-cancel-not-called",
                &function.path,
                line,
                message,
                Vec::new(),
            ));
        }
    }
    findings
}

fn response_body_not_closed(
    sources: &BTreeMap<String, String>,
    functions: &[FunctionSource],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for function in functions {
        let source = &sources[&function.path];
        let file_functions = functions
            .iter()
            .filter(|candidate| candidate.path == function.path)
            .collect::<Vec<_>>();
        for request in HTTP_RESPONSE.captures_iter(&function.source) {
            let complete = request.get(0).unwrap();
            let response = request.name("response").unwrap().as_str();
            if let Some(receiver) = request.name("receiver")
                && !is_http_client_receiver(receiver.as_str(), &function.source, source)
            {
                continue;
            }
            let close =
                Regex::new(&format!(r"\b{}\.Body\.Close\s*\(", regex::escape(response))).unwrap();
            if close.is_match(&function.source)
                || closed_by_local_helper(response, &function.source, &file_functions)
            {
                continue;
            }
            let line = function.line + newline_count(&function.source[..complete.start()]);
            findings.push(finding(
                "go-response-body-not-closed",
                &function.path,
                line,
                "HTTP response body is not closed in this function".to_owned(),
                Vec::new(),
            ));
        }
    }
    findings
}

fn closed_by_local_helper(response: &str, caller: &str, functions: &[&FunctionSource]) -> bool {
    let call = Regex::new(&format!(
        r"\b(?:[A-Za-z_]\w*\.)?(?P<name>[A-Za-z_]\w*)\s*\(\s*{}\s*\)",
        regex::escape(response)
    ))
    .unwrap();
    for matched in call.captures_iter(caller) {
        let Some(name) = matched.name("name").map(|capture| capture.as_str()) else {
            continue;
        };
        for helper in functions {
            if helper.name != name {
                continue;
            }
            let parameter = Regex::new(&format!(
                r"\b{}\s*\(\s*(?P<parameter>[A-Za-z_]\w*)\s+\*http\.Response\b",
                regex::escape(name)
            ))
            .unwrap();
            let Some(parameter) = parameter.captures(&helper.source) else {
                continue;
            };
            let Some(parameter) = parameter.name("parameter").map(|capture| capture.as_str())
            else {
                continue;
            };
            let close = Regex::new(&format!(
                r"\b{}\.Body\.Close\s*\(",
                regex::escape(parameter)
            ))
            .unwrap();
            if close.is_match(&helper.source) {
                return true;
            }
        }
    }
    false
}

fn is_http_client_receiver(receiver: &str, function_source: &str, source: &str) -> bool {
    if receiver == "http.DefaultClient" {
        return true;
    }
    let name = receiver.rsplit('.').next().unwrap_or(receiver);
    let escaped = regex::escape(name);
    let evidence = if receiver.contains('.') {
        source
    } else {
        function_source
    };
    let Ok(client_pattern) = Regex::new(&format!(
        r"(?:\b{escaped}\s+\*http\.Client\b|\b{escaped}\s*:?=\s*(?:&\s*)?http\.Client\s*\{{)"
    )) else {
        return false;
    };
    client_pattern.is_match(evidence)
}

fn sql_rows_error(functions: &[FunctionSource]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for function in functions {
        for query in SQL_QUERY.captures_iter(&function.source) {
            let complete = query.get(0).unwrap();
            let rows = query.name("rows").unwrap().as_str();
            let tail = &function.source[complete.end()..];
            let next = Regex::new(&format!(r"\b{}\.Next\s*\(\s*\)", regex::escape(rows))).unwrap();
            let Some(iteration) = next.find(tail) else {
                continue;
            };
            let error = Regex::new(&format!(r"\b{}\.Err\s*\(\s*\)", regex::escape(rows))).unwrap();
            if error.is_match(tail) {
                continue;
            }
            let line = function.line
                + newline_count(&function.source[..complete.end() + iteration.start()]);
            findings.push(finding(
                "go-sql-rows-error-not-checked",
                &function.path,
                line,
                format!("SQL row iteration does not check `{rows}.Err()`"),
                Vec::new(),
            ));
        }
    }
    findings
}

fn world_writable(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        for matched in PERMISSION_CALL.captures_iter(source) {
            let complete = matched.get(0).unwrap();
            if let Some(flags) = matched.name("flags")
                && !creates_file(flags.as_str(), source)
            {
                continue;
            }
            findings.push(finding(
                "go-world-writable",
                path,
                1 + newline_count(&source[..complete.start()]),
                "world-writable file permission used".to_owned(),
                Vec::new(),
            ));
        }
    }
    findings
}

fn creates_file(flags: &str, source: &str) -> bool {
    if CREATE_FLAG.is_match(flags) {
        return true;
    }
    let identifier = flags.trim();
    if !IDENTIFIER.is_match(identifier) {
        return false;
    }
    Regex::new(&format!(
        r"\b{}\s*:?=\s*[^\n]*\bos\.O_CREATE\b",
        regex::escape(identifier)
    ))
    .unwrap()
    .is_match(source)
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    code_flow: Vec<CodeFlowStep>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Go rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Go rule severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow,
    }
}

fn mask_non_code(line: &str, in_block_comment: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut state = GoLineMaskState::from_block_comment(*in_block_comment);
    let mut index = 0;
    while index < bytes.len() {
        state = state.mask_next(bytes, &mut index, &mut result);
    }
    *in_block_comment = state.is_block_comment();
    String::from_utf8(result).expect("masked Go source must remain UTF-8")
}

#[derive(Clone, Copy)]
enum GoLineMaskState {
    Code,
    BlockComment,
    Quote { delimiter: u8, escaped: bool },
}

impl GoLineMaskState {
    fn from_block_comment(in_block_comment: bool) -> Self {
        if in_block_comment {
            Self::BlockComment
        } else {
            Self::Code
        }
    }

    fn is_block_comment(self) -> bool {
        matches!(self, Self::BlockComment)
    }

    fn mask_next(self, bytes: &[u8], index: &mut usize, result: &mut Vec<u8>) -> Self {
        match self {
            Self::Code => mask_go_line_code(bytes, index, result),
            Self::BlockComment => mask_go_line_block_comment(bytes, index, result),
            Self::Quote { delimiter, escaped } => {
                mask_go_line_quote(bytes, index, result, delimiter, escaped)
            }
        }
    }
}

fn mask_go_line_code(bytes: &[u8], index: &mut usize, result: &mut Vec<u8>) -> GoLineMaskState {
    let byte = bytes[*index];
    let next = bytes.get(*index + 1).copied();
    if matches!(byte, b'"' | b'\'' | b'`') {
        result.push(b' ');
        *index += 1;
        GoLineMaskState::Quote {
            delimiter: byte,
            escaped: false,
        }
    } else if byte == b'/' && next == Some(b'*') {
        result.extend_from_slice(b"  ");
        *index += 2;
        GoLineMaskState::BlockComment
    } else if byte == b'/' && next == Some(b'/') {
        *index = bytes.len();
        GoLineMaskState::Code
    } else {
        result.push(byte);
        *index += 1;
        GoLineMaskState::Code
    }
}

fn mask_go_line_block_comment(
    bytes: &[u8],
    index: &mut usize,
    result: &mut Vec<u8>,
) -> GoLineMaskState {
    if bytes[*index] == b'*' && bytes.get(*index + 1) == Some(&b'/') {
        result.extend_from_slice(b"  ");
        *index += 2;
        GoLineMaskState::Code
    } else {
        result.push(b' ');
        *index += 1;
        GoLineMaskState::BlockComment
    }
}

fn mask_go_line_quote(
    bytes: &[u8],
    index: &mut usize,
    result: &mut Vec<u8>,
    delimiter: u8,
    escaped: bool,
) -> GoLineMaskState {
    let byte = bytes[*index];
    result.push(b' ');
    *index += 1;
    if escaped {
        GoLineMaskState::Quote {
            delimiter,
            escaped: false,
        }
    } else if byte == b'\\' {
        GoLineMaskState::Quote {
            delimiter,
            escaped: true,
        }
    } else if byte == delimiter {
        GoLineMaskState::Code
    } else {
        GoLineMaskState::Quote {
            delimiter,
            escaped: false,
        }
    }
}

#[derive(Clone, Copy)]
enum GoStructureState {
    Code,
    LineComment,
    BlockComment,
    Quote(u8),
}

impl GoStructureState {
    fn mask_next(self, bytes: &[u8], index: &mut usize, result: &mut Vec<u8>) -> GoStructureState {
        match self {
            GoStructureState::Code => mask_go_code(bytes, index, result),
            GoStructureState::LineComment => mask_go_line_comment(bytes, index, result),
            GoStructureState::BlockComment => mask_go_block_comment(bytes, index, result),
            GoStructureState::Quote(delimiter) => {
                mask_go_quoted_text(bytes, index, result, delimiter)
            }
        }
    }
}

fn go_structure(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut state = GoStructureState::Code;
    let mut index = 0;
    while index < bytes.len() {
        state = state.mask_next(bytes, &mut index, &mut result);
    }
    String::from_utf8(result).expect("structured Go source must remain UTF-8")
}

fn mask_go_code(bytes: &[u8], index: &mut usize, result: &mut Vec<u8>) -> GoStructureState {
    let byte = bytes[*index];
    let next = bytes.get(*index + 1).copied();
    if byte == b'/' && next == Some(b'/') {
        result.extend_from_slice(b"  ");
        *index += 2;
        GoStructureState::LineComment
    } else if byte == b'/' && next == Some(b'*') {
        result.extend_from_slice(b"  ");
        *index += 2;
        GoStructureState::BlockComment
    } else if matches!(byte, b'"' | b'\'' | b'`') {
        result.push(b' ');
        *index += 1;
        GoStructureState::Quote(byte)
    } else {
        result.push(byte);
        *index += 1;
        GoStructureState::Code
    }
}

fn mask_go_line_comment(bytes: &[u8], index: &mut usize, result: &mut Vec<u8>) -> GoStructureState {
    let byte = bytes[*index];
    result.push(if byte == b'\n' { b'\n' } else { b' ' });
    *index += 1;
    if byte == b'\n' {
        GoStructureState::Code
    } else {
        GoStructureState::LineComment
    }
}

fn mask_go_block_comment(
    bytes: &[u8],
    index: &mut usize,
    result: &mut Vec<u8>,
) -> GoStructureState {
    let byte = bytes[*index];
    if byte == b'*' && bytes.get(*index + 1) == Some(&b'/') {
        result.extend_from_slice(b"  ");
        *index += 2;
        GoStructureState::Code
    } else {
        result.push(if byte == b'\n' { b'\n' } else { b' ' });
        *index += 1;
        GoStructureState::BlockComment
    }
}

fn mask_go_quoted_text(
    bytes: &[u8],
    index: &mut usize,
    result: &mut Vec<u8>,
    delimiter: u8,
) -> GoStructureState {
    let byte = bytes[*index];
    let next = bytes.get(*index + 1).copied();
    result.push(if byte == b'\n' { b'\n' } else { b' ' });
    if delimiter != b'`' && byte == b'\\' && next.is_some() {
        result.push(if next == Some(b'\n') { b'\n' } else { b' ' });
        *index += 2;
        GoStructureState::Quote(delimiter)
    } else {
        *index += 1;
        if byte == delimiter {
            GoStructureState::Code
        } else {
            GoStructureState::Quote(delimiter)
        }
    }
}

fn newline_count(source: &str) -> usize {
    source.bytes().filter(|byte| *byte == b'\n').count()
}

static HTTP_CLIENT_NO_TIMEOUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"http\.Client\s*\{\s*\}").unwrap());
static INSECURE_TLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"InsecureSkipVerify\s*:\s*true").unwrap());
static SHELL_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"exec\.Command(?:Context)?\s*\((?:[^,\n]+,\s*)?["'](?:/bin/)?(?:ba|z|da|k)?sh["']\s*,\s*["']-c["']"#,
    )
    .unwrap()
});
static DEFER_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdefer\b").unwrap());
static FOR_SCOPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|\W)for(?:\s|$)").unwrap());
static ANONYMOUS_FUNCTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfunc\s*\(").unwrap());
static LOOP_EXIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:return\b|break\b|continue\b|goto\b)").unwrap());
static DERIVED_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z_]\w*\s*,\s*(?P<cancel>[A-Za-z_]\w*|_)\s*:=\s*context\.(?:WithCancel|WithCancelCause|WithTimeout|WithTimeoutCause|WithDeadline|WithDeadlineCause)\s*\(").unwrap()
});
static HTTP_RESPONSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<response>[A-Za-z_]\w*)\s*,\s*(?:err|_)\s*:=\s*(?:http\.(?:Get|Post|PostForm)|(?P<receiver>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.Do)\s*\(").unwrap()
});
static SQL_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<rows>[A-Za-z_]\w*)\s*,\s*(?:[A-Za-z_]\w*|_)\s*:=\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.Query(?:Context)?\s*\(").unwrap()
});
static PERMISSION_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"os\.(?:Chmod\s*\([^,\n]+|WriteFile\s*\([^,\n]+,[^,\n]+|OpenFile\s*\([^,\n]+,\s*(?P<flags>[^,\n]+))\s*,\s*(?:0[oO]|0)?[0-7]*[2367]\b").unwrap()
});
static CREATE_FLAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bos\.O_CREATE\b").unwrap());
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_every_go_rule_in_registry_order() {
        let findings = analyze(&sources(&[(
            "main.go",
            r#"package main

func inspect(db *DB) {
    for {
        defer release()
    }
    ctx, cancel := context.WithCancel(context.Background())
    client := http.Client{}
    transport := &tls.Config{InsecureSkipVerify: true}
    response, err := client.Do(request)
    command := exec.Command("sh", "-c", input)
    rows, err := db.Query("select 1")
    for rows.Next() {}
    os.Chmod("data", 0777)
}
"#,
        )]));

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.severity.as_str(),
                    finding.line,
                    finding.end_line,
                    finding.message.as_str(),
                    finding.confidence.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "go-defer-in-loop",
                    "warn",
                    5,
                    0,
                    "defer inside a loop accumulates until the surrounding function returns",
                    "high",
                ),
                (
                    "go-derived-context-cancel-not-called",
                    "warn",
                    7,
                    0,
                    "derived context cancel function `cancel` is never called",
                    "high",
                ),
                (
                    "go-http-client-no-timeout",
                    "warn",
                    8,
                    0,
                    "HTTP client has no timeout",
                    "high",
                ),
                (
                    "go-insecure-tls",
                    "error",
                    9,
                    0,
                    "TLS certificate verification is disabled",
                    "high",
                ),
                (
                    "go-response-body-not-closed",
                    "warn",
                    10,
                    0,
                    "HTTP response body is not closed in this function",
                    "high",
                ),
                (
                    "go-shell-command",
                    "warn",
                    11,
                    0,
                    "shell command execution with -c expands an injection boundary",
                    "high",
                ),
                (
                    "go-sql-rows-error-not-checked",
                    "warn",
                    13,
                    0,
                    "SQL row iteration does not check `rows.Err()`",
                    "high",
                ),
                (
                    "go-world-writable",
                    "warn",
                    14,
                    0,
                    "world-writable file permission used",
                    "high",
                ),
            ]
        );
        assert_eq!(
            findings[3].code_flow,
            vec![CodeFlowStep {
                path: "main.go".to_owned(),
                line: 9,
                message: "TLS verification disabled here".to_owned(),
            }]
        );
        assert_eq!(
            findings[5].code_flow,
            vec![CodeFlowStep {
                path: "main.go".to_owned(),
                line: 11,
                message: "shell command execution sink".to_owned(),
            }]
        );
        assert_eq!(
            findings[3].to_json()["code_flow"][0]["message"],
            "TLS verification disabled here"
        );
    }

    #[test]
    fn ignores_safe_forms_and_masked_source_patterns() {
        let findings = analyze(&sources(&[(
            "safe.go",
            r#"package main

func safe(db *DB) {
    for {
        defer release()
        continue
    }
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    client := http.Client{Timeout: time.Second}
    transport := &tls.Config{InsecureSkipVerify: false}
    response, err := http.Get(url)
    defer response.Body.Close()
    command := exec.Command("tool", "-c")
    rows, err := db.Query("select 1")
    for rows.Next() {}
    if err := rows.Err(); err != nil {}
    os.Chmod("data", 0644)
    // http.Client{}
    text := "InsecureSkipVerify: true"
}
"#,
        )]));

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn distinguishes_nested_function_defers_from_loop_defers() {
        let findings = analyze(&sources(&[(
            "defer.go",
            r#"package main

func work(items []Item) {
    for _, item := range items {
        defer item.Close()
        func() {
            defer item.Close()
        }()
        if item.Done() {
            return
        }
    }
}
"#,
        )]));

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("go-defer-in-loop", 5)]
        );
    }

    #[test]
    fn reports_discarded_cancel_but_accepts_transfer() {
        let findings = analyze(&sources(&[(
            "context.go",
            r#"package main

func discarded() {
    ctx, _ := context.WithTimeout(context.Background(), time.Second)
}

func transferred() context.CancelFunc {
    ctx, cancel := context.WithCancel(context.Background())
    return cancel
}
"#,
        )]));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "go-derived-context-cancel-not-called");
        assert_eq!(findings[0].line, 4);
        assert_eq!(
            findings[0].message,
            "derived context discards its cancel function"
        );
    }

    #[test]
    fn understands_http_client_receivers_and_local_closing_helpers() {
        let findings = analyze(&sources(&[(
            "client.go",
            r#"package main

func closeResponse(response *http.Response) {
    response.Body.Close()
}

func safe(request *http.Request) {
    client := &http.Client{Timeout: time.Second}
    response, err := client.Do(request)
    closeResponse(response)
}

func unsafe(request *http.Request, service *Service) {
    response, err := service.Do(request)
    direct, err := http.Get("https://example.com")
}
"#,
        )]));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "go-response-body-not-closed");
        assert_eq!(findings[0].line, 15);
    }

    #[test]
    fn malformed_http_helper_call_preserves_response_finding() {
        let findings = analyze(&sources(&[(
            "malformed.go",
            r#"package main

func malformed(request *http.Request) {
    client := &http.Client{Timeout: time.Second}
    response, err := client.Do(request)
    closeResponse(response
}
"#,
        )]));

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("go-response-body-not-closed", 5)]
        );
    }

    #[test]
    fn requires_create_for_world_writable_open_file_permissions() {
        let findings = analyze(&sources(&[(
            "permissions.go",
            r#"package main

func files() {
    flags := os.O_WRONLY | os.O_CREATE
    os.OpenFile("created", flags, 0666)
    os.OpenFile("existing", os.O_WRONLY, 0666)
    os.WriteFile("written", data, 0666)
}
"#,
        )]));

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("go-world-writable", 5), ("go-world-writable", 7)]
        );
    }

    #[test]
    fn shell_detection_intentionally_includes_comments_and_strings() {
        let findings = analyze(&sources(&[(
            "shell.go",
            r#"package main

func commands() {
    // exec.Command("bash", "-c", input)
    text := `exec.CommandContext(ctx, "/bin/sh", "-c", input)`
}
"#,
        )]));

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("go-shell-command", 4), ("go-shell-command", 5)]
        );
    }

    fn sources(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
            .collect()
    }
}
