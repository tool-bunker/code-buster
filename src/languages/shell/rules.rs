use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use super::is_shell_source;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;

#[derive(Debug)]
struct LogicalCommand {
    line: usize,
    code: String,
}

#[derive(Default)]
struct ShellScanState {
    unquoted_expansion_reported: bool,
    ignored_failure_reported: bool,
}

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources
        .iter()
        .filter(|(path, source)| is_shell_source(path, source))
    {
        findings.extend(analyze_source(path, source));
    }
    findings
}

fn analyze_source(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut state = ShellScanState::default();
    for command in logical_commands(source) {
        analyze_command(path, &command, &mut state, &mut findings);
    }
    findings
}

fn analyze_command(
    path: &str,
    command: &LogicalCommand,
    state: &mut ShellScanState,
    findings: &mut Vec<Finding>,
) {
    let code = command.code.trim();
    if code.is_empty() || code.starts_with("#!") {
        return;
    }
    let outside_quotes = mask_quoted_content(code);
    let dangerous_rm = report_security_findings(path, command, code, &outside_quotes, findings);
    report_general_findings(
        path,
        command,
        code,
        &outside_quotes,
        dangerous_rm,
        state,
        findings,
    );
}

fn report_security_findings(
    path: &str,
    command: &LogicalCommand,
    code: &str,
    outside_quotes: &str,
    findings: &mut Vec<Finding>,
) -> bool {
    if CURL_PIPE_SHELL.is_match(outside_quotes) {
        findings.push(finding(
            "shell-download-pipe-execution",
            path,
            command.line,
            "downloaded content is piped directly to a shell interpreter",
            "high",
        ));
    }
    if EVAL_COMMAND
        .captures(code)
        .and_then(|captures| captures.name("argument"))
        .is_some_and(|argument| dynamic_shell_text(argument.as_str()))
    {
        findings.push(finding(
            "shell-dynamic-eval",
            path,
            command.line,
            "eval executes dynamically constructed shell text",
            "high",
        ));
    }
    let dangerous_rm = dangerous_recursive_remove(code, outside_quotes);
    if dangerous_rm {
        findings.push(finding(
            "shell-unguarded-recursive-remove",
            path,
            command.line,
            "recursive forced removal uses an expansion that can widen the target",
            "high",
        ));
    }
    if MKTEMP_DRY_RUN.is_match(outside_quotes) || predictable_temp_creation(code) {
        findings.push(finding(
            "shell-predictable-temp-file",
            path,
            command.line,
            "temporary path can be predicted before it is safely created",
            "high",
        ));
    }
    if contains_exposed_secret_argument(code, outside_quotes) {
        findings.push(finding(
            "shell-secret-command-argument",
            path,
            command.line,
            "secret is passed through a process argument",
            "high",
        ));
    }
    dangerous_rm
}

fn report_general_findings(
    path: &str,
    command: &LogicalCommand,
    code: &str,
    outside_quotes: &str,
    dangerous_rm: bool,
    state: &mut ShellScanState,
    findings: &mut Vec<Finding>,
) {
    if !dangerous_rm
        && !state.unquoted_expansion_reported
        && command_argument_region(code).is_some_and(contains_unquoted_parameter_expansion)
    {
        findings.push(finding(
            "shell-unquoted-expansion",
            path,
            command.line,
            "unquoted expansion can trigger word splitting or pathname expansion",
            "medium",
        ));
        state.unquoted_expansion_reported = true;
    }
    if !state.ignored_failure_reported && IGNORED_FAILURE.is_match(outside_quotes) {
        findings.push(finding(
            "shell-ignored-command-failure",
            path,
            command.line,
            "command failure is unconditionally discarded",
            "medium",
        ));
        state.ignored_failure_reported = true;
    }
}

#[derive(Default)]
struct LogicalCommandBuilder {
    current: String,
    start_line: usize,
    heredoc: Option<(String, bool)>,
    lexer: ShellLexer,
}

impl LogicalCommandBuilder {
    fn push_line(&mut self, index: usize, raw: &str) -> Option<LogicalCommand> {
        if self.consume_heredoc_line(raw) {
            return None;
        }
        let mut code = strip_shell_comment(raw, &mut self.lexer);
        if self.current.is_empty() {
            self.start_line = index + 1;
        }
        let continued = ends_with_unescaped_backslash(&code);
        if continued {
            code.pop();
            self.lexer.finish_line_continuation();
        }
        if !self.current.is_empty() {
            self.current.push(' ');
        }
        self.current.push_str(code.trim());
        if continued
            || self.lexer.in_quote()
            || has_unclosed_non_splitting_region(&self.current)
            || self.current.trim().is_empty()
        {
            return None;
        }
        self.heredoc = heredoc_delimiter(&self.current);
        Some(LogicalCommand {
            line: self.start_line,
            code: std::mem::take(&mut self.current),
        })
    }

    fn consume_heredoc_line(&mut self, raw: &str) -> bool {
        let Some((delimiter, strip_tabs)) = self.heredoc.as_ref() else {
            return false;
        };
        let candidate = if *strip_tabs {
            raw.trim_start_matches('\t')
        } else {
            raw
        };
        if candidate.trim_end() == delimiter {
            self.heredoc = None;
        }
        true
    }

    fn finish(self) -> Option<LogicalCommand> {
        (!self.current.trim().is_empty()).then_some(LogicalCommand {
            line: self.start_line,
            code: self.current,
        })
    }
}

fn logical_commands(source: &str) -> Vec<LogicalCommand> {
    let mut commands = Vec::new();
    let mut builder = LogicalCommandBuilder::default();
    for (index, raw) in source.lines().enumerate() {
        commands.extend(builder.push_line(index, raw));
    }
    commands.extend(builder.finish());
    commands
}

#[derive(Clone, Copy)]
enum ShellCharacter {
    Unquoted(char),
    Quoted,
    QuoteDelimiter(char),
}

#[derive(Default)]
struct ShellLexer {
    quote: Option<char>,
    escaped: bool,
}

impl ShellLexer {
    fn in_quote(&self) -> bool {
        self.quote.is_some()
    }

    fn finish_line_continuation(&mut self) {
        self.escaped = false;
    }

    fn consume(&mut self, character: char) -> ShellCharacter {
        if self.escaped {
            self.escaped = false;
            return if self.quote.is_some() {
                ShellCharacter::Quoted
            } else {
                ShellCharacter::Unquoted(character)
            };
        }
        if character == '\\' && self.quote != Some('\'') {
            self.escaped = true;
            return if self.quote.is_some() {
                ShellCharacter::Quoted
            } else {
                ShellCharacter::Unquoted(character)
            };
        }
        if self.quote == Some(character) {
            self.quote = None;
            return ShellCharacter::QuoteDelimiter(character);
        }
        if self.quote.is_some() {
            return ShellCharacter::Quoted;
        }
        if matches!(character, '\'' | '"' | '`') {
            self.quote = Some(character);
            ShellCharacter::QuoteDelimiter(character)
        } else {
            ShellCharacter::Unquoted(character)
        }
    }
}

fn strip_shell_comment(line: &str, lexer: &mut ShellLexer) -> String {
    let mut output = String::with_capacity(line.len());
    let mut word_boundary = !lexer.in_quote();
    for character in line.chars() {
        match lexer.consume(character) {
            ShellCharacter::Unquoted('#') if word_boundary => break,
            ShellCharacter::Unquoted(value) => {
                output.push(value);
                word_boundary =
                    value.is_whitespace() || matches!(value, ';' | '&' | '|' | '(' | ')');
            }
            ShellCharacter::QuoteDelimiter(value) => {
                output.push(value);
                word_boundary = false;
            }
            ShellCharacter::Quoted => output.push(character),
        }
    }
    output
}

fn ends_with_unescaped_backslash(line: &str) -> bool {
    let count = line
        .trim_end()
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'\\')
        .count();
    count % 2 == 1
}

fn heredoc_delimiter(command: &str) -> Option<(String, bool)> {
    let captures = HEREDOC.captures(command)?;
    let matched = captures.get(0)?;
    if command.as_bytes().get(matched.start() + 2) == Some(&b'<') {
        return None;
    }
    let delimiter = captures.get(2)?.as_str().to_owned();
    let strip_tabs = captures.get(1).is_some_and(|value| value.as_str() == "-");
    Some((delimiter, strip_tabs))
}

fn has_unclosed_non_splitting_region(code: &str) -> bool {
    let bytes = code.as_bytes();
    let mut index = 0usize;
    let mut test_depth = 0usize;
    let mut arithmetic_depth = 0usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if is_shell_escape(byte, quote) {
            index += 2;
            continue;
        }
        if consume_shell_quote(byte, &mut quote) {
            index += 1;
            continue;
        }
        match bytes.get(index..index + 2) {
            Some(b"[[") => test_depth += 1,
            Some(b"]]") => test_depth = test_depth.saturating_sub(1),
            Some(b"((") => arithmetic_depth += 1,
            Some(b"))") => arithmetic_depth = arithmetic_depth.saturating_sub(1),
            _ => {
                index += 1;
                continue;
            }
        }
        index += 2;
    }
    test_depth > 0 || arithmetic_depth > 0
}

fn mask_quoted_content(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut lexer = ShellLexer::default();
    for character in line.chars() {
        match lexer.consume(character) {
            ShellCharacter::Unquoted(value) | ShellCharacter::QuoteDelimiter(value) => {
                output.push(value);
            }
            ShellCharacter::Quoted => output.push(' '),
        }
    }
    output
}

fn dynamic_shell_text(argument: &str) -> bool {
    let argument = argument.trim();
    let statically_quoted = argument
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .is_some_and(|value| !value.contains('\''));
    !statically_quoted
        && (argument.contains('$') || argument.contains('`') || argument.contains("$("))
}

fn dangerous_recursive_remove(command: &str, outside_quotes: &str) -> bool {
    RM_COMMAND.captures_iter(outside_quotes).any(|captures| {
        let Some(masked_arguments) = captures.name("arguments") else {
            return false;
        };
        let arguments = &command[masked_arguments.start()..masked_arguments.end()];
        has_rm_flag(arguments, 'r')
            && has_rm_flag(arguments, 'f')
            && (contains_unquoted_parameter_expansion(arguments)
                || variable_followed_by_glob(arguments))
    })
}

fn has_rm_flag(arguments: &str, flag: char) -> bool {
    arguments.split_whitespace().any(|word| {
        word == match flag {
            'r' => "--recursive",
            'f' => "--force",
            _ => "",
        } || word
            .strip_prefix('-')
            .filter(|flags| !flags.starts_with('-'))
            .is_some_and(|flags| flags.contains(flag))
    })
}

fn variable_followed_by_glob(arguments: &str) -> bool {
    VARIABLE_PATH_GLOB.captures_iter(arguments).any(|captures| {
        captures
            .name("braced")
            .is_none_or(|value| !value.as_str().contains('?'))
    })
}

fn predictable_temp_creation(command: &str) -> bool {
    TEMP_CREATION
        .captures_iter(command)
        .chain(TEMP_REDIRECTION.captures_iter(command))
        .filter_map(|captures| captures.name("path"))
        .any(|path| !path.as_str().contains('$'))
}

fn command_argument_region(mut command: &str) -> Option<&str> {
    command = command.trim_start();
    if is_standalone_assignment(command) {
        return None;
    }
    loop {
        let word_end = shell_word_end(command);
        let word = &command[..word_end];
        if !is_assignment_word(word) {
            break;
        }
        command = command[word_end..].trim_start();
        if command.is_empty() {
            return None;
        }
    }
    if command.is_empty() || NON_SPLITTING_CONTEXT.is_match(command) {
        None
    } else {
        Some(command)
    }
}

fn shell_word_end(command: &str) -> usize {
    let bytes = command.as_bytes();
    let mut index = 0usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if is_shell_escape(byte, quote) {
            index += 2;
            continue;
        }
        if let Some(end) = quoted_expansion_end(bytes, index, quote) {
            index = end;
            continue;
        }
        if consume_shell_quote(byte, &mut quote) {
            index += 1;
            continue;
        }
        if byte.is_ascii_whitespace() {
            return index;
        }
        index += 1;
    }
    bytes.len()
}

fn is_assignment_word(word: &str) -> bool {
    let Some(equals) = word.find('=') else {
        return false;
    };
    let raw_name = word[..equals]
        .split_once('[')
        .map_or(&word[..equals], |pair| pair.0);
    let name = raw_name.strip_suffix('+').unwrap_or(raw_name);
    !name.is_empty()
        && is_identifier_start(name.as_bytes()[0])
        && name
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn is_standalone_assignment(command: &str) -> bool {
    let Some(equals) = command.find('=') else {
        return false;
    };
    if command[..equals]
        .bytes()
        .any(|byte| byte.is_ascii_whitespace())
        || !is_assignment_word(&command[..=equals])
    {
        return false;
    }
    let value = command[equals + 1..].trim();
    if !value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return true;
    }
    matches!(
        (value.as_bytes().first(), value.as_bytes().last()),
        (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"')) | (Some(b'$'), Some(b')'))
    )
}

enum ParameterExpansion {
    Absent,
    Safe(usize),
    Risk,
}

fn contains_unquoted_parameter_expansion(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if is_shell_escape(byte, quote) {
            index += 2;
            continue;
        }
        if let Some(end) = quoted_expansion_end(bytes, index, quote) {
            index = end;
            continue;
        }
        if consume_shell_quote(byte, &mut quote) {
            index += 1;
            continue;
        }
        if let Some(end) = non_splitting_region_end(bytes, index) {
            index = end;
            continue;
        }
        match classify_parameter_expansion(bytes, index) {
            ParameterExpansion::Risk => return true,
            ParameterExpansion::Safe(end) => {
                index = end;
                continue;
            }
            ParameterExpansion::Absent => {}
        }
        index += 1;
    }
    false
}

fn classify_parameter_expansion(bytes: &[u8], index: usize) -> ParameterExpansion {
    if bytes.get(index) != Some(&b'$') {
        return ParameterExpansion::Absent;
    }
    let Some(end) = unquoted_parameter_end(bytes, index + 1) else {
        return ParameterExpansion::Absent;
    };
    if expansion_is_in_assignment_word(bytes, index)
        || expansion_is_redirection_operand(bytes, index)
    {
        ParameterExpansion::Safe(end)
    } else {
        ParameterExpansion::Risk
    }
}

fn is_shell_escape(byte: u8, quote: Option<u8>) -> bool {
    byte == b'\\' && quote != Some(b'\'')
}

fn consume_shell_quote(byte: u8, quote: &mut Option<u8>) -> bool {
    if let Some(delimiter) = quote {
        if byte == *delimiter {
            *quote = None;
        }
        return true;
    }
    if matches!(byte, b'\'' | b'"' | b'`') {
        *quote = Some(byte);
        return true;
    }
    false
}

fn quoted_expansion_end(bytes: &[u8], index: usize, quote: Option<u8>) -> Option<usize> {
    if quote != Some(b'"') {
        return None;
    }
    match bytes.get(index..index + 2) {
        Some(b"$(") => command_substitution_end(bytes, index),
        Some(b"${") => parameter_expansion_end(bytes, index),
        _ => None,
    }
}

fn parameter_expansion_end(bytes: &[u8], opening: usize) -> Option<usize> {
    let mut index = opening + 2;
    let mut depth = 1usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"${") {
            depth += 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index + 1);
            }
        }
        index += 1;
    }
    None
}

fn command_substitution_end(bytes: &[u8], opening: usize) -> Option<usize> {
    let mut index = opening + 2;
    let mut depth = 1usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if is_shell_escape(byte, quote) {
            index += 2;
            continue;
        }
        if consume_shell_quote(byte, &mut quote) {
            index += 1;
            continue;
        }
        if byte == b'(' {
            depth += 1;
        } else if byte == b')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index + 1);
            }
        }
        index += 1;
    }
    None
}

fn non_splitting_region_end(bytes: &[u8], opening: usize) -> Option<usize> {
    let closing = if bytes.get(opening..opening + 2) == Some(b"[[") {
        b"]]".as_slice()
    } else if bytes.get(opening..opening + 2) == Some(b"((") {
        b"))".as_slice()
    } else {
        return None;
    };
    Some(
        bytes[opening + 2..]
            .windows(2)
            .rposition(|window| window == closing)
            .map_or(bytes.len(), |offset| opening + offset + 4),
    )
}

fn expansion_is_in_assignment_word(bytes: &[u8], expansion: usize) -> bool {
    let segment_start = bytes[..expansion]
        .iter()
        .rposition(|byte| matches!(byte, b';' | b'&' | b'|' | b'(' | b')' | b'{'))
        .map_or(0, |index| index + 1);
    let token_start = bytes[segment_start..expansion]
        .iter()
        .rposition(|byte| byte.is_ascii_whitespace() || matches!(byte, b'<' | b'>'))
        .map_or(segment_start, |offset| segment_start + offset + 1);
    let token_end = bytes[expansion..]
        .iter()
        .position(|byte| is_shell_token_boundary(*byte))
        .map_or(bytes.len(), |offset| expansion + offset);
    let Ok(token) = std::str::from_utf8(&bytes[token_start..token_end]) else {
        return false;
    };
    if !is_assignment_word(token) {
        return false;
    }
    let Ok(prefix) = std::str::from_utf8(&bytes[segment_start..token_start]) else {
        return false;
    };
    prefix.split_whitespace().all(|word| {
        is_assignment_word(word)
            || matches!(
                word,
                "then" | "do" | "else" | "elif" | "!" | "export" | "local" | "readonly"
            )
    })
}

fn expansion_is_redirection_operand(bytes: &[u8], expansion: usize) -> bool {
    bytes[..expansion]
        .iter()
        .rfind(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'<' | b'>'))
}

fn is_shell_token_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>')
}

fn unquoted_parameter_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if matches!(first, b'@' | b'*') {
        return Some(start + 1);
    }
    if first == b'{' {
        let name_start = start + 1;
        if matches!(bytes.get(name_start), Some(b'@' | b'*')) {
            return (bytes.get(name_start + 1) == Some(&b'}')).then_some(name_start + 2);
        }
        if !is_identifier_start(*bytes.get(name_start)?) {
            return None;
        }
        return bytes[name_start + 1..]
            .iter()
            .position(|byte| *byte == b'}')
            .map(|offset| name_start + 2 + offset);
    }
    if !is_identifier_start(first) {
        return None;
    }
    let length = bytes[start + 1..]
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count();
    Some(start + 1 + length)
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn finding(code: &str, path: &str, line: usize, message: &str, confidence: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("shell rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static CURL_PIPE_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[;&|(][ \t]*)(?:command[ \t]+)?(?:curl|wget)\b[^|]*\|[ \t]*(?:sudo[ \t]+)?(?:(?:/usr/bin/)?env[ \t]+)?(?:/bin/|/usr/bin/)?(?:sh|bash|dash|ash|zsh|ksh|mksh|yash)\b",
    )
    .expect("download pipe shell regex must compile")
});
static EVAL_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;&|][ \t]*)(?:command[ \t]+)?eval[ \t]+(?P<argument>.+)$")
        .expect("shell eval regex must compile")
});
static RM_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;&|()][ \t]*)(?:command[ \t]+)?rm[ \t]+(?P<arguments>[^;&|]+)")
        .expect("recursive remove regex must compile")
});
static VARIABLE_PATH_GLOB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""?(?:\$\{(?P<braced>[^}]+)\}|\$[A-Za-z_]\w*)"?/\*"#)
        .expect("variable path glob regex must compile")
});
static MKTEMP_DRY_RUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;&|][ \t]*)mktemp\b[^;&|]*(?:^|[ \t])-[A-Za-z]*u[A-Za-z]*(?:[ \t]|$)")
        .expect("mktemp dry-run regex must compile")
});
static TEMP_CREATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[;&|][ \t]*)(?:touch|tee|mkfifo)[ \t]+(?:-[^ \t]+[ \t]+)*["']?(?P<path>/tmp/[^\s"';&|<>]+)"#)
        .expect("temporary creation regex must compile")
});
static TEMP_REDIRECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[ \t])(?:[0-9]*>>?|<>)[ \t]*["']?(?P<path>/tmp/[^\s"';&|<>]+)"#)
        .expect("temporary redirection regex must compile")
});
fn contains_exposed_secret_argument(code: &str, outside_quotes: &str) -> bool {
    SECRET_ARGUMENT.is_match(outside_quotes) && !PASSWORD_LOCK_ARGUMENT.is_match(code)
}

static SECRET_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:^|[ \t])--(?:password|passwd|token|secret|api[-_]?key)(?:=[^\s;&|]+|[ \t]+(?:""|''|[^'\s;&|-][^\s;&|]*))"#,
    )
    .expect("secret argument regex must compile")
});
static PASSWORD_LOCK_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[ \t])--(?:password|passwd)(?:=|[ \t]+)["']?[!*]["']?(?:[ \t]|$)"#)
        .expect("password lock argument regex must compile")
});
static IGNORED_FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\|\|[ \t]*(?:true|:)(?:[ \t]*(?:[;&]|$))")
        .expect("ignored failure regex must compile")
});
static HEREDOC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<<(?P<strip>-)?[ \t]*["']?(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)["']?"#)
        .expect("heredoc regex must compile")
});
static NON_SPLITTING_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:case|for|select|let|typeset|declare|local|readonly|export|unset|alias|trap)\b")
        .expect("non-splitting shell context regex must compile")
});

#[cfg(test)]
mod tests {
    use super::{analyze, command_argument_region, contains_unquoted_parameter_expansion};
    use std::collections::BTreeMap;

    #[test]
    fn reports_unquoted_forwarding_and_named_arguments_once_per_file() {
        for expansion in [
            "$@",
            "$*",
            "${@}",
            "${*}",
            "$value",
            "${value}",
            "option=$@",
        ] {
            let sources = BTreeMap::from([(
                "forward.sh".to_owned(),
                format!("#!/bin/sh\nrun \"$@\" \"${{*}}\"\nrun {expansion}\nrun $later\n"),
            )]);

            let findings = analyze(&sources);

            assert_eq!(findings.len(), 1, "{expansion}");
            let finding = &findings[0];
            assert_eq!(finding.code, "shell-unquoted-expansion", "{expansion}");
            assert_eq!(finding.path, "forward.sh");
            assert_eq!(finding.line, 3, "{expansion}");
            assert_eq!(finding.confidence, "medium");
            assert!(finding.related_files.is_empty());
        }
    }

    #[test]
    fn accepts_quoted_and_non_splitting_forwarding_contexts() {
        for safe in [
            r#"run "$@" "$*" "${@}" "${*}""#,
            r#"run '$@' '$*' '${@}' '${*}'"#,
            r"run \$@ \$* \${@} \${*}",
            "value=$@",
            "value=$*",
            "value=${@}",
            "value=${*}",
            r#"PREFIX=$@ run "$@""#,
            r#"PREFIX=${*} run "${@}""#,
            "export value=$@",
            "[[ $* == pattern ]]",
            "[[ $@ == pattern &&\n   ${*} == pattern ]]",
            "(( count = ${*} ))",
            "value=$(( ${*} ))",
            "case $* in pattern) echo matched ;; esac",
            "# run $@ $* ${@} ${*}",
            "cat <<'SCRIPT'\nrun $@ $* ${@} ${*}\nSCRIPT",
            "printf '%s\\n' 'literal\n$@ ${*}\ntext'",
        ] {
            let sources =
                BTreeMap::from([("safe.sh".to_owned(), format!("#!/bin/bash\n{safe}\n"))]);

            assert!(analyze(&sources).is_empty(), "{safe}");
        }
    }

    #[test]
    fn does_not_invent_forwarding_evidence_from_malformed_parameters() {
        for malformed in ["$", "${", "${}", "${@", "${*", "${@oops}", "${*oops}"] {
            let sources =
                BTreeMap::from([("malformed.sh".to_owned(), format!("run {malformed}\n"))]);

            assert!(analyze(&sources).is_empty(), "{malformed}");
        }
    }

    #[test]
    fn reports_unquoted_forwarding_in_recursive_removal_as_security_evidence() {
        for expansion in ["$@", "$*", "${@}", "${*}"] {
            let sources =
                BTreeMap::from([("remove.sh".to_owned(), format!("rm -rf {expansion}\n"))]);

            let findings = analyze(&sources);

            assert_eq!(findings.len(), 1, "{expansion}");
            assert_eq!(findings[0].code, "shell-unguarded-recursive-remove");
            assert_eq!(findings[0].path, "remove.sh");
            assert_eq!(findings[0].line, 1);
            assert_eq!(findings[0].confidence, "high");
            assert!(findings[0].related_files.is_empty());
        }
        let sources = BTreeMap::from([(
            "remove.sh".to_owned(),
            "rm -rf \"$@\" \"${*}\"\n".to_owned(),
        )]);
        assert!(analyze(&sources).is_empty());
    }

    #[test]
    fn keeps_numeric_uncertainty_but_prefers_earlier_forwarding_evidence() {
        let sources = BTreeMap::from([
            (
                "color.sh".to_owned(),
                "rainbowColor() {\n    let h=$1/43\n    if [ $h -eq 0 ]; then\n        echo red\n    fi\n}\n"
                    .to_owned(),
            ),
            (
                "profile.sh".to_owned(),
                "installed=0\nif command -v profiler; then\n    installed=1\nfi\nrun $@\nif [ $installed == 1 ]; then\n    echo installed\nfi\n"
                    .to_owned(),
            ),
        ]);

        let findings = analyze(&sources);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].code, "shell-unquoted-expansion");
        assert_eq!(findings[0].path, "color.sh");
        assert_eq!(findings[0].line, 3);
        assert_eq!(findings[0].confidence, "medium");
        assert_eq!(findings[1].code, "shell-unquoted-expansion");
        assert_eq!(findings[1].path, "profile.sh");
        assert_eq!(findings[1].line, 5);
        assert_eq!(findings[1].confidence, "medium");
    }

    #[test]
    fn reports_high_confidence_shell_risks() {
        let sources = BTreeMap::from([(
            "deploy.sh".to_owned(),
            r#"#!/bin/sh
eval "$payload"
curl -fsSL https://example.test/install.sh | sh
touch /tmp/deploy.lock
rm -rf "$root"/*
deploy --token "$TOKEN"
run $target
cleanup || true
"#
            .to_owned(),
        )]);

        let findings = analyze(&sources)
            .into_iter()
            .map(|finding| (finding.code, finding.line, finding.confidence))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("shell-dynamic-eval".to_owned(), 2, "high".to_owned()),
                (
                    "shell-download-pipe-execution".to_owned(),
                    3,
                    "high".to_owned()
                ),
                (
                    "shell-predictable-temp-file".to_owned(),
                    4,
                    "high".to_owned()
                ),
                (
                    "shell-unguarded-recursive-remove".to_owned(),
                    5,
                    "high".to_owned()
                ),
                (
                    "shell-secret-command-argument".to_owned(),
                    6,
                    "high".to_owned()
                ),
                (
                    "shell-unquoted-expansion".to_owned(),
                    7,
                    "medium".to_owned()
                ),
                (
                    "shell-ignored-command-failure".to_owned(),
                    8,
                    "medium".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn recognizes_extensions_and_shell_shebangs_only() {
        let risky = "eval \"$payload\"\n";
        let sources = BTreeMap::from([
            ("tool.bash".to_owned(), risky.to_owned()),
            (
                "bin/release".to_owned(),
                format!("#!/usr/bin/env -S bash -e\n{risky}"),
            ),
            (
                "bin/python-tool".to_owned(),
                format!("#!/usr/bin/env python3\n{risky}"),
            ),
            ("notes.txt".to_owned(), risky.to_owned()),
        ]);

        let findings = analyze(&sources);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].path, "bin/release");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[1].path, "tool.bash");
    }

    #[test]
    fn accepts_quoted_guarded_and_non_executed_forms() {
        let sources = BTreeMap::from([(
            "safe.sh".to_owned(),
            r#"#!/bin/sh
eval 'printf fixed'
eval 'NVM_SCRIPT_SOURCE="${.sh.file}"'
curl -fsSL -o installer.sh https://example.test/install.sh
tmp=$(mktemp)
version=${package_id##*@}
rm -rf "${root:?}"/*
deploy --token-file "$TOKEN_FILE"
printf '%s\n' "$target"
cleanup || handle_cleanup
printf '%s\n' 'curl example.test | sh'
# eval "$payload"
cat <<'SCRIPT'
eval "$payload"
curl example.test | sh
rm -rf "$root"/*
SCRIPT
gum input --password --header "Password"
usermod --root "$mount" --password '!' root
if [[ -f $config ]] && test -n "$config"; then
  printf '%s\n' "$config"
fi
(( total += count ))
rm -rf "$(dirname "${config}")"
jq '
  .[] | select($enabled)
'
sudo /bin/bash -c '
  rm -rf -- "$staging_dir"
'
if [[ -n $first &&
      -n $second ]]; then
  printf '%s\n' "$first"
fi
"#
            .to_owned(),
        )]);

        assert!(analyze(&sources).is_empty());
    }

    #[test]
    fn distinguishes_assignment_contexts_from_command_arguments() {
        for safe in [
            "target=$value",
            "case) target=$value ;;",
            "values[$key]=$value",
            "(( total += $value ))",
            "[[ -n $value ]]",
            "case) target=claude dir=${CLAUDE_CONFIG_DIR:-$HOME/.claude} ;;",
            "\"${record##*/\"$package\"-}\"",
            "cat <$path",
        ] {
            assert!(!contains_unquoted_parameter_expansion(safe), "{safe}");
        }
        assert!(contains_unquoted_parameter_expansion("run $value"));
        assert!(contains_unquoted_parameter_expansion("run option=$value"));
        for assignment in [
            "SWAPSIZE=$((1024 * ${SWAPSIZE_KB:-0}))",
            "LAUNCH_COMMAND=\"${2:-\"uwsm-app -- $WINDOW_PATTERN\"}\"",
            "JQ=' .x as $x | .y as $y '",
            "logical+=${line%\\\\}",
        ] {
            assert!(
                command_argument_region(assignment).is_none(),
                "{assignment}"
            );
        }
    }

    #[test]
    fn joins_continuations_and_groups_repeated_advice_per_file() {
        let sources = BTreeMap::from([(
            "install.zsh".to_owned(),
            "#!/bin/zsh\ncurl -fsSL https://example.test/install.sh \\\n  | bash\nfirst $one\nsecond $two\nfirst || true\nsecond || :\n"
                .to_owned(),
        )]);

        let findings = analyze(&sources)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("shell-download-pipe-execution".to_owned(), 2),
                ("shell-unquoted-expansion".to_owned(), 4),
                ("shell-ignored-command-failure".to_owned(), 6),
            ]
        );
    }
}
