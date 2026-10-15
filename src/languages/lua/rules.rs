use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::languages::strip_quoted_literals as strip_literals;
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources
        .iter()
        .filter(|(path, source)| is_lua_source(path, source))
    {
        findings.extend(analyze_source(path, source));
    }
    findings
}

fn is_lua_source(path: &str, source: &str) -> bool {
    if path.ends_with(".lua") || path.ends_with(".luau") {
        return true;
    }
    let Some(shebang) = source
        .split('\n')
        .next()
        .and_then(|line| line.strip_prefix("#!"))
    else {
        return false;
    };
    let mut arguments = shebang.split_whitespace();
    let Some(interpreter) = arguments.next() else {
        return false;
    };
    let mut command = interpreter.rsplit('/').next().unwrap_or(interpreter);
    if command == "env" {
        let Some(argument) = arguments.next() else {
            return false;
        };
        command = if argument == "-S" {
            let Some(command) = arguments.next() else {
                return false;
            };
            command
        } else {
            argument
        };
    }
    LUA_INTERPRETER.is_match(command.rsplit('/').next().unwrap_or(command))
}

struct LuaScanState {
    block_depth: i32,
    hot_function_depth: Option<i32>,
    table_depth: i32,
    local_scopes: Vec<BTreeSet<String>>,
    pending_block_terminator: Option<&'static str>,
}

struct LuaLine<'a> {
    path: &'a str,
    code_lines: &'a [String],
    code_refs: &'a [&'a str],
    index: usize,
    line: &'a str,
    in_hot_function: bool,
}

impl LuaLine<'_> {
    fn add(&self, findings: &mut Vec<Finding>, code: &str, message: &str) {
        findings.push(finding(code, self.path, self.index + 1, message));
    }
}

fn analyze_source(path: &str, source: &str) -> Vec<Finding> {
    let raw_lines = source.split('\n').collect::<Vec<_>>();
    let code_lines = code_outside_long_brackets_and_comments(&raw_lines);
    let code_refs = code_lines.iter().map(String::as_str).collect::<Vec<_>>();
    let mut findings = Vec::new();
    let mut state = LuaScanState {
        block_depth: 0,
        hot_function_depth: None,
        table_depth: 0,
        local_scopes: vec![BTreeSet::new()],
        pending_block_terminator: None,
    };

    for (index, code) in code_lines.iter().enumerate() {
        let line = code.trim();
        let starts_hot_function = declares_hot_function(line);
        let context = LuaLine {
            path,
            code_lines: &code_lines,
            code_refs: &code_refs,
            index,
            line,
            in_hot_function: state.hot_function_depth.is_some() || starts_hot_function,
        };
        analyze_lua_assignment(&context, &state, &mut findings);
        register_local_function(line, &mut state);
        analyze_lua_execution(&context, &state, &mut findings);
        analyze_lua_hot_path(&context, &mut findings);
        if mutates_iterated_table(context.code_refs, index, line) {
            context.add(
                &mut findings,
                "lua-mutate-pairs",
                "table may be mutated while iterating",
            );
        }
        register_local_declaration(line, &mut state);
        update_lua_scopes(line, &mut state);
        update_lua_depths(line, starts_hot_function, &mut state);
    }
    findings
}

fn analyze_lua_assignment(
    context: &LuaLine<'_>,
    state: &LuaScanState,
    findings: &mut Vec<Finding>,
) {
    let assignment = leading_assignment(context.line);
    let assigns_local =
        assignment.is_some_and(|name| state.local_scopes.iter().any(|scope| scope.contains(name)));
    if state.table_depth == 0
        && !context.line.starts_with("local ")
        && !context.line.starts_with("function ")
        && assignment.is_some()
        && !assigns_local
    {
        context.add(
            findings,
            "lua-global-assignment",
            "possible global assignment",
        );
    }
}

fn analyze_lua_execution(context: &LuaLine<'_>, state: &LuaScanState, findings: &mut Vec<Finding>) {
    if uses_global_dynamic_load(
        context.code_refs,
        context.index,
        context.line,
        &state.local_scopes,
    ) {
        context.add(
            findings,
            "lua-loadstring",
            "dynamic Lua code execution used",
        );
    }
    if context.line.contains("os.execute(") || context.line.contains("io.popen(") {
        context.add(findings, "lua-os-execute", "shell command execution used");
    }
    if context.line.starts_with("pcall(")
        && context
            .code_lines
            .get(context.index + 1)
            .map(|next| next.trim())
            .is_none_or(|next| matches!(next, "" | "end" | "return"))
    {
        context.add(
            findings,
            "lua-pcall-swallow",
            "pcall result appears ignored",
        );
    }
}

fn analyze_lua_hot_path(context: &LuaLine<'_>, findings: &mut Vec<Finding>) {
    if context.in_hot_function
        && (context.line.contains("print(") || context.line.contains("warn("))
    {
        context.add(
            findings,
            "lua-print-in-loop",
            "logging inside update/draw-like function",
        );
    }
    if context.in_hot_function
        && !context.line.starts_with("type ")
        && (context.line.contains(" = {") || context.line.starts_with("return {"))
    {
        context.add(
            findings,
            "lua-table-alloc-in-loop",
            "table allocation inside update/draw-like function",
        );
    }
}

fn register_local_function(line: &str, state: &mut LuaScanState) {
    if let Some(capture) = LOCAL_FUNCTION_DECLARATION.captures(line)
        && let Some(scope) = current_lua_scope(state)
    {
        scope.insert(capture[1].to_owned());
    }
}

fn register_local_declaration(line: &str, state: &mut LuaScanState) {
    if let Some(capture) = LOCAL_DECLARATION.captures(line)
        && let Some(scope) = current_lua_scope(state)
    {
        scope.extend(capture[1].split(',').map(str::trim).map(str::to_owned));
    }
}

fn current_lua_scope(state: &mut LuaScanState) -> Option<&mut BTreeSet<String>> {
    state.local_scopes.last_mut()
}

fn update_lua_scopes(line: &str, state: &mut LuaScanState) {
    let completes_pending = state
        .pending_block_terminator
        .is_some_and(|terminator| contains_word(line, terminator));
    if completes_pending {
        state.pending_block_terminator = None;
    }
    open_lua_scope(line, completes_pending, state);
    close_lua_scopes(line, state);
}

fn open_lua_scope(line: &str, completes_pending: bool, state: &mut LuaScanState) {
    let function_declaration = FUNCTION_DECLARATION.captures(line);
    let block_declaration = BLOCK_DECLARATION.captures(line);
    let opens_standalone_do = line == "do" && !completes_pending;
    if function_declaration.is_some() || block_declaration.is_some() || opens_standalone_do {
        let mut scope = BTreeSet::new();
        if let Some(declaration) = function_declaration.as_ref() {
            scope.extend(
                declaration[1]
                    .split(',')
                    .map(str::trim)
                    .filter(|name| WORD.is_match(name))
                    .map(str::to_owned),
            );
        }
        if let Some(loop_declaration) = LOOP_DECLARATION.captures(line) {
            scope.extend(
                loop_declaration[1]
                    .split(',')
                    .map(str::trim)
                    .map(str::to_owned),
            );
        }
        state.local_scopes.push(scope);
    }
    if let Some(declaration) = block_declaration {
        let terminator = match &declaration[1] {
            "if" => Some("then"),
            "for" | "while" => Some("do"),
            _ => None,
        };
        if let Some(terminator) = terminator
            && !contains_word(line, terminator)
        {
            state.pending_block_terminator = Some(terminator);
        }
    }
}

fn close_lua_scopes(line: &str, state: &mut LuaScanState) {
    let closing_scopes = END_WORD.find_iter(line).count()
        + usize::from(line.starts_with("until") && word_boundary_after(line, 5));
    for _ in 0..closing_scopes {
        if state.local_scopes.len() > 1 {
            state.local_scopes.pop();
        }
    }
}

fn update_lua_depths(line: &str, starts_hot_function: bool, state: &mut LuaScanState) {
    state.table_depth += line.matches('{').count() as i32;
    state.table_depth -= line.matches('}').count() as i32;
    state.table_depth = state.table_depth.max(0);
    let depth_before_line = state.block_depth;
    state.block_depth += block_depth_delta(line);
    if starts_hot_function {
        state.hot_function_depth = Some(depth_before_line + 1);
    }
    if state
        .hot_function_depth
        .is_some_and(|depth| state.block_depth < depth)
    {
        state.hot_function_depth = None;
    }
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Lua rule metadata must exist");
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

fn leading_assignment(line: &str) -> Option<&str> {
    let capture = LEADING_ASSIGNMENT.captures(line)?;
    let whole = capture.get(0)?;
    let assignment = capture.get(1)?;
    (line.as_bytes().get(whole.end()) != Some(&b'=')).then(|| assignment.as_str())
}

fn uses_global_dynamic_load(
    lines: &[&str],
    line_index: usize,
    line: &str,
    local_scopes: &[BTreeSet<String>],
) -> bool {
    DYNAMIC_LOAD.find_iter(line).any(|matched| {
        is_global_dynamic_load_reference(line, &matched, local_scopes)
            && dynamic_load_candidate_is_called(lines, line_index, &line[matched.end()..])
    })
}

fn is_global_dynamic_load_reference(
    line: &str,
    matched: &regex::Match<'_>,
    local_scopes: &[BTreeSet<String>],
) -> bool {
    let name = matched.as_str();
    if local_scopes.iter().any(|scope| scope.contains(name)) {
        return false;
    }

    let prefix = line[..matched.start()].trim_end();
    !is_function_declaration_prefix(prefix) && !prefix.ends_with(['.', ':'])
}

fn is_function_declaration_prefix(prefix: &str) -> bool {
    let Some(before) = prefix.strip_suffix("function") else {
        return false;
    };
    before.is_empty() || !is_word_byte(before.as_bytes().last().copied())
}

fn dynamic_load_candidate_is_called(
    lines: &[&str],
    line_index: usize,
    current_suffix: &str,
) -> bool {
    let suffix = current_suffix.trim_start();
    if !suffix.is_empty() {
        return suffix.starts_with('(');
    }

    for line in &lines[line_index + 1..] {
        let candidate = strip_literals(line);
        let suffix = candidate.split("--").next().unwrap_or("").trim_start();
        if !suffix.is_empty() {
            return suffix.starts_with('(');
        }
    }
    false
}

fn mutates_iterated_table(lines: &[&str], line_index: usize, line: &str) -> bool {
    let Some(iterated) = iteration_target(line) else {
        return false;
    };
    let aliases = qualified_iteration_aliases(lines, line_index, iterated);

    contains_mutation_candidate(lines, line_index, &aliases)
}

fn iteration_target(line: &str) -> Option<&str> {
    let capture = PAIRS_LOOP.captures(line)?;
    let iterated = capture.get(1)?.as_str().trim();
    TABLE_EXPRESSION.is_match(iterated).then_some(iterated)
}

fn qualified_iteration_aliases(
    lines: &[&str],
    line_index: usize,
    iterated: &str,
) -> BTreeSet<String> {
    let scope_start = iteration_scope_start(lines, line_index);
    let local_aliases = collect_local_aliases(&lines[scope_start..line_index]);
    let mut aliases = BTreeSet::from([iterated.to_owned()]);

    loop {
        let previous_count = aliases.len();
        for (name, value) in &local_aliases {
            if aliases.contains(name) || aliases.contains(value) {
                aliases.insert(name.clone());
                aliases.insert(value.clone());
            }
        }
        if aliases.len() == previous_count {
            return aliases;
        }
    }
}

fn iteration_scope_start(lines: &[&str], line_index: usize) -> usize {
    for index in (0..line_index).rev() {
        if FUNCTION_START.is_match(lua_candidate(lines[index]).trim()) {
            return index + 1;
        }
    }
    0
}

fn collect_local_aliases(lines: &[&str]) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for line in lines {
        let candidate = lua_candidate(line);
        let Some(assignment) = ALIAS_ASSIGNMENT.captures(candidate.trim()) else {
            continue;
        };
        let name = assignment[2].to_owned();
        if assignment.get(1).is_some() {
            aliases.insert(name, assignment[3].to_owned());
        } else {
            aliases.remove(&name);
        }
    }
    aliases
}

fn contains_mutation_candidate(
    lines: &[&str],
    line_index: usize,
    aliases: &BTreeSet<String>,
) -> bool {
    let mut depth = 1_i32;
    for line in &lines[line_index + 1..] {
        let candidate = lua_candidate(line);
        let candidate = candidate.trim();
        if aliases.iter().any(|alias| mutates_table(candidate, alias)) {
            return true;
        }
        depth += block_depth_delta(candidate);
        if depth <= 0 {
            break;
        }
    }
    false
}

fn lua_candidate(line: &str) -> String {
    let mut candidate = strip_literals(line);
    if let Some(comment_start) = candidate.find("--") {
        candidate.truncate(comment_start);
    }
    candidate
}

fn mutates_table(line: &str, table: &str) -> bool {
    let escaped = regex::escape(table);
    let Ok(indexed_assignment) =
        Regex::new(&format!(r"(?:^|[^A-Za-z0-9_.]){escaped}\s*\[[^\]]+\]\s*="))
    else {
        return false;
    };
    let Ok(structural_call) = Regex::new(&format!(
        r"table\.(?:insert|remove|sort)\s*\(\s*{escaped}(?:\s*[,\)])"
    )) else {
        return false;
    };
    let Ok(move_destination) = Regex::new(&format!(
        r"table\.move\s*\([^,]+,[^,]+,[^,]+,[^,]+,\s*{escaped}(?:\s*[,\)])"
    )) else {
        return false;
    };
    indexed_assignment
        .find(line)
        .is_some_and(|matched| line.as_bytes().get(matched.end()) != Some(&b'='))
        || structural_call.is_match(line)
        || move_destination.is_match(line)
}

fn declares_hot_function(line: &str) -> bool {
    let qualified = HOT_FUNCTION_DECLARATION
        .captures(line)
        .or_else(|| HOT_FUNCTION_ASSIGNMENT.captures(line));
    let Some(qualified) = qualified else {
        return false;
    };
    qualified[1]
        .split(['.', ':'])
        .next_back()
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("update") || name.eq_ignore_ascii_case("draw")
        })
}

fn block_depth_delta(line: &str) -> i32 {
    let mut delta = i32::from(FUNCTION_WORD.is_match(line));
    if BLOCK_OPEN.is_match(line) {
        delta += 1;
    }
    delta -= END_WORD.find_iter(line).count() as i32;
    if line.starts_with("until") && word_boundary_after(line, 5) {
        delta -= 1;
    }
    delta
}

fn code_outside_long_brackets_and_comments(lines: &[&str]) -> Vec<String> {
    let mut result = Vec::with_capacity(lines.len());
    let mut long_bracket_end = None;
    for line in lines {
        let scanned = without_long_brackets_and_comments(&strip_literals(line), long_bracket_end);
        result.push(scanned.0);
        long_bracket_end = scanned.1;
    }
    result
}

fn without_long_brackets_and_comments(
    line: &str,
    mut long_bracket_end: Option<String>,
) -> (String, Option<String>) {
    let mut code = String::new();
    let mut offset = 0;
    if let Some(closing) = long_bracket_end.as_ref() {
        let Some(close) = line.find(closing) else {
            return (code, long_bracket_end);
        };
        offset = close + closing.len();
        long_bracket_end = None;
    }
    while offset < line.len() {
        let remainder = &line[offset..];
        let comment = remainder.find("--").map(|found| offset + found);
        let opening = LONG_BRACKET_OPENING.captures(remainder);
        let opening_offset = opening
            .as_ref()
            .and_then(|capture| capture.get(0))
            .map(|matched| offset + matched.start());
        if let Some(comment) = comment
            && opening_offset.is_none_or(|opening| comment < opening)
        {
            code.push_str(&line[offset..comment]);
            let comment_source = &line[comment..];
            let Some(comment_opening) = LONG_COMMENT_OPENING.captures(comment_source) else {
                break;
            };
            let Some(comment_match) = comment_opening.get(0) else {
                break;
            };
            let closing = format!("]{}]", &comment_opening[1]);
            let search_start = comment + comment_match.end();
            let Some(relative_close) = line[search_start..].find(&closing) else {
                return (code, Some(closing));
            };
            offset = search_start + relative_close + closing.len();
            continue;
        }
        let Some(opening) = opening else {
            code.push_str(&line[offset..]);
            break;
        };
        let Some(matched) = opening.get(0) else {
            code.push_str(&line[offset..]);
            break;
        };
        let opening_offset = offset + matched.start();
        code.push_str(&line[offset..opening_offset]);
        let closing = format!("]{}]", &opening[1]);
        let search_start = offset + matched.end();
        let Some(relative_close) = line[search_start..].find(&closing) else {
            return (code, Some(closing));
        };
        offset = search_start + relative_close + closing.len();
    }
    (code, long_bracket_end)
}

fn contains_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(offset, _)| {
        !is_word_byte(
            offset
                .checked_sub(1)
                .and_then(|index| line.as_bytes().get(index).copied()),
        ) && !is_word_byte(line.as_bytes().get(offset + word.len()).copied())
    })
}

fn is_word_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn word_boundary_after(line: &str, offset: usize) -> bool {
    !is_word_byte(line.as_bytes().get(offset).copied())
}

static LEADING_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_]\w*)\s*=").unwrap());
static LOCAL_FUNCTION_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\blocal\s+function\s+([A-Za-z_]\w*)\s*\(").unwrap());
static DYNAMIC_LOAD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bload(?:string)?\b").unwrap());
static LOCAL_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^local\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)(?:\s*=|\s*$)").unwrap()
});
static FUNCTION_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfunction\s*(?:[A-Za-z_][\w.:]*)?\s*\(([^)]*)\)").unwrap());
static BLOCK_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(if|for|while|repeat)\b").unwrap());
static LOOP_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^for\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+(?:in\b|=)").unwrap()
});
static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\w+$").unwrap());
static END_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bend\b").unwrap());
static PAIRS_LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^for\b.*\bin\s+(?:i?pairs)\s*\((.+)\)\s*do\s*$").unwrap());
static TABLE_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$").unwrap());
static FUNCTION_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:local\s+)?function\b").unwrap());
static ALIAS_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(local\s+)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$").unwrap()
});
static HOT_FUNCTION_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfunction\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*\(").unwrap());
static HOT_FUNCTION_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*=\s*function\s*\(").unwrap()
});
static FUNCTION_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfunction\b").unwrap());
static BLOCK_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:if\b.*\bthen|for\b.*\bdo|while\b.*\bdo|repeat\b|do\b)").unwrap()
});
static LONG_BRACKET_OPENING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[(=*)\[").unwrap());
static LONG_COMMENT_OPENING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^--\[(=*)\[").unwrap());
static LUA_INTERPRETER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:lua(?:5\.[1-4])?|luajit(?:2\.\d+)?|resty)$").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::analyze;

    #[test]
    fn reports_all_lua_rule_codes_with_original_locations() {
        let sources = BTreeMap::from([(
            "main.lua".to_owned(),
            "value = 1\n\
function update()\n\
  print(\"frame\")\n\
  local state = {}\n\
end\n\
os.execute(\"echo unsafe\")\n\
loadstring(\"return 1\")\n\
pcall(work)\n\
return\n\
local values = {}\n\
for key in pairs(values) do\n\
  values[key] = nil\n\
end\n"
                .to_owned(),
        )]);

        let findings = analyze(&sources);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line, finding.end_line))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("lua-global-assignment", 1, 1),
                ("lua-print-in-loop", 3, 3),
                ("lua-table-alloc-in-loop", 4, 4),
                ("lua-os-execute", 6, 6),
                ("lua-loadstring", 7, 7),
                ("lua-pcall-swallow", 8, 8),
                ("lua-mutate-pairs", 11, 11),
            ])
        );
    }

    #[test]
    fn respects_lua_lexical_scope_and_hot_callback_boundaries() {
        let sources = BTreeMap::from([(
            "safe.luau".to_owned(),
            "configure {\n\
  enabled = true,\n\
}\n\
local function load(source)\n\
  return source\n\
end\n\
load(source)\n\
Loader.load(source)\n\
local function run(value)\n\
  value = tostring(value)\n\
  pcall(work)\n\
  use(value)\n\
end\n\
function drawing()\n\
  print(\"not hot\")\n\
  local state = {}\n\
end\n\
function update()\n\
  type State = { ready: boolean }\n\
  local runtime = {}\n\
end\n"
                .to_owned(),
        )]);

        let findings = analyze(&sources)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(findings, vec![("lua-table-alloc-in-loop".to_owned(), 20)]);
    }

    #[test]
    fn analyzes_recognized_extensionless_lua_shebangs_only() {
        let sources = BTreeMap::from([
            (
                "bin/lua-tool".to_owned(),
                "#!/usr/bin/env -S lua5.4 -E\nundeclared = 1".to_owned(),
            ),
            (
                "bin/shell-tool".to_owned(),
                "#!/bin/sh\nundeclared = 1".to_owned(),
            ),
        ]);

        let findings = analyze(&sources)
            .into_iter()
            .map(|finding| (finding.code, finding.path, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![(
                "lua-global-assignment".to_owned(),
                "bin/lua-tool".to_owned(),
                2,
            )]
        );
    }

    #[test]
    fn malformed_lua_preserves_root_scope_and_does_not_abort_analysis() {
        let sources = BTreeMap::from([(
            "malformed.lua".to_owned(),
            "end\n\
end\n\
local load = safe\n\
load(source)\n\
undeclared = 1\n\
local unfinished = [=[\n\
loadstring(\"not code\")\n"
                .to_owned(),
        )]);

        let findings = analyze(&sources)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(findings, vec![("lua-global-assignment".to_owned(), 5)]);
    }
}
