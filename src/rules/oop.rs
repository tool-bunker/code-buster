use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;

#[derive(Clone)]
struct OopMethod {
    name: String,
    parameters: Vec<Parameter>,
    body: String,
    is_public: bool,
    is_static: bool,
    is_override: bool,
}

struct MethodCandidate<'a> {
    start: usize,
    end: usize,
    modifiers: &'a str,
    name: &'a str,
    parameter_source: &'a str,
    terminator: &'a str,
    arrow: bool,
}

struct QualifiedMethodCandidate<'a> {
    candidate: MethodCandidate<'a>,
    parameters: Vec<Parameter>,
}

#[derive(Clone)]
struct Parameter {
    type_name: String,
    name: String,
}
struct ParameterGroup {
    names: Vec<String>,
    declarations: Vec<(String, usize)>,
}

#[derive(Clone)]
struct OopClass {
    path: String,
    line: usize,
    name: String,
    is_interface: bool,
    parent: Option<String>,
    interfaces: Vec<String>,
    methods: Vec<OopMethod>,
    fields: BTreeSet<String>,
}

struct Project {
    classes: Vec<OopClass>,
    sources: BTreeMap<String, String>,
}
pub struct OopAnalysisOutput {
    pub findings: Vec<Finding>,
    pub durations_milliseconds: BTreeMap<String, u128>,
}

#[cfg(test)]
pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    analyze_profiled(sources).findings
}

pub fn analyze_profiled(sources: &BTreeMap<String, String>) -> OopAnalysisOutput {
    let partitions: [&[&str]; 3] = [&[".cs"], &[".java"], &[".ts", ".tsx"]];
    let mut findings = Vec::new();
    let mut durations = BTreeMap::new();
    for extensions in partitions {
        let selected = sources
            .iter()
            .filter(|(path, _)| extensions.iter().any(|extension| path.ends_with(extension)));
        if selected.clone().next().is_none() {
            continue;
        }
        let started = Instant::now();
        let project = parse_project(selected);
        record_oop_duration(&mut durations, "oop.parse", started);
        findings.extend(analyze_project(&project, &mut durations));
    }
    OopAnalysisOutput {
        findings,
        durations_milliseconds: durations,
    }
}

fn analyze_project(project: &Project, durations: &mut BTreeMap<String, u128>) -> Vec<Finding> {
    let mut findings = Vec::new();
    macro_rules! run {
        ($name:literal, $analysis:expr) => {{
            let started = Instant::now();
            findings.extend($analysis);
            record_oop_duration(durations, $name, started);
        }};
    }
    run!("oop.data-clumps", data_clumps(project));
    run!("oop.interface-pressure", interface_pressure(project));
    run!("oop.refused-bequests", refused_bequests(project));
    run!(
        "oop.single-use-abstractions",
        single_use_abstractions(project)
    );
    run!("oop.middle-men", middle_men(project));
    run!("oop.strategy-dispatch", strategy_dispatch(project));
    run!("oop.state-behavior", state_behavior(project));
    run!("oop.feature-envy", feature_envy(project));
    run!("oop.service-locators", service_locators(project));
    run!(
        "oop.observer-notifications",
        observer_notifications(project)
    );
    run!("oop.message-chains", message_chains(project));
    run!("oop.boundary-bypasses", boundary_bypasses(project));
    run!(
        "oop.repeated-adapter-mappings",
        repeated_adapter_mappings(project)
    );
    run!("oop.template-workflows", template_workflows(project));
    findings
}

fn record_oop_duration(durations: &mut BTreeMap<String, u128>, name: &str, started: Instant) {
    *durations.entry(name.to_owned()).or_default() += started.elapsed().as_millis();
}

fn parse_project<'a>(sources: impl Iterator<Item = (&'a String, &'a String)>) -> Project {
    let mut classes = Vec::new();
    let mut masked_sources = BTreeMap::new();
    for (path, source) in sources {
        let code = mask_non_code(source, is_typescript(path));
        masked_sources.insert(path.clone(), code.clone());
        let matching = matching_braces(&code);
        for declaration in CLASS_DECLARATION.captures_iter(&code) {
            let whole = declaration.get(0).unwrap();
            let open = whole.end() - 1;
            let Some(close) = matching.get(&open).copied() else {
                continue;
            };
            let kind = &declaration[1];
            let name = declaration[2].to_owned();
            let base_source = [declaration.get(3), declaration.get(4), declaration.get(5)]
                .into_iter()
                .flatten()
                .map(|matched| matched.as_str())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            let bases = base_types(&base_source);
            let body = &code[open + 1..close];
            classes.push(OopClass {
                path: path.clone(),
                line: code[..whole.start()]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1,
                name,
                is_interface: kind == "interface",
                parent: None,
                interfaces: if kind == "class" { bases } else { Vec::new() },
                methods: methods(body, path),
                fields: fields(body, path),
            });
        }
    }
    let interface_names = classes
        .iter()
        .filter(|class| class.is_interface)
        .map(|class| class.name.clone())
        .collect::<BTreeSet<_>>();
    for class in &mut classes {
        if class.is_interface {
            continue;
        }
        class.parent = class
            .interfaces
            .iter()
            .find(|base| !interface_names.contains(*base))
            .cloned();
        class
            .interfaces
            .retain(|base| interface_names.contains(base));
    }
    Project {
        classes,
        sources: masked_sources,
    }
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("OOP rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

pub(crate) fn single_use_abstraction_finding(
    code: &str,
    contract_name: &str,
    implementation_name: &str,
    contract_path: &str,
    contract_line: usize,
    implementation_path: &str,
) -> Finding {
    finding(
        code,
        contract_path,
        contract_line,
        format!(
            "{contract_name} is a speculative extension point: one stateless implementation, {implementation_name}, constructed once for one small operation"
        ),
        "medium",
        if implementation_path == contract_path {
            Vec::new()
        } else {
            vec![implementation_path.to_owned()]
        },
    )
}

fn methods(body: &str, path: &str) -> Vec<OopMethod> {
    let depths = brace_depths(body);
    let typescript = is_typescript(path);
    let mut methods = Vec::new();
    if typescript {
        collect_method_declarations(
            body,
            &depths,
            true,
            &TS_METHOD_DECLARATION,
            false,
            &mut methods,
        );
        collect_method_declarations(
            body,
            &depths,
            true,
            &TS_ARROW_METHOD_DECLARATION,
            true,
            &mut methods,
        );
    } else {
        collect_method_declarations(
            body,
            &depths,
            false,
            &METHOD_DECLARATION,
            false,
            &mut methods,
        );
    }
    methods
}

fn collect_method_declarations(
    body: &str,
    depths: &[i32],
    typescript: bool,
    pattern: &Regex,
    arrow: bool,
    methods: &mut Vec<OopMethod>,
) {
    for declaration in pattern.captures_iter(body) {
        let Some(candidate) = extract_method_candidate(&declaration, arrow) else {
            continue;
        };
        let Some(candidate) = qualify_method_candidate(candidate, depths, typescript) else {
            continue;
        };
        if let Some(method) = method_from_candidate(body, candidate, typescript) {
            methods.push(method);
        }
    }
}

fn extract_method_candidate<'a>(
    declaration: &regex::Captures<'a>,
    arrow: bool,
) -> Option<MethodCandidate<'a>> {
    let whole = declaration.get(0)?;
    Some(MethodCandidate {
        start: whole.start(),
        end: whole.end(),
        modifiers: declaration.get(1).map_or("", |matched| matched.as_str()),
        name: declaration.get(2)?.as_str(),
        parameter_source: declaration.get(3)?.as_str(),
        terminator: declaration.get(4)?.as_str(),
        arrow,
    })
}

fn qualify_method_candidate<'a>(
    candidate: MethodCandidate<'a>,
    depths: &[i32],
    typescript: bool,
) -> Option<QualifiedMethodCandidate<'a>> {
    if depths.get(candidate.start) != Some(&0) {
        return None;
    }
    Some(QualifiedMethodCandidate {
        parameters: parameters(candidate.parameter_source, typescript)?,
        candidate,
    })
}

fn method_from_candidate(
    body: &str,
    qualified: QualifiedMethodCandidate<'_>,
    typescript: bool,
) -> Option<OopMethod> {
    let QualifiedMethodCandidate {
        candidate,
        parameters,
    } = qualified;
    let method_body = candidate_method_body(body, &candidate)?;
    let previous_line = body
        .get(..candidate.start)?
        .split('\n')
        .next_back()
        .unwrap_or("");
    Some(OopMethod {
        name: candidate.name.to_owned(),
        parameters,
        body: method_body,
        is_public: if typescript {
            !PRIVATE_OR_PROTECTED.is_match(candidate.modifiers)
        } else {
            contains_word(candidate.modifiers, "public")
        },
        is_static: contains_word(candidate.modifiers, "static"),
        is_override: contains_word(candidate.modifiers, "override")
            || previous_line.trim_end().ends_with("@Override"),
    })
}

fn candidate_method_body(body: &str, candidate: &MethodCandidate<'_>) -> Option<String> {
    if candidate.arrow {
        let next = next_non_whitespace(body, candidate.end);
        return if body.as_bytes().get(next) == Some(&b'{') {
            block_method_body(body, next)
        } else {
            expression_method_body(body, candidate.end)
        };
    }
    match candidate.terminator {
        "=>" => expression_method_body(body, candidate.end),
        "{" => block_method_body(body, candidate.end.checked_sub(1)?),
        _ => Some(String::new()),
    }
}

fn expression_method_body(body: &str, start: usize) -> Option<String> {
    let expression = body.get(start..)?;
    let relative_end = expression.find(';')?;
    Some(expression[..relative_end].trim().to_owned())
}

fn block_method_body(body: &str, open: usize) -> Option<String> {
    let close = matching_brace(body, open)?;
    Some(body.get(open + 1..close)?.trim().to_owned())
}

fn fields(body: &str, path: &str) -> BTreeSet<String> {
    let depths = brace_depths(body);
    let typescript = is_typescript(path);
    let pattern = if typescript {
        &*TS_FIELD_DECLARATION
    } else {
        &*FIELD_DECLARATION
    };
    let mut fields = pattern
        .captures_iter(body)
        .filter_map(|capture| {
            let whole = capture.get(0)?;
            let name = capture.get(1)?;
            (depths.get(whole.start()) == Some(&0)).then(|| name.as_str().to_owned())
        })
        .collect::<BTreeSet<_>>();
    if typescript {
        for constructor in TS_CONSTRUCTOR.captures_iter(body) {
            fields.extend(
                TS_PARAMETER_FIELD
                    .captures_iter(&constructor[1])
                    .map(|capture| capture[1].to_owned()),
            );
        }
    }
    fields
}

fn parameters(source: &str, typescript: bool) -> Option<Vec<Parameter>> {
    let source = source.trim().trim_end_matches(',');
    if source.is_empty() {
        return Some(Vec::new());
    }
    let mut result = Vec::new();
    for raw in source.split(',') {
        let parameter = raw.split('=').next().unwrap_or("").trim();
        if (typescript && (parameter.starts_with('[') || parameter.starts_with('{')))
            || (!typescript && (parameter.contains('[') || parameter.contains(']')))
        {
            return None;
        }
        let capture = if typescript {
            TS_PARAMETER.captures(parameter)
        } else {
            TYPED_PARAMETER.captures(parameter)
        }?;
        result.push(if typescript {
            Parameter {
                type_name: WHITESPACE.replace_all(&capture[2], "").into_owned(),
                name: capture[1].to_owned(),
            }
        } else {
            Parameter {
                type_name: capture[1].to_owned(),
                name: capture[2].to_owned(),
            }
        });
    }
    Some(result)
}

fn base_types(source: &str) -> Vec<String> {
    source
        .split(',')
        .map(str::trim)
        .map(|value| GENERIC_SUFFIX.replace(value, "").into_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn brace_depths(source: &str) -> Vec<i32> {
    let mut result = vec![0; source.len() + 1];
    let mut depth = 0;
    for (index, byte) in source.bytes().enumerate() {
        result[index] = depth;
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
        }
    }
    result[source.len()] = depth;
    result
}

fn matching_braces(source: &str) -> BTreeMap<usize, usize> {
    let mut opens = Vec::new();
    let mut result = BTreeMap::new();
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'{' {
            opens.push(index);
        } else if byte == b'}'
            && let Some(open) = opens.pop()
        {
            result.insert(open, index);
        }
    }
    result
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0;
    for (index, byte) in source.bytes().enumerate().skip(open) {
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn next_non_whitespace(source: &str, start: usize) -> usize {
    source[start..]
        .char_indices()
        .find(|(_, character)| !character.is_whitespace())
        .map_or(source.len(), |(offset, _)| start + offset)
}

#[derive(Default)]
struct OopMaskState {
    quote: Option<char>,
    raw_quote_count: usize,
    escaped: bool,
    line_comment: bool,
    block_comment: bool,
}

fn mask_non_code(source: &str, typescript: bool) -> String {
    let characters = source.chars().collect::<Vec<_>>();
    let mut result = characters.clone();
    let mut state = OopMaskState::default();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        if state.line_comment {
            mask_oop_line_comment(character, &mut result, index, &mut state);
        } else if state.block_comment {
            index = mask_oop_block_comment(character, next, &mut result, index, &mut state);
        } else if state.raw_quote_count > 0 {
            index = mask_oop_raw_string(&characters, &mut result, index, &mut state);
        } else if let Some(delimiter) = state.quote {
            index =
                mask_oop_quoted_string(character, next, delimiter, &mut result, index, &mut state);
        } else {
            index = start_oop_non_code(
                &characters,
                &mut result,
                index,
                character,
                next,
                typescript,
                &mut state,
            );
        }
        index += 1;
    }
    result.into_iter().collect()
}

fn mask_oop_line_comment(
    character: char,
    result: &mut [char],
    index: usize,
    state: &mut OopMaskState,
) {
    if character == '\n' {
        state.line_comment = false;
    } else {
        result[index] = ' ';
    }
}

fn mask_oop_block_comment(
    character: char,
    next: Option<char>,
    result: &mut [char],
    mut index: usize,
    state: &mut OopMaskState,
) -> usize {
    if character == '*' && next == Some('/') {
        result[index] = ' ';
        result[index + 1] = ' ';
        index += 1;
        state.block_comment = false;
    } else if character != '\n' && character != '\r' {
        result[index] = ' ';
    }
    index
}

fn mask_oop_raw_string(
    characters: &[char],
    result: &mut [char],
    mut index: usize,
    state: &mut OopMaskState,
) -> usize {
    if characters[index] != '\n' && characters[index] != '\r' {
        result[index] = ' ';
    }
    let count = characters[index..]
        .iter()
        .take_while(|character| **character == '"')
        .count();
    if count >= state.raw_quote_count {
        for offset in 1..state.raw_quote_count {
            result[index + offset] = ' ';
        }
        index += state.raw_quote_count - 1;
        state.raw_quote_count = 0;
    }
    index
}

fn mask_oop_quoted_string(
    character: char,
    next: Option<char>,
    delimiter: char,
    result: &mut [char],
    mut index: usize,
    state: &mut OopMaskState,
) -> usize {
    if character != '\n' && character != '\r' {
        result[index] = ' ';
    }
    if delimiter == '"' && character == '"' && next == Some('"') {
        result[index + 1] = ' ';
        index += 1;
        state.escaped = false;
        return index;
    }
    if !state.escaped && character == delimiter {
        state.quote = None;
    }
    state.escaped = !state.escaped && character == '\\';
    if character != '\\' {
        state.escaped = false;
    }
    index
}

fn start_oop_non_code(
    characters: &[char],
    result: &mut [char],
    mut index: usize,
    character: char,
    next: Option<char>,
    typescript: bool,
    state: &mut OopMaskState,
) -> usize {
    if character == '/' && next == Some('/') {
        result[index] = ' ';
        result[index + 1] = ' ';
        index += 1;
        state.line_comment = true;
    } else if character == '/' && next == Some('*') {
        result[index] = ' ';
        result[index + 1] = ' ';
        index += 1;
        state.block_comment = true;
    } else if character == '"' {
        index = start_oop_double_quote(characters, result, index, state);
    } else if character == '\'' || typescript && character == '`' {
        result[index] = ' ';
        state.quote = Some(character);
    }
    index
}

fn start_oop_double_quote(
    characters: &[char],
    result: &mut [char],
    mut index: usize,
    state: &mut OopMaskState,
) -> usize {
    let count = characters[index..]
        .iter()
        .take_while(|character| **character == '"')
        .count();
    if count >= 3 {
        state.raw_quote_count = count;
        for offset in 0..count {
            result[index + offset] = ' ';
        }
        index += count - 1;
    } else {
        result[index] = ' ';
        state.quote = Some('"');
    }
    index
}

fn is_typescript(path: &str) -> bool {
    path.ends_with(".ts") || path.ends_with(".tsx")
}

fn is_implicit_override_language(path: &str) -> bool {
    path.ends_with(".java") || is_typescript(path)
}

fn contains_word(source: &str, word: &str) -> bool {
    identifier_pattern(word).is_match(source)
}

fn identifier_pattern(identifier: &str) -> Regex {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .expect("escaped identifier regex must compile")
}

fn word_pattern(source: &str) -> Regex {
    Regex::new(&format!(r"\b{}\b", regex::escape(source))).expect("escaped word regex must compile")
}

static CLASS_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\b(?:public|internal|private|protected|abstract|sealed|static|partial|final|strictfp|new|\s)*\b(class|interface)\s+([A-Za-z_]\w*)(?:\s*<[^>{}]+>)?\s*(?:(?::\s*([^\n{]+))|(?:extends\s+([A-Za-z_]\w*)\s*)?(?:implements\s+([^\n{]+))?)?\s*\{").unwrap()
});
static METHOD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*((?:(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|extern|unsafe|new|partial)\s+)*)[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|<[^(){};]+>|\[\]|\?)*\s+([A-Za-z_]\w*)\s*(?:<[^>{}]+>)?\s*\(([^)]*)\)\s*(?:where[^\n{;=]+\s*)?(=>|\{|;)").unwrap()
});
static TS_METHOD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*((?:(?:public|private|protected|static|abstract|async|override|readonly|declare|get|set)\s+)*)([A-Za-z_$][\w$]*|constructor)\s*(?:<[^>{}]+>)?\s*\(([^)]*)\)\s*(?::\s*[^={;\n]+)?\s*(=>|\{|;)").unwrap()
});
static TS_ARROW_METHOD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*((?:(?:public|private|protected|static|readonly|declare|override)\s+)*)([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*(?::\s*[^=;\n]+)?\s*(=>)").unwrap()
});
static TS_CLUMP_CALLABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:(?:export|default|declare|public|private|protected|static|async|abstract|override)\s+)*(?:function\s+)?([A-Za-z_$][\w$]*)(?:\s*<[^>{}]+>)?\s*\(([^()]*)\)\s*(?::\s*[^={;\n]+)?\s*(?:\{|=>|;)",
    )
    .unwrap()
});
static FIELD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:private|protected|internal)\s+(?:readonly\s+)?(?:static\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|<[^(){};]+>|\[\]|\?)*\s+([A-Za-z_]\w*)\s*(?:=[^;]+)?;").unwrap()
});
static TS_FIELD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:(?:public|private|protected|static|readonly|declare|abstract)\s+)*([A-Za-z_$][\w$]*)[!?]?\s*:\s*[^;=]+(?:=[^;]+)?;").unwrap()
});
static TS_CONSTRUCTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\bconstructor\s*\(([^)]*)\)").unwrap());
static TS_PARAMETER_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:private|protected)\s+(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*:").unwrap()
});
static TS_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)\??\s*:\s*(.+)$")
        .unwrap()
});
static TYPED_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?:ref|out|in|params|this)\s+)?([A-Za-z_]\w*(?:[.<>?\[\],]\w*)*)\s+([A-Za-z_]\w*)$",
    )
    .unwrap()
});
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static GENERIC_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<.*>").unwrap());
static PRIVATE_OR_PROTECTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:private|protected)\b").unwrap());
static REJECTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bthrow\s+new\s+(?:NotSupportedException|NotImplementedException|UnsupportedOperationException|Error)\b").unwrap()
});
static COMPLEX_BEHAVIOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:if|for|while|switch|catch|await|yield|synchronized|lock|using|try)\b")
        .unwrap()
});
static NEW_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+[A-Za-z_$]").unwrap());
static FORWARDED_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:return\s+)?(?:this\.)?([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(([^)]*)\)\s*;?\s*$",
    )
    .unwrap()
});
static SWITCH_BODY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\bswitch\s*\([^)]*\)\s*\{([^{}]*)\}").unwrap());
static CASE_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcase\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*:").unwrap());
static STATE_SWITCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\bswitch\s*\(\s*(?:this\.)?(_?[A-Za-z_]\w*)\s*\)\s*\{([^{}]*)\}").unwrap()
});
static RAW_CASE_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcase\s+([^:]+):").unwrap());
static MEMBER_ACCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)").unwrap());
static SERVICE_LOCATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_]\w*(?:Locator|Services|Container)|Locator|Services|Container)\s*\.\s*(?:[Gg]et|[Rr]esolve|[Gg]etService)\s*(?:<\s*([A-Za-z_]\w*)\s*>\s*\(|\(\s*([A-Za-z_]\w*)\.class)").unwrap()
});
static MESSAGE_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\([^;()]*\))?){4,}").unwrap()
});
static NEW_NAMED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+([A-Z]\w*)\s*\(").unwrap());
static BOUNDARY_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:private|protected)\s+(?:(?:readonly|final)\s+)?([A-Z]\w*(?:Client|Dao|Database|DataSource|Store|Service|Gateway))\s+_?\w+\s*[;=]").unwrap()
});
static TS_BOUNDARY_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:private|protected)\s+(?:readonly\s+)?[A-Za-z_$][\w$]*\s*:\s*([A-Z]\w*(?:Client|Dao|Database|DataSource|Store|Service|Gateway))\b").unwrap()
});
static OBJECT_INITIALIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\bnew\s+([A-Z]\w*)\s*\{([^{}]+)\}").unwrap());
static OBJECT_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Z]\w*)\s*=\s*([a-z_]\w*)\.([A-Z]\w*)").unwrap());
static JAVA_MAPPING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?s)\bnew\s+([A-Z]\w*)\s*\(\s*((?:[a-z_]\w*\s*\.\s*get[A-Z]\w*\s*\(\s*\)\s*,?\s*){3,})\)",
    )
    .unwrap()
});
static JAVA_GETTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-z_]\w*\s*\.\s*get([A-Z]\w*)\s*\(\s*\)").unwrap());
static TS_OBJECT_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\breturn\s*\{([^{}]+)\}").unwrap());
static TS_OBJECT_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([a-z_$][\w$]*)\s*:\s*([a-z_$][\w$]*)\.([a-z_$][\w$]*)").unwrap()
});
static CALL_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\(").unwrap());

include!("oop/smells.rs");
include!("oop/tests.rs");
