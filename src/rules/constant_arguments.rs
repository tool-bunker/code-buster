use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;
use crate::rust_rules::function_lexical_facts;
use crate::trivial_wrappers::{mask_comments_and_strings, matching_delimiter, split_top_level};
use crate::yagni_call_index::{Call, YagniCallIndex};

pub(crate) fn analyze(index: &YagniCallIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (target, function) in candidate_functions(index) {
        let Some(evidence) = aggregate_call_evidence(index, target, function) else {
            continue;
        };
        findings.extend(
            qualify_constant_parameters(
                &index.stripped_sources[target],
                &evidence.parameters,
                &evidence.calls,
            )
            .map(|constant| emit_constant_argument_finding(function, &evidence, constant)),
        );
    }
    findings
}

struct CallEvidence<'a> {
    parameters: Vec<String>,
    calls: Vec<&'a Call>,
}

struct QualifiedConstant<'a> {
    parameter: &'a str,
    value: String,
}

fn candidate_functions<'index, 'source>(
    index: &'index YagniCallIndex<'source>,
) -> impl Iterator<Item = (usize, &'source FunctionSource)> + 'index
where
    'source: 'index,
{
    index
        .ordered
        .iter()
        .copied()
        .enumerate()
        .filter(move |(_, function)| {
            supported_path(&function.path)
                && is_private(function)
                && index.name_counts.get(function.name.as_str()) == Some(&1)
                && !OVERRIDE.is_match(&function.source)
        })
}

fn aggregate_call_evidence<'index>(
    index: &'index YagniCallIndex<'_>,
    target: usize,
    function: &FunctionSource,
) -> Option<CallEvidence<'index>> {
    let parameters = required_parameter_names(function)?;
    if parameters.is_empty() {
        return None;
    }
    let calls = index.visible_calls(target, &function.name);
    (calls.len() >= 3
        && !calls
            .iter()
            .any(|call| call.arguments.len() != parameters.len())
        && index.reference_counts.get(function.name.as_str()) == Some(&(calls.len() + 1)))
    .then_some(CallEvidence { parameters, calls })
}

fn qualify_constant_parameters<'a>(
    function_code: &'a str,
    parameters: &'a [String],
    calls: &'a [&Call],
) -> impl Iterator<Item = QualifiedConstant<'a>> + 'a {
    parameters
        .iter()
        .enumerate()
        .filter_map(move |(parameter_index, parameter)| {
            if identifier_count(function_code, parameter) < 2 {
                return None;
            }
            let constant = simple_constant(&calls[0].arguments[parameter_index])?;
            calls[1..]
                .iter()
                .all(|call| {
                    simple_constant(&call.arguments[parameter_index]).as_deref() == Some(&constant)
                })
                .then_some(QualifiedConstant {
                    parameter,
                    value: constant,
                })
        })
}

fn emit_constant_argument_finding(
    function: &FunctionSource,
    evidence: &CallEvidence<'_>,
    constant: QualifiedConstant<'_>,
) -> Finding {
    Finding {
        code: "constant-argument-parameter".to_owned(),
        severity: Severity::Info,
        path: function.path.clone(),
        line: function.line,
        end_line: function.end_line + usize::from(function.path.ends_with(".rs")),
        message: format!(
            "`{}` receives the constant `{}` for parameter `{}` at all {} visible call sites",
            function.name,
            constant.value,
            constant.parameter,
            evidence.calls.len()
        ),
        confidence: "high".to_owned(),
        why: "A parameter whose callers always supply one value advertises flexibility that the current code does not use.".to_owned(),
        suggestion: "Move the constant into the private function and remove the parameter until callers need real variation.".to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

pub(crate) fn code_without_comments_and_strings(function: &FunctionSource) -> String {
    if function.path.ends_with(".rs") {
        return function_lexical_facts(&function.source).0;
    }
    let code = mask_comments_and_strings(&function.source);
    if !function.path.ends_with(".py") {
        return code;
    }
    let mut bytes = code.into_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                bytes[index] = b' ';
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    String::from_utf8(bytes).expect("masking preserves UTF-8")
}

fn supported_path(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "c" | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hh"
            | "hpp"
            | "hxx"
            | "cs"
            | "dart"
            | "go"
            | "java"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "mts"
            | "cts"
            | "py"
            | "rs"
    )
}

pub(crate) fn is_private(function: &FunctionSource) -> bool {
    if function.name.starts_with('_') {
        return true;
    }
    let extension = Path::new(&function.path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" => {
            CPP_STATIC.is_match(&function.source)
        }
        "cs" | "java" => PRIVATE.is_match(&function.source),
        "go" => function.name.chars().next().is_some_and(char::is_lowercase),
        "rs" => !RUST_PUBLIC.is_match(&function.source),
        _ => false,
    }
}

pub(crate) fn required_parameter_names(function: &FunctionSource) -> Option<Vec<String>> {
    let open = declaration_open(&function.source, &function.name)?;
    let close = matching_delimiter(&function.source, open, b'(', b')')?;
    let parameters = &function.source[open + 1..close];
    if parameters.contains(['{', '[']) {
        return None;
    }
    let mut result = Vec::new();
    for raw in split_top_level(parameters) {
        let mut parameter = raw.trim().trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, '{' | '}' | '[' | ']')
        });
        if parameter.is_empty() || is_cpp(&function.path) && parameter == "void" {
            continue;
        }
        if let Some((before_default, _)) = parameter.split_once('=') {
            parameter = before_default.trim();
        }
        if parameter.contains(['(', '{', '[']) {
            return None;
        }
        let name_source = parameter
            .split_once(':')
            .map_or(parameter, |(before_colon, _)| before_colon);
        let identifiers = IDENTIFIER
            .find_iter(name_source)
            .map(|identifier| identifier.as_str())
            .collect::<Vec<_>>();
        let name = if function.path.ends_with(".go") {
            identifiers.first()
        } else {
            identifiers.last()
        }?;
        if !matches!(*name, "this" | "self") {
            result.push((*name).to_owned());
        }
    }
    Some(result)
}

pub(crate) fn declaration_open(source: &str, name: &str) -> Option<usize> {
    source.match_indices(name).find_map(|(start, _)| {
        let before = source[..start].chars().next_back();
        let end = start + name.len();
        let after = source[end..].chars().next();
        if before.is_some_and(is_identifier) || after.is_some_and(is_identifier) {
            return None;
        }
        let whitespace = source[end..].len() - source[end..].trim_start().len();
        (source.as_bytes().get(end + whitespace) == Some(&b'(')).then_some(end + whitespace)
    })
}

fn simple_constant(argument: &str) -> Option<String> {
    let normalized = WHITESPACE.replace_all(argument, "").into_owned();
    (SIMPLE_CONSTANT.is_match(&normalized) || ENUM_CONSTANT.is_match(&normalized))
        .then_some(normalized)
}

pub(crate) fn identifier_count(source: &str, identifier: &str) -> usize {
    source
        .match_indices(identifier)
        .filter(|(start, _)| {
            let end = start + identifier.len();
            !source[..*start]
                .chars()
                .next_back()
                .is_some_and(is_identifier)
                && !source[end..].chars().next().is_some_and(is_identifier)
        })
        .count()
}

fn is_identifier(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
}

fn is_cpp(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx")
    )
}

static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\b").unwrap());
static OVERRIDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)@\s*override\b|\boverride\b").unwrap());
static CPP_STATIC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*static\b").unwrap());
static PRIVATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bprivate\b").unwrap());
static RUST_PUBLIC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*pub(?:\s|\()").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static SIMPLE_CONSTANT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:true|false|True|False|null|None|nil|-?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))$",
    )
    .unwrap()
});
static ENUM_CONSTANT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Z][A-Za-z0-9_$]*\.)+[A-Za-z_$][\w$]*$|^[A-Z][A-Z0-9_]*$").unwrap()
});
