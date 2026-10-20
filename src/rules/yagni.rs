use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::constant_arguments::{
    declaration_open, identifier_count, is_private, required_parameter_names,
};
use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;
use crate::rule_catalog;
use crate::rust_rules::function_lexical_facts;
use crate::trivial_wrappers::{
    direct_returned_expression, forwarded_parameter_names, mask_comments_and_strings,
    matching_delimiter, source_language, split_top_level,
};
use crate::yagni_call_index::{Call, YagniCallIndex};

pub(crate) fn analyze(index: &YagniCallIndex<'_>) -> Vec<Finding> {
    let mut findings = single_product_factories(index);
    findings.extend(unused_customization_hooks(index));
    findings.extend(unused_optional_parameters(index));
    findings.extend(unused_configuration_options(index));
    findings
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum GenericLanguage {
    Cpp,
    Rust,
}

struct GenericCandidate<'a> {
    function: &'a FunctionSource,
    parameter: String,
    language: GenericLanguage,
}

struct GenericCall {
    concrete_type: String,
    path: String,
}

pub(crate) fn single_concrete_generics(
    index: &YagniCallIndex<'_>,
    sources: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let masked_sources = sources
        .iter()
        .filter_map(|(path, source)| {
            generic_language(path).map(|language| {
                let masked = match language {
                    GenericLanguage::Rust => function_lexical_facts(source).0,
                    GenericLanguage::Cpp => mask_comments_and_strings(source),
                };
                (path.clone(), masked)
            })
        })
        .collect::<BTreeMap<_, _>>();
    let mut candidates = rust_generic_candidates(index);
    candidates.extend(cpp_generic_candidates(index, &masked_sources));

    candidates
        .into_iter()
        .filter_map(|candidate| {
            let calls = concrete_generic_calls(&candidate, &masked_sources)?;
            let concrete_type = &calls[0].concrete_type;
            let mut result = finding(
                "single-concrete-generic",
                candidate.function,
                format!(
                    "`{}` is generic over `{}`, but all {} visible explicit uses select `{concrete_type}`",
                    candidate.function.name,
                    candidate.parameter,
                    calls.len()
                ),
            );
            result.related_files = calls
                .into_iter()
                .map(|call| call.path)
                .filter(|path| path != &candidate.function.path)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            Some(result)
        })
        .collect()
}

fn rust_generic_candidates<'a>(index: &'a YagniCallIndex<'_>) -> Vec<GenericCandidate<'a>> {
    index
        .ordered
        .iter()
        .copied()
        .filter_map(|function| {
            if !function.path.ends_with(".rs")
                || !is_private(function)
                || function.contract_signature
                || index.name_counts.get(function.name.as_str()) != Some(&1)
            {
                return None;
            }
            let capture = RUST_SINGLE_TYPE_GENERIC.captures(&function.source)?;
            if capture.name("name")?.as_str() != function.name {
                return None;
            }
            let parameter = capture.name("parameter")?.as_str().to_owned();
            (identifier_count(
                &crate::constant_arguments::code_without_comments_and_strings(function),
                &parameter,
            ) >= 2)
                .then_some(GenericCandidate {
                    function,
                    parameter,
                    language: GenericLanguage::Rust,
                })
        })
        .collect()
}

fn cpp_generic_candidates<'a>(
    index: &'a YagniCallIndex<'_>,
    sources: &BTreeMap<String, String>,
) -> Vec<GenericCandidate<'a>> {
    let mut result = Vec::new();
    for (path, source) in sources {
        if generic_language(path) != Some(GenericLanguage::Cpp) || is_cpp_header(path) {
            continue;
        }
        for capture in CPP_SINGLE_TYPE_GENERIC.captures_iter(source) {
            let (Some(name), Some(parameter)) = (capture.name("name"), capture.name("parameter"))
            else {
                continue;
            };
            let line = source_line(source, name.start());
            let Some(function) = index.ordered.iter().copied().find(|function| {
                function.path == *path && function.name == name.as_str() && function.line == line
            }) else {
                continue;
            };
            if !is_private(function)
                || index.name_counts.get(function.name.as_str()) != Some(&1)
                || identifier_count(
                    &crate::constant_arguments::code_without_comments_and_strings(function),
                    parameter.as_str(),
                ) == 0
            {
                continue;
            }
            result.push(GenericCandidate {
                function,
                parameter: parameter.as_str().to_owned(),
                language: GenericLanguage::Cpp,
            });
        }
    }
    result
}

fn concrete_generic_calls(
    candidate: &GenericCandidate<'_>,
    sources: &BTreeMap<String, String>,
) -> Option<Vec<GenericCall>> {
    let mut reference_count = 0;
    let mut calls = Vec::new();
    for (path, source) in sources {
        if generic_language(path) != Some(candidate.language) {
            continue;
        }
        for identifier in IDENTIFIER
            .find_iter(source)
            .filter(|identifier| identifier.as_str() == candidate.function.name)
        {
            reference_count += 1;
            let Some(concrete_type) = explicit_generic_call(
                source,
                identifier.end(),
                candidate.language,
                &candidate.parameter,
            ) else {
                continue;
            };
            calls.push(GenericCall {
                concrete_type,
                path: path.clone(),
            });
        }
    }
    let (first, remaining) = calls.split_first()?;
    (calls.len() >= 2
        && reference_count == calls.len() + 1
        && remaining
            .iter()
            .all(|call| call.concrete_type == first.concrete_type))
    .then_some(calls)
}

fn explicit_generic_call(
    source: &str,
    identifier_end: usize,
    language: GenericLanguage,
    parameter: &str,
) -> Option<String> {
    let mut cursor = skip_whitespace(source, identifier_end);
    if language == GenericLanguage::Rust {
        (source.as_bytes().get(cursor..cursor + 2) == Some(b"::")).then_some(())?;
        cursor = skip_whitespace(source, cursor + 2);
    }
    (source.as_bytes().get(cursor) == Some(&b'<')).then_some(())?;
    let close = matching_angle(source, cursor)?;
    let argument = single_generic_argument(&source[cursor + 1..close])?;
    let after = skip_whitespace(source, close + 1);
    (source.as_bytes().get(after) == Some(&b'(') && concrete_type_argument(argument, parameter))
        .then(|| normalize_type(argument))
}

fn matching_angle(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (relative, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + relative);
                }
            }
            b';' | b'{' | b'}' if depth == 1 => return None,
            _ => {}
        }
    }
    None
}

fn single_generic_argument(source: &str) -> Option<&str> {
    let mut angle_depth = 0_usize;
    let mut delimiter_depth = 0_usize;
    for byte in source.bytes() {
        match byte {
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.checked_sub(1)?,
            b'(' | b'[' => delimiter_depth += 1,
            b')' | b']' => delimiter_depth = delimiter_depth.checked_sub(1)?,
            b',' if angle_depth == 0 && delimiter_depth == 0 => return None,
            _ => {}
        }
    }
    (angle_depth == 0 && delimiter_depth == 0)
        .then(|| source.trim())
        .filter(|argument| !argument.is_empty())
}

fn concrete_type_argument(argument: &str, parameter: &str) -> bool {
    let argument = argument.trim();
    if argument == parameter
        || matches!(
            argument,
            "_" | "auto" | "decltype(auto)" | "impl Trait" | "dyn Trait"
        )
        || GENERIC_TYPE_VARIABLE.is_match(argument)
        || !TYPE_ARGUMENT.is_match(argument)
    {
        return false;
    }
    let simple = argument
        .chars()
        .all(|character| character == '_' || character.is_ascii_alphanumeric());
    !simple
        || PRIMITIVE_TYPE.is_match(argument)
        || argument.chars().next().is_some_and(char::is_uppercase)
}

fn normalize_type(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn skip_whitespace(source: &str, mut cursor: usize) -> usize {
    while source
        .as_bytes()
        .get(cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        cursor += 1;
    }
    cursor
}

fn generic_language(path: &str) -> Option<GenericLanguage> {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase()
        .as_str()
    {
        "rs" => Some(GenericLanguage::Rust),
        "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" => Some(GenericLanguage::Cpp),
        _ => None,
    }
}

fn is_cpp_header(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "h" | "hh" | "hpp" | "hxx"
    )
}

fn source_line(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn single_product_factories(index: &YagniCallIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (target, function) in index.ordered.iter().enumerate() {
        if !supports(function, SINGLE_PRODUCT_FACTORY_LANGUAGES)
            || !is_private(function)
            || index.name_counts.get(function.name.as_str()) != Some(&1)
            || OVERRIDE.is_match(&function.source)
        {
            continue;
        }
        let Some(product) = single_product(function) else {
            continue;
        };
        let calls = index.visible_calls(target, &function.name);
        if calls.len() != 1 || index.reference_counts.get(function.name.as_str()) != Some(&2) {
            continue;
        }
        findings.push(finding(
            "single-product-factory",
            function,
            format!(
                "`{}` has one caller and only constructs `{product}` with unchanged arguments",
                function.name
            ),
        ));
    }
    findings
}

fn unused_customization_hooks(index: &YagniCallIndex<'_>) -> Vec<Finding> {
    unused_parameters(index, OptionalParameterKind::CustomizationHook)
}

fn unused_optional_parameters(index: &YagniCallIndex<'_>) -> Vec<Finding> {
    unused_parameters(index, OptionalParameterKind::Parameter)
}

fn unused_parameters(index: &YagniCallIndex<'_>, kind: OptionalParameterKind) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (target, function) in candidates(index, OPTIONAL_PARAMETER_LANGUAGES) {
        let Some(calls) = complete_calls(index, target, function) else {
            continue;
        };
        for parameter in optional_parameters(function)
            .into_iter()
            .filter(|parameter| kind.includes(parameter))
        {
            if calls
                .iter()
                .any(|call| parameter.is_supplied(&call.arguments))
            {
                continue;
            }
            findings.push(finding(
                kind.code(),
                function,
                format!(
                    "`{}` exposes {} `{}`, but none of its {} visible callers supplies it",
                    function.name,
                    kind.role(),
                    parameter.name,
                    calls.len()
                ),
            ));
        }
    }
    findings
}

fn unused_configuration_options(index: &YagniCallIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (target, function) in candidates(index, OPTIONAL_PARAMETER_LANGUAGES) {
        let Some((parameters, calls)) = configuration_evidence(index, target, function) else {
            continue;
        };
        let body = function_body_code(function);
        for (parameter_index, parameter) in parameters.iter().enumerate() {
            if !CONFIGURATION_PARAMETER.is_match(parameter) {
                continue;
            }
            let Some(common_keys) = common_configuration_keys(&calls, parameter_index) else {
                continue;
            };
            let Some(read_keys) = read_configuration_keys(&body, parameter) else {
                continue;
            };
            for option in common_keys
                .into_iter()
                .filter(|key| !read_keys.contains(key.as_str()))
            {
                findings.push(finding(
                    "unused-configuration-option",
                    function,
                    format!(
                        "`{}` receives configuration option `{option}` from all {} visible callers but never reads it",
                        function.name,
                        calls.len()
                    ),
                ));
            }
        }
    }
    findings
}

fn configuration_evidence<'index>(
    index: &'index YagniCallIndex<'_>,
    target: usize,
    function: &FunctionSource,
) -> Option<(Vec<String>, Vec<&'index Call>)> {
    let parameters = required_parameter_names(function)?;
    if parameters.is_empty() {
        return None;
    }
    let calls = complete_calls(index, target, function)?;
    if calls
        .iter()
        .any(|call| call.arguments.len() != parameters.len())
    {
        return None;
    }
    Some((parameters, calls))
}

fn common_configuration_keys(calls: &[&Call], parameter_index: usize) -> Option<BTreeSet<String>> {
    let (first, remaining) = calls.split_first()?;
    let mut common_keys = configuration_keys(&first.arguments[parameter_index])?;
    if common_keys.is_empty() {
        return None;
    }
    for call in remaining {
        let keys = configuration_keys(&call.arguments[parameter_index])?;
        common_keys.retain(|key| keys.contains(key));
    }
    (!common_keys.is_empty()).then_some(common_keys)
}

fn read_configuration_keys<'body>(
    body: &'body str,
    parameter: &str,
) -> Option<BTreeSet<&'body str>> {
    let access = Regex::new(&format!(
        r"\b{}\s*(?:(?:\?|!)\s*)?\.\s*([A-Za-z_$][\w$]*)",
        regex::escape(parameter)
    ))
    .ok()?;
    let mut access_count = 0;
    let mut read_keys = BTreeSet::new();
    for capture in access.captures_iter(body) {
        access_count += 1;
        read_keys.insert(capture.get(1)?.as_str());
    }
    (identifier_count(body, parameter) == access_count).then_some(read_keys)
}

fn single_product(function: &FunctionSource) -> Option<String> {
    if !FACTORY_NAME.is_match(&function.name) {
        return None;
    }
    let language = source_language(&function.path)?;
    let open = declaration_open(&function.source, &function.name)?;
    let close = matching_delimiter(&function.source, open, b'(', b')')?;
    let parameters = forwarded_parameter_names(&function.source[open + 1..close], language)?;
    let expression = direct_returned_expression(&function.source[close + 1..])?;
    let construction = CONSTRUCTION.captures(expression)?;
    let arguments = split_top_level(construction.get(2)?.as_str())
        .into_iter()
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    if arguments != parameters {
        return None;
    }
    Some(construction.get(1)?.as_str().to_owned())
}

fn function_body_code(function: &FunctionSource) -> String {
    let Some(open) = declaration_open(&function.source, &function.name) else {
        return String::new();
    };
    let Some(close) = matching_delimiter(&function.source, open, b'(', b')') else {
        return String::new();
    };
    let masked = &crate::constant_arguments::code_without_comments_and_strings(function);
    masked[close + 1..].to_owned()
}

fn configuration_keys(argument: &str) -> Option<BTreeSet<String>> {
    let argument = argument.trim();
    let source = if argument.starts_with('{') && argument.ends_with('}') {
        &argument[1..argument.len() - 1]
    } else {
        CONSTRUCTOR_ARGUMENTS.captures(argument)?.get(1)?.as_str()
    };
    let mut keys = BTreeSet::new();
    for raw in split_top_level(source) {
        let member = raw.trim();
        if member.is_empty() {
            continue;
        }
        let key = KEYED_MEMBER.captures(member)?.get(1)?.as_str().to_owned();
        if !keys.insert(key) {
            return None;
        }
    }
    Some(keys)
}

#[derive(Clone, Copy, Debug)]
enum OptionalParameterKind {
    CustomizationHook,
    Parameter,
}

impl OptionalParameterKind {
    fn includes(self, parameter: &OptionalParameter) -> bool {
        match self {
            Self::CustomizationHook => parameter.callback_like && parameter.invoked,
            Self::Parameter => !parameter.callback_like || !parameter.invoked,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::CustomizationHook => "unused-customization-hook",
            Self::Parameter => "unused-optional-parameter",
        }
    }

    fn role(self) -> &'static str {
        match self {
            Self::CustomizationHook => "optional customization hook",
            Self::Parameter => "optional parameter",
        }
    }
}

#[derive(Debug)]
struct OptionalParameter {
    name: String,
    positional_index: usize,
    named: bool,
    callback_like: bool,
    invoked: bool,
}

impl OptionalParameter {
    fn is_supplied(&self, arguments: &[String]) -> bool {
        if arguments.iter().any(|argument| {
            let trimmed = argument.trim_start();
            trimmed
                .strip_prefix(&self.name)
                .is_some_and(|suffix| suffix.trim_start().starts_with([':', '=']))
        }) {
            return true;
        }
        if self.named {
            return false;
        }
        let positional_arguments = arguments
            .iter()
            .filter(|argument| !NAMED_ARGUMENT.is_match(argument))
            .count();
        positional_arguments > self.positional_index
    }
}

fn optional_parameters(function: &FunctionSource) -> Vec<OptionalParameter> {
    let Some(open) = declaration_open(&function.source, &function.name) else {
        return Vec::new();
    };
    let Some(close) = matching_delimiter(&function.source, open, b'(', b')') else {
        return Vec::new();
    };
    let masked = crate::constant_arguments::code_without_comments_and_strings(function);
    let body = &masked[close + 1..];
    let mut parameters = Vec::new();
    let mut positional_index = 0;
    for raw_group in split_top_level(&function.source[open + 1..close]) {
        let group = parameter_group(raw_group);
        for declaration in split_top_level(group.declarations) {
            if let Some(parameter) =
                parse_optional_parameter(function, declaration, group, body, &mut positional_index)
            {
                parameters.push(parameter);
            }
        }
    }
    parameters
}

#[derive(Clone, Copy)]
struct ParameterGroup<'a> {
    declarations: &'a str,
    named: bool,
    optional: bool,
}

fn parameter_group(group: &str) -> ParameterGroup<'_> {
    let declarations = group.trim();
    let wrapped = declarations.len() >= 2
        && ((declarations.starts_with('{') && declarations.ends_with('}'))
            || (declarations.starts_with('[') && declarations.ends_with(']')));
    if wrapped {
        ParameterGroup {
            declarations: &declarations[1..declarations.len() - 1],
            named: declarations.starts_with('{'),
            optional: true,
        }
    } else {
        ParameterGroup {
            declarations,
            named: false,
            optional: false,
        }
    }
}

fn parse_optional_parameter(
    function: &FunctionSource,
    raw: &str,
    group: ParameterGroup<'_>,
    body: &str,
    positional_index: &mut usize,
) -> Option<OptionalParameter> {
    let parameter = raw.trim();
    if parameter.is_empty() {
        return None;
    }
    let (declaration_part, has_default) = parameter
        .split_once('=')
        .map_or((parameter, false), |(before, _)| (before.trim(), true));
    let name_source = declaration_part
        .split_once(':')
        .map_or(declaration_part, |(before, _)| before);
    let name = IDENTIFIER.find_iter(name_source).last()?.as_str();
    if matches!(name, "this" | "self") {
        return None;
    }
    let parameter_position = *positional_index;
    if !group.named {
        *positional_index += 1;
    }
    if !is_optional_parameter(name, declaration_part, group.optional, has_default)
        || identifier_count(body, name) == 0
        || (function.path.ends_with(".cs")
            && CSHARP_CALLER_INFO_ATTRIBUTE.is_match(declaration_part))
    {
        return None;
    }
    let callback_invocation = Regex::new(&format!(
        r"\b{}\s*(?:(?:\?|!)\s*\.\s*)?(?:(?:call|Invoke)\s*)?\(",
        regex::escape(name)
    ))
    .ok()?;
    Some(OptionalParameter {
        name: name.to_owned(),
        positional_index: parameter_position,
        named: group.named,
        callback_like: ON_CALLBACK.is_match(name) || CALLBACK_NAME.is_match(name),
        invoked: callback_invocation.is_match(body),
    })
}

fn is_optional_parameter(
    name: &str,
    declaration: &str,
    group_optional: bool,
    has_default: bool,
) -> bool {
    group_optional
        || has_default
        || Regex::new(&format!(r"\b{}\s*\?", regex::escape(name)))
            .is_ok_and(|nullable| nullable.is_match(declaration))
}

fn candidates<'index, 'source>(
    index: &'index YagniCallIndex<'source>,
    languages: &'static [&'static str],
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
            supports(function, languages)
                && is_private(function)
                && index.name_counts.get(function.name.as_str()) == Some(&1)
                && !OVERRIDE.is_match(&function.source)
        })
}

fn complete_calls<'index>(
    index: &'index YagniCallIndex<'_>,
    target: usize,
    function: &FunctionSource,
) -> Option<Vec<&'index Call>> {
    let calls = index.visible_calls(target, &function.name);
    (calls.len() >= 3
        && index.reference_counts.get(function.name.as_str()) == Some(&(calls.len() + 1)))
    .then_some(calls)
}

fn supports(function: &FunctionSource, languages: &[&str]) -> bool {
    source_language(&function.path).is_some_and(|language| languages.contains(&language))
}

fn finding(code: &str, function: &FunctionSource, message: String) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("YAGNI rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::Info,
        path: function.path.clone(),
        line: function.line,
        end_line: legacy_end_line(function),
        message,
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

fn legacy_end_line(function: &FunctionSource) -> usize {
    function.line + function.source.matches('\n').count()
}

const SINGLE_PRODUCT_FACTORY_LANGUAGES: &[&str] = &[
    "cpp",
    "csharp",
    "dart",
    "java",
    "javascript",
    "typescript",
    "python",
];
const OPTIONAL_PARAMETER_LANGUAGES: &[&str] =
    &["csharp", "dart", "javascript", "typescript", "python"];

static OVERRIDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)@\s*override\b|\boverride\b").expect("override regex"));
static FACTORY_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^_?(?:(?:[Cc]reate|[Mm]ake|[Bb]uild|[Pp]rovide)(?:[A-Z_].*)?|.*Factory)$")
        .expect("factory name regex")
});
static CONSTRUCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?:new|const)\s+)?([A-Z][A-Za-z0-9_$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(([^()]*)\)$",
    )
    .expect("construction regex")
});
static CONFIGURATION_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:config|configuration|options|settings|preferences)$")
        .expect("configuration parameter regex")
});
static CONSTRUCTOR_ARGUMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:new|const)\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\((.*)\)$")
        .expect("configuration constructor regex")
});
static KEYED_MEMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_$][\w$]*)\s*(?::|=)").expect("keyed member regex"));
static NAMED_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*\s*(?::|=)").expect("named argument regex"));
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*").expect("identifier regex"));
static CSHARP_CALLER_INFO_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\[\s*(?:[A-Za-z_]\w*\.)*Caller(?:MemberName|FilePath|LineNumber|ArgumentExpression)(?:Attribute)?\b[^\]]*\]",
    )
    .expect("C# caller info attribute regex")
});
static ON_CALLBACK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^on[A-Z_]").expect("callback prefix regex"));
static CALLBACK_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:callback|hook|customiz(?:e|er)|transform|decorator|factory|builder|handler|interceptor|strategy)",
    )
    .expect("callback name regex")
});

static RUST_SINGLE_TYPE_GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^[ \t]*(?:(?:const|async|unsafe)[ \t]+)*(?:extern[ \t]+"[^"]+"[ \t]+)?fn[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*<[ \t]*(?P<parameter>[A-Za-z_]\w*)(?:[ \t]*:[^,>{}\r\n]+)?[ \t]*>[ \t]*\("#,
    )
    .expect("Rust single-type generic regex")
});
static CPP_SINGLE_TYPE_GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*template[ \t]*<[ \t]*(?:typename|class)[ \t]+(?P<parameter>[A-Za-z_]\w*)[ \t]*>[ \t]*\r?\n[ \t]*static[ \t]+[^\r\n;{}()]*?[ \t*&](?P<name>[A-Za-z_]\w*)[ \t]*\(",
    )
    .expect("C++ single-type generic regex")
});
static TYPE_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_:<>,*&'\[\]\s]*$").expect("type argument regex")
});
static GENERIC_TYPE_VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])[TUVKE](?:$|[^A-Za-z0-9_])")
        .expect("generic type variable regex")
});
static PRIMITIVE_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:bool|char|double|f(?:32|64)|float|i(?:8|16|32|64|128|size)|int|long|short|size_t|str|String|u(?:8|16|32|64|128|size)|unsigned)$",
    )
    .expect("primitive type regex")
});

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::function_sources;

    fn codes(path: &str, source: &str) -> BTreeSet<String> {
        let functions =
            function_sources::extract(&BTreeMap::from([(path.to_owned(), source.to_owned())]));
        analyze(&YagniCallIndex::new(&functions))
            .into_iter()
            .map(|finding| finding.code)
            .collect()
    }
    fn generic_findings(path: &str, source: &str) -> Vec<Finding> {
        let sources = BTreeMap::from([(path.to_owned(), source.to_owned())]);
        let functions = function_sources::extract(&sources);
        let index = YagniCallIndex::new(&functions);
        single_concrete_generics(&index, &sources)
    }

    #[test]
    fn reports_private_generics_with_one_concrete_type_in_rust_and_cpp() {
        let fixtures = [
            (
                "src/interpolate.rs",
                "fn interpolate<T: Copy>(left: T, right: T) -> T { choose(left, right) }\n\
                 fn first() { consume(interpolate::<f32>(1.0, 2.0)); }\n\
                 fn second() { consume(interpolate::<f32>(3.0, 4.0)); }\n",
                1,
                "f32",
            ),
            (
                "src/interpolate.cpp",
                "template <typename T>\n\
                 static T interpolate(T left, T right) { return choose(left, right); }\n\
                 void first() { consume(interpolate<float>(1.0f, 2.0f)); }\n\
                 void second() { consume(interpolate<float>(3.0f, 4.0f)); }\n",
                2,
                "float",
            ),
        ];

        for (path, source, line, concrete_type) in fixtures {
            let findings = generic_findings(path, source);
            assert_eq!(findings.len(), 1, "{path}: {findings:?}");
            let finding = &findings[0];
            assert_eq!(finding.code, "single-concrete-generic");
            assert_eq!(finding.path, path);
            assert_eq!(finding.line, line);
            assert_eq!(finding.confidence, "high");
            assert!(finding.message.contains(concrete_type), "{path}");
        }
    }

    #[test]
    fn accepts_public_inferred_varying_and_single_use_generics() {
        let rust = r#"pub fn public<T: Copy>(value: T) -> T { value }
fn varied<T: Copy>(value: T) -> T { value }
fn inferred<T: Copy>(value: T) -> T { value }
fn once<T: Copy>(value: T) -> T { value }
fn use_all() {
    consume(varied::<f32>(1.0));
    consume(varied::<f64>(2.0));
    consume(inferred(1_u32));
    consume(inferred(2_u32));
    consume(once::<u32>(1));
    // once::<u32>(2)
    let example = "once::<u32>(3)";
}"#;
        let cpp = r#"template <typename T>
T public_template(T value) { return value; }
template <typename T>
static T varied(T value) { return value; }
void use_all() {
    consume(varied<float>(1.0f));
    consume(varied<double>(2.0));
}"#;

        assert!(generic_findings("src/generics.rs", rust).is_empty());
        assert!(generic_findings("src/generics.cpp", cpp).is_empty());
        assert!(generic_findings(
            "include/generics.hpp",
            "template <typename T>\nstatic T local(T value) { return value; }\nvoid a() { local<int>(1); }\nvoid b() { local<int>(2); }\n",
        )
        .is_empty());
    }

    #[test]
    fn recognizes_single_product_factories_in_supported_languages() {
        let fixtures = [
            (
                "src/factory.cpp",
                "static Product createProduct(int value) { return Product(value); }\nvoid useProduct() { auto product = createProduct(1); }\n",
            ),
            (
                "src/Factory.cs",
                "class Factory {\nprivate static Product CreateProduct(int value) { return new Product(value); }\npublic static void UseProduct() { var product = CreateProduct(1); }\n}\n",
            ),
            (
                "src/Factory.java",
                "class Factory {\nprivate static Product createProduct(int value) { return new Product(value); }\nstatic void useProduct() { Product product = createProduct(1); }\n}\n",
            ),
            (
                "src/factory.ts",
                "function _createProduct(value: number) { return new Product(value); }\nfunction useProduct() { const product = _createProduct(1); }\n",
            ),
            (
                "factory.py",
                "def _create_product(value: int):\n    return Product(value)\n\ndef use_product():\n    product = _create_product(1)\n",
            ),
        ];

        for (path, source) in fixtures {
            assert!(
                codes(path, source).contains("single-product-factory"),
                "{path}"
            );
        }
    }

    #[test]
    fn distinguishes_unused_hooks_from_other_optional_parameters() {
        let fixtures = [
            (
                "src/Option.cs",
                "class Option {\nprivate static int Save(int value, Func<int, int>? customize = null, bool validate = true) { return validate ? customize?.Invoke(value) ?? value : 0; }\npublic static int First() { return Save(1); }\npublic static int Second() { return Save(2); }\npublic static int Third() { return Save(3); }\n}\n",
            ),
            (
                "src/option.ts",
                "function _save(value: number, customize?: Customizer, validate = true) { return validate ? customize?.(value) ?? value : 0; }\nfunction first() { return _save(1); }\nfunction second() { return _save(2); }\nfunction third() { return _save(3); }\n",
            ),
            (
                "option.py",
                "def _save(value: int, customize=None, validate=True) -> int:\n    return customize(value) if customize and validate else value\n\ndef first():\n    return _save(1)\n\ndef second():\n    return _save(2)\n\ndef third():\n    return _save(3)\n",
            ),
        ];

        for (path, source) in fixtures {
            let findings = codes(path, source);
            assert!(findings.contains("unused-customization-hook"), "{path}");
            assert!(findings.contains("unused-optional-parameter"), "{path}");
        }
    }

    #[test]
    fn keeps_same_named_nested_python_functions_out_of_caller_groups() {
        let findings = codes(
            "color.py",
            "def _clamp(value, minimum=0, maximum=255):\n    return min(max(value, minimum), maximum)\n\ndef first():\n    return _clamp(1)\n\ndef second():\n    return _clamp(2)\n\ndef third():\n    return _clamp(3)\n\ndef scale(value):\n    def _clamp(value):\n        return value\n    return _clamp(value)\n",
        );

        assert!(!findings.contains("unused-optional-parameter"));
    }

    #[test]
    fn ignores_compiler_supplied_csharp_caller_information() {
        let findings = codes(
            "src/Cache.cs",
            "class Cache {\n\
             private void Trigger([CallerMemberName] string? operation = null, bool suppress = false) { if (!suppress) Log(operation); }\n\
             public void First() { Trigger(); }\n\
             public void Second() { Trigger(); }\n\
             public void Third() { Trigger(); }\n\
             public void Silent() { Trigger(suppress: true); }\n\
             }\n",
        );

        assert!(!findings.contains("unused-optional-parameter"));
    }

    #[test]
    fn recognizes_unused_configuration_members_across_object_syntaxes() {
        let fixtures = [
            (
                "src/Configuration.cs",
                "class Configuration {\nprivate static int Render(int value, RenderOptions options) { return options.cache ? value : 0; }\npublic static int First() { return Render(1, new RenderOptions(cache: true, trace: false)); }\npublic static int Second() { return Render(2, new RenderOptions(cache: false, trace: true)); }\npublic static int Third() { return Render(3, new RenderOptions(cache: true, trace: true)); }\n}\n",
            ),
            (
                "src/configuration.ts",
                "function _render(value: number, options: RenderOptions) { return options.cache ? value : 0; }\nfunction first() { return _render(1, {cache: true, trace: false}); }\nfunction second() { return _render(2, {cache: false, trace: true}); }\nfunction third() { return _render(3, {cache: true, trace: true}); }\n",
            ),
            (
                "configuration.py",
                "def _render(value: int, options: RenderOptions) -> int:\n    return value if options.cache else 0\n\ndef first():\n    return _render(1, RenderOptions(cache=True, trace=False))\n\ndef second():\n    return _render(2, RenderOptions(cache=False, trace=True))\n\ndef third():\n    return _render(3, RenderOptions(cache=True, trace=True))\n",
            ),
        ];

        for (path, source) in fixtures {
            assert!(
                codes(path, source).contains("unused-configuration-option"),
                "{path}"
            );
        }
    }
}
