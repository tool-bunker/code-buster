use std::collections::{BTreeMap, BTreeSet};

use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;
use crate::rule_catalog;

const MIN_KEYS: usize = 4;
const MAX_KEYS: usize = 12;
const MIN_PARAMETERS: usize = 4;
const MAX_PARAMETERS: usize = 10;
const MIN_FUNCTIONS: usize = 3;
const MIN_SINGLE_FILE_FUNCTIONS: usize = 4;

#[derive(Clone, Copy)]
enum Language {
    Python,
    Rust,
}

#[derive(Clone, Copy)]
enum FindingKind {
    MapShape,
    ParameterClump,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Token<'a> {
    Identifier(&'a str),
    String(&'a str),
    Symbol(u8),
}

#[derive(Debug)]
struct Evidence {
    path: String,
    function: String,
    line: usize,
    identity: Vec<String>,
    members: Vec<String>,
}

pub fn python(functions: &[FunctionSource]) -> Vec<Finding> {
    analyze_language(
        functions,
        Language::Python,
        "py-repeated-dictionary-shape",
        "py-object-soup",
        |path| path.ends_with(".py"),
    )
}

pub fn rust(functions: &[FunctionSource]) -> Vec<Finding> {
    analyze_language(
        functions,
        Language::Rust,
        "rust-repeated-dynamic-map-shape",
        "rust-object-soup",
        |path| path.ends_with(".rs"),
    )
}

fn analyze_language(
    functions: &[FunctionSource],
    language: Language,
    map_code: &'static str,
    parameter_code: &'static str,
    supports_path: impl Fn(&str) -> bool,
) -> Vec<Finding> {
    let mut map_evidence = Vec::new();
    let mut parameter_evidence = Vec::new();
    for function in functions
        .iter()
        .filter(|function| supports_path(&function.path))
        .filter(|function| !is_test_function(function, language))
        .filter(|function| !is_domain_finding_factory(function, language))
    {
        let tokens = tokenize(&function.source, language);
        let Some((parameters_start, parameters_end)) = function_parameters(&tokens) else {
            continue;
        };
        map_evidence.extend(function_map_evidence(
            function,
            language,
            &tokens,
            parameters_start,
            parameters_end,
        ));
        let contract_signature = function.contract_signature
            || matches!(language, Language::Python)
                && python_declaration_only(&tokens, parameters_end);
        if !contract_signature
            && let Some(evidence) = function_parameter_evidence(
                function,
                language,
                &tokens,
                parameters_start,
                parameters_end,
            )
        {
            parameter_evidence.push(evidence);
        }
    }
    let mut findings = aggregate(map_evidence, map_code, FindingKind::MapShape);
    findings.extend(aggregate(
        parameter_evidence,
        parameter_code,
        FindingKind::ParameterClump,
    ));
    findings
}

fn is_test_function(function: &FunctionSource, language: Language) -> bool {
    matches!(language, Language::Python)
        && (function.name == "test" || function.name.starts_with("test_"))
}

fn is_domain_finding_factory(function: &FunctionSource, language: Language) -> bool {
    matches!(language, Language::Rust)
        && function.name == "finding"
        && function.source.contains("-> Finding")
}

fn python_declaration_only(tokens: &[Token<'_>], parameters_end: usize) -> bool {
    let Some(colon) = tokens[parameters_end + 1..]
        .iter()
        .position(|token| *token == Token::Symbol(b':'))
        .map(|offset| parameters_end + 1 + offset)
    else {
        return false;
    };
    let body = &tokens[colon + 1..];
    let markers = body
        .iter()
        .copied()
        .filter(|token| !matches!(token, Token::String(_)))
        .collect::<Vec<_>>();
    !body.is_empty()
        && matches!(
            markers.as_slice(),
            [] | [Token::Identifier("pass")]
                | [
                    Token::Identifier("raise"),
                    Token::Identifier("NotImplementedError")
                ]
                | [
                    Token::Identifier("raise"),
                    Token::Identifier("NotImplementedError"),
                    Token::Symbol(b'('),
                    Token::Symbol(b')')
                ]
                | [
                    Token::Symbol(b'.'),
                    Token::Symbol(b'.'),
                    Token::Symbol(b'.')
                ]
        )
}

fn function_map_evidence(
    function: &FunctionSource,
    language: Language,
    tokens: &[Token<'_>],
    parameters_start: usize,
    parameters_end: usize,
) -> Vec<Evidence> {
    let parameters = dynamic_parameters(tokens, parameters_start, parameters_end, language);
    if parameters.is_empty() {
        return Vec::new();
    }
    let accesses = parameter_key_accesses(tokens, parameters_end + 1, &parameters, language);
    let mut seen_shapes = BTreeSet::new();
    accesses
        .into_values()
        .filter(|keys| (MIN_KEYS..=MAX_KEYS).contains(&keys.len()))
        .filter_map(|keys| {
            let keys = keys.into_iter().collect::<Vec<_>>();
            seen_shapes.insert(keys.clone()).then(|| Evidence {
                path: function.path.clone(),
                function: function.name.clone(),
                line: function.line,
                identity: keys.clone(),
                members: keys,
            })
        })
        .collect()
}

fn function_parameter_evidence(
    function: &FunctionSource,
    language: Language,
    tokens: &[Token<'_>],
    parameters_start: usize,
    parameters_end: usize,
) -> Option<Evidence> {
    let mut parameters = top_level_ranges(tokens, parameters_start, parameters_end)
        .into_iter()
        .filter_map(|(start, end)| simple_parameter(&tokens[start..end], language))
        .collect::<Vec<_>>();
    if !(MIN_PARAMETERS..=MAX_PARAMETERS).contains(&parameters.len()) {
        return None;
    }
    parameters.sort_by(|left, right| left.0.cmp(&right.0));
    Some(Evidence {
        path: function.path.clone(),
        function: function.name.clone(),
        line: function.line,
        identity: parameters
            .iter()
            .map(|(_, identity)| identity.clone())
            .collect(),
        members: parameters.into_iter().map(|(name, _)| name).collect(),
    })
}

fn simple_parameter(tokens: &[Token<'_>], language: Language) -> Option<(String, String)> {
    let colon = top_level_symbol(tokens, b':');
    let equals = top_level_symbol(tokens, b'=');
    let name_end = colon.or(equals).unwrap_or(tokens.len());
    if tokens[..name_end]
        .iter()
        .any(|token| matches!(token, Token::Symbol(b'*' | b'(' | b'[' | b'{' | b'&')))
    {
        return None;
    }
    let names = tokens[..name_end]
        .iter()
        .filter_map(|token| match token {
            Token::Identifier(name) if !matches!(*name, "mut" | "ref") => Some(*name),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [name] = names.as_slice() else {
        return None;
    };
    if matches!(*name, "self" | "cls" | "_" | "findings") {
        return None;
    }

    let identity = match language {
        Language::Python => (*name).to_owned(),
        Language::Rust => {
            let colon = colon?;
            let type_tokens = &tokens[colon + 1..equals.unwrap_or(tokens.len())];
            if !rust_loose_parameter_type(type_tokens) {
                return None;
            }
            let parameter_type = normalized_tokens(type_tokens)?;
            format!("{name}:{parameter_type}")
        }
    };
    Some(((*name).to_owned(), identity))
}

fn rust_loose_parameter_type(tokens: &[Token<'_>]) -> bool {
    tokens.iter().all(|token| match token {
        Token::Identifier(identifier) => matches!(
            *identifier,
            "mut"
                | "str"
                | "String"
                | "bool"
                | "char"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "f32"
                | "f64"
                | "Option"
        ),
        Token::String(_) | Token::Symbol(_) => true,
    })
}

fn normalized_tokens(tokens: &[Token<'_>]) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }
    let mut normalized = String::new();
    for token in tokens {
        match token {
            Token::Identifier(identifier) => normalized.push_str(identifier),
            Token::String(value) => {
                normalized.push('"');
                normalized.push_str(value);
                normalized.push('"');
            }
            Token::Symbol(symbol) => normalized.push(char::from(*symbol)),
        }
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn function_parameters(tokens: &[Token<'_>]) -> Option<(usize, usize)> {
    let function_keyword = tokens
        .iter()
        .position(|token| matches!(token, Token::Identifier("def" | "fn")))?;
    let opening = tokens[function_keyword + 1..]
        .iter()
        .position(|token| *token == Token::Symbol(b'('))?
        + function_keyword
        + 1;
    let closing = matching_symbol(tokens, opening, b'(', b')')?;
    Some((opening + 1, closing))
}

fn dynamic_parameters<'a>(
    tokens: &'a [Token<'a>],
    start: usize,
    end: usize,
    language: Language,
) -> BTreeSet<&'a str> {
    top_level_ranges(tokens, start, end)
        .into_iter()
        .filter_map(|(segment_start, segment_end)| {
            dynamic_parameter(&tokens[segment_start..segment_end], language)
        })
        .collect()
}

fn dynamic_parameter<'a>(tokens: &'a [Token<'a>], language: Language) -> Option<&'a str> {
    let colon = top_level_symbol(tokens, b':');
    let name_end = colon.unwrap_or_else(|| top_level_symbol(tokens, b'=').unwrap_or(tokens.len()));
    let name = tokens[..name_end].iter().find_map(|token| match token {
        Token::Identifier(name) if !matches!(*name, "self" | "cls" | "mut" | "ref") => Some(*name),
        _ => None,
    })?;
    match language {
        Language::Python => {
            let Some(colon) = colon else {
                return Some(name);
            };
            python_dynamic_annotation(&tokens[colon + 1..]).then_some(name)
        }
        Language::Rust => {
            let colon = colon?;
            rust_dynamic_map_type(&tokens[colon + 1..]).then_some(name)
        }
    }
}

fn python_dynamic_annotation(tokens: &[Token<'_>]) -> bool {
    let annotation_end = top_level_symbol(tokens, b'=').unwrap_or(tokens.len());
    tokens[..annotation_end].iter().any(|token| {
        matches!(
            token,
            Token::Identifier("dict" | "Dict" | "Mapping" | "MutableMapping" | "Any" | "object")
        )
    })
}

fn rust_dynamic_map_type(tokens: &[Token<'_>]) -> bool {
    let type_end = top_level_symbol(tokens, b'=').unwrap_or(tokens.len());
    let identifiers = tokens[..type_end]
        .iter()
        .filter_map(|token| match token {
            Token::Identifier(identifier) => Some(*identifier),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let map = identifiers.contains("HashMap") || identifiers.contains("BTreeMap");
    let serde_map = identifiers.contains("serde_json") && identifiers.contains("Map");
    let dynamic_value = identifiers.contains("Value") || identifiers.contains("Any");
    (map || serde_map) && identifiers.contains("String") && dynamic_value
        || identifiers.contains("serde_json") && identifiers.contains("Value")
}

fn parameter_key_accesses<'a>(
    tokens: &[Token<'a>],
    start: usize,
    parameters: &BTreeSet<&'a str>,
    language: Language,
) -> BTreeMap<&'a str, BTreeSet<String>> {
    let mut accesses = BTreeMap::<&str, BTreeSet<String>>::new();
    for index in start..tokens.len() {
        let Token::Identifier(name) = tokens[index] else {
            continue;
        };
        if !parameters.contains(name) {
            continue;
        }
        let key = indexed_key(tokens, index).or_else(|| method_key(tokens, index, language));
        if let Some(key) = key.filter(|key| valid_key(key)) {
            accesses.entry(name).or_default().insert(key.to_owned());
        }
    }
    accesses
}

fn indexed_key<'a>(tokens: &[Token<'a>], index: usize) -> Option<&'a str> {
    match tokens.get(index + 1..index + 4)? {
        [Token::Symbol(b'['), Token::String(key), Token::Symbol(b']')] => Some(*key),
        _ => None,
    }
}

fn method_key<'a>(tokens: &[Token<'a>], index: usize, language: Language) -> Option<&'a str> {
    let method = match language {
        Language::Python => ["get", "pop", "setdefault"].as_slice(),
        Language::Rust => ["get", "get_mut", "contains_key", "remove"].as_slice(),
    };
    match tokens.get(index + 1..index + 5)? {
        [
            Token::Symbol(b'.'),
            Token::Identifier(name),
            Token::Symbol(b'('),
            Token::String(key),
        ] if method.contains(name) => Some(*key),
        _ => None,
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

// code-buster-ignore complex-function: evidence sorting, qualification, and grouping form one deterministic reduction.
fn aggregate(evidence: Vec<Evidence>, code: &'static str, kind: FindingKind) -> Vec<Finding> {
    let mut groups = BTreeMap::<Vec<String>, Vec<Evidence>>::new();
    for candidate in evidence {
        groups
            .entry(candidate.identity.clone())
            .or_default()
            .push(candidate);
    }
    let mut findings = Vec::new();
    for mut occurrences in groups.into_values() {
        occurrences.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.function.cmp(&right.function))
        });
        occurrences.dedup_by(|left, right| {
            left.path == right.path && left.line == right.line && left.function == right.function
        });
        let files = occurrences
            .iter()
            .map(|occurrence| occurrence.path.as_str())
            .collect::<BTreeSet<_>>();
        let functions = occurrences
            .iter()
            .map(|occurrence| occurrence.function.as_str())
            .collect::<BTreeSet<_>>();
        if occurrences.len() < MIN_FUNCTIONS
            || files.len() == 1 && occurrences.len() < MIN_SINGLE_FILE_FUNCTIONS
            || matches!(kind, FindingKind::ParameterClump) && functions.len() < MIN_FUNCTIONS
        {
            continue;
        }
        findings.push(grouped_finding(code, kind, &occurrences, files.len()));
    }
    findings
}

fn grouped_finding(
    code: &'static str,
    kind: FindingKind,
    occurrences: &[Evidence],
    file_count: usize,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("grouped rule metadata must exist");
    let first = &occurrences[0];
    let (subject, member_label) = match kind {
        FindingKind::MapShape => ("fixed map shape", "keys"),
        FindingKind::ParameterClump => ("loose parameter group", "parameters"),
    };
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: first.path.clone(),
        line: first.line,
        end_line: first.line,
        message: format!(
            "{subject} crosses {} functions in {} file{}",
            occurrences.len(),
            file_count,
            if file_count == 1 { "" } else { "s" }
        ),
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: occurrences[1..]
            .iter()
            .map(|occurrence| format!("{}:{}", occurrence.path, occurrence.line))
            .collect(),
        snippet: format!("{member_label}: {}", first.members.join(", ")),
        code_flow: Vec::new(),
    }
}

fn matching_symbol(tokens: &[Token<'_>], opening: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(opening) {
        match token {
            Token::Symbol(symbol) if *symbol == open => depth += 1,
            Token::Symbol(symbol) if *symbol == close => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn top_level_ranges(tokens: &[Token<'_>], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut segment_start = start;
    let mut depths = [0usize; 4];
    for (index, token) in tokens.iter().copied().enumerate().take(end).skip(start) {
        update_depths(token, &mut depths);
        if token == Token::Symbol(b',') && depths.iter().all(|depth| *depth == 0) {
            ranges.push((segment_start, index));
            segment_start = index + 1;
        }
    }
    if segment_start < end {
        ranges.push((segment_start, end));
    }
    ranges
}

fn top_level_symbol(tokens: &[Token<'_>], symbol: u8) -> Option<usize> {
    let mut depths = [0usize; 4];
    for (index, token) in tokens.iter().copied().enumerate() {
        if token == Token::Symbol(symbol) && depths.iter().all(|depth| *depth == 0) {
            return Some(index);
        }
        update_depths(token, &mut depths);
    }
    None
}

fn update_depths(token: Token<'_>, depths: &mut [usize; 4]) {
    let Token::Symbol(symbol) = token else {
        return;
    };
    let (slot, opening) = match symbol {
        b'(' => (0, true),
        b')' => (0, false),
        b'[' => (1, true),
        b']' => (1, false),
        b'{' => (2, true),
        b'}' => (2, false),
        b'<' => (3, true),
        b'>' => (3, false),
        _ => return,
    };
    if opening {
        depths[slot] += 1;
    } else {
        depths[slot] = depths[slot].saturating_sub(1);
    }
}

// code-buster-ignore complex-function: the tokenizer keeps comment, string, and symbol cursor state in one pass.
fn tokenize(source: &str, language: Language) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if let Some(end) = comment_end(bytes, index, language) {
            index = end;
        } else if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                index += 1;
            }
            tokens.push(Token::Identifier(&source[start..index]));
        } else if bytes[index] == b'"'
            || matches!(language, Language::Python) && bytes[index] == b'\''
        {
            let quote = bytes[index];
            let (body_start, body_end, end) = quoted_literal(bytes, index, quote, language);
            tokens.push(Token::String(&source[body_start..body_end]));
            index = end;
        } else {
            tokens.push(Token::Symbol(bytes[index]));
            index += 1;
        }
    }
    tokens
}

fn comment_end(source: &[u8], index: usize, language: Language) -> Option<usize> {
    match language {
        Language::Python if source[index] == b'#' => Some(line_end(source, index)),
        Language::Rust if source.get(index..index + 2) == Some(b"//") => {
            Some(line_end(source, index))
        }
        Language::Rust if source.get(index..index + 2) == Some(b"/*") => {
            Some(rust_block_comment_end(source, index))
        }
        _ => None,
    }
}

fn line_end(source: &[u8], index: usize) -> usize {
    source[index..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(source.len(), |offset| index + offset)
}

fn rust_block_comment_end(source: &[u8], mut index: usize) -> usize {
    let mut depth = 0usize;
    while index < source.len() {
        if source.get(index..index + 2) == Some(b"/*") {
            depth += 1;
            index += 2;
        } else if source.get(index..index + 2) == Some(b"*/") {
            depth = depth.saturating_sub(1);
            index += 2;
            if depth == 0 {
                return index;
            }
        } else {
            index += 1;
        }
    }
    source.len()
}

fn quoted_literal(
    source: &[u8],
    start: usize,
    quote: u8,
    language: Language,
) -> (usize, usize, usize) {
    let triple = matches!(language, Language::Python)
        && source.get(start..start + 3) == Some([quote, quote, quote].as_slice());
    let width = if triple { 3 } else { 1 };
    let body_start = start + width;
    let mut index = body_start;
    while index < source.len() {
        if source[index] == b'\\' {
            index = (index + 2).min(source.len());
            continue;
        }
        let closes = if triple {
            source.get(index..index + 3) == Some([quote, quote, quote].as_slice())
        } else {
            source.get(index) == Some(&quote)
        };
        if closes {
            return (body_start, index, index + width);
        }
        index += 1;
    }
    (body_start, source.len(), source.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_sources;

    fn functions<const N: usize>(sources: [(&str, &str); N]) -> Vec<FunctionSource> {
        function_sources::extract(
            &sources
                .into_iter()
                .map(|(path, source)| (path.to_owned(), source.to_owned()))
                .collect(),
        )
    }

    #[test]
    fn reports_distributed_python_dictionary_shapes() {
        let functions = functions([
            (
                "app/user.py",
                "def display(user: dict[str, object]):\n    return (\n        user[\"id\"], user[\"email\"],\n        user[\"role\"], user[\"active\"],\n    )\n\ndef authorize(user):\n    return user.get(\"id\"), user.get(\"email\"), user.get(\"role\"), user.get(\"active\")\n",
            ),
            (
                "app/audit.py",
                "def audit(user: dict):\n    return user[\"id\"], user[\"email\"], user[\"role\"], user[\"active\"]\n",
            ),
        ]);

        let findings = python(&functions);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "py-repeated-dictionary-shape");
        assert_eq!(findings[0].path, "app/audit.py");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].confidence, "medium");
        assert_eq!(findings[0].related_files.len(), 2);
        assert_eq!(findings[0].snippet, "keys: active, email, id, role");
    }

    #[test]
    fn reports_distributed_rust_dynamic_map_shapes() {
        let functions = functions([
            (
                "src/user.rs",
                r#"fn display(user: &HashMap<String, Value>) {
    let _ = (&user["id"], &user["email"], &user["role"], &user["active"]);
}
fn authorize(user: &HashMap<String, Value>) {
    let _ = (user.get("id"), user.get("email"), user.get("role"), user.get("active"));
}"#,
            ),
            (
                "src/audit.rs",
                r#"fn audit(user: &BTreeMap<String, serde_json::Value>) {
    let _ = (&user["id"], &user["email"], &user["role"], &user["active"]);
}"#,
            ),
        ]);

        let findings = rust(&functions);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "rust-repeated-dynamic-map-shape");
        assert_eq!(findings[0].path, "src/audit.rs");
        assert_eq!(findings[0].related_files.len(), 2);
    }

    #[test]
    fn reports_distributed_python_parameter_clumps() {
        let functions = functions([
            (
                "app/user.py",
                r#"def display(
    name: str,
    email: str,
    role: str,
    active: bool = True,
):
    return name, email, role, active

def authorize(active: bool, role: str, email: str, name: str):
    example = "def ignored(name, email, role, active)"
    # def ignored_too(name, email, role, active)
    return active and role and email and name and example
"#,
            ),
            (
                "app/audit.py",
                "def audit(name, email, role, active):\n    return name, email, role, active\n",
            ),
        ]);

        let findings = python(&functions);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "py-object-soup")
            .expect("repeated loose Python parameters must be reported");

        assert_eq!(findings.len(), 1);
        assert_eq!(finding.path, "app/audit.py");
        assert_eq!(finding.line, 1);
        assert_eq!(finding.confidence, "medium");
        assert_eq!(finding.related_files.len(), 2);
        assert_eq!(finding.snippet, "parameters: active, email, name, role");
    }

    #[test]
    fn reports_distributed_rust_parameter_clumps() {
        let functions = functions([
            (
                "src/user.rs",
                r#"fn display(
    name: &str,
    email: &str,
    role: &str,
    active: bool,
) {
    let _ = (name, email, role, active);
}
fn authorize(active: bool, role: &str, email: &str, name: &str) {
    let _ = (active, role, email, name);
}"#,
            ),
            (
                "src/audit.rs",
                r#"fn audit(name: &str, email: &str, role: &str, active: bool) {
    let _ = (name, email, role, active);
}"#,
            ),
        ]);

        let findings = rust(&functions);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "rust-object-soup")
            .expect("repeated loose Rust parameters must be reported");

        assert_eq!(findings.len(), 1);
        assert_eq!(finding.path, "src/audit.rs");
        assert_eq!(finding.related_files.len(), 2);
        assert_eq!(finding.snippet, "parameters: active, email, name, role");
    }

    #[test]
    fn ignores_repeated_finding_factory_parameters() {
        let functions = functions([
            (
                "src/a.rs",
                "fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding { todo!() }",
            ),
            (
                "src/b.rs",
                "fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding { todo!() }",
            ),
            (
                "src/c.rs",
                "fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding { todo!() }",
            ),
        ]);

        assert!(rust(&functions).is_empty());
    }

    #[test]
    fn ignores_mutable_finding_accumulators_when_grouping_parameters() {
        let functions = functions([
            (
                "src/a.rs",
                "fn first(path: &str, line: usize, code: &str, findings: &mut Vec<Finding>) {}",
            ),
            (
                "src/b.rs",
                "fn second(path: &str, line: usize, code: &str, findings: &mut Vec<Finding>) {}",
            ),
            (
                "src/c.rs",
                "fn third(path: &str, line: usize, code: &str, findings: &mut Vec<Finding>) {}",
            ),
            (
                "src/d.rs",
                "fn fourth(path: &str, line: usize, code: &str, findings: &mut Vec<Finding>) {}",
            ),
        ]);

        assert!(rust(&functions).is_empty());
    }

    #[test]
    fn ignores_groups_already_carried_by_domain_and_collection_types() {
        let functions = functions([
            (
                "src/a.rs",
                "fn first(path: &str, lines: &[&str], current: &PythonLine, disabled: &BTreeSet<String>) {}",
            ),
            (
                "src/b.rs",
                "fn second(path: &str, lines: &[&str], current: &PythonLine, disabled: &BTreeSet<String>) {}",
            ),
            (
                "src/c.rs",
                "fn third(path: &str, lines: &[&str], current: &PythonLine, disabled: &BTreeSet<String>) {}",
            ),
            (
                "src/d.rs",
                "fn fourth(path: &str, lines: &[&str], current: &PythonLine, disabled: &BTreeSet<String>) {}",
            ),
        ]);

        assert!(rust(&functions).is_empty());
    }
    #[test]
    fn ignores_python_parameter_groups_without_distinct_project_repetition() {
        let functions = functions([
            (
                "app/one.py",
                "def handle(name, email, role, active):\n    return name\n",
            ),
            (
                "app/two.py",
                "def handle(active, role, email, name):\n    return email\n",
            ),
            (
                "app/three.py",
                "def handle(name, email, role, active):\n    return role\n",
            ),
            (
                "app/local.py",
                "def first(host, port, user, password):\n    return host\n\ndef second(host, port, user, password):\n    return port\n\ndef third(host, port, user, password):\n    return user\n\ndef test_fourth(host, port, user, password):\n    return password\n",
            ),
        ]);

        assert!(python(&functions).is_empty());
    }

    #[test]
    fn ignores_rust_parameter_groups_with_type_drift_or_trait_style_names() {
        let functions = functions([
            (
                "src/one.rs",
                "fn handle(name: &str, email: &str, role: &str, active: bool) {}\n",
            ),
            (
                "src/two.rs",
                "fn handle(active: bool, role: &str, email: &str, name: &str) {}\n",
            ),
            (
                "src/three.rs",
                "fn handle(name: &str, email: &str, role: &str, active: bool) {}\n",
            ),
            (
                "src/four.rs",
                "fn convert(name: String, email: &str, role: &str, active: bool) {}\n",
            ),
        ]);

        assert!(rust(&functions).is_empty());
    }

    #[test]
    fn ignores_python_compiler_callbacks_and_declaration_stubs() {
        let functions = functions([
            (
                "compiler/first.py",
                "@lower_builtin(Target, Source)\ndef emit_first(context, builder, sig, args):\n    return builder.call(args)\n",
            ),
            (
                "compiler/second.py",
                "@numba.extending.lower_cast(Source, Target)\ndef emit_second(context, builder, sig, args):\n    return builder.cast(args)\n",
            ),
            (
                "compiler/third.py",
                "@lower_constant(Value)\ndef emit_third(context, builder, sig, args):\n    return builder.constant(args)\n",
            ),
            (
                "api/contracts.py",
                r#"def create(context, builder, sig, args) -> Result[
    Created
]: ...
def update(context, builder, sig, args) -> Result[
    Updated
]: ...
def delete(context, builder, sig, args) -> Result[
    Deleted
]: ...
"#,
            ),
        ]);

        assert!(python(&functions).is_empty());
    }

    #[test]
    fn ignores_python_standard_contract_decorators_and_noop_stubs() {
        let functions = functions([
            (
                "contracts/first.py",
                "@override\ndef create(context, builder, sig, args):\n    return context\n",
            ),
            (
                "contracts/second.py",
                "@typing.override\ndef update(context, builder, sig, args):\n    return builder\n",
            ),
            (
                "contracts/third.py",
                "@abstractmethod\ndef delete(context, builder, sig, args):\n    raise NotImplementedError\n",
            ),
            (
                "hooks.py",
                "def before(client, context, event, state):\n    \"\"\"Run before the hook.\"\"\"\n    pass\n\ndef during(client, context, event, state):\n    pass\n\ndef after(client, context, event, state):\n    \"\"\"Run after the hook.\"\"\"\n\ndef finish(client, context, event, state):\n    \"\"\"Run after all hooks.\"\"\"\n    ...\n",
            ),
        ]);

        assert!(python(&functions).is_empty());
    }

    #[test]
    fn ignores_python_not_implemented_declarations() {
        let functions = functions([(
            "contracts.py",
            "def create(context, builder, sig, args):\n    raise NotImplementedError\n\
             def update(context, builder, sig, args):\n    raise NotImplementedError()\n\
             def delete(context, builder, sig, args):\n    \"\"\"Delete a value.\"\"\"\n    raise NotImplementedError\n\
             def inspect(context, builder, sig, args):\n    raise NotImplementedError()\n",
        )]);

        assert!(python(&functions).is_empty());
    }

    #[test]
    fn keeps_python_parameter_clumps_with_non_contract_decorators() {
        let functions = functions([
            (
                "app/first.py",
                "@cache\ndef create(context, builder, sig, args):\n    return context\n",
            ),
            (
                "app/second.py",
                "@cache\ndef update(context, builder, sig, args):\n    return builder\n",
            ),
            (
                "app/third.py",
                "@cache\ndef delete(context, builder, sig, args):\n    return sig\n",
            ),
        ]);

        let findings = python(&functions);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "py-object-soup");
    }

    #[test]
    fn ignores_rust_parameter_groups_required_by_trait_contracts() {
        let functions = functions([
            (
                "src/render.rs",
                "trait Render { fn render(&self, context: &Context, input: Input, span: Span, state: &State); }\nimpl<const N: usize> Render for Page<{ N }> {\n    fn render(&self, context: &Context, input: Input, span: Span, state: &State) {}\n}\n",
            ),
            (
                "src/execute.rs",
                "trait Execute { fn execute(&self, context: &Context, input: Input, span: Span, state: &State); }\nimpl Execute for Command {\n    fn execute(&self, context: &Context, input: Input, span: Span, state: &State) {}\n}\n",
            ),
            (
                "src/dispatch.rs",
                "trait Dispatch { fn dispatch(&self, context: &Context, input: Input, span: Span, state: &State); }\nimpl Dispatch for Handler {\n    fn dispatch(&self, context: &Context, input: Input, span: Span, state: &State) {}\n}\n",
            ),
        ]);

        assert!(rust(&functions).is_empty());
    }

    #[test]
    fn ignores_rust_parameter_groups_required_by_external_bindings() {
        let functions = functions([(
            "src/bindings.rs",
            r#"
#[napi_sym]
fn create(context: &Context, input: Input, span: Span, state: &State) {}
#[unsafe(no_mangle)]
pub extern "C" fn update(context: &Context, input: Input, span: Span, state: &State) {}
#[export_name = "delete_binding"]
fn delete(context: &Context, input: Input, span: Span, state: &State) {}
#[wasm_bindgen]
fn export_wasm(context: &Context, input: Input, span: Span, state: &State) {}
#[pyfunction]
fn export_python(context: &Context, input: Input, span: Span, state: &State) {}
#[jni_mangle("example.Bridge")]
fn export_jni(context: &Context, input: Input, span: Span, state: &State) {}
#[op2]
impl Bridge {
    fn inspect(context: &Context, input: Input, span: Span, state: &State) {}
    fn render(context: &Context, input: Input, span: Span, state: &State) {}
}
#[pyo3::pymethods]
impl PythonBridge {
    fn encode(context: &Context, input: Input, span: Span, state: &State) {}
}
#[napi_derive::napi]
impl NodeBridge {
    fn decode(context: &Context, input: Input, span: Span, state: &State) {}
}
"#,
        )]);

        assert!(functions.iter().all(|function| function.contract_signature));
        assert!(rust(&functions).is_empty());
    }

    #[test]
    fn keeps_dynamic_map_shape_evidence_inside_trait_methods() {
        let functions = functions([
            (
                "src/render.rs",
                "impl Render for Page {\n    fn render(&self, data: &HashMap<String, Value>) {\n        let _ = (data.get(\"id\"), data.get(\"email\"), data.get(\"role\"), data.get(\"active\"));\n    }\n}\n",
            ),
            (
                "src/execute.rs",
                "impl Execute for Command {\n    fn execute(&self, data: &HashMap<String, Value>) {\n        let _ = (data.get(\"id\"), data.get(\"email\"), data.get(\"role\"), data.get(\"active\"));\n    }\n}\n",
            ),
            (
                "src/dispatch.rs",
                "impl Dispatch for Handler {\n    fn dispatch(&self, data: &HashMap<String, Value>) {\n        let _ = (data.get(\"id\"), data.get(\"email\"), data.get(\"role\"), data.get(\"active\"));\n    }\n}\n",
            ),
        ]);

        let findings = rust(&functions);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "rust-repeated-dynamic-map-shape");
    }

    #[test]
    fn ignores_typed_python_models_tests_and_small_or_local_shapes() {
        let functions = functions([(
            "app/user.py",
            r#"def first(user: User):
    return user["id"], user["email"], user["role"], user["active"]
def second(user):
    return user["id"], user["email"], user["role"]
def test_mapping(user):
    return user["id"], user["email"], user["role"], user["active"]
def literal_example(user):
    text = 'user["id"] user["email"] user["role"] user["active"]'
    # user["id"], user["email"], user["role"], user["active"]
    return text
"#,
        )]);

        assert!(python(&functions).is_empty());
    }

    #[test]
    fn ignores_rust_structs_dynamic_metadata_and_inline_tests() {
        let functions = functions([(
            "src/lib.rs",
            r#"fn typed(user: &User) {
    let _ = (&user["id"], &user["email"], &user["role"], &user["active"]);
}
fn first(metadata: &HashMap<String, Value>) {
    let _ = (&metadata["id"], &metadata["email"], &metadata["role"], &metadata["active"]);
}
fn second(metadata: &HashMap<String, Value>) {
    let _ = (&metadata["id"], &metadata["email"], &metadata["role"], &metadata["active"]);
}
#[cfg(test)]
mod tests {
    #[test]
    fn third(metadata: &HashMap<String, Value>) {
        let _ = (&metadata["id"], &metadata["email"], &metadata["role"], &metadata["active"]);
    }
}
"#,
        )]);

        assert!(rust(&functions).is_empty());
    }
}
