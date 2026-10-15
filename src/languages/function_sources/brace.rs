fn brace_functions(path: &str, source: &str, patterns: &[&Regex]) -> Vec<FunctionSource> {
    let mut candidates = Vec::new();
    let mut openings = BTreeSet::new();
    for pattern in patterns {
        for captures in pattern.captures_iter(source) {
            let Some(complete) = captures.get(0) else {
                continue;
            };
            let Some(name) = captures.name("name") else {
                continue;
            };
            let Some(opening_offset) = source[complete.start()..complete.end()].rfind('{') else {
                continue;
            };
            let opening = complete.start() + opening_offset;
            if !openings.insert(opening) {
                continue;
            }
            let normalized_name = name.as_str();
            if is_control_keyword(normalized_name) {
                continue;
            }
            let Some(closing) = matching_brace(source, opening) else {
                continue;
            };
            let line = line_at(source, complete.start());
            candidates.push(FunctionSource {
                path: path.to_owned(),
                name: normalized_name.to_owned(),
                line,
                end_line: line_at(source, closing),
                contract_signature: false,
                source: source[complete.start()..=closing].to_owned(),
            });
        }
    }
    candidates
}

fn java_functions(path: &str, source: &str) -> Vec<FunctionSource> {
    let lines = source.split('\n').collect::<Vec<_>>();
    let mut functions = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let declaration = JAVA_LEADING_BLOCK
            .replace(lines[index].trim_start(), "")
            .into_owned();
        let Some(captures) = JAVA_METHOD.captures(&declaration) else {
            index += 1;
            continue;
        };
        if JAVA_CONTROL.is_match(&declaration) {
            index += 1;
            continue;
        }
        let name = captures.name("name").unwrap().as_str().to_owned();
        let end = brace_delimited_end(&lines, index);
        functions.push(FunctionSource {
            path: path.to_owned(),
            name,
            line: index + 1,
            end_line: end + 1,
            contract_signature: false,
            source: lines[index..=end].join("\n"),
        });
        index = end + 1;
    }
    functions
}

struct CsharpFunctionCandidate {
    start: usize,
    name: String,
}

fn csharp_functions(path: &str, source: &str) -> Vec<FunctionSource> {
    let lines = source.split('\n').collect::<Vec<_>>();
    let mut functions = Vec::new();
    let mut search_start = 0;
    while let Some(candidate) = next_csharp_function_candidate(&lines, search_start) {
        let end = brace_delimited_end(&lines, candidate.start);
        search_start = end + 1;
        functions.push(build_csharp_function(path, &lines, candidate, end));
    }
    functions
}

fn next_csharp_function_candidate(
    lines: &[&str],
    search_start: usize,
) -> Option<CsharpFunctionCandidate> {
    for start in search_start..lines.len() {
        let Some(name) = csharp_candidate_name(lines, start) else {
            continue;
        };
        return Some(CsharpFunctionCandidate { start, name });
    }
    None
}

fn csharp_candidate_name(lines: &[&str], start: usize) -> Option<String> {
    let line = lines[start];
    let candidate = line.trim_start();
    if !line.contains('(') || is_excluded_csharp_candidate(candidate) {
        return None;
    }

    csharp_method_name(&csharp_signature(lines, start))
}

fn is_excluded_csharp_candidate(candidate: &str) -> bool {
    const EXCLUDED_PREFIXES: [&str; 4] = ["//", "/*", "*", "where "];
    EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| candidate.starts_with(prefix))
        || CSHARP_TYPE_DECLARATION.is_match(candidate)
        || CSHARP_CONTROL.is_match(candidate)
}

fn csharp_signature(lines: &[&str], start: usize) -> String {
    let mut signature_end = start;
    let mut signature = lines[start].to_owned();
    while !signature.contains('{')
        && !signature.contains(';')
        && !signature.contains("=>")
        && signature_end + 1 < lines.len()
        && signature_end - start < 12
    {
        signature_end += 1;
        signature.push('\n');
        signature.push_str(lines[signature_end]);
    }
    signature
}

fn build_csharp_function(
    path: &str,
    lines: &[&str],
    candidate: CsharpFunctionCandidate,
    end: usize,
) -> FunctionSource {
    FunctionSource {
        path: path.to_owned(),
        name: candidate.name,
        line: candidate.start + 1,
        end_line: end + 1,
        contract_signature: false,
        source: lines[candidate.start..=end].join("\n"),
    }
}

fn brace_delimited_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0isize;
    let mut started = false;
    for (index, line) in lines.iter().enumerate().skip(start) {
        depth += line.matches('{').count() as isize;
        depth -= line.matches('}').count() as isize;
        started |= line.contains('{');
        if started && depth <= 0 {
            return index;
        }
    }
    lines.len().saturating_sub(1)
}

fn csharp_method_name(signature: &str) -> Option<String> {
    let body = signature.find('{')?;
    let bytes = signature.as_bytes();
    let mut index = 0usize;
    while index < body {
        if !is_csharp_identifier_start(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < body && is_csharp_identifier_part(bytes[index]) {
            index += 1;
        }
        let name = &signature[start..index];
        if is_csharp_non_method_name(name) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(bytes, index, body);
        if bytes.get(cursor) == Some(&b'<') {
            let Some(generic_end) = matching_delimiter(signature, cursor, b'<', b'>') else {
                continue;
            };
            cursor = skip_ascii_whitespace(bytes, generic_end + 1, body);
        }
        if bytes.get(cursor) != Some(&b'(') {
            continue;
        }
        let Some(parameters_end) = matching_delimiter(signature, cursor, b'(', b')') else {
            continue;
        };
        if parameters_end < body
            && is_csharp_declaration_suffix(&signature[parameters_end + 1..body])
        {
            return Some(name.to_owned());
        }
    }
    None
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize, end: usize) -> usize {
    while index < end && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn is_csharp_declaration_suffix(suffix: &str) -> bool {
    let suffix = suffix.trim();
    if suffix.is_empty() || suffix.starts_with("where ") {
        return true;
    }
    let Some(initializer) = suffix.strip_prefix(':').map(str::trim_start) else {
        return false;
    };
    let Some(name_end) = initializer.find(|character: char| !character.is_ascii_alphabetic())
    else {
        return false;
    };
    if !matches!(&initializer[..name_end], "base" | "this") {
        return false;
    }
    let bytes = initializer.as_bytes();
    let opening = skip_ascii_whitespace(bytes, name_end, bytes.len());
    bytes.get(opening) == Some(&b'(')
        && matching_delimiter(initializer, opening, b'(', b')')
            .is_some_and(|closing| initializer[closing + 1..].trim().is_empty())
}

fn is_csharp_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_csharp_identifier_part(byte: u8) -> bool {
    is_csharp_identifier_start(byte) || byte.is_ascii_digit()
}

fn is_csharp_non_method_name(name: &str) -> bool {
    matches!(
        name,
        "public"
            | "private"
            | "protected"
            | "internal"
            | "static"
            | "virtual"
            | "override"
            | "abstract"
            | "sealed"
            | "async"
            | "unsafe"
            | "extern"
            | "partial"
            | "new"
            | "extension"
            | "bool"
            | "byte"
            | "char"
            | "decimal"
            | "double"
            | "float"
            | "int"
            | "long"
            | "object"
            | "sbyte"
            | "short"
            | "string"
            | "uint"
            | "ulong"
            | "ushort"
            | "void"
    )
}
static JAVA_LEADING_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:}\s*)+(?:else\s+)?").expect("Java leading block regex must compile")
});
static JAVA_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{")
        .expect("Java method regex must compile")
});
static JAVA_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:if|for|while|switch|catch|try|synchronized)\b")
        .expect("Java control regex must compile")
});
static CSHARP_TYPE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:public|internal|private|protected)\s+)?(?:(?:static|sealed|abstract|partial)\s+)*(?:class|interface|struct|enum|record)\s+([A-Za-z_]\w*)",
    )
    .expect("C# type declaration regex must compile")
});
static CSHARP_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:if|for|foreach|while|switch|catch|using|lock)\b")
        .expect("C# control regex must compile")
});
static BRACE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:public|private|protected|static|abstract|override|readonly|async|get|set)[ \t]+)*(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:<[^>{}]*>)?[ \t]*\([^;{}]*\)[^{;]*\{")
        .expect("brace method regex must compile")
});
