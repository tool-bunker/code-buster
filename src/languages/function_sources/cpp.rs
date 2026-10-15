fn cpp_functions(
    path: &str,
    source: &str,
    stringifying_macros: &BTreeSet<String>,
) -> Vec<FunctionSource> {
    let masked = mask_comments_and_strings(source);
    let raw_lines = masked.split('\n').collect::<Vec<_>>();
    let preprocessed = mask_inactive_preprocessor_branches(&raw_lines);
    let lines = mask_cpp_stringifying_arguments(preprocessed, stringifying_macros);
    let mut functions = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some(name) = discover_cpp_function_candidate(&lines, index) else {
            index += 1;
            continue;
        };
        let end = extract_cpp_function(path, &lines, index, name, &mut functions);
        index = end + 1;
    }
    functions
}

fn discover_cpp_function_candidate(lines: &[String], index: usize) -> Option<String> {
    let first_line = &lines[index];
    if !qualifies_as_cpp_declaration(first_line) {
        return None;
    }

    let (matched, name) = cpp_declaration_candidate(first_line);
    if matched {
        return name;
    }
    if !is_cpp_signature_start(first_line) {
        return None;
    }

    cpp_declaration_candidate(&assemble_cpp_signature(lines, index)).1
}

fn qualifies_as_cpp_declaration(line: &str) -> bool {
    let trimmed = line.trim_start();
    !CPP_CONTROL.is_match(trimmed)
        && !trimmed.starts_with(':')
        && !trimmed.starts_with("typedef ")
}

fn cpp_declaration_candidate(declaration: &str) -> (bool, Option<String>) {
    let Some(declaration) = CPP_OBJECTIVE_C_METHOD
        .captures(declaration)
        .or_else(|| CPP_FUNCTION.captures(declaration))
    else {
        return (false, None);
    };
    let name = declaration.name("name").map(|name| name.as_str());
    (
        true,
        name.filter(|name| !CPP_CONTROL_NAME.is_match(name))
            .map(str::to_owned),
    )
}

fn is_cpp_signature_start(line: &str) -> bool {
    CPP_UNQUALIFIED_SIGNATURE.is_match(line)
        || CPP_QUALIFIED_SIGNATURE.is_match(line)
        || CPP_OBJECTIVE_C_SIGNATURE.is_match(line)
}

fn assemble_cpp_signature(lines: &[String], index: usize) -> String {
    let mut signature = String::new();
    for line in lines.iter().skip(index).take(21) {
        signature.push_str(line);
        signature.push('\n');
        if line.contains('{') || line.contains(';') {
            break;
        }
    }
    signature
}

fn extract_cpp_function(
    path: &str,
    lines: &[String],
    start: usize,
    name: String,
    functions: &mut Vec<FunctionSource>,
) -> usize {
    let end = brace_delimited_end_owned(lines, start);
    let source = lines[start..=end].join("\n");
    functions.extend(cpp_function_and_lambdas(
        path,
        name,
        start + 1,
        &source,
    ));
    end
}

fn cpp_function_and_lambdas(
    path: &str,
    name: String,
    line: usize,
    source: &str,
) -> Vec<FunctionSource> {
    let masked = mask_comments_and_strings(source);
    let mut lambdas = BTreeMap::<usize, (usize, usize)>::new();
    for matched in CPP_LAMBDA.find_iter(&masked) {
        let Some(relative_opening) = masked[matched.start()..matched.end()].find('{') else {
            continue;
        };
        let opening = matched.start() + relative_opening;
        let Some(end) = matching_delimiter(&masked, opening, b'{', b'}') else {
            continue;
        };
        lambdas.insert(opening, (matched.start(), end));
    }

    let mut functions = vec![FunctionSource {
        path: path.to_owned(),
        name,
        line,
        end_line: line + source.matches('\n').count(),
        contract_signature: false,
        source: mask_nested_cpp_lambdas(source, 0, None, source.len() - 1, &lambdas),
    }];
    for (opening, (start, end)) in &lambdas {
        functions.push(FunctionSource {
            path: path.to_owned(),
            name: "<lambda>".to_owned(),
            line: line + source[..*start].matches('\n').count(),
            end_line: line + source[..=*end].matches('\n').count(),
            contract_signature: false,
            source: mask_nested_cpp_lambdas(source, *start, Some(*opening), *end, &lambdas),
        });
    }
    functions
}

fn mask_nested_cpp_lambdas(
    source: &str,
    start: usize,
    opening: Option<usize>,
    end: usize,
    lambdas: &BTreeMap<usize, (usize, usize)>,
) -> String {
    let mut result = source.as_bytes()[start..=end].to_vec();
    for (nested_opening, (nested_start, nested_end)) in lambdas {
        if opening.is_some_and(|opening| *nested_opening <= opening) || *nested_end > end {
            continue;
        }
        for byte in &mut result[nested_start - start..=nested_end - start] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(result).expect("C++ lambda masking preserves UTF-8")
}

fn cpp_stringifying_macros<'a>(sources: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    let mut definitions = BTreeMap::<String, (String, String)>::new();
    for source in sources {
        for captures in CPP_FUNCTION_MACRO_DEFINITION.captures_iter(source) {
            definitions.insert(
                captures.get(1).unwrap().as_str().to_owned(),
                (
                    captures.get(2).unwrap().as_str().to_owned(),
                    captures.get(3).unwrap().as_str().to_owned(),
                ),
            );
        }
    }
    let mut result = BTreeSet::new();
    for (name, (parameter, replacement)) in &definitions {
        let pattern = Regex::new(&format!(r"(^|[^#])#\s*{}\b", regex::escape(parameter))).unwrap();
        if pattern.is_match(replacement) {
            result.insert(name.clone());
        }
    }
    loop {
        let mut changed = false;
        for (name, (parameter, replacement)) in &definitions {
            if result.contains(name) {
                continue;
            }
            let wraps_stringifier = result.iter().any(|stringifier| {
                Regex::new(&format!(
                    r"\b{}\s*\(\s*{}\s*\)",
                    regex::escape(stringifier),
                    regex::escape(parameter)
                ))
                .unwrap()
                .is_match(replacement)
            });
            if wraps_stringifier {
                result.insert(name.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    result
}

fn mask_cpp_stringifying_arguments(
    lines: Vec<String>,
    macro_names: &BTreeSet<String>,
) -> Vec<String> {
    if macro_names.is_empty() {
        return lines;
    }
    let source = lines.join("\n");
    let mut masked = source.as_bytes().to_vec();
    let Ok(invocation) = Regex::new(&format!(
        r"\b(?:{})\s*\(",
        macro_names
            .iter()
            .map(|name| regex::escape(name))
            .collect::<Vec<_>>()
            .join("|")
    )) else {
        return lines;
    };
    for matched in invocation.find_iter(&source) {
        let line_start = source[..matched.start()]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        if CPP_DEFINE.is_match(&source[line_start..matched.start()]) {
            continue;
        }
        let Some(open) = source[matched.start()..]
            .find('(')
            .map(|offset| matched.start() + offset)
        else {
            continue;
        };
        let Some(close) = matching_delimiter(&source, open, b'(', b')') else {
            continue;
        };
        for byte in &mut masked[open + 1..close] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(masked)
        .expect("C++ macro masking preserves UTF-8")
        .split('\n')
        .map(str::to_owned)
        .collect()
}

fn brace_delimited_end_owned(lines: &[String], start: usize) -> usize {
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
static CPP_LAMBDA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\[[^\]\r\n]*\]\s*(?:\([^;{}]*\))?\s*(?:(?:mutable|constexpr|consteval)\s+)*(?:noexcept(?:\s*\([^)]*\))?\s*)?(?:->\s*[^{}]+)?\{",
    )
    .expect("C++ lambda regex must compile")
});
static CPP_FUNCTION_MACRO_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*#\s*define\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s+([^\r\n]+)$")
        .expect("C++ macro definition regex must compile")
});
static CPP_DEFINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*#\s*define\b").expect("C++ define regex must compile"));
static CPP_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[\s*&])(?:[A-Za-z_]\w*::)*(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{",
    )
    .expect("C++ function regex must compile")
});
static CPP_UNQUALIFIED_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:[A-Za-z_]\w*[\s*&]+)+[A-Za-z_]\w*\s*\(")
        .expect("C++ unqualified signature regex must compile")
});
static CPP_QUALIFIED_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:[A-Za-z_]\w*::)+(?:~?[A-Za-z_]\w*)\s*\(")
        .expect("C++ qualified signature regex must compile")
});
static CPP_OBJECTIVE_C_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*[-+]\s*\(").expect("Objective-C signature regex must compile")
});
static CPP_OBJECTIVE_C_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*[-+]\s*\([^)]*\)\s*(?P<name>[A-Za-z_]\w*)[^;{}]*\{")
        .expect("Objective-C method regex must compile")
});
static CPP_CONTROL_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:if|for|while|switch|catch)$").expect("C++ control name regex must compile")
});
static CPP_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:if|for|while|switch|catch)\b").expect("C++ control regex must compile")
});
