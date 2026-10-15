fn indentation_functions(path: &str, source: &str, extension: &str) -> Vec<FunctionSource> {
    let declaration = match extension {
        "nim" | "nims" => &*NIM_FUNCTION,
        "mojo" => &*MOJO_FUNCTION,
        _ => &*PYTHON_FUNCTION,
    };
    let lines: Vec<&str> = source.split('\n').collect();
    let masked_source = mask_comments_and_strings(source);
    let masked_lines = masked_source.split('\n').collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some(captures) = declaration.captures(masked_lines[index]) else {
            index += 1;
            continue;
        };
        let Some(name) = captures.name("name").map(|matched| matched.as_str()) else {
            continue;
        };
        let indentation = indent(lines[index], extension.starts_with("nim"));
        let mut signature_depth = if extension == "py" {
            update_delimiter_depth(masked_lines[index], 0)
        } else {
            0
        };
        let mut end = index + 1;
        while end < lines.len()
            && (signature_depth > 0
                || lines[end].trim().is_empty()
                || indent(lines[end], extension.starts_with("nim")) > indentation)
        {
            if signature_depth > 0 {
                signature_depth = update_delimiter_depth(masked_lines[end], signature_depth);
            }
            end += 1;
        }
        let source = lines[index..end].join("\n");
        result.push(FunctionSource {
            path: path.to_owned(),
            name: name.to_owned(),
            line: index + 1,
            end_line: index + source.matches('\n').count() + 1,
            contract_signature: extension == "py" && python_contract_signature(&lines, index),
            source,
        });
        index = if extension == "py" { index + 1 } else { end };
    }
    result
}

fn python_contract_signature(lines: &[&str], function_line: usize) -> bool {
    let function_indent = indent(lines[function_line], false);
    for line in lines[..function_line].iter().rev() {
        if line.trim().is_empty()
            || indent(line, false) != function_indent
            || !line.trim_start().starts_with('@')
        {
            break;
        }
        let decorator = line
            .trim_start()
            .trim_start_matches('@')
            .split(['(', ' ', '\t'])
            .next()
            .unwrap_or_default()
            .rsplit('.')
            .next()
            .unwrap_or_default();
        if matches!(
            decorator,
            "abstractmethod"
                | "box"
                | "lower_builtin"
                | "lower_cast"
                | "lower_constant"
                | "lower_getattr"
                | "lower_setattr"
                | "overload"
                | "override"
                | "unbox"
        ) {
            return true;
        }
    }
    false
}

fn update_delimiter_depth(line: &str, mut depth: usize) -> usize {
    for byte in line.bytes() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}
static PYTHON_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*(?:\[[^]]+\])?[ \t]*\(",
    )
    .expect("Python function regex must compile")
});
static MOJO_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*def[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*(?:\[[^]]*\])?[ \t]*\([^)]*\)[^:]*:")
        .expect("Mojo function regex must compile")
});
static NIM_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*(?:proc|func|method|iterator)[ \t]+`?(?P<name>[A-Za-z_]\w*)`?[*]?[ \t]*(?:\[[^]]*\])?[ \t]*\(")
        .expect("Nim function regex must compile")
});
