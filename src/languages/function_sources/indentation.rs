fn indentation_functions(path: &str, source: &str, extension: &str) -> Vec<FunctionSource> {
    let declaration = match extension {
        "nim" | "nims" => &*NIM_FUNCTION,
        "mojo" => &*MOJO_FUNCTION,
        _ => &*PYTHON_FUNCTION,
    };
    let lines: Vec<&str> = source.split('\n').collect();
    let mut result = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some(captures) = declaration.captures(lines[index]) else {
            index += 1;
            continue;
        };
        let Some(name) = captures.name("name").map(|matched| matched.as_str()) else {
            continue;
        };
        let indentation = indent(lines[index], extension.starts_with("nim"));
        let mut end = index + 1;
        while end < lines.len()
            && (lines[end].trim().is_empty()
                || indent(lines[end], extension.starts_with("nim")) > indentation)
        {
            end += 1;
        }
        let source = lines[index..end].join("\n");
        result.push(FunctionSource {
            path: path.to_owned(),
            name: name.to_owned(),
            line: index + 1,
            end_line: index + source.matches('\n').count() + 1,
            source,
        });
        index = if extension == "py" { index + 1 } else { end };
    }
    result
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
