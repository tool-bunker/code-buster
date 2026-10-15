fn rust_functions(path: &str, source: &str) -> Vec<FunctionSource> {
    let (masked, test_lines) = function_lexical_facts(source);
    let mut functions = Vec::new();
    for captures in RUST_FUNCTION.captures_iter(&masked) {
        let complete = captures
            .get(0)
            .expect("Rust function pattern must include a complete match");
        let Some(name) = captures.name("name") else {
            continue;
        };
        let Some(opening_offset) = masked[complete.start()..complete.end()].find('{') else {
            continue;
        };
        let opening = complete.start() + opening_offset;
        let line = line_at(&masked, complete.start());
        if test_lines.contains(&(line - 1)) {
            continue;
        }
        let Some(closing) = matching_masked_brace(&masked, opening) else {
            continue;
        };
        functions.push(FunctionSource {
            path: path.to_owned(),
            name: name.as_str().to_owned(),
            line,
            end_line: line_at(source, closing),
            source: source[complete.start()..=closing].to_owned(),
        });
    }
    functions
}
static RUST_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?(?:unsafe[ \t]+)?(?:extern[ \t]+"[^"]+"[ \t]+)?fn[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*(?:<[^>{}]*>)?[ \t]*\([^;{}]*\)[^{;]*\{"#)
        .expect("Rust function regex must compile")
});
