fn go_functions(path: &str, source: &str) -> Vec<FunctionSource> {
    let mut functions = Vec::new();
    let mut offset = 0;
    let mut line = 1;
    while offset <= source.len() {
        let line_end = source[offset..]
            .find('\n')
            .map_or(source.len(), |relative| offset + relative);
        let current = &source[offset..line_end];
        let Some(declaration) = GO_FUNCTION_DECLARATION.captures(current) else {
            if line_end == source.len() {
                break;
            }
            offset = line_end + 1;
            line += 1;
            continue;
        };
        let name = declaration.name("name").unwrap().as_str().to_owned();
        let start = offset;
        let start_line = line;
        let mut end = line_end;
        let mut end_line = line;
        let mut depth = 0isize;
        let mut started = false;
        loop {
            let body_line = &source[offset..end];
            depth += body_line.bytes().filter(|byte| *byte == b'{').count() as isize;
            depth -= body_line.bytes().filter(|byte| *byte == b'}').count() as isize;
            started |= body_line.contains('{');
            if started && depth <= 0 || end == source.len() {
                break;
            }
            offset = end + 1;
            line += 1;
            end = source[offset..]
                .find('\n')
                .map_or(source.len(), |relative| offset + relative);
            end_line = line;
        }
        functions.push(FunctionSource {
            path: path.to_owned(),
            name,
            line: start_line,
            end_line,
            source: source[start..end].to_owned(),
        });
        if end == source.len() {
            break;
        }
        offset = end + 1;
        line += 1;
    }
    functions
}
static GO_FUNCTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*func[ \t]+(?:\([^)]*\)[ \t]*)?(?P<name>[A-Za-z_]\w*)[ \t]*\(")
        .expect("Go function declaration regex must compile")
});
