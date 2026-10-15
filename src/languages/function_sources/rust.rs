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
            contract_signature: rust_contract_signature(
                &masked,
                complete.start(),
                complete.as_str(),
            ),
            source: source[complete.start()..=closing].to_owned(),
        });
    }
    functions
}

fn rust_contract_signature(source: &str, function_start: usize, header: &str) -> bool {
    rust_trait_or_binding_method(source, function_start)
        || header
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|word| word == "extern")
        || rust_binding_attributes(rust_item_prefix(source, function_start))
}

fn rust_item_prefix(source: &str, item_start: usize) -> &str {
    let prefix = &source[..item_start];
    let boundary = prefix
        .rfind(['{', '}', ';'])
        .map_or(0, |boundary| boundary + 1);
    &prefix[boundary..]
}

fn rust_binding_attributes(source: &str) -> bool {
    source
        .split("#[")
        .skip(1)
        .filter_map(|attribute| attribute.split_once(']').map(|(attribute, _)| attribute))
        .flat_map(|attribute| {
            attribute
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        })
        .any(|word| {
            matches!(
                word,
                "export_name"
                    | "jni_mangle"
                    | "napi"
                    | "napi_sym"
                    | "no_mangle"
                    | "op2"
                    | "pyfunction"
                    | "pymethods"
                    | "wasm_bindgen"
            )
        })
}

fn rust_trait_or_binding_method(source: &str, function_start: usize) -> bool {
    let mut openings = Vec::new();
    for (index, byte) in source.bytes().take(function_start).enumerate() {
        match byte {
            b'{' => openings.push(index),
            b'}' => {
                openings.pop();
            }
            _ => {}
        }
    }
    let Some((&opening, parent_openings)) = openings.split_last() else {
        return false;
    };
    let container_start = parent_openings.last().map_or(0, |parent| parent + 1);
    let mut container = None;
    let mut implementation_has_for = false;
    for word in source[container_start..opening]
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|word| !word.is_empty())
    {
        match word {
            "trait" => container = Some("trait"),
            "impl" => {
                container = Some("impl");
                implementation_has_for = false;
            }
            "for" if container == Some("impl") => implementation_has_for = true,
            _ => {}
        }
    }
    let trait_contract =
        container == Some("trait") || container == Some("impl") && implementation_has_for;
    trait_contract || rust_binding_attributes(rust_item_prefix(source, opening))
}
static RUST_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?(?:unsafe[ \t]+)?(?:extern[ \t]+"[^"]+"[ \t]+)?fn[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*(?:<[^>{}]*>)?[ \t]*\([^;{}]*\)[^{;]*\{"#)
        .expect("Rust function regex must compile")
});
