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

#[derive(Default)]
pub(crate) struct RustComplexityContext {
    quote_bindings: BTreeSet<String>,
    quote_lines: Vec<(usize, usize)>,
}

impl RustComplexityContext {
    pub(crate) fn new(source: &str) -> Self {
        if !source.contains("quote::") {
            return Self::default();
        }
        let (masked, _) = function_lexical_facts(source);
        let mut quote_bindings = BTreeSet::new();
        for captures in RUST_QUOTE_IMPORT.captures_iter(&masked) {
            for import in captures["imports"].trim_matches(['{', '}']).split(',') {
                let mut words = import.split_whitespace();
                if words.next() != Some("quote") {
                    continue;
                }
                let name = match (words.next(), words.next(), words.next()) {
                    (None, None, None) => "quote",
                    (Some("as"), Some(alias), None) => alias,
                    _ => continue,
                };
                quote_bindings.insert(name.to_owned());
            }
        }
        // Local macro shadowing is deliberately conservative without name resolution.
        for captures in RUST_MACRO_DEFINITION.captures_iter(&masked) {
            quote_bindings.remove(captures.name("name").expect("macro name capture").as_str());
        }
        let quote_lines = rust_quote_templates(&masked, Some(&quote_bindings))
            .into_iter()
            .map(|(start, end)| (line_at(source, start), line_at(source, end)))
            .collect();
        Self { quote_bindings, quote_lines }
    }

    pub(crate) fn contains_template_function(&self, line: usize) -> bool {
        self.quote_lines.iter().any(|&(start, end)| start < line && line <= end)
    }
}

pub(crate) fn rust_complexity_source(
    source: &str,
    context: Option<&RustComplexityContext>,
) -> String {
    let (masked, _) = function_lexical_facts(source);
    let templates = rust_quote_templates(&masked, context.map(|context| &context.quote_bindings));
    let mut bytes = masked.into_bytes();
    for (start, end) in templates {
        blank_rust_complexity_bytes(&mut bytes[start..=end]);
    }
    for (start, _) in source.match_indices("||") {
        if bytes.get(start..start + 2) == Some(b"||")
            && rust_empty_closure_prefix(&bytes[..start])
        {
            bytes[start..start + 2].fill(b' ');
        }
    }
    let masked = String::from_utf8(bytes).expect("Rust template masking preserves UTF-8");
    // Skip the owner, retaining independent extraction of every nested callable.
    let nested_functions = RUST_FUNCTION.find_iter(&masked).skip(1);
    let mut excluded = BTreeMap::new();
    for declaration in nested_functions.chain(RUST_LOCAL_IMPL.find_iter(&masked)) {
        if let Some(end) = matching_masked_brace(&masked, declaration.end() - 1) {
            excluded.insert(declaration.start(), end);
        }
    }
    let mut bytes = masked.into_bytes();
    let mut masked_until = None;
    for (start, end) in excluded {
        if masked_until.is_some_and(|previous_end| start <= previous_end) {
            continue;
        }
        blank_rust_complexity_bytes(&mut bytes[start..=end]);
        masked_until = Some(end);
    }
    String::from_utf8(bytes).expect("Rust scope masking preserves UTF-8")
}

fn blank_rust_complexity_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        if !matches!(*byte, b'\n' | b'\r') {
            *byte = b' ';
        }
    }
}

fn rust_empty_closure_prefix(prefix: &[u8]) -> bool {
    let end = prefix
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    let prefix = &prefix[..end];
    if prefix.last().is_none_or(|byte| b"([{,=;".contains(byte))
        || prefix.ends_with(b"=>")
    {
        return true;
    }
    ["move", "async", "return", "break"].iter().any(|keyword| {
        prefix.strip_suffix(keyword.as_bytes()).is_some_and(|before| {
            before.last().is_none_or(|byte| {
                byte.is_ascii() && !byte.is_ascii_alphanumeric() && !b"_#.".contains(byte)
            })
        })
    })
}

fn rust_quote_templates(
    masked: &str,
    imported: Option<&BTreeSet<String>>,
) -> Vec<(usize, usize)> {
    RUST_MACRO_INVOCATION
        .captures_iter(masked)
        .filter(|captures| {
            let path = captures.name("path").map_or("", |path| path.as_str());
            let name = captures.name("name").expect("macro name capture").as_str();
            (matches!(path, "quote::" | "::quote::") && name == "quote")
                || (path.is_empty() && imported.is_some_and(|names| names.contains(name)))
        })
        .filter_map(|captures| {
            let opening = captures.name("opening")?.start();
            let (open, close) = match masked.as_bytes()[opening] {
                b'{' => (b'{', b'}'),
                b'(' => (b'(', b')'),
                b'[' => (b'[', b']'),
                _ => return None,
            };
            matching_delimiter(masked, opening, open, close).map(|closing| (opening, closing))
        })
        .collect()
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

static RUST_LOCAL_IMPL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:unsafe[ \t]+)?impl\b[^;{]*\{")
        .expect("Rust local impl regex must compile")
});
static RUST_QUOTE_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\buse\s+(?:::)?quote::(?P<imports>\{[^{};]*\}|[^{};]+);")
        .expect("Rust quote import regex must compile")
});
static RUST_MACRO_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bmacro_rules\s*!\s*(?P<name>[A-Za-z_]\w*)")
        .expect("Rust macro definition regex must compile")
});
static RUST_MACRO_INVOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<path>(?:::)?(?:[A-Za-z_]\w*::)*)(?P<name>[A-Za-z_]\w*)\s*!\s*(?P<opening>[{(\[])")
        .expect("Rust macro invocation regex must compile")
});
