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
    templates: Vec<(usize, usize, usize)>,
    line_offsets: Vec<usize>,
    quote_lines: Vec<(usize, usize)>,
}

impl RustComplexityContext {
    pub(crate) fn for_sources(sources: &BTreeMap<String, String>) -> BTreeMap<String, Self> {
        // Index declarations once per analysis, not once per extracted function.
        let files = sources
            .iter()
            .filter(|(path, _)| path.ends_with(".rs"))
            .map(|(path, source)| {
                let (masked, _) = function_lexical_facts(source);
                (path.as_str(), RustQuoteFile::new(masked))
            })
            .collect::<BTreeMap<_, _>>();
        files
            .iter()
            .map(|(&path, file)| {
                let imported_wrappers = file
                    .imports
                    .iter()
                    .filter_map(|(_, _, target)| {
                        rust_imported_quote_wrapper(path, target, &files)
                            .map(|wrapper| (target.as_str(), wrapper))
                    })
                    .collect::<BTreeMap<_, _>>();
                let mut templates = Vec::new();
                for captures in RUST_MACRO_INVOCATION.captures_iter(&file.masked) {
                    let name = captures.name("name").expect("macro name").as_str();
                    let prefix = captures.name("path").expect("macro path").as_str();
                    let opening = captures.name("opening").expect("macro opening").start();
                    let Some((open, close)) = rust_delimiter(file.masked.as_bytes()[opening])
                    else {
                        continue;
                    };
                    let Some(closing) = matching_delimiter(&file.masked, opening, open, close)
                    else {
                        continue;
                    };
                    if let Some(spanned) = file.quote_macro(prefix, name, opening) {
                        let start = if spanned {
                            let Some(start) =
                                rust_quote_span_end(&file.masked, opening + 1, closing)
                            else {
                                continue;
                            };
                            start
                        } else {
                            opening
                        };
                        templates.push((opening, start, closing));
                        continue;
                    }
                    let Some(wrapper) =
                        rust_quote_wrapper(file, prefix, name, opening, &imported_wrappers)
                    else {
                        continue;
                    };
                    // Unqualified macro names in a macro_rules transcriber resolve at
                    // the invocation site. Do not infer quote semantics from its spelling.
                    if file.quote_macro(&wrapper.quote_path, &wrapper.quote_name, opening)
                        != Some(false)
                    {
                        continue;
                    }
                    let Some(arguments) = rust_macro_tokens(&file.masked, opening + 1, closing, 0)
                    else {
                        continue;
                    };
                    let Some((start, end)) =
                        rust_match_quote_pattern(&wrapper.pattern, &arguments, &wrapper.payload)
                    else {
                        continue;
                    };
                    templates.push((start, start, end));
                }
                let quote_lines = templates
                    .iter()
                    .map(|&(_, start, end)| {
                        (line_at(&file.masked, start), line_at(&file.masked, end))
                    })
                    .collect();
                let line_offsets = std::iter::once(0)
                    .chain(
                        file.masked
                            .match_indices('\n')
                            .map(|(offset, _)| offset + 1),
                    )
                    .collect();
                (
                    path.to_owned(),
                    Self {
                        templates,
                        line_offsets,
                        quote_lines,
                    },
                )
            })
            .collect()
    }

    pub(crate) fn contains_template_function(&self, line: usize) -> bool {
        self.quote_lines
            .iter()
            .any(|&(start, end)| start < line && line <= end)
    }
}

struct RustQuoteFile {
    masked: String,
    scopes: Vec<(usize, usize)>,
    imports: Vec<(usize, String, String)>,
    definitions: Vec<(usize, String, Option<RustQuoteWrapper>)>,
    namespaces: Vec<(usize, String)>,
}

struct RustQuoteWrapper {
    pattern: Vec<RustQuotePattern>,
    payload: String,
    quote_path: String,
    quote_name: String,
}

struct RustMacroToken {
    text: String,
    children: Vec<RustMacroToken>,
    start: usize,
    end: usize,
}

enum RustQuotePattern {
    Literal(String),
    Group(String, Vec<Self>),
    Capture { name: String, identifier_only: bool },
    IdentifierList { separator: String, required: bool },
}

struct RustVisibleBinding<'a, T> {
    offset: usize,
    scope: usize,
    value: Option<&'a T>,
}

impl RustQuoteFile {
    fn new(masked: String) -> Self {
        let scopes = rust_quote_scopes(&masked);
        let imports = rust_macro_imports(&masked);
        let definitions = RUST_MACRO_DEFINITION
            .captures_iter(&masked)
            .map(|captures| {
                let declaration = captures.get(0).expect("macro definition");
                let name = captures["name"].to_owned();
                (
                    declaration.start(),
                    name,
                    rust_forwarding_quote(&masked, declaration.end()),
                )
            })
            .collect();
        let namespaces = RUST_QUOTE_NAMESPACE
            .captures_iter(&masked)
            .filter_map(|captures| {
                let declaration = captures.get(0)?.start();
                if let Some(module) = captures.name("module") {
                    return Some((declaration, module.as_str().to_owned()));
                }
                let original = captures.name("crate")?.as_str();
                let alias = captures.name("alias")?.as_str();
                (original != alias).then(|| (declaration, alias.to_owned()))
            })
            .collect();
        Self {
            masked,
            scopes,
            imports,
            definitions,
            namespaces,
        }
    }

    fn scope(&self, offset: usize) -> (usize, usize) {
        self.scopes
            .iter()
            .copied()
            .filter(|&(start, end)| start < offset && offset < end)
            .max_by_key(|&(start, _)| start)
            .unwrap_or((0, self.masked.len()))
    }

    fn visible(&self, declaration: usize, offset: usize) -> bool {
        let (start, end) = self.scope(declaration);
        start <= offset && offset <= end
    }

    fn definition(&self, name: &str, offset: usize) -> Option<Option<&RustQuoteWrapper>> {
        let bindings = self
            .definitions
            .iter()
            .filter(|(_, binding, _)| binding == name)
            .map(|(declaration, _, wrapper)| (*declaration, wrapper));
        let candidate = self.visible_binding(offset, bindings)?;
        if self.imports.iter().any(|(declaration, binding, _)| {
            binding == name
                && self.visible(*declaration, offset)
                && self.scope(*declaration).0 > candidate.scope
        }) {
            return None;
        }
        if candidate.offset >= offset {
            return Some(None);
        }
        Some(candidate.value.and_then(Option::as_ref))
    }

    fn imported(&self, name: &str, offset: usize) -> Option<&str> {
        let bindings = self
            .imports
            .iter()
            .filter(|(_, binding, _)| binding == name)
            .map(|(declaration, _, target)| (*declaration, target));
        self.visible_binding(offset, bindings)?
            .value
            .map(String::as_str)
    }

    fn visible_binding<'a, T: 'a>(
        &self,
        offset: usize,
        bindings: impl Iterator<Item = (usize, &'a T)>,
    ) -> Option<RustVisibleBinding<'a, T>> {
        let mut nearest: Option<RustVisibleBinding<'a, T>> = None;
        for (declaration, value) in bindings {
            if !self.visible(declaration, offset) {
                continue;
            }
            let scope = self.scope(declaration).0;
            match nearest.as_mut() {
                Some(binding) if binding.scope == scope => binding.value = None,
                Some(binding) if binding.scope > scope => {}
                _ => {
                    nearest = Some(RustVisibleBinding {
                        offset: declaration,
                        scope,
                        value: Some(value),
                    })
                }
            }
        }
        nearest
    }

    fn quote_macro(&self, prefix: &str, name: &str, offset: usize) -> Option<bool> {
        if !prefix.is_empty() {
            let owner = prefix.trim_start_matches("::").strip_suffix("::")?;
            if self.namespace_shadowed(owner, offset) {
                return None;
            }
            return rust_quote_macro(owner, name);
        }
        if self.definition(name, offset).is_some() {
            return None;
        }
        let (owner, symbol) = self
            .imported(name, offset)?
            .trim_start_matches("::")
            .rsplit_once("::")?;
        if self.namespace_shadowed(owner, offset) {
            return None;
        }
        rust_quote_macro(owner, symbol)
    }

    fn namespace_shadowed(&self, owner: &str, offset: usize) -> bool {
        self.namespaces
            .iter()
            .any(|(declaration, name)| name == owner && self.visible(*declaration, offset))
            || self.imported(owner, offset).is_some_and(|target| {
                // A proven quote macro import occupies the macro namespace, not
                // the module/type namespace used by its own crate-qualified path.
                target != owner
                    && target
                        .trim_start_matches("::")
                        .rsplit_once("::")
                        .and_then(|(crate_name, name)| rust_quote_macro(crate_name, name))
                        .is_none()
            })
    }
}

fn rust_quote_wrapper<'a>(
    file: &'a RustQuoteFile,
    prefix: &str,
    name: &str,
    offset: usize,
    imports: &BTreeMap<&str, &'a RustQuoteWrapper>,
) -> Option<&'a RustQuoteWrapper> {
    if !prefix.is_empty() {
        return None;
    }
    if let Some(definition) = file.definition(name, offset) {
        return definition;
    }
    imports.get(file.imported(name, offset)?).copied()
}

fn rust_imported_quote_wrapper<'a>(
    path: &str,
    imported: &str,
    files: &'a BTreeMap<&str, RustQuoteFile>,
) -> Option<&'a RustQuoteWrapper> {
    let mut parts = imported.split("::");
    // Only explicitly declared sibling modules are resolved. No stem search,
    // cross-crate guess, wildcard or arbitrary re-export inference.
    let (module, exported) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("super"), Some(module), Some(exported), None) => (module, exported),
        _ => return None,
    };
    let (directory, filename) = path.rsplit_once('/')?;
    let consumer = filename.strip_suffix(".rs")?;
    if matches!(consumer, "lib" | "main" | "mod") {
        return None;
    }
    let parent_candidates = [
        format!("{directory}/mod.rs"),
        format!("{directory}.rs"),
        format!("{directory}/lib.rs"),
        format!("{directory}/main.rs"),
    ];
    let parent = rust_single_quote_candidate(
        parent_candidates
            .iter()
            .filter_map(|parent| files.get(parent.as_str())),
    )?;
    let declared = RUST_QUOTE_MODULE
        .captures_iter(&parent.masked)
        .filter(|captures| parent.scope(captures.get(0).expect("module").start()).0 == 0)
        .map(|captures| captures["name"].to_owned())
        .collect::<BTreeSet<_>>();
    // An explicitly path-mapped module or a competing conventional source
    // invalidates this deliberately small conventional-module proof.
    if RUST_QUOTE_PATH_ATTRIBUTE.is_match(&parent.masked)
        || files.contains_key(format!("{directory}/{consumer}/mod.rs").as_str())
    {
        return None;
    }
    if !declared.contains(module) || !declared.contains(consumer) {
        return None;
    }
    let candidates = [
        format!("{directory}/{module}.rs"),
        format!("{directory}/{module}/mod.rs"),
    ];
    let provider = rust_single_quote_candidate(
        candidates
            .iter()
            .filter_map(|provider| files.get(provider.as_str())),
    )?;
    let exports = RUST_QUOTE_EXPORT
        .captures_iter(&provider.masked)
        .filter(|captures| {
            captures
                .name("alias")
                .map_or(&captures["name"], |alias| alias.as_str())
                == exported
                && provider
                    .scope(captures.get(0).expect("macro export").start())
                    .0
                    == 0
        });
    let export = rust_single_quote_candidate(exports)?;
    let definitions = provider
        .definitions
        .iter()
        .filter(|(offset, name, _)| name == &export["name"] && provider.scope(*offset).0 == 0);
    let definition = rust_single_quote_candidate(definitions)?;
    definition.2.as_ref()
}

fn rust_macro_tokens(
    source: &str,
    mut offset: usize,
    end: usize,
    depth: usize,
) -> Option<Vec<RustMacroToken>> {
    if depth > 32 {
        return None;
    }
    let mut tokens = Vec::new();
    while offset < end {
        if source.as_bytes()[offset].is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        let token = rust_macro_token(source, offset, end, depth)?;
        offset = token.end + 1;
        tokens.push(token);
    }
    Some(tokens)
}

fn rust_macro_token(
    source: &str,
    start: usize,
    end: usize,
    depth: usize,
) -> Option<RustMacroToken> {
    let bytes = source.as_bytes();
    if let Some((open, close)) = rust_delimiter(bytes[start]) {
        let closing = matching_delimiter(source, start, open, close)?;
        if closing >= end {
            return None;
        }
        return Some(RustMacroToken {
            text: source[start..start + 1].to_owned(),
            children: rust_macro_tokens(source, start + 1, closing, depth + 1)?,
            start,
            end: closing,
        });
    }
    if !bytes[start].is_ascii() {
        return None;
    }
    let length = if rust_macro_word_byte(bytes[start]) {
        bytes[start..end]
            .iter()
            .take_while(|&&byte| rust_macro_word_byte(byte))
            .count()
    } else {
        1
    };
    Some(RustMacroToken {
        text: source[start..start + length].to_owned(),
        children: Vec::new(),
        start,
        end: start + length - 1,
    })
}

fn rust_macro_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn rust_forwarding_quote(source: &str, offset: usize) -> Option<RustQuoteWrapper> {
    let opening = offset + source[offset..].find(|character: char| !character.is_whitespace())?;
    let (open, close) = rust_delimiter(*source.as_bytes().get(opening)?)?;
    let closing = matching_delimiter(source, opening, open, close)?;
    let tokens = rust_macro_tokens(source, opening + 1, closing, 0)?;
    // One matcher only: multiple alternatives can select a runtime transcriber.
    if !(tokens.len() == 4 || tokens.len() == 5 && tokens[4].text == ";")
        || tokens[1].text != "="
        || tokens[2].text != ">"
        || rust_delimiter(tokens[0].text.as_bytes()[0]).is_none()
        || rust_delimiter(tokens[3].text.as_bytes()[0]).is_none()
    {
        return None;
    }
    let body_start = tokens[3].start + 1;
    let body_end = tokens[3].end;
    let body = &source[body_start..body_end];
    let mut forwards = RUST_QUOTE_FORWARD.captures_iter(body);
    let forward = forwards.next()?;
    if forwards.next().is_some() {
        return None;
    }
    let payload = forward["payload"].to_owned();
    let uses = RUST_QUOTE_VARIABLE
        .captures_iter(body)
        .filter(|captures| captures["name"] == payload)
        .count();
    if uses != 1 {
        return None;
    }
    let quoted = forward.get(0)?;
    // Inspect disjoint setup slices directly: capture offsets are UTF-8
    // boundaries, so neither byte reconstruction nor a masking allocation is needed.
    if RUST_QUOTE_SETUP_BRANCH.is_match(&body[..quoted.start()])
        || RUST_QUOTE_SETUP_BRANCH.is_match(&body[quoted.end()..])
    {
        return None;
    }
    Some(RustQuoteWrapper {
        pattern: rust_quote_pattern(tokens.into_iter().next()?.children, &payload)?,
        payload,
        quote_path: forward["path"].to_owned(),
        quote_name: forward["name"].to_owned(),
    })
}

fn rust_quote_pattern(tokens: Vec<RustMacroToken>, payload: &str) -> Option<Vec<RustQuotePattern>> {
    let mut tokens = tokens.into_iter();
    let mut pattern = Vec::new();
    while let Some(token) = tokens.next() {
        let item = match token.text.as_str() {
            "$" => rust_quote_metavariable(&mut tokens, payload)?,
            _ if rust_delimiter(token.text.as_bytes()[0]).is_some() => {
                RustQuotePattern::Group(token.text, rust_quote_pattern(token.children, payload)?)
            }
            _ => RustQuotePattern::Literal(token.text),
        };
        pattern.push(item);
    }
    Some(pattern)
}

fn rust_quote_metavariable(
    tokens: &mut std::vec::IntoIter<RustMacroToken>,
    payload: &str,
) -> Option<RustQuotePattern> {
    let name = tokens.next()?;
    if name.text == "(" {
        return rust_quote_identifier_list(name.children, tokens, payload);
    }
    let colon = tokens.next()?;
    let fragment = tokens.next()?;
    let identifier_only = match (colon.text.as_str(), fragment.text.as_str()) {
        (":", "ident") if name.text != payload => true,
        (":", "tt") => false,
        _ => return None,
    };
    Some(RustQuotePattern::Capture {
        name: name.text,
        identifier_only,
    })
}

fn rust_quote_identifier_list(
    repeated: Vec<RustMacroToken>,
    tokens: &mut std::vec::IntoIter<RustMacroToken>,
    payload: &str,
) -> Option<RustQuotePattern> {
    let [dollar, name, colon, fragment] = repeated.as_slice() else {
        return None;
    };
    if (
        dollar.text.as_str(),
        colon.text.as_str(),
        fragment.text.as_str(),
    ) != ("$", ":", "ident")
        || name.text == payload
    {
        return None;
    }
    let separator = tokens.next()?.text;
    let required = match tokens.next()?.text.as_str() {
        "*" => false,
        "+" => true,
        _ => return None,
    };
    // This bounded grammar supports a terminal identifier-list repetition,
    // not backtracking or arbitrary macro_rules expansion.
    if !tokens.as_slice().is_empty() {
        return None;
    }
    Some(RustQuotePattern::IdentifierList {
        separator,
        required,
    })
}

fn rust_match_quote_pattern(
    pattern: &[RustQuotePattern],
    arguments: &[RustMacroToken],
    payload: &str,
) -> Option<(usize, usize)> {
    let mut found = None;
    rust_match_quote_arguments(pattern, arguments, payload, &mut found)?;
    found
}

fn rust_match_quote_arguments(
    pattern: &[RustQuotePattern],
    arguments: &[RustMacroToken],
    payload: &str,
    found: &mut Option<(usize, usize)>,
) -> Option<()> {
    let mut arguments = arguments.iter();
    for item in pattern {
        if let RustQuotePattern::IdentifierList {
            separator,
            required,
        } = item
        {
            return rust_match_quote_identifiers(arguments.as_slice(), separator, *required);
        }
        item.match_argument(arguments.next()?, payload, found)?;
    }
    arguments.next().is_none().then_some(())
}

impl RustQuotePattern {
    fn match_argument(
        &self,
        argument: &RustMacroToken,
        payload: &str,
        found: &mut Option<(usize, usize)>,
    ) -> Option<()> {
        match self {
            Self::Literal(text) => (text == &argument.text).then_some(()),
            Self::Group(delimiter, pattern) => {
                if delimiter != &argument.text {
                    return None;
                }
                rust_match_quote_arguments(pattern, &argument.children, payload, found)
            }
            Self::Capture {
                name,
                identifier_only,
            } => {
                if *identifier_only && !rust_macro_identifier(argument) {
                    return None;
                }
                if name == payload && found.replace((argument.start, argument.end)).is_some() {
                    return None;
                }
                Some(())
            }
            Self::IdentifierList { .. } => None,
        }
    }
}

fn rust_match_quote_identifiers(
    arguments: &[RustMacroToken],
    separator: &str,
    required: bool,
) -> Option<()> {
    if arguments.is_empty() {
        return (!required).then_some(());
    }
    if arguments.len().is_multiple_of(2) {
        return None;
    }
    arguments
        .iter()
        .enumerate()
        .all(|(index, argument)| {
            if index.is_multiple_of(2) {
                rust_macro_identifier(argument)
            } else {
                argument.text == separator
            }
        })
        .then_some(())
}

fn rust_macro_identifier(token: &RustMacroToken) -> bool {
    token.children.is_empty()
        && token.text.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || index > 0 && byte.is_ascii_digit()
        })
}

pub(crate) fn rust_complexity_source(
    source: &str,
    context: Option<&RustComplexityContext>,
    line: usize,
) -> String {
    let (masked, _) = function_lexical_facts(source);
    let templates = if let Some(context) = context {
        let offset = context
            .line_offsets
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(0);
        context
            .templates
            .iter()
            .filter(|&&(opening, _, end)| opening >= offset && end < offset + source.len())
            .map(|&(opening, start, end)| (opening - offset, start - offset, end - offset))
            .collect()
    } else {
        rust_quote_templates(&masked)
    };
    let mut bytes = masked.into_bytes();
    for (opening, start, end) in templates {
        bytes[opening] = b' ';
        blank_rust_complexity_bytes(&mut bytes[start..=end]);
    }
    for (start, _) in source.match_indices("||") {
        if bytes.get(start..start + 2) == Some(b"||") && rust_empty_closure_prefix(&bytes[..start])
        {
            bytes[start + 1] = b' ';
        }
    }
    let masked = String::from_utf8(bytes).expect("Rust template masking preserves UTF-8");
    rust_complexity_without_nested_callables(masked)
}

fn rust_complexity_without_nested_callables(masked: String) -> String {
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
    if prefix.last().is_none_or(|byte| b"([{,=;:&!".contains(byte)) || prefix.ends_with(b"=>") {
        return true;
    }
    ["move", "async", "return", "break"].iter().any(|keyword| {
        prefix
            .strip_suffix(keyword.as_bytes())
            .is_some_and(|before| {
                before.last().is_none_or(|byte| {
                    byte.is_ascii() && !byte.is_ascii_alphanumeric() && !b"_#.".contains(byte)
                })
            })
    })
}

fn rust_quote_macro(crate_name: &str, name: &str) -> Option<bool> {
    match (crate_name, name) {
        ("quote", "quote") | ("syn", "parse_quote") => Some(false),
        ("quote", "quote_spanned") | ("syn", "parse_quote_spanned") => Some(true),
        _ => None,
    }
}

fn rust_quote_templates(masked: &str) -> Vec<(usize, usize, usize)> {
    RUST_MACRO_INVOCATION
        .captures_iter(masked)
        .filter_map(|captures| {
            let path = captures.name("path").map_or("", |path| path.as_str());
            let name = captures.name("name")?.as_str();
            let spanned =
                rust_quote_macro(path.trim_start_matches("::").strip_suffix("::")?, name)?;
            let opening = captures.name("opening")?.start();
            let (open, close) = rust_delimiter(masked.as_bytes()[opening])?;
            let closing = matching_delimiter(masked, opening, open, close)?;
            let start = if spanned {
                rust_quote_span_end(masked, opening + 1, closing)?
            } else {
                opening
            };
            Some((opening, start, closing))
        })
        .collect()
}

fn rust_delimiter(byte: u8) -> Option<(u8, u8)> {
    match byte {
        b'{' => Some((b'{', b'}')),
        b'(' => Some((b'(', b')')),
        b'[' => Some((b'[', b']')),
        _ => None,
    }
}

fn rust_quote_span_end(masked: &str, mut offset: usize, closing: usize) -> Option<usize> {
    let bytes = masked.as_bytes();
    while offset < closing {
        if bytes.get(offset..offset + 2) == Some(b"=>") {
            return Some(offset);
        }
        if let Some((open, close)) = rust_delimiter(bytes[offset]) {
            offset = matching_delimiter(masked, offset, open, close)?;
        }
        offset += 1;
    }
    None
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
static RUST_MACRO_USE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\buse\s+(?P<tree>[^;{}]+(?:::\{[^{};]*\})?)\s*;")
        .expect("Rust macro import regex must compile")
});
static RUST_QUOTE_MODULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bmod\s+(?P<name>[A-Za-z_]\w*)\s*;").expect("Rust quote module regex must compile")
});
static RUST_QUOTE_EXPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bpub(?:\([^)]*\))?\s+use\s+(?:self::)?(?P<name>[A-Za-z_]\w*)(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?\s*;")
        .expect("Rust quote export regex must compile")
});
static RUST_QUOTE_FORWARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<path>(?:::)?(?:[A-Za-z_]\w*::)*)(?P<name>[A-Za-z_]\w*)\s*!\s*\$\s*(?P<payload>[A-Za-z_]\w*)")
        .expect("Rust quote forwarding regex must compile")
});
static RUST_QUOTE_VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\s*(?P<name>[A-Za-z_]\w*)").expect("Rust quote variable regex must compile")
});
static RUST_QUOTE_SETUP_BRANCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:if|for|while|loop|match|macro_rules|use|fn)\b|&&|\|\||!")
        .expect("Rust quote setup branch regex must compile")
});
static RUST_MACRO_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bmacro_rules\s*!\s*(?P<name>[A-Za-z_]\w*)")
        .expect("Rust macro definition regex must compile")
});
static RUST_MACRO_INVOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<path>(?:::)?(?:[A-Za-z_]\w*::)*)(?P<name>[A-Za-z_]\w*)\s*!\s*(?P<opening>[{(\[])",
    )
    .expect("Rust macro invocation regex must compile")
});
static RUST_QUOTE_PATH_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"#\s*\[\s*path\s*=").expect("Rust quote path attribute regex must compile")
});
static RUST_QUOTE_NAMESPACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:mod\s+(?P<module>[A-Za-z_]\w*)|extern\s+crate\s+(?P<crate>[A-Za-z_]\w*)(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?)")
        .expect("Rust quote namespace regex must compile")
});

fn rust_quote_scopes(masked: &str) -> Vec<(usize, usize)> {
    let mut scopes = Vec::new();
    let mut stack = Vec::new();
    for (offset, byte) in masked.bytes().enumerate() {
        match byte {
            b'{' => stack.push(offset),
            b'}' => {
                if let Some(start) = stack.pop() {
                    scopes.push((start, offset));
                }
            }
            _ => {}
        }
    }
    scopes
}

fn rust_macro_imports(masked: &str) -> Vec<(usize, String, String)> {
    let mut imports = Vec::new();
    for captures in RUST_MACRO_USE.captures_iter(masked) {
        let offset = captures.get(0).expect("use declaration").start();
        let tree = captures["tree"].trim();
        let (prefix, leaves) = tree.split_once('{').map_or(("", tree), |(prefix, leaves)| {
            (prefix, leaves.trim_end_matches('}').trim())
        });
        for leaf in leaves.split(',').map(str::trim) {
            if let Some((binding, target)) = rust_macro_import_leaf(prefix, leaf) {
                imports.push((offset, binding, target));
            }
        }
    }
    imports
}

fn rust_macro_import_leaf(prefix: &str, leaf: &str) -> Option<(String, String)> {
    let mut words = leaf.split_whitespace();
    let target = words.next()?;
    let binding = match (words.next(), words.next(), words.next()) {
        (None, None, None) => target.rsplit("::").next()?,
        (Some("as"), Some(alias), None) => alias,
        _ => return None,
    };
    if binding == "*" || target.contains(['{', '}']) {
        return None;
    }
    Some((binding.to_owned(), format!("{prefix}{target}")))
}

fn rust_single_quote_candidate<T>(mut candidates: impl Iterator<Item = T>) -> Option<T> {
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}
