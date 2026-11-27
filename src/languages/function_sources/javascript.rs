fn javascript_functions(path: &str, source: &str) -> Vec<FunctionSource> {
    let masked = mask_javascript_strings_and_comments(source);
    let candidates = javascript_function_candidates(&masked);
    javascript_sources_from_candidates(path, source, &masked, &candidates)
}

pub(crate) struct JavascriptFunctionRegion {
    pub name: String,
    pub start: usize,
    pub body: std::ops::Range<usize>,
}

pub(crate) fn javascript_function_regions(masked: &str) -> Vec<JavascriptFunctionRegion> {
    let ends = javascript_matching_braces(masked);
    javascript_function_candidates(masked)
        .into_iter()
        .filter_map(|(opening, (start, name))| {
            Some(JavascriptFunctionRegion {
                name,
                start,
                body: opening + 1..*ends.get(&opening)?,
            })
        })
        .collect()
}

fn javascript_function_candidates(source: &str) -> BTreeMap<usize, (usize, String)> {
    let mut candidates = BTreeMap::new();
    javascript_keyword_function_candidates(source, &mut candidates);
    javascript_named_block_candidates(source, &JS_BLOCK_METHOD, b'(', &mut candidates);
    javascript_named_block_candidates(source, &JS_ARROW, b'=', &mut candidates);
    javascript_anonymous_arrow_candidates(source, &mut candidates);
    candidates
}

fn javascript_keyword_function_candidates(
    source: &str,
    candidates: &mut BTreeMap<usize, (usize, String)>,
) {
    let bytes = source.as_bytes();
    for (keyword, _) in source.match_indices("function") {
        let end = keyword + "function".len();
        if (keyword > 0 && is_javascript_identifier_byte(bytes[keyword - 1]))
            || (end < bytes.len() && is_javascript_identifier_byte(bytes[end]))
        {
            continue;
        }
        if let Some((opening, name)) = javascript_function_candidate(source, keyword) {
            candidates.entry(opening).or_insert((keyword, name));
        }
    }
}

fn javascript_named_block_candidates(
    source: &str,
    pattern: &Regex,
    required_line_token: u8,
    candidates: &mut BTreeMap<usize, (usize, String)>,
) {
    for captures in pattern.captures_iter(source) {
        let Some(complete) = captures.get(0) else {
            continue;
        };
        let line_end = source[complete.start()..]
            .find('\n')
            .map_or(source.len(), |relative| complete.start() + relative);
        if !source.as_bytes()[complete.start()..line_end].contains(&required_line_token) {
            continue;
        }
        let Some(relative_opening) = complete.as_str().find('{') else {
            continue;
        };
        let Some(name) = captures.name("name") else {
            continue;
        };
        if is_control_keyword(name.as_str()) {
            continue;
        }
        candidates
            .entry(complete.start() + relative_opening)
            .or_insert((complete.start(), name.as_str().to_owned()));
    }
}

fn javascript_anonymous_arrow_candidates(
    source: &str,
    candidates: &mut BTreeMap<usize, (usize, String)>,
) {
    for matched in JS_BLOCK_ARROW.find_iter(source) {
        candidates
            .entry(matched.end() - 1)
            .or_insert((matched.start(), "<anonymous>".to_owned()));
    }
}

fn javascript_sources_from_candidates(
    path: &str,
    source: &str,
    masked: &str,
    candidates: &BTreeMap<usize, (usize, String)>,
) -> Vec<FunctionSource> {
    let ends = javascript_matching_braces(masked);
    candidates
        .iter()
        .filter_map(|(opening, (start, name))| {
            javascript_source_from_candidate(
                path, source, candidates, &ends, *opening, *start, name,
            )
        })
        .collect()
}

fn javascript_source_from_candidate(
    path: &str,
    source: &str,
    candidates: &BTreeMap<usize, (usize, String)>,
    ends: &BTreeMap<usize, usize>,
    opening: usize,
    start: usize,
    name: &str,
) -> Option<FunctionSource> {
    let end = *ends.get(&opening)?;
    let mut bytes = source.as_bytes()[start..=end].to_vec();
    for (nested_opening, (nested_start, _)) in candidates.range((opening + 1)..=end) {
        let Some(nested_end) = ends.get(nested_opening) else {
            continue;
        };
        if *nested_end > end {
            continue;
        }
        for byte in &mut bytes[(nested_start - start)..=(nested_end - start)] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    Some(FunctionSource {
        path: path.to_owned(),
        name: name.to_owned(),
        line: line_at(source, start),
        end_line: line_at(source, end),
        contract_signature: false,
        source: String::from_utf8(bytes).expect("masked JavaScript functions remain UTF-8"),
    })
}

fn javascript_function_candidate(source: &str, keyword: usize) -> Option<(usize, String)> {
    let bytes = source.as_bytes();
    let limit = (keyword + 64 * 1024).min(bytes.len());
    let mut offset = skip_javascript_whitespace(bytes, keyword + "function".len(), limit);
    if bytes.get(offset) == Some(&b'*') {
        offset = skip_javascript_whitespace(bytes, offset + 1, limit);
    }
    let name_start = offset;
    while offset < limit && is_javascript_identifier_byte(bytes[offset]) {
        offset += 1;
    }
    let name = if offset == name_start {
        "<anonymous>"
    } else {
        &source[name_start..offset]
    };
    let opening = javascript_function_body(bytes, offset, limit)?;
    Some((opening, name.to_owned()))
}

fn javascript_function_body(bytes: &[u8], offset: usize, limit: usize) -> Option<usize> {
    let mut offset = skip_javascript_whitespace(bytes, offset, limit);
    if bytes.get(offset) != Some(&b'(') {
        return None;
    }
    let mut depth = 1usize;
    offset += 1;
    while offset < limit && depth > 0 {
        match bytes[offset] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        offset += 1;
    }
    if depth != 0 {
        return None;
    }
    while offset < limit {
        match bytes[offset] {
            b'{' => return Some(offset),
            b';' | b'=' => return None,
            _ => offset += 1,
        }
    }
    None
}

fn skip_javascript_whitespace(bytes: &[u8], mut offset: usize, limit: usize) -> usize {
    while offset < limit && bytes[offset] <= b' ' {
        offset += 1;
    }
    offset
}

fn javascript_matching_braces(source: &str) -> BTreeMap<usize, usize> {
    let mut openings = Vec::new();
    let mut result = BTreeMap::new();
    for (offset, byte) in source.bytes().enumerate() {
        match byte {
            b'{' => openings.push(offset),
            b'}' => {
                if let Some(opening) = openings.pop() {
                    result.insert(opening, offset);
                }
            }
            _ => {}
        }
    }
    result
}

pub(crate) fn mask_javascript_strings_and_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut result = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            index = mask_javascript_line_comment(bytes, &mut result, index);
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            index = mask_javascript_block_comment(bytes, &mut result, index);
        } else if bytes[index] == b'/' && starts_javascript_regex_literal(source, index) {
            index = mask_javascript_regex(bytes, &mut result, index);
        } else if matches!(bytes[index], b'\'' | b'"' | b'`') {
            index = mask_javascript_string(bytes, &mut result, index);
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).expect("masking preserves UTF-8 bytes")
}

pub(crate) fn javascript_relative_imports(source: &str) -> impl Iterator<Item = &str> {
    let mut masked = None;
    JS_RELATIVE_IMPORT
        .captures_iter(source)
        .filter_map(move |capture| {
            let keyword = capture.name("keyword")?;
            let code = masked.get_or_insert_with(|| mask_javascript_strings_and_comments(source));
            if code.get(keyword.range()) != Some("import") {
                return None;
            }
            capture.name("source").map(|source| source.as_str())
        })
}

pub(crate) fn relative_javascript_module(path: &str, import: &str) -> Option<String> {
    let mut directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
    let mut relative = import;
    while let Some(parent) = relative.strip_prefix("../") {
        if directory.is_empty() {
            return None;
        }
        directory = directory
            .rsplit_once('/')
            .map_or("", |(directory, _)| directory);
        relative = parent;
    }
    let relative = relative.strip_prefix("./").unwrap_or(relative);
    if relative
        .split('/')
        .any(|part| matches!(part, "" | "." | ".."))
    {
        return None;
    }
    Some(if directory.is_empty() {
        relative.to_owned()
    } else {
        format!("{directory}/{relative}")
    })
}

fn mask_javascript_line_comment(bytes: &[u8], result: &mut [u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        result[index] = b' ';
        index += 1;
    }
    index
}

fn mask_javascript_block_comment(bytes: &[u8], result: &mut [u8], mut index: usize) -> usize {
    result[index] = b' ';
    result[index + 1] = b' ';
    index += 2;
    while index + 1 < bytes.len() && bytes.get(index..index + 2) != Some(b"*/") {
        if bytes[index] != b'\n' {
            result[index] = b' ';
        }
        index += 1;
    }
    if index + 1 < bytes.len() {
        result[index] = b' ';
        result[index + 1] = b' ';
        index += 2;
    }
    index
}

pub(crate) fn javascript_regex_literal_end(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(index) != Some(&b'/')
        || matches!(bytes.get(index + 1), Some(b'/' | b'*'))
        || !starts_javascript_regex_literal(source, index)
    {
        return None;
    }
    Some(javascript_regex_end(bytes, index))
}

fn mask_javascript_regex(bytes: &[u8], result: &mut [u8], index: usize) -> usize {
    let end = javascript_regex_end(bytes, index);
    result[index..end].fill(b' ');
    end
}

fn javascript_regex_end(bytes: &[u8], mut index: usize) -> usize {
    let mut in_character_class = false;
    index += 1;
    while index < bytes.len() && bytes[index] != b'\n' {
        match bytes[index] {
            b'\\' => index = javascript_escape_end(bytes, index),
            b'[' => {
                in_character_class = true;
                index += 1;
            }
            b']' => {
                in_character_class = false;
                index += 1;
            }
            b'/' if !in_character_class => {
                index += 1;
                while index < bytes.len() && is_javascript_identifier_byte(bytes[index]) {
                    index += 1;
                }
                break;
            }
            _ => index += 1,
        }
    }
    index
}

fn mask_javascript_string(bytes: &[u8], result: &mut [u8], mut index: usize) -> usize {
    let quote = bytes[index];
    result[index] = b' ';
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = mask_javascript_escape(bytes, result, index);
            continue;
        }
        let closes = bytes[index] == quote;
        if bytes[index] != b'\n' {
            result[index] = b' ';
        }
        index += 1;
        if closes {
            break;
        }
    }
    index
}

fn javascript_escape_end(bytes: &[u8], index: usize) -> usize {
    let next = index + 1;
    if bytes.get(next).is_some_and(|byte| *byte != b'\n') {
        next + 1
    } else {
        next
    }
}

fn mask_javascript_escape(bytes: &[u8], result: &mut [u8], index: usize) -> usize {
    let end = javascript_escape_end(bytes, index);
    result[index..end].fill(b' ');
    end
}

fn starts_javascript_regex_literal(source: &str, slash: usize) -> bool {
    let bytes = source.as_bytes();
    let mut index = slash;
    while index > 0 && matches!(bytes[index - 1], b' ' | b'\t' | b'\n' | b'\r') {
        index -= 1;
    }
    if index == 0 {
        return true;
    }
    let previous = bytes[index - 1];
    if matches!(
        previous,
        b'!' | b'%'
            | b'&'
            | b'('
            | b'*'
            | b'+'
            | b','
            | b'-'
            | b':'
            | b';'
            | b'<'
            | b'='
            | b'>'
            | b'?'
            | b'['
            | b'^'
            | b'{'
            | b'|'
            | b'~'
    ) {
        return true;
    }
    if !is_javascript_identifier_byte(previous) {
        return false;
    }
    let end = index;
    while index > 0 && is_javascript_identifier_byte(bytes[index - 1]) {
        index -= 1;
    }
    matches!(
        &source[index..end],
        "await"
            | "case"
            | "delete"
            | "in"
            | "instanceof"
            | "new"
            | "of"
            | "return"
            | "throw"
            | "typeof"
            | "void"
            | "yield"
    )
}

fn is_javascript_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}
static JS_RELATIVE_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^[ \t]*(?P<keyword>import)\s+(?:[A-Za-z_$][\w$]*(?:\s*,\s*\{[^}]*\})?|\{[^}]*\}|\*\s+as\s+[A-Za-z_$][\w$]*)\s+from\s*["'](?P<source>\.{1,2}/[^"'\\\r\n]+)["']"#,
    )
    .expect("relative JavaScript import regex must compile")
});
static JS_BLOCK_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:public|private|protected|static|abstract|override|readonly|async|get|set)[ \t]+)*(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:<[^>{}]*>)?[ \t]*\([^();{}]*\)[ \t]*(?::[ \t]*[^={};]+)?[ \t]*\{")
        .expect("JavaScript method regex must compile")
});
static JS_ARROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:\??[ \t]*:[ \t]*[^=]+)?=[ \t]*(?:async[ \t]+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)[ \t]*(?::[ \t]*[^=]+)?=>[ \t]*\{")
        .expect("JavaScript arrow regex must compile")
});
static JS_BLOCK_ARROW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"=>\s*\{").expect("JavaScript block arrow regex must compile"));

#[cfg(test)]
mod javascript_source_tests {
    use super::javascript_functions;

    #[test]
    fn incomplete_javascript_does_not_abort_complete_function_extraction() {
        let functions = javascript_functions(
            "src/broken.js",
            "function complete() {\n  return true;\n}\n\
             class Broken {\n\
               method() {\n\
                 const arrow = () => {\n",
        );

        assert_eq!(
            functions
                .iter()
                .map(|function| {
                    (
                        function.name.as_str(),
                        function.line,
                        function.end_line,
                        function.source.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [("complete", 1, 3, "function complete() {\n  return true;\n}",)]
        );
    }
}
