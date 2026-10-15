use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{
    attached_declaration_line, index::DartSourceIndex, quote_aware_matching_delimiter,
    quote_aware_split_top_level, top_level_arrow,
};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        let original = index.source(path);
        let source = index.comments_masked(path);
        let classes = classes(source);
        findings.extend(json_cast_findings(path, source, &classes));
        let enum_names = enum_names(source);
        for class in &classes {
            findings.extend(class_findings(path, source, original, class, &enum_names));
        }
    }
    findings
}

#[derive(Debug)]
struct Class {
    start: usize,
    fields: Vec<Field>,
    methods: Vec<Method>,
}

#[derive(Debug)]
struct Field {
    type_name: String,
    name: String,
    is_static: bool,
    is_late_final: bool,
    has_initializer: bool,
}

#[derive(Debug)]
struct Method {
    name: String,
    start: usize,
    body_start: usize,
    end: usize,
    header: String,
    parameters: String,
    is_constructor: bool,
}

fn classes(source: &str) -> Vec<Class> {
    CLASS_START
        .captures_iter(source)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            let open = whole.end() - 1;
            let close = quote_aware_matching_delimiter(source, open, b'{', b'}')?;
            let name = captures.get(1)?.as_str().to_owned();
            let (fields, methods) = class_members(source, &name, open + 1, close);
            Some(Class {
                start: whole.start(),
                fields,
                methods,
            })
        })
        .collect()
}

fn class_members(
    source: &str,
    class_name: &str,
    start: usize,
    end: usize,
) -> (Vec<Field>, Vec<Method>) {
    let mut fields = Vec::new();
    let mut methods = Vec::new();
    let mut scanner = ClassMemberScanner::new(source, start, end);
    while let Some(candidate) = scanner.next_candidate() {
        match parse_class_member(source, class_name, candidate) {
            ParsedClassMember::Fields(parsed) => fields.extend(parsed),
            ParsedClassMember::Method(method) => methods.push(method),
            ParsedClassMember::None => {}
        }
    }
    (fields, methods)
}

#[derive(Clone, Copy)]
enum ClassMemberCandidate {
    Block {
        start: usize,
        open: usize,
        end: usize,
    },
    Statement {
        start: usize,
        end: usize,
    },
}

enum ParsedClassMember {
    Fields(Vec<Field>),
    Method(Method),
    None,
}

struct ClassMemberScanner<'a> {
    source: &'a str,
    end: usize,
    member_start: usize,
    index: usize,
    paren_depth: usize,
    bracket_depth: usize,
    curly_depth: usize,
    quote: Option<u8>,
}

impl<'a> ClassMemberScanner<'a> {
    fn new(source: &'a str, start: usize, end: usize) -> Self {
        Self {
            source,
            end,
            member_start: start,
            index: start,
            paren_depth: 0,
            bracket_depth: 0,
            curly_depth: 0,
            quote: None,
        }
    }

    fn next_candidate(&mut self) -> Option<ClassMemberCandidate> {
        while self.index < self.end {
            if let Some(candidate) = self.advance_lexical_transition() {
                return Some(candidate);
            }
        }
        None
    }

    fn advance_lexical_transition(&mut self) -> Option<ClassMemberCandidate> {
        let byte = self.source.as_bytes()[self.index];
        if self.advance_quoted(byte) {
            return None;
        }
        let candidate = match byte {
            b'\'' | b'"' => {
                self.quote = Some(byte);
                None
            }
            b'{' if self.at_top_level() => self.method_block_candidate(),
            b';' if self.at_top_level() => Some(self.statement_candidate()),
            _ => {
                self.update_depth(byte);
                None
            }
        };
        if candidate.is_none() {
            self.index += 1;
        }
        candidate
    }

    fn statement_candidate(&mut self) -> ClassMemberCandidate {
        let candidate = ClassMemberCandidate::Statement {
            start: self.member_start,
            end: self.index + 1,
        };
        self.advance_to(self.index + 1);
        candidate
    }

    fn advance_quoted(&mut self, byte: u8) -> bool {
        let Some(quote) = self.quote else {
            return false;
        };
        if byte == b'\\' && self.index + 1 < self.end {
            self.index += 2;
            return true;
        }
        if byte == quote {
            self.quote = None;
        }
        self.index += 1;
        true
    }

    fn method_block_candidate(&mut self) -> Option<ClassMemberCandidate> {
        let prefix = &self.source[self.member_start..self.index];
        if !looks_like_method_header(prefix) {
            self.curly_depth += 1;
            return None;
        }
        let close =
            quote_aware_matching_delimiter(self.source, self.index, b'{', b'}').unwrap_or(self.end);
        let candidate = ClassMemberCandidate::Block {
            start: self.member_start,
            open: self.index,
            end: close + 1,
        };
        self.advance_to(close + 1);
        Some(candidate)
    }

    fn advance_to(&mut self, index: usize) {
        self.index = index;
        self.member_start = index;
    }

    fn at_top_level(&self) -> bool {
        self.paren_depth == 0 && self.bracket_depth == 0 && self.curly_depth == 0
    }

    fn update_depth(&mut self, byte: u8) {
        match byte {
            b'(' => self.paren_depth += 1,
            b')' => self.paren_depth = self.paren_depth.saturating_sub(1),
            b'[' => self.bracket_depth += 1,
            b']' => self.bracket_depth = self.bracket_depth.saturating_sub(1),
            b'{' => self.curly_depth += 1,
            b'}' => self.curly_depth = self.curly_depth.saturating_sub(1),
            _ => {}
        }
    }
}

fn parse_class_member(
    source: &str,
    class_name: &str,
    candidate: ClassMemberCandidate,
) -> ParsedClassMember {
    match candidate {
        ClassMemberCandidate::Block { start, open, end } => {
            parse_method(source, class_name, start, open, end)
                .map_or(ParsedClassMember::None, ParsedClassMember::Method)
        }
        ClassMemberCandidate::Statement { start, end } => {
            parse_class_statement(source, class_name, start, end)
        }
    }
}

fn parse_class_statement(
    source: &str,
    class_name: &str,
    start: usize,
    end: usize,
) -> ParsedClassMember {
    let segment = &source[start..end];
    if let Some(arrow) = top_level_arrow(segment)
        && looks_like_method_header(segment)
        && let Some(method) = parse_method(source, class_name, start, start + arrow, end)
    {
        ParsedClassMember::Method(method)
    } else {
        ParsedClassMember::Fields(parse_fields(segment))
    }
}

fn looks_like_method_header(prefix: &str) -> bool {
    let signature = prefix.split("=>").next().unwrap_or(prefix).trim();
    signature.ends_with(')') || METHOD_BLOCK_SUFFIX.is_match(signature)
}

fn parse_method(
    source: &str,
    class_name: &str,
    start: usize,
    marker: usize,
    end: usize,
) -> Option<Method> {
    let header = source[start..marker].trim();
    let (name, parameters, is_constructor) = if let Some(close) = header.rfind(')') {
        let open = matching_open_delimiter(header, close, b'(', b')')?;
        let before = header[..open].trim_end();
        let name_match = IDENTIFIER.find_iter(before).last()?;
        let name = name_match.as_str().to_owned();
        let constructor_prefix = before[..name_match.start()].trim_end();
        let is_constructor = name == class_name
            || constructor_prefix.ends_with(&format!("{class_name}."))
            || constructor_prefix
                .split_whitespace()
                .last()
                .is_some_and(|value| value.ends_with(&format!("{class_name}.")));
        (name, header[open + 1..close].to_owned(), is_constructor)
    } else {
        let captures = GETTER_HEADER.captures(header)?;
        let name = captures.name("name")?.as_str().to_owned();
        (name, String::new(), false)
    };
    Some(Method {
        name,
        start: start + source[start..marker].find(|character: char| !character.is_whitespace())?,
        body_start: marker
            + if source.as_bytes()[marker] == b'{' {
                1
            } else {
                2
            },
        end,
        header: header.to_owned(),
        parameters,
        is_constructor,
    })
}

fn parse_fields(segment: &str) -> Vec<Field> {
    let Some(captures) = FIELD_DECLARATION.captures(segment) else {
        return Vec::new();
    };
    let modifiers = captures
        .name("modifiers")
        .map_or("", |value| value.as_str());
    let type_name = captures.name("type").unwrap().as_str().to_owned();
    quote_aware_split_top_level(captures.name("variables").unwrap().as_str(), b',')
        .into_iter()
        .filter_map(|variable| {
            let captures = FIELD_VARIABLE.captures(variable.trim())?;
            let name = captures.get(1)?.as_str().to_owned();
            Some(Field {
                type_name: type_name.clone(),
                name,
                is_static: modifiers.split_whitespace().any(|value| value == "static"),
                is_late_final: modifiers.split_whitespace().any(|value| value == "late")
                    && modifiers.split_whitespace().any(|value| value == "final"),
                has_initializer: captures.get(2).is_some(),
            })
        })
        .collect()
}

fn enum_names(source: &str) -> BTreeSet<String> {
    ENUM_START
        .captures_iter(source)
        .filter_map(|captures| captures.get(1).map(|name| name.as_str().to_owned()))
        .collect()
}

fn class_findings(
    path: &str,
    source: &str,
    original: &str,
    class: &Class,
    enum_names: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let methods = class
        .methods
        .iter()
        .map(|method| (method.name.as_str(), method))
        .collect::<HashMap<_, _>>();

    add_public_boundary_findings(path, source, original, class, &mut findings);
    add_copy_with_finding(path, source, class, &methods, &mut findings);
    add_json_contract_findings(path, source, class, enum_names, &methods, &mut findings);
    findings
}

fn add_public_boundary_findings(
    path: &str,
    source: &str,
    original: &str,
    class: &Class,
    findings: &mut Vec<Finding>,
) {
    for method in class.methods.iter().filter(|method| {
        !method.is_constructor
            && !method.name.starts_with('_')
            && !method.name.starts_with("toJson")
    }) {
        if MAP_STRING_DYNAMIC.is_match(&method.header) {
            findings.push(finding_range(
                "dart-map-string-dynamic-boundary",
                path,
                attached_declaration_line(original, line_at(source, method.start)),
                line_at(source, method.end.saturating_sub(1)),
                &format!(
                    "public method `{}` exposes Map<String, dynamic>",
                    method.name
                ),
            ));
        }
    }
}

fn add_copy_with_finding(
    path: &str,
    source: &str,
    class: &Class,
    methods: &HashMap<&str, &Method>,
    findings: &mut Vec<Finding>,
) {
    let Some(copy_with) = methods.get("copyWith") else {
        return;
    };
    let fields = class
        .fields
        .iter()
        .filter(|field| !field.is_static && !field.name.starts_with('_'))
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    let mut represented = parameter_names(&copy_with.parameters);
    represented.extend(preserved_copy_fields(
        &source[copy_with.body_start.min(copy_with.end)..copy_with.end],
        &fields,
    ));
    let missing = fields.difference(&represented).cloned().collect::<Vec<_>>();
    if fields.len() > 1 && !missing.is_empty() {
        findings.push(finding_range(
            "dart-copy-with-missing-field",
            path,
            line_at(source, copy_with.start),
            line_at(source, copy_with.end.saturating_sub(1)),
            &format!("copyWith omits instance fields: [{}]", missing.join(", ")),
        ));
    }
}

fn add_json_contract_findings(
    path: &str,
    source: &str,
    class: &Class,
    enum_names: &BTreeSet<String>,
    methods: &HashMap<&str, &Method>,
    findings: &mut Vec<Finding>,
) {
    let Some(to_json) = methods.get("toJson") else {
        return;
    };
    let to_json_text = &source[to_json.start..to_json.end];
    if let Some(from_json) = methods.get("fromJson") {
        let decoder_text = &source[from_json.start..from_json.end];
        add_serialization_asymmetry_finding(
            path,
            source,
            class,
            to_json_text,
            decoder_text,
            findings,
        );
        add_late_final_findings(path, source, class, to_json_text, decoder_text, findings);
    }
    add_enum_persistence_finding(
        path,
        source,
        class,
        enum_names,
        to_json,
        to_json_text,
        findings,
    );
}

fn add_serialization_asymmetry_finding(
    path: &str,
    source: &str,
    class: &Class,
    to_json_text: &str,
    decoder_text: &str,
    findings: &mut Vec<Finding>,
) {
    let written = ordered_captures(&JSON_KEY, to_json_text);
    let mut read = ordered_captures(&JSON_ACCESS_KEY, decoder_text);
    for key in ordered_captures(&JSON_READER_KEY, decoder_text) {
        if !read.contains(&key) {
            read.push(key);
        }
    }
    let written_set = written.iter().collect::<BTreeSet<_>>();
    let read_set = read.iter().collect::<BTreeSet<_>>();
    if !written.is_empty() && !read.is_empty() && written_set != read_set {
        let only_written = written
            .iter()
            .filter(|key| !read.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        let only_read = read
            .iter()
            .filter(|key| !written.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        findings.push(finding(
            "dart-json-serialization-asymmetry",
            path,
            line_at(source, class.start),
            &format!(
                "toJson/fromJson fields differ: write-only={} read-only={}",
                dart_set(&only_written),
                dart_set(&only_read)
            ),
        ));
    }
}

fn add_late_final_findings(
    path: &str,
    source: &str,
    class: &Class,
    to_json_text: &str,
    decoder_text: &str,
    findings: &mut Vec<Finding>,
) {
    for field in class.fields.iter().filter(|field| {
        field.is_late_final
            && !field.has_initializer
            && contains_identifier(to_json_text, &field.name)
    }) {
        let restored = Regex::new(&format!(
            r"\b{}\s*=\s*(?:json|map|data)\s*\[",
            regex::escape(&field.name)
        ))
        .unwrap()
        .is_match(decoder_text);
        if !restored {
            findings.push(finding(
                "dart-late-final-persistence",
                path,
                line_at(source, class.start),
                &format!(
                    "persisted late final field `{}` is not restored explicitly",
                    field.name
                ),
            ));
        }
    }
}

fn add_enum_persistence_finding(
    path: &str,
    source: &str,
    class: &Class,
    enum_names: &BTreeSet<String>,
    to_json: &Method,
    to_json_text: &str,
    findings: &mut Vec<Finding>,
) {
    let enum_fields = class
        .fields
        .iter()
        .filter(|field| enum_names.contains(field.type_name.trim_end_matches('?')))
        .map(|field| field.name.as_str());
    if enum_fields.into_iter().any(|field| {
        Regex::new(&format!(
            r#"['\"][^'\"]+['\"]\s*:\s*(?:this\.)?{}\.name\b"#,
            regex::escape(field)
        ))
        .unwrap()
        .is_match(to_json_text)
    }) {
        findings.push(finding(
            "dart-enum-name-persistence",
            path,
            line_at(source, to_json.start),
            "enum name is used as a persisted representation",
        ));
    }
}

fn parameter_names(parameters: &str) -> BTreeSet<String> {
    let parameters = strip_parameter_delimiters(parameters);
    quote_aware_split_top_level(parameters, b',')
        .into_iter()
        .filter_map(|parameter| {
            IDENTIFIER
                .find_iter(parameter.split('=').next().unwrap_or(parameter))
                .map(|matched| matched.as_str())
                .filter(|identifier| {
                    !matches!(
                        *identifier,
                        "required" | "final" | "const" | "covariant" | "this" | "super"
                    )
                })
                .last()
                .map(str::to_owned)
        })
        .collect()
}

fn strip_parameter_delimiters(parameters: &str) -> &str {
    let trimmed = parameters.trim();
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn preserved_copy_fields(body: &str, candidates: &BTreeSet<String>) -> BTreeSet<String> {
    let mut preserved = BTreeSet::new();
    for field in candidates {
        let named = Regex::new(&format!(
            r"\b{}\s*:\s*[^,\n)]*\b(?:this\s*\.\s*)?{}\b",
            regex::escape(field),
            regex::escape(field)
        ))
        .unwrap();
        if named.is_match(body) {
            preserved.insert(field.clone());
        }
    }
    for fresh in FRESH_CASCADE.find_iter(body) {
        let tail = &body[fresh.end() - 2..];
        for assignment in CASCADE_ASSIGNMENT.captures_iter(tail) {
            let target = assignment.get(1).unwrap().as_str();
            let value = assignment.get(2).unwrap().as_str();
            if target == value && candidates.contains(target) {
                preserved.insert(target.to_owned());
            }
        }
    }
    preserved
}

fn json_cast_findings(path: &str, source: &str, classes: &[Class]) -> Vec<Finding> {
    let try_regions = fallback_try_regions(source);
    JSON_CAST
        .captures_iter(source)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            if try_regions
                .iter()
                .any(|(start, end)| *start <= whole.start() && whole.end() <= *end)
                || guarded_by_type_test(source, &captures)
                || fallback_protected_decoder(source, classes, whole.start(), &try_regions)
            {
                return None;
            }
            Some(finding(
                "dart-json-cast-without-validation",
                path,
                line_at(source, whole.start()),
                "decoded JSON value is cast without validation",
            ))
        })
        .collect()
}

fn fallback_try_regions(source: &str) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    for matched in TRY_START.find_iter(source) {
        let open = matched.end() - 1;
        let Some(body_end) = quote_aware_matching_delimiter(source, open, b'{', b'}') else {
            continue;
        };
        let suffix = &source[body_end + 1..];
        let Some(catch_match) = CATCH_AFTER.captures(suffix) else {
            continue;
        };
        let catch_whole = catch_match.get(0).unwrap();
        let catch_open = body_end + 1 + catch_whole.end() - 1;
        let Some(catch_end) = quote_aware_matching_delimiter(source, catch_open, b'{', b'}') else {
            continue;
        };
        if RETURN_NULL.is_match(&source[catch_open + 1..catch_end]) {
            regions.push((open + 1, body_end));
        }
    }
    regions
}

fn fallback_protected_decoder(
    source: &str,
    classes: &[Class],
    offset: usize,
    try_regions: &[(usize, usize)],
) -> bool {
    let Some(method) = classes
        .iter()
        .flat_map(|class| &class.methods)
        .find(|method| method.start <= offset && offset < method.end)
    else {
        return false;
    };
    if !method.name.starts_with('_')
        || !(method.name.to_ascii_lowercase().contains("fromjson")
            || method.name.to_ascii_lowercase().contains("decode"))
    {
        return false;
    }
    let declaration_offset = IDENTIFIER
        .find_iter(&source[method.start..method.body_start])
        .find(|identifier| identifier.as_str() == method.name)
        .map(|identifier| method.start + identifier.start());
    let usages = IDENTIFIER
        .find_iter(source)
        .filter(|identifier| {
            identifier.as_str() == method.name && Some(identifier.start()) != declaration_offset
        })
        .collect::<Vec<_>>();
    !usages.is_empty()
        && usages.iter().all(|usage| {
            try_regions
                .iter()
                .any(|(start, end)| *start <= usage.start() && usage.end() <= *end)
        })
}

fn guarded_by_type_test(source: &str, captures: &regex::Captures<'_>) -> bool {
    let Some(whole) = captures.get(0) else {
        return false;
    };
    let Some(operand) = captures.name("operand").map(|value| value.as_str()) else {
        return false;
    };
    let Some(cast_type) = captures.name("type").map(|value| value.as_str().trim()) else {
        return false;
    };

    for if_region in if_regions(source) {
        if if_region.then_start <= whole.start()
            && whole.end() <= if_region.then_end
            && condition_guarantees_type(&if_region.condition, operand, cast_type, true)
        {
            return true;
        }
        if let Some((start, end)) = if_region.else_range
            && start <= whole.start()
            && whole.end() <= end
            && condition_guarantees_type(&if_region.condition, operand, cast_type, false)
        {
            return true;
        }
    }

    let start = whole.start().saturating_sub(300);
    let prefix = &source[start..whole.start()];
    let ternary = Regex::new(&format!(
        r"(?s){}\s+is\s+(!\s*)?([A-Za-z_]\w*(?:\s*<[^>]+>)?\??)\s*\?[^:]*$",
        regex::escape(operand)
    ))
    .unwrap();
    ternary.captures(prefix).is_some_and(|guard| {
        guard.get(1).is_none()
            && guard
                .get(2)
                .is_some_and(|guard_type| guard_type_allows_cast(guard_type.as_str(), cast_type))
    })
}

struct IfRegion {
    condition: String,
    then_start: usize,
    then_end: usize,
    else_range: Option<(usize, usize)>,
}

fn if_regions(source: &str) -> Vec<IfRegion> {
    let mut result = Vec::new();
    for matched in IF_START.find_iter(source) {
        let open = matched.end() - 1;
        let Some(close) = quote_aware_matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        let Some((then_start, then_end)) = statement_range(source, close + 1) else {
            continue;
        };
        let mut cursor = then_end;
        while cursor < source.len() && source.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let else_range = source[cursor..]
            .starts_with("else")
            .then(|| statement_range(source, cursor + 4))
            .flatten();
        result.push(IfRegion {
            condition: source[open + 1..close].to_owned(),
            then_start,
            then_end,
            else_range,
        });
    }
    result
}

fn statement_range(source: &str, mut start: usize) -> Option<(usize, usize)> {
    while start < source.len() && source.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    if source.as_bytes().get(start) == Some(&b'{') {
        let end = quote_aware_matching_delimiter(source, start, b'{', b'}')?;
        return Some((start + 1, end));
    }
    let end = expression_end(source, start);
    Some((start, end))
}

#[derive(Clone, Copy)]
enum ConditionOperator {
    And,
    Or,
}

enum ConditionTerm<'a> {
    Negated(&'a str),
    Compound {
        left: &'a str,
        operator: ConditionOperator,
        right: &'a str,
    },
    TypeTest(&'a str),
}

fn condition_guarantees_type(
    condition: &str,
    operand: &str,
    cast_type: &str,
    when_true: bool,
) -> bool {
    match parse_condition_term(condition) {
        ConditionTerm::Negated(rest) => {
            condition_guarantees_type(rest, operand, cast_type, !when_true)
        }
        ConditionTerm::Compound {
            left,
            operator,
            right,
        } => {
            compound_condition_guarantees_type(left, operator, right, operand, cast_type, when_true)
        }
        ConditionTerm::TypeTest(type_test) => {
            type_test_guarantees_type(type_test, operand, cast_type, when_true)
        }
    }
}

fn parse_condition_term(condition: &str) -> ConditionTerm<'_> {
    let condition = strip_parentheses(condition.trim());
    if let Some(rest) = condition.strip_prefix('!') {
        return ConditionTerm::Negated(rest);
    }
    if let Some((left, right)) = split_operator(condition, "&&") {
        return ConditionTerm::Compound {
            left,
            operator: ConditionOperator::And,
            right,
        };
    }
    if let Some((left, right)) = split_operator(condition, "||") {
        return ConditionTerm::Compound {
            left,
            operator: ConditionOperator::Or,
            right,
        };
    }
    ConditionTerm::TypeTest(condition)
}

fn compound_condition_guarantees_type(
    left: &str,
    operator: ConditionOperator,
    right: &str,
    operand: &str,
    cast_type: &str,
    when_true: bool,
) -> bool {
    let left = condition_guarantees_type(left, operand, cast_type, when_true);
    let right = condition_guarantees_type(right, operand, cast_type, when_true);
    match (operator, when_true) {
        (ConditionOperator::And, true) | (ConditionOperator::Or, false) => left || right,
        (ConditionOperator::And, false) | (ConditionOperator::Or, true) => left && right,
    }
}

fn type_test_guarantees_type(
    condition: &str,
    operand: &str,
    cast_type: &str,
    when_true: bool,
) -> bool {
    let Some(guard) = TYPE_TEST.captures(condition) else {
        return false;
    };
    let same_operand = compact(guard.name("operand").unwrap().as_str()) == compact(operand);
    let positive = guard.name("not").is_none();
    same_operand
        && when_true == positive
        && guard_type_allows_cast(guard.name("type").unwrap().as_str(), cast_type)
}

fn split_operator<'a>(source: &'a str, operator: &str) -> Option<(&'a str, &'a str)> {
    let bytes = source.as_bytes();
    let operator = operator.as_bytes();
    let mut depths = [0usize; 3];
    let mut index = 0usize;
    while index + operator.len() <= bytes.len() {
        match bytes[index] {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'[' => depths[1] += 1,
            b']' => depths[1] = depths[1].saturating_sub(1),
            b'{' => depths[2] += 1,
            b'}' => depths[2] = depths[2].saturating_sub(1),
            _ => {}
        }
        if depths == [0, 0, 0] && &bytes[index..index + operator.len()] == operator {
            return Some((&source[..index], &source[index + operator.len()..]));
        }
        index += 1;
    }
    None
}

fn strip_parentheses(mut value: &str) -> &str {
    loop {
        let trimmed = value.trim();
        if trimmed.starts_with('(')
            && quote_aware_matching_delimiter(trimmed, 0, b'(', b')') == Some(trimmed.len() - 1)
        {
            value = &trimmed[1..trimmed.len() - 1];
        } else {
            return trimmed;
        }
    }
}

fn guard_type_allows_cast(guard: &str, cast: &str) -> bool {
    let guard = compact(guard);
    let cast = compact(cast);
    if guard == cast {
        return true;
    }
    if guard.contains('<') {
        return false;
    }
    guard.trim_end_matches('?')
        == cast
            .split('<')
            .next()
            .unwrap_or(&cast)
            .trim_end_matches('?')
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .unwrap()
        .is_match(source)
}

fn ordered_captures(pattern: &Regex, source: &str) -> Vec<String> {
    let mut values = Vec::new();
    for captures in pattern.captures_iter(source) {
        let Some(value) = captures.get(1).map(|value| value.as_str().to_owned()) else {
            continue;
        };
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values
}

fn dart_set(values: &[String]) -> String {
    format!("{{{}}}", values.join(", "))
}

fn matching_open_delimiter(source: &str, close: usize, opening: u8, closing: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    for index in (0..=close).rev() {
        if bytes[index] == closing {
            depth += 1;
        } else if bytes[index] == opening {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn expression_end(source: &str, start: usize) -> usize {
    let mut depths = [0usize; 3];
    for (index, byte) in source.as_bytes().iter().enumerate().skip(start) {
        match *byte {
            b'(' => depths[0] += 1,
            b')' if depths[0] > 0 => depths[0] -= 1,
            b'[' => depths[1] += 1,
            b']' if depths[1] > 0 => depths[1] -= 1,
            b'{' => depths[2] += 1,
            b'}' if depths[2] > 0 => depths[2] -= 1,
            b';' if depths == [0, 0, 0] => return index + 1,
            _ => {}
        }
    }
    source.len()
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding_range(code: &str, path: &str, line: usize, end_line: usize, message: &str) -> Finding {
    let mut result = finding(code, path, line, message);
    result.end_line = end_line;
    result
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart model contract metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart model contract severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: if matches!(
            code,
            "dart-json-cast-without-validation"
                | "dart-map-string-dynamic-boundary"
                | "dart-copy-with-missing-field"
        ) {
            "high"
        } else {
            "medium"
        }
        .to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+([A-Za-z_]\w*)[^\{;]*\{").unwrap());
static ENUM_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\benum\s+([A-Za-z_]\w*)\s*\{").unwrap());
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]\w*").unwrap());
static METHOD_BLOCK_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\)\s*(?:async\s*)?(?:sync\s*\*)?$|\b(?:get|set)\s+\w+$").unwrap()
});
static GETTER_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bget\s+(?P<name>[A-Za-z_]\w*)\s*$").unwrap());
static FIELD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^\s*(?P<modifiers>(?:(?:static|late|final|const|covariant)\s+)*)(?P<type>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:<[^;=]+>)?\??)\s+(?P<variables>[^;]+);\s*$").unwrap()
});
static FIELD_VARIABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^([A-Za-z_]\w*)\s*(?:=\s*(.+))?$").unwrap());
static MAP_STRING_DYNAMIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bMap\s*<\s*String\s*,\s*dynamic\s*>").unwrap());
static JSON_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['\"]([^'\"]+)['\"]\s*:"#).unwrap());
static JSON_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\b(?:json|map|data)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]"#).unwrap());
static JSON_READER_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:reader\s*\.\s*\w+|required\w*)\s*\(\s*['\"]([^'\"]+)['\"]"#).unwrap()
});
static JSON_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<operand>\b(?:json|data|body|payload|map)\s*\[\s*[^\]\n]+\s*\])\s*!?\s+as\s+(?P<type>[A-Za-z_]\w*(?:\s*<[^>;\n]+>)?\??)").unwrap()
});
static TRY_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btry\s*\{").unwrap());
static CATCH_AFTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^\s*(?:on\s+[^\{]+)?(?:catch\s*\([^)]*\))?\s*\{").unwrap());
static RETURN_NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\breturn\s+null\s*;").unwrap());
static IF_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bif\s*\(").unwrap());
static TYPE_TEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<operand>.+?)\s+is\s+(?P<not>!\s*)?(?P<type>[A-Za-z_]\w*(?:\s*<[^>]+>)?\??)$")
        .unwrap()
});
static FRESH_CASCADE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^\s*|\breturn\s+|=>\s+)(?:const\s+|new\s+)?[A-Z]\w*(?:<[^>]+>)?\s*\([^;]*?\)\s*\.\.",
    )
    .unwrap()
});
static CASCADE_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\.([A-Za-z_]\w*)\s*=\s*(?:this\.)?([A-Za-z_]\w*)").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn finds_json_cast_and_serialization_contract_risks() {
        let fixture = Fixture::new([(
            "lib/model.dart",
            "class Model {\n  Model(this.id, this.name);\n  final int id;\n  final String name;\n  factory Model.fromJson(Map<String, dynamic> json) =>\n      Model(json['id'] as int, json['title'] as String);\n  Map<String, Object?> toJson() => {'id': id, 'name': name};\n}",
        )]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-json-cast-without-validation".to_owned(), 6),
                ("dart-json-cast-without-validation".to_owned(), 6),
                ("dart-json-serialization-asymmetry".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn honors_type_guards_and_corrupt_input_fallbacks() {
        let fixture = Fixture::new([(
            "lib/cache.dart",
            "class Cache {\n  int _valueFromJson(Map<String, Object?> json) => json['value'] as int;\n  Object? guarded(Map<String, dynamic> json) {\n    if (json['name'] is String) return json['name'] as String;\n    return json['items'] is List ? json['items'] as List<dynamic> : null;\n  }\n  int? decode(Map<String, Object?> json) {\n    try { return _valueFromJson(json); } on Object { return null; }\n  }\n}",
        )]);

        assert!(findings_for(&fixture, "dart-json-cast-without-validation").is_empty());
    }
    #[test]
    fn recognizes_fallback_protected_decoder_tearoffs() {
        let fixture = Fixture::new([(
            "lib/cache.dart",
            "class Cache {\n  List<String> _itemsFromJson(Map<String, Object?> json) =>\n      ((json['items'] as List<Object?>?) ?? const <Object?>[])\n          .whereType<String>()\n          .toList(growable: false);\n  List<String>? safe(List<Map<String, Object?>> values) {\n    try { return values.expand(_itemsFromJson).toList(); } on Object { return null; }\n  }\n}",
        )]);

        assert!(findings_for(&fixture, "dart-json-cast-without-validation").is_empty());
    }

    #[test]
    fn reports_decoders_used_outside_a_fallback() {
        let fixture = Fixture::new([(
            "lib/cache.dart",
            "class Cache {\n  int _valueFromJson(Map<String, Object?> json) => json['value'] as int;\n  int? safe(Map<String, Object?> json) {\n    try { return _valueFromJson(json); } on Object { return null; }\n  }\n  int unsafe(Map<String, Object?> json) => _valueFromJson(json);\n}",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-json-cast-without-validation")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn scopes_serialization_to_exact_methods_and_validated_readers() {
        let fixture = Fixture::new([
            (
                "lib/product.dart",
                "class Product {\n  Product(this.id);\n  final String id;\n  factory Product.fromJson(Map<String, Object?> json) => Product(json['id'] as String);\n  static String _toJsonString(Object? value) => '$value';\n}",
            ),
            (
                "lib/model.dart",
                "class Model {\n  Model(this.id, this.count);\n  final String id;\n  final int count;\n  factory Model.fromJson(Map<String, Object?> json) {\n    final reader = Reader(json);\n    int requiredInt(String key) => json[key] as int;\n    return Model(reader.string('id'), requiredInt('count'));\n  }\n  Map<String, Object?> toJson() => {'id': id, 'count': count};\n}",
            ),
        ]);

        assert!(findings_for(&fixture, "dart-json-serialization-asymmetry").is_empty());
    }

    #[test]
    fn reports_json_casts_through_dynamic_keys() {
        let fixture = Fixture::new([(
            "lib/reader.dart",
            "int requiredInt(Map<String, Object?> json, String key) => json[key] as int;",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-json-cast-without-validation")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn reports_public_dynamic_copy_and_persistence_contracts() {
        let fixture = Fixture::new([(
            "lib/contracts.dart",
            "enum Mode { ready }\nclass Contract {\n  Contract(this.id, this.name);\n  final int id;\n  final String name;\n  late final String token;\n  Mode mode = Mode.ready;\n  Contract copyWith({int? id}) => Contract(id ?? this.id, name);\n  factory Contract.fromJson(Map<String, Object?> json) => Contract(json['id'] as int, json['name'] as String);\n  Map<String, dynamic> expose() => {'id': id};\n  Map<String, Object?> toJson() => {'id': id, 'name': name, 'token': token, 'mode': mode.name};\n  String imageUrl() => 'https://example.test/image.png';\n}",
        )]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("dart-copy-with-missing-field".to_owned(), 8),
                ("dart-enum-name-persistence".to_owned(), 11),
                ("dart-json-cast-without-validation".to_owned(), 9),
                ("dart-json-cast-without-validation".to_owned(), 9),
                ("dart-json-serialization-asymmetry".to_owned(), 2),
                ("dart-late-final-persistence".to_owned(), 2),
                ("dart-map-string-dynamic-boundary".to_owned(), 10),
            ]
        );
    }

    #[test]
    fn accepts_preserved_copy_fields_and_explicit_restoration() {
        let fixture = Fixture::new([(
            "lib/contracts.dart",
            "class Contract {\n  Contract(this.id, this.name);\n  final int id;\n  final String name;\n  late final String token;\n  String mode = 'ready';\n  Contract copyWith({int? id, String? name, String? token, String? mode}) {\n    final result = Contract(id ?? this.id, name ?? this.name);\n    result.token = token ?? this.token;\n    result.mode = mode ?? this.mode;\n    return result;\n  }\n  factory Contract.fromJson(Map<String, Object?> json) {\n    final result = Contract(json['id'] as int, json['name'] as String);\n    result.token = json['token'] as String;\n    return result;\n  }\n  Map<String, Object?> toJson() => {'id': id, 'name': name, 'token': token};\n}",
        )]);

        let codes = code_lines(&fixture);
        assert!(!codes.iter().any(|(code, _)| matches!(
            code.as_str(),
            "dart-copy-with-missing-field"
                | "dart-json-serialization-asymmetry"
                | "dart-late-final-persistence"
        )));
    }

    #[test]
    fn distinguishes_fresh_and_unrelated_cascades() {
        let safe = Fixture::new([(
            "lib/render_context.dart",
            "class RenderContext {\n  int listDepth = 0;\n  bool ordered = false;\n  int recursion = 0;\n  RenderContext copyWith({int? listDepth, bool? ordered}) => RenderContext()\n    ..listDepth = listDepth ?? this.listDepth\n    ..ordered = ordered ?? this.ordered\n    ..recursion = recursion;\n}",
        )]);
        assert!(findings_for(&safe, "dart-copy-with-missing-field").is_empty());

        let unsafe_fixture = Fixture::new([(
            "lib/model.dart",
            "class Holder { int recursion = 0; }\nclass Model {\n  int count = 0;\n  int recursion = 0;\n  final Holder other = Holder();\n  Model copyWith({int? count}) {\n    other..recursion = recursion;\n    return Model()..count = count ?? this.count;\n  }\n}",
        )]);
        let finding = findings_for(&unsafe_fixture, "dart-copy-with-missing-field")
            .into_iter()
            .next()
            .unwrap();
        assert!(finding.message.contains("other, recursion"));
    }

    #[test]
    fn incomplete_models_do_not_abort_or_hide_valid_cast_findings() {
        let fixture = Fixture::new([(
            "lib/incomplete.dart",
            "class Valid {\n  Object read(Map<String, Object?> data) => data['id'] as int;\n}\nclass Incomplete {\n  Object? read(Map<String, Object?> data) {\n    if (data['name'] is String) return data['name'] as String;\n",
        )]);

        assert_eq!(
            findings_for(&fixture, "dart-json-cast-without-validation")
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    fn findings_for(fixture: &Fixture, code: &str) -> Vec<Finding> {
        analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == code)
            .collect()
    }

    fn code_lines(fixture: &Fixture) -> Vec<(String, usize)> {
        let mut findings = analyze(&fixture.context())
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();
        findings.sort();
        findings
    }

    struct Fixture {
        sources: BTreeMap<String, String>,
    }

    impl Fixture {
        fn new<const N: usize>(sources: [(&str, &str); N]) -> Self {
            Self {
                sources: sources
                    .into_iter()
                    .map(|(path, source)| (path.to_owned(), source.to_owned()))
                    .collect(),
            }
        }

        fn context(&self) -> SourceAnalysisContext<'_> {
            SourceAnalysisContext::unchanged(&self.sources)
        }
    }
}
