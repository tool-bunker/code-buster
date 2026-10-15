use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

#[cfg(test)]
use crate::dart_core_rules::mask_comments_preserving_strings;
use crate::dart_null_assertion::dart_source_with_interpolations;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;

use super::{
    attached_documentation_line, index::DartSourceIndex, quote_aware_split_top_level_with_angles,
    top_level_arrow,
};

#[derive(Clone)]
struct Parameter {
    type_name: String,
    name: String,
}

#[derive(Clone)]
struct Method {
    name: String,
    line: usize,
    return_type: Option<String>,
    parameters: Option<Vec<Parameter>>,
    body: String,
    is_empty: bool,
    is_static: bool,
    is_override: bool,
    is_constructor: bool,
}

#[derive(Clone)]
struct Field {
    type_name: String,
    name: String,
    is_static: bool,
    is_final: bool,
    is_const: bool,
}

#[derive(Clone)]
struct Class {
    path: String,
    line: usize,
    name: String,
    parent: Option<String>,
    interfaces: Vec<String>,
    has_mixin: bool,
    fields: Vec<Field>,
    methods: Vec<Method>,
}

struct Project {
    sources: BTreeMap<String, String>,
    classes: Vec<Class>,
    functions: Vec<(String, Method)>,
}

#[cfg(test)]
pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let originals = sources
        .iter()
        .filter(|(path, _)| path.ends_with(".dart"))
        .map(|(path, source)| (path.clone(), source.clone()))
        .collect::<BTreeMap<_, _>>();
    let dart_sources = originals
        .iter()
        .map(|(path, source)| (path.clone(), mask_comments_preserving_strings(source)))
        .collect::<BTreeMap<_, _>>();
    analyze_project(originals, dart_sources)
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let originals = index
        .paths()
        .map(|path| (path.to_owned(), index.source(path).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let dart_sources = index
        .paths()
        .map(|path| (path.to_owned(), index.comments_masked(path).to_owned()))
        .collect::<BTreeMap<_, _>>();
    analyze_project(originals, dart_sources)
}

fn analyze_project(
    originals: BTreeMap<String, String>,
    dart_sources: BTreeMap<String, String>,
) -> Vec<Finding> {
    if dart_sources.is_empty() {
        return Vec::new();
    }
    let mut project = parse_project(dart_sources);
    for class in &mut project.classes {
        if let Some(source) = originals.get(&class.path) {
            class.line = attached_documentation_line(source, class.line);
            for method in &mut class.methods {
                method.line = attached_documentation_line(source, method.line);
            }
        }
    }
    for (path, method) in &mut project.functions {
        if let Some(source) = originals.get(path) {
            method.line = attached_documentation_line(source, method.line);
        }
    }
    let mut findings = Vec::new();
    findings.extend(data_clumps(&project));
    findings.extend(strategy_dispatch(&project));
    findings.extend(interface_pressure(&project));
    findings.extend(state_behavior(&project));
    findings.extend(single_use_abstractions(&project));
    findings.extend(refused_bequests(&project));
    findings.extend(middle_men(&project));
    findings.extend(observer_notifications(&project));
    findings.extend(message_chains(&project));
    findings.extend(feature_envy(&project));
    findings.extend(service_locators(&project));
    findings.extend(boundary_bypasses(&project));
    findings.extend(repeated_adapter_mappings(&project));
    findings.extend(template_workflows(&project));
    findings
}

fn parse_project(sources: BTreeMap<String, String>) -> Project {
    let mut collector = ProjectCollector::default();
    for (path, source) in &sources {
        collector.collect_source(path, source);
    }
    Project {
        sources,
        classes: collector.classes,
        functions: collector.functions,
    }
}

#[derive(Default)]
struct ProjectCollector {
    classes: Vec<Class>,
    functions: Vec<(String, Method)>,
}

impl ProjectCollector {
    fn collect_source(&mut self, path: &str, source: &str) {
        SourceCollector::new(path, source, &mut self.classes, &mut self.functions).collect();
    }
}

struct SourceCollector<'source, 'output> {
    path: &'source str,
    source: &'source str,
    structure: String,
    class_ranges: Vec<(usize, usize)>,
    classes: &'output mut Vec<Class>,
    functions: &'output mut Vec<(String, Method)>,
}

impl<'source, 'output> SourceCollector<'source, 'output> {
    fn new(
        path: &'source str,
        source: &'source str,
        classes: &'output mut Vec<Class>,
        functions: &'output mut Vec<(String, Method)>,
    ) -> Self {
        Self {
            path,
            source,
            structure: mask_strings(source),
            class_ranges: Vec::new(),
            classes,
            functions,
        }
    }

    fn collect(mut self) {
        self.collect_standard_classes();
        self.collect_broad_classes();
        self.collect_mixin_functions();
        self.collect_top_level_functions();
    }

    fn collect_standard_classes(&mut self) {
        for declaration in CLASS_DECLARATION.captures_iter(&self.structure) {
            let Some((class, range)) =
                standard_class(self.path, self.source, &self.structure, &declaration)
            else {
                continue;
            };
            self.classes.push(class);
            self.class_ranges.push(range);
        }
    }

    fn collect_broad_classes(&mut self) {
        for declaration in BROAD_CLASS_DECLARATION.captures_iter(&self.structure) {
            let Some(whole) = declaration.get(0) else {
                continue;
            };
            if self.range_contains(whole.start()) {
                continue;
            }
            let Some((class, range)) =
                broad_class(self.path, self.source, &self.structure, &declaration)
            else {
                continue;
            };
            self.classes.push(class);
            self.class_ranges.push(range);
        }
    }

    fn collect_mixin_functions(&mut self) {
        for declaration in MIXIN_DECLARATION.captures_iter(&self.structure) {
            let Some(whole) = declaration.get(0) else {
                continue;
            };
            let Some(name) = declaration.get(1).map(|capture| capture.as_str()) else {
                continue;
            };
            if name == "class" || self.range_contains(whole.start()) {
                continue;
            }
            let open = whole.end() - 1;
            let Some(close) = matching_delimiter(&self.structure, open, b'{', b'}') else {
                continue;
            };
            let (_, methods) =
                parse_scope(self.source, &self.structure, open + 1, close, Some(name));
            self.functions.extend(
                methods
                    .into_iter()
                    .map(|method| (self.path.to_owned(), method)),
            );
            self.class_ranges.push((whole.start(), close + 1));
        }
    }

    fn collect_top_level_functions(self) {
        let mut top_level = self.source.as_bytes().to_vec();
        let mut top_level_structure = self.structure.into_bytes();
        for (start, end) in self.class_ranges {
            for bytes in [&mut top_level, &mut top_level_structure] {
                mask_non_newline_bytes(&mut bytes[start..end]);
            }
        }
        let top_level = String::from_utf8(top_level).expect("masked Dart source remains UTF-8");
        let top_level_structure =
            String::from_utf8(top_level_structure).expect("structural Dart source remains UTF-8");
        let (_, methods) = parse_scope(&top_level, &top_level_structure, 0, top_level.len(), None);
        self.functions.extend(
            methods
                .into_iter()
                .map(|method| (self.path.to_owned(), method)),
        );
    }

    fn range_contains(&self, index: usize) -> bool {
        self.class_ranges
            .iter()
            .any(|(start, end)| *start <= index && index < *end)
    }
}

fn standard_class(
    path: &str,
    source: &str,
    structure: &str,
    declaration: &regex::Captures<'_>,
) -> Option<(Class, (usize, usize))> {
    let whole = declaration.get(0)?;
    let open = whole.end() - 1;
    let close = matching_delimiter(structure, open, b'{', b'}')?;
    let name = declaration.get(1)?.as_str().to_owned();
    let (fields, methods) = parse_scope(source, structure, open + 1, close, Some(&name));
    let class = Class {
        path: path.to_owned(),
        line: line_at(source, whole.start()),
        name,
        parent: declaration
            .get(2)
            .map(|capture| base_type(capture.as_str())),
        interfaces: declaration
            .get(4)
            .map(|capture| parse_interfaces(capture.as_str()))
            .unwrap_or_default(),
        has_mixin: declaration.get(3).is_some(),
        fields,
        methods,
    };
    Some((class, (whole.start(), close + 1)))
}

fn broad_class(
    path: &str,
    source: &str,
    structure: &str,
    declaration: &regex::Captures<'_>,
) -> Option<(Class, (usize, usize))> {
    let whole = declaration.get(0)?;
    let open = whole.end() - 1;
    let close = matching_delimiter(structure, open, b'{', b'}')?;
    let name = declaration.get(1)?.as_str().to_owned();
    let header = &source[whole.start()..open];
    let (fields, methods) = parse_scope(source, structure, open + 1, close, Some(&name));
    let class = Class {
        path: path.to_owned(),
        line: line_at(source, whole.start()),
        name,
        parent: EXTENDS_CLAUSE
            .captures(header)
            .and_then(|capture| capture.get(1))
            .map(|capture| base_type(capture.as_str())),
        interfaces: IMPLEMENTS_CLAUSE
            .captures(header)
            .and_then(|capture| capture.get(1))
            .map(|capture| parse_interfaces(capture.as_str()))
            .unwrap_or_default(),
        has_mixin: header.contains(" with "),
        fields,
        methods,
    };
    Some((class, (whole.start(), close + 1)))
}

fn parse_interfaces(source: &str) -> Vec<String> {
    quote_aware_split_top_level_with_angles(source, b',')
        .into_iter()
        .map(base_type)
        .filter(|value| !value.is_empty())
        .collect()
}

fn parse_scope(
    source: &str,
    structure: &str,
    start: usize,
    end: usize,
    class_name: Option<&str>,
) -> (Vec<Field>, Vec<Method>) {
    ScopeParser::new(source, structure, start, end, class_name).parse()
}

#[derive(Default)]
struct ScopeDepth {
    round: usize,
    square: usize,
    curly: usize,
}

struct ScopeParser<'a> {
    source: &'a str,
    structure: &'a str,
    bytes: &'a [u8],
    end: usize,
    class_name: Option<&'a str>,
    fields: Vec<Field>,
    methods: Vec<Method>,
    member_start: usize,
    index: usize,
    depth: ScopeDepth,
    quote: Option<(u8, usize)>,
}

impl<'a> ScopeParser<'a> {
    fn new(
        source: &'a str,
        structure: &'a str,
        start: usize,
        end: usize,
        class_name: Option<&'a str>,
    ) -> Self {
        Self {
            source,
            structure,
            bytes: structure.as_bytes(),
            end,
            class_name,
            fields: Vec::new(),
            methods: Vec::new(),
            member_start: start,
            index: start,
            depth: ScopeDepth::default(),
            quote: None,
        }
    }

    fn parse(mut self) -> (Vec<Field>, Vec<Method>) {
        while self.index < self.end {
            if self.consume_quoted_byte() || self.start_quote() {
                continue;
            }
            self.consume_code_byte();
        }
        (self.fields, self.methods)
    }

    fn consume_quoted_byte(&mut self) -> bool {
        let Some((delimiter, width)) = self.quote else {
            return false;
        };
        let byte = self.bytes[self.index];
        if width == 1 && byte == b'\\' && self.index + 1 < self.end {
            self.index += 2;
            return true;
        }
        if self.quote_closes(delimiter, width) {
            self.index += width;
            self.quote = None;
            return true;
        }
        self.index += 1;
        true
    }

    fn quote_closes(&self, delimiter: u8, width: usize) -> bool {
        self.bytes[self.index] == delimiter
            && (width == 1
                || self
                    .bytes
                    .get(self.index..self.index + width)
                    .is_some_and(|slice| slice.iter().all(|candidate| *candidate == delimiter)))
    }

    fn start_quote(&mut self) -> bool {
        let byte = self.bytes[self.index];
        if !matches!(byte, b'\'' | b'"') {
            return false;
        }
        let width = if self.bytes.get(self.index + 1) == Some(&byte)
            && self.bytes.get(self.index + 2) == Some(&byte)
        {
            3
        } else {
            1
        };
        self.quote = Some((byte, width));
        self.index += width;
        true
    }

    fn consume_code_byte(&mut self) {
        match self.bytes[self.index] {
            b'(' => self.depth.round += 1,
            b')' => self.depth.round = self.depth.round.saturating_sub(1),
            b'[' => self.depth.square += 1,
            b']' => self.depth.square = self.depth.square.saturating_sub(1),
            b'{' => {
                if self.at_top_level() && self.consume_callable_block() {
                    return;
                }
                self.depth.curly += 1;
            }
            b'}' => self.depth.curly = self.depth.curly.saturating_sub(1),
            b';' if self.at_top_level() => self.finish_semicolon_member(),
            _ => {}
        }
        self.index += 1;
    }

    fn at_top_level(&self) -> bool {
        self.depth.round == 0 && self.depth.square == 0 && self.depth.curly == 0
    }

    fn consume_callable_block(&mut self) -> bool {
        let prefix = &self.source[self.member_start..self.index];
        if !looks_like_callable(prefix) {
            return false;
        }
        let close =
            matching_delimiter(self.structure, self.index, b'{', b'}').unwrap_or(self.end - 1);
        if let Some(method) = parse_method(
            self.source,
            self.class_name,
            self.member_start,
            self.index,
            close + 1,
            false,
        ) {
            self.methods.push(method);
        }
        self.index = close + 1;
        self.member_start = self.index;
        true
    }

    fn finish_semicolon_member(&mut self) {
        let segment = &self.source[self.member_start..=self.index];
        if let Some(arrow) = top_level_arrow(segment) {
            self.push_arrow_method(segment, arrow);
        } else if looks_like_callable(&segment[..segment.len() - 1]) {
            if let Some(method) = parse_method(
                self.source,
                self.class_name,
                self.member_start,
                self.index,
                self.index + 1,
                true,
            ) {
                self.methods.push(method);
            }
        } else if self.class_name.is_some() {
            self.fields.extend(parse_fields(segment));
        }
        self.member_start = self.index + 1;
    }

    fn push_arrow_method(&mut self, segment: &str, arrow: usize) {
        if !looks_like_callable(&segment[..arrow]) {
            return;
        }
        if let Some(method) = parse_method(
            self.source,
            self.class_name,
            self.member_start,
            self.member_start + arrow,
            self.index + 1,
            false,
        ) {
            self.methods.push(method);
        }
    }
}

fn looks_like_callable(prefix: &str) -> bool {
    let signature = prefix.trim();
    GETTER_SIGNATURE.is_match(signature)
        || signature.ends_with(')')
        || CALLABLE_SUFFIX.is_match(signature)
}

fn parse_method(
    source: &str,
    class_name: Option<&str>,
    start: usize,
    marker: usize,
    end: usize,
    is_empty: bool,
) -> Option<Method> {
    let header = source[start..marker].trim();
    let (name, before_name, constructor, parameters) =
        if let Some(getter) = GETTER_SIGNATURE.captures(header) {
            let whole = getter.get(0).unwrap();
            (
                getter.get(1).unwrap().as_str().to_owned(),
                header[..whole.start()].trim(),
                false,
                Some(Vec::new()),
            )
        } else if let Some((open, close, name, before_name)) =
            class_name.and_then(|class_name| constructor_signature(header, class_name))
        {
            (
                name.to_owned(),
                before_name,
                true,
                parse_parameters(&header[open + 1..close]),
            )
        } else {
            let close = header.rfind(')')?;
            let open = matching_open_delimiter(header, close, b'(', b')')?;
            let before = header[..open].trim_end();
            if let Some(operator) = OPERATOR_SIGNATURE.captures(before) {
                let operator_name = operator.get(1)?;
                let operator_signature = operator.get(0)?;
                (
                    operator_name.as_str().to_owned(),
                    before[..operator_signature.start()].trim(),
                    false,
                    parse_parameters(&header[open + 1..close]),
                )
            } else {
                let name_match = IDENTIFIER.find_iter(before).last()?;
                let name = name_match.as_str().to_owned();
                let before_name = before[..name_match.start()].trim();
                (
                    name,
                    before_name,
                    false,
                    parse_parameters(&header[open + 1..close]),
                )
            }
        };
    let return_type = if constructor {
        None
    } else {
        method_return_type(before_name)
    };
    let body = if is_empty {
        String::new()
    } else if source[marker..].starts_with("=>") {
        source[marker + 2..end - 1].trim().to_owned()
    } else {
        source[marker + 1..end - 1].trim().to_owned()
    };
    Some(Method {
        name,
        line: line_at(
            source,
            start + source[start..marker].find(|character: char| !character.is_whitespace())?,
        ),
        return_type,
        parameters,
        body,
        is_empty,
        is_static: WORD_STATIC.is_match(header),
        is_override: header.contains("@override"),
        is_constructor: constructor,
    })
}

struct ConstructorSignatureSpan {
    class_start: usize,
    name_start: usize,
    name_end: usize,
    open: usize,
    close: usize,
}

enum ConstructorCandidate {
    NotConstructor,
    Unterminated,
    Signature(ConstructorSignatureSpan),
}

struct ConstructorSignatureScanner<'a> {
    header: &'a str,
    class_name: &'a str,
}

impl<'a> ConstructorSignatureScanner<'a> {
    fn new(header: &'a str, class_name: &'a str) -> Self {
        Self { header, class_name }
    }

    fn scan(&self) -> Option<ConstructorSignatureSpan> {
        for (start, _) in self.header.match_indices(self.class_name) {
            match self.scan_candidate(start) {
                ConstructorCandidate::NotConstructor => {}
                ConstructorCandidate::Unterminated => return None,
                ConstructorCandidate::Signature(signature) => return Some(signature),
            }
        }
        None
    }

    fn scan_candidate(&self, class_start: usize) -> ConstructorCandidate {
        let bytes = self.header.as_bytes();
        let class_end = class_start + self.class_name.len();
        if has_identifier_neighbor(bytes, class_start, class_end) {
            return ConstructorCandidate::NotConstructor;
        }

        let mut cursor = class_end;
        let mut name_start = class_start;
        if bytes.get(cursor) == Some(&b'.') {
            name_start = cursor + 1;
            cursor = identifier_end(bytes, name_start);
            if cursor == name_start {
                return ConstructorCandidate::NotConstructor;
            }
        }
        let name_end = cursor;
        cursor = whitespace_end(bytes, cursor);
        if bytes.get(cursor) != Some(&b'(') {
            return ConstructorCandidate::NotConstructor;
        }
        let Some(close) = matching_delimiter(self.header, cursor, b'(', b')') else {
            return ConstructorCandidate::Unterminated;
        };
        ConstructorCandidate::Signature(ConstructorSignatureSpan {
            class_start,
            name_start,
            name_end,
            open: cursor,
            close,
        })
    }
}

fn has_identifier_neighbor(bytes: &[u8], start: usize, end: usize) -> bool {
    start
        .checked_sub(1)
        .and_then(|index| bytes.get(index))
        .is_some_and(|byte| is_identifier_byte(*byte))
        || bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn identifier_end(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes
        .get(cursor)
        .is_some_and(|byte| is_identifier_byte(*byte))
    {
        cursor += 1;
    }
    cursor
}

fn whitespace_end(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn constructor_signature<'a>(
    header: &'a str,
    class_name: &str,
) -> Option<(usize, usize, &'a str, &'a str)> {
    let signature = ConstructorSignatureScanner::new(header, class_name).scan()?;
    Some((
        signature.open,
        signature.close,
        &header[signature.name_start..signature.name_end],
        header[..signature.class_start].trim(),
    ))
}

fn method_return_type(before_name: &str) -> Option<String> {
    let mut source = before_name.trim();
    while let Some(annotation) = METHOD_ANNOTATION.find(source)
        && annotation.start() == 0
    {
        source = source[annotation.end()..].trim_start();
    }
    while let Some(modifier) = ["static", "external", "abstract", "covariant"]
        .into_iter()
        .find(|modifier| {
            source
                .strip_prefix(*modifier)
                .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        })
    {
        source = source[modifier.len()..].trim_start();
    }
    (!source.is_empty()).then(|| base_type(source))
}

fn parse_parameters(source: &str) -> Option<Vec<Parameter>> {
    if source.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut parameters = Vec::new();
    for raw in split_parameters(source) {
        let parameter = raw
            .trim()
            .trim_start_matches(['{', '['])
            .trim_end_matches(['}', ']'])
            .trim();
        if parameter.is_empty() {
            continue;
        }
        let capture = PARAMETER_DECLARATION.captures(parameter)?;
        parameters.push(Parameter {
            type_name: WHITESPACE.replace_all(&capture["type"], " ").into_owned(),
            name: capture["name"].to_owned(),
        });
    }
    Some(parameters)
}

#[derive(Default)]
struct ParameterScanState {
    round: usize,
    angle: usize,
    quote: Option<u8>,
}

enum ParameterScanTransition {
    Advance(usize),
    OptionalGroup,
}

impl ParameterScanState {
    fn advance(&mut self, byte: u8) -> ParameterScanTransition {
        if let Some(delimiter) = self.quote {
            return self.advance_quoted(byte, delimiter);
        }
        match byte {
            b'\'' | b'"' => self.quote = Some(byte),
            b'(' => self.round += 1,
            b')' => self.round = self.round.saturating_sub(1),
            b'<' => self.angle += 1,
            b'>' => self.angle = self.angle.saturating_sub(1),
            b'{' | b'[' if self.at_top_level() => {
                return ParameterScanTransition::OptionalGroup;
            }
            _ => {}
        }
        ParameterScanTransition::Advance(1)
    }

    fn advance_quoted(&mut self, byte: u8, delimiter: u8) -> ParameterScanTransition {
        if byte == b'\\' {
            return ParameterScanTransition::Advance(2);
        }
        if byte == delimiter {
            self.quote = None;
        }
        ParameterScanTransition::Advance(1)
    }

    fn at_top_level(&self) -> bool {
        self.round == 0 && self.angle == 0
    }
}

struct ParameterScanner<'a> {
    source: &'a str,
    index: usize,
    state: ParameterScanState,
}

impl<'a> ParameterScanner<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            index: 0,
            state: ParameterScanState::default(),
        }
    }

    fn next_optional_group(&mut self) -> Option<(usize, u8)> {
        let bytes = self.source.as_bytes();
        while self.index < bytes.len() {
            let index = self.index;
            let byte = bytes[index];
            match self.state.advance(byte) {
                ParameterScanTransition::Advance(width) => self.index += width,
                ParameterScanTransition::OptionalGroup => {
                    self.index += 1;
                    return Some((index, byte));
                }
            }
        }
        None
    }
}

fn split_parameters(source: &str) -> Vec<&str> {
    let mut scanner = ParameterScanner::new(source);
    while let Some((index, opening)) = scanner.next_optional_group() {
        if let Some(parameters) = split_optional_parameter_group(source, index, opening) {
            return parameters;
        }
    }
    quote_aware_split_top_level_with_angles(source, b',')
}

fn split_optional_parameter_group(
    source: &str,
    group_start: usize,
    opening: u8,
) -> Option<Vec<&str>> {
    let prefix = source[..group_start].trim_end();
    if !prefix.is_empty() && !prefix.ends_with(',') {
        return None;
    }
    let closing = if opening == b'{' { b'}' } else { b']' };
    let trimmed = source.trim_end();
    if trimmed.as_bytes().last() != Some(&closing) {
        return None;
    }
    let mut parameters =
        quote_aware_split_top_level_with_angles(prefix.strip_suffix(',').unwrap_or(prefix), b',');
    parameters.extend(quote_aware_split_top_level_with_angles(
        &source[group_start + 1..trimmed.len() - 1],
        b',',
    ));
    Some(parameters)
}

fn parse_fields(segment: &str) -> Vec<Field> {
    let Some(capture) = FIELD_DECLARATION.captures(segment.trim()) else {
        return Vec::new();
    };
    let modifiers = capture.name("modifiers").map_or("", |value| value.as_str());
    let type_name = capture.name("type").unwrap().as_str().trim().to_owned();
    quote_aware_split_top_level_with_angles(capture.name("variables").unwrap().as_str(), b',')
        .into_iter()
        .filter_map(|variable| {
            let name = IDENTIFIER.find(variable.trim())?.as_str().to_owned();
            Some(Field {
                type_name: type_name.clone(),
                name,
                is_static: modifiers.split_whitespace().any(|value| value == "static"),
                is_final: modifiers.split_whitespace().any(|value| value == "final"),
                is_const: modifiers.split_whitespace().any(|value| value == "const"),
            })
        })
        .collect()
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart OOP metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

struct CallbackScanner<'a> {
    source: &'a str,
    candidates: regex::Matches<'static, 'a>,
}

impl<'a> CallbackScanner<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            candidates: CALLBACK_START.find_iter(source),
        }
    }

    fn candidate_end(&self, start: usize, end: usize) -> Option<usize> {
        if self.source[start..end].trim_end().ends_with('{') {
            matching_delimiter(self.source, end - 1, b'{', b'}').map(|close| close + 1)
        } else {
            Some(callback_expression_end(self.source, end))
        }
    }
}

impl Iterator for CallbackScanner<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(candidate) = self.candidates.next() {
            let start = candidate.start();
            if has_non_callback_prefix(self.source, start) {
                continue;
            }
            if let Some(end) = self.candidate_end(start, candidate.end()) {
                return Some((start, end));
            }
        }
        None
    }
}

fn has_non_callback_prefix(source: &str, start: usize) -> bool {
    let previous_word = source[..start]
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .rfind(|word| !word.is_empty())
        .unwrap_or("");
    let previous_byte = source[..start]
        .bytes()
        .rfind(|byte| !byte.is_ascii_whitespace());
    matches!(previous_word, "for" | "if" | "while" | "switch" | "catch")
        || previous_byte.is_some_and(is_identifier_byte)
}

fn direct_body(body: &str) -> String {
    let structure = mask_strings(body);
    let mut result = body.as_bytes().to_vec();
    for (start, end) in CallbackScanner::new(&structure) {
        mask_non_newline_bytes(&mut result[start..end]);
    }
    String::from_utf8(result).expect("masked direct body remains UTF-8")
}

fn callback_expression_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depths = [0usize; 3];
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => depths[0] += 1,
            b')' if depths[0] == 0 && depths[1] == 0 && depths[2] == 0 => return index,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'[' => depths[1] += 1,
            b']' => depths[1] = depths[1].saturating_sub(1),
            b'{' => depths[2] += 1,
            b'}' => depths[2] = depths[2].saturating_sub(1),
            b',' | b';' if depths == [0, 0, 0] => return index,
            _ => {}
        }
        index += 1;
    }
    source.len()
}

fn mask_strings(source: &str) -> String {
    StringMasker::new(source).mask()
}

#[derive(Clone, Copy)]
struct StringLiteral {
    delimiter: u8,
    width: usize,
    raw: bool,
}

struct StringMasker<'a> {
    source: &'a [u8],
    output: Vec<u8>,
    index: usize,
}

impl<'a> StringMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            output: source.as_bytes().to_vec(),
            index: 0,
        }
    }

    fn mask(mut self) -> String {
        while self.index < self.source.len() {
            self.consume_next();
        }
        String::from_utf8(self.output).expect("masked Dart strings remain UTF-8")
    }

    fn consume_next(&mut self) {
        let Some(literal) = self.literal_at_index() else {
            self.index += 1;
            return;
        };
        self.consume_literal(literal);
    }

    fn literal_at_index(&self) -> Option<StringLiteral> {
        let delimiter = self.source[self.index];
        if !matches!(delimiter, b'\'' | b'"') {
            return None;
        }
        Some(StringLiteral {
            delimiter,
            width: self.delimiter_width(delimiter),
            raw: self.has_raw_prefix(),
        })
    }

    fn delimiter_width(&self, delimiter: u8) -> usize {
        if self.source.get(self.index + 1) == Some(&delimiter)
            && self.source.get(self.index + 2) == Some(&delimiter)
        {
            3
        } else {
            1
        }
    }

    fn has_raw_prefix(&self) -> bool {
        self.index > 0
            && matches!(self.source[self.index - 1], b'r' | b'R')
            && (self.index == 1
                || !self.source[self.index - 2].is_ascii_alphanumeric()
                    && !matches!(self.source[self.index - 2], b'_' | b'$'))
    }

    fn consume_literal(&mut self, literal: StringLiteral) {
        let start = self.index;
        self.index += literal.width;
        while self.index < self.source.len() {
            if self.consume_escape(literal) {
                continue;
            }
            if self.literal_closes(literal) {
                self.index += literal.width;
                break;
            }
            self.index += 1;
        }
        let end = self.index.min(self.source.len());
        mask_non_newline_bytes(&mut self.output[start..end]);
    }

    fn consume_escape(&mut self, literal: StringLiteral) -> bool {
        if !literal.raw && literal.width == 1 && self.source[self.index] == b'\\' {
            self.index += 2;
            true
        } else {
            false
        }
    }

    fn literal_closes(&self, literal: StringLiteral) -> bool {
        self.source[self.index] == literal.delimiter
            && (literal.width == 1
                || self
                    .source
                    .get(self.index..self.index + literal.width)
                    .is_some_and(|slice| {
                        slice
                            .iter()
                            .all(|candidate| *candidate == literal.delimiter)
                    }))
    }
}

fn mask_non_newline_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

fn is_locator_name(name: &str) -> bool {
    matches!(
        name.replace('_', "").to_ascii_lowercase().as_str(),
        "getit" | "locator" | "servicelocator"
    )
}

fn base_type(source: &str) -> String {
    let source = source.trim().trim_end_matches('?');
    source
        .find('<')
        .map_or(source, |index| &source[..index])
        .trim()
        .to_owned()
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn next_non_whitespace(source: &str, start: usize) -> usize {
    source[start..]
        .char_indices()
        .find(|(_, character)| !character.is_whitespace())
        .map_or(source.len(), |(offset, _)| start + offset)
}

struct DelimiterScanner<'a> {
    bytes: &'a [u8],
    opening: u8,
    closing: u8,
    depth: usize,
    quote: Option<(u8, usize)>,
    index: usize,
}

impl<'a> DelimiterScanner<'a> {
    fn new(source: &'a str, open: usize, opening: u8, closing: u8) -> Self {
        Self {
            bytes: source.as_bytes(),
            opening,
            closing,
            depth: 0,
            quote: None,
            index: open,
        }
    }

    fn matching_close(mut self) -> Option<usize> {
        while self.index < self.bytes.len() {
            if self.consume_quoted_byte() || self.start_quote() {
                continue;
            }
            let index = self.index;
            if self.consume_delimiter()? {
                return Some(index);
            }
            self.index += 1;
        }
        None
    }

    fn consume_quoted_byte(&mut self) -> bool {
        let Some((delimiter, width)) = self.quote else {
            return false;
        };
        if width == 1 && self.bytes[self.index] == b'\\' {
            self.index += 2;
        } else if self.quote_closes(delimiter, width) {
            self.quote = None;
            self.index += width;
        } else {
            self.index += 1;
        }
        true
    }

    fn quote_closes(&self, delimiter: u8, width: usize) -> bool {
        self.bytes[self.index] == delimiter
            && (width == 1
                || self
                    .bytes
                    .get(self.index..self.index + width)
                    .is_some_and(|slice| slice.iter().all(|candidate| *candidate == delimiter)))
    }

    fn start_quote(&mut self) -> bool {
        let delimiter = self.bytes[self.index];
        if !matches!(delimiter, b'\'' | b'"') {
            return false;
        }
        let width = if self.bytes.get(self.index + 1) == Some(&delimiter)
            && self.bytes.get(self.index + 2) == Some(&delimiter)
        {
            3
        } else {
            1
        };
        self.quote = Some((delimiter, width));
        self.index += width;
        true
    }

    fn consume_delimiter(&mut self) -> Option<bool> {
        if self.bytes[self.index] == self.opening {
            self.depth += 1;
        } else if self.bytes[self.index] == self.closing {
            self.depth = self.depth.checked_sub(1)?;
            return Some(self.depth == 0);
        }
        Some(false)
    }
}

fn matching_delimiter(source: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    DelimiterScanner::new(source, open, opening, closing).matching_close()
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

fn identifier_pattern(identifier: &str) -> Regex {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier))).unwrap()
}

static CLASS_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\b(?:(?:abstract|base|final|interface|sealed|mixin)\s+)*class\s+([A-Za-z_$][\w$]*)(?:\s*<[^>{}]+>)?\s*(?:extends\s+([A-Za-z_$][\w$]*(?:<[^>{}]+>)?))?\s*(?:(with\s+[^\n{]+))?\s*(?:implements\s+([^\n{]+))?\s*\{").unwrap()
});
static BROAD_CLASS_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)\bclass\s+([A-Za-z_$][\w$]*)[^{};]*\{").unwrap());
static EXTENDS_CLAUSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bextends\s+([A-Za-z_$][\w$]*(?:<[^{}]+>)?)").unwrap());
static IMPLEMENTS_CLAUSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bimplements\s+([^{}]+)$").unwrap());
static MIXIN_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)\bmixin\s+([A-Za-z_$][\w$]*)[^{}]*\{").unwrap());
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*").unwrap());
static METHOD_ANNOTATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^@[A-Za-z_$][\w$]*(?:\s*\([^)]*\))?\s*").unwrap());
static OPERATOR_SIGNATURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\boperator\s+([^\s(]+)\s*$").unwrap());
static GETTER_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\bget\s+([A-Za-z_$][\w$]*)\s*(?:async\*?|sync\*)?\s*$").unwrap()
});
static CALLABLE_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\)\s*(?:(?:async\*?|sync\*)|(?::|=).*)$").unwrap());
static PARAMETER_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?s)^\s*(?:required\s+)?(?:final\s+)?(?P<type>[A-Za-z_$][\w$]*(?:<[^>]+>)?(?:\s+Function\s*\(.*\))?\??)\s+(?:this\.)?(?P<name>[A-Za-z_$][\w$]*)(?:\s*=.*)?\s*$",
    )
    .unwrap()
});
static FIELD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^(?P<modifiers>(?:(?:late|final|const|static|external|covariant)\s+)*)(?P<type>[A-Za-z_$][\w$]*(?:<[^;=]+>)?\??)\s+(?P<variables>[^;]+);$").unwrap()
});
static WORD_STATIC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bstatic\b").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static SWITCH_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bswitch\s*\(").unwrap());
static CASE_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcase\s+(.+?)(?:\s+when\s+.+?)?\s*:").unwrap());
static CALL_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*(?:<[^;(){}]+>)?\s*\(").unwrap());
static DIRECT_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:this\.)?([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\((.*)\)$").unwrap()
});
static CALL_WITH_TARGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(").unwrap());
static UNSUPPORTED_THROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bthrow\s+(?:UnsupportedError|UnimplementedError)\s*\(").unwrap()
});
static COMPLEX_BEHAVIOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:await|for|if|switch|try|while)\b").unwrap());
static DART_LOCATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:(?:\b([A-Za-z_$][\w$]*)\s*<)|(?:\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*<))\s*([A-Za-z_$][\w$]*(?:<[^>]+>)?)\s*>\s*\(").unwrap()
});
static TYPE_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Z][A-Za-z_$\d]*)\s*(?:<[^;(){}]+>)?\s*\(").unwrap());
static CALLBACK_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\((?:[^;{}()]|\{[^;{}()]*\})*\)\s*(?:async\s*)?(?:=>|\{)").unwrap()
});
const CONTROL_WORDS: &[&str] = &["if", "for", "while", "switch", "catch", "assert"];
const IGNORED_TYPES: &[&str] = &[
    "bool", "double", "dynamic", "int", "num", "Object", "String",
];

include!("oop/smells.rs");
include!("oop/tests.rs");
