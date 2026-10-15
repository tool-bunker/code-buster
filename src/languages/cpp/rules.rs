use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let sources = sources_compiled_as_cpp(context.sources());
    if sources.is_empty() {
        return Vec::new();
    }
    let mut findings = source_pattern_findings(&sources);
    findings.extend(macro_constants(&sources));
    findings.extend(raw_owning_new(&sources));
    findings.extend(virtual_without_destructor(&sources));
    findings
}

fn sources_compiled_as_cpp(sources: &BTreeMap<String, String>) -> BTreeMap<&str, &str> {
    let explicit = sources
        .keys()
        .filter(|path| has_explicit_cpp_extension(path))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if explicit.is_empty() {
        return BTreeMap::new();
    }
    let has_c_or_objective_c = sources
        .keys()
        .any(|path| has_extension(path, &[".c", ".m"]));
    sources
        .iter()
        .filter(|(path, _)| {
            explicit.contains(path.as_str())
                || (!has_c_or_objective_c && path.to_ascii_lowercase().ends_with(".h"))
        })
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect()
}

fn has_explicit_cpp_extension(path: &str) -> bool {
    path.ends_with(".C")
        || has_extension(
            path,
            &[
                ".cc", ".cpp", ".cxx", ".c++", ".cp", ".hh", ".hpp", ".hxx", ".h++", ".ipp",
                ".inl", ".tpp", ".mm",
            ],
        )
}

fn has_extension(path: &str, extensions: &[&str]) -> bool {
    let lower = path.to_ascii_lowercase();
    extensions
        .iter()
        .any(|extension| lower.ends_with(extension))
}

#[derive(Default)]
struct SourcePatternMatches {
    using_namespace_std: bool,
    manual_delete: bool,
    c_style_cast: bool,
    null: bool,
    goto: bool,
    non_const_ref: bool,
    allocation_api: bool,
    unsafe_c_string: bool,
    rand: bool,
    const_cast: bool,
    reinterpret_cast: bool,
    memset_zero: bool,
}

impl SourcePatternMatches {
    fn for_line(line: &str) -> Self {
        let mut matches = Self::default();
        matches.match_interface_patterns(line);
        matches.match_memory_patterns(line);
        matches.match_cast_patterns(line);
        matches.match_legacy_language_patterns(line);
        matches
    }

    fn match_interface_patterns(&mut self, line: &str) {
        self.using_namespace_std = USING_NAMESPACE_STD.is_match(line);
        self.non_const_ref = NON_CONST_REF.is_match(line)
            && !CONST_REFERENCE_EXCLUSION.is_match(line)
            && !line.contains("&&");
    }

    fn match_memory_patterns(&mut self, line: &str) {
        self.manual_delete = MANUAL_DELETE.is_match(line);
        self.allocation_api = CPP_ALLOCATION_API.is_match(line);
        self.unsafe_c_string = has_unsafe_c_string_call(line);
        self.memset_zero = MEMSET_ZERO.is_match(line);
    }

    fn match_cast_patterns(&mut self, line: &str) {
        self.c_style_cast = has_c_style_cast(line);
        self.const_cast = CONST_CAST.is_match(line);
        self.reinterpret_cast = REINTERPRET_CAST.is_match(line);
    }

    fn match_legacy_language_patterns(&mut self, line: &str) {
        self.null = CPP_NULL.is_match(line);
        self.goto = CPP_GOTO.is_match(line);
        self.rand = CPP_RAND.is_match(line);
    }
}

fn source_pattern_findings(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let mut in_block_comment = false;
        for (index, raw) in source.split('\n').enumerate() {
            let line = mask_non_code(raw, &mut in_block_comment);
            let matches = SourcePatternMatches::for_line(&line);
            emit_source_pattern_findings(&mut findings, &matches, path, index + 1);
        }
    }
    findings
}

fn emit_source_pattern_findings(
    findings: &mut Vec<Finding>,
    matches: &SourcePatternMatches,
    path: &str,
    line_number: usize,
) {
    emit_pattern_finding(
        findings,
        matches.using_namespace_std,
        "cpp-using-namespace-std",
        path,
        line_number,
        "using namespace std used",
    );
    emit_pattern_finding(
        findings,
        matches.manual_delete,
        "cpp-manual-delete",
        path,
        line_number,
        "manual delete used",
    );
    emit_pattern_finding(
        findings,
        matches.c_style_cast,
        "cpp-cast",
        path,
        line_number,
        "C-style cast used",
    );
    emit_pattern_finding(
        findings,
        matches.null,
        "cpp-null",
        path,
        line_number,
        "NULL used instead of nullptr",
    );
    emit_pattern_finding(
        findings,
        matches.goto,
        "cpp-goto",
        path,
        line_number,
        "goto statement used",
    );
    emit_pattern_finding(
        findings,
        matches.non_const_ref,
        "cpp-non-const-ref-param",
        path,
        line_number,
        "non-const reference parameter may hide mutation",
    );
    emit_pattern_finding(
        findings,
        matches.allocation_api,
        "cpp-malloc-free",
        path,
        line_number,
        "C allocation API used in C++ code",
    );
    emit_pattern_finding(
        findings,
        matches.unsafe_c_string,
        "cpp-unsafe-c-string",
        path,
        line_number,
        "unsafe C string/buffer API used",
    );
    emit_pattern_finding(
        findings,
        matches.rand,
        "cpp-rand",
        path,
        line_number,
        "C rand/srand used",
    );
    emit_pattern_finding(
        findings,
        matches.const_cast,
        "cpp-const-cast",
        path,
        line_number,
        "const_cast used",
    );
    emit_pattern_finding(
        findings,
        matches.reinterpret_cast,
        "cpp-reinterpret-cast",
        path,
        line_number,
        "reinterpret_cast used",
    );
    emit_pattern_finding(
        findings,
        matches.memset_zero,
        "cpp-memset-zero",
        path,
        line_number,
        "memset used for zero-initialization",
    );
}

#[inline]
fn emit_pattern_finding(
    findings: &mut Vec<Finding>,
    matched: bool,
    code: &str,
    path: &str,
    line_number: usize,
    message: &str,
) {
    if matched {
        findings.push(finding(code, path, line_number, message));
    }
}

fn has_c_style_cast(line: &str) -> bool {
    if OBJECTIVE_C_PARAMETER_CAST.is_match(line) {
        return false;
    }
    C_STYLE_CAST.captures_iter(line).any(|capture| {
        let Some(matched_cast) = capture.get(0) else {
            return false;
        };
        let tail = line[matched_cast.end()..].trim_start();
        let Some(first) = tail.chars().next() else {
            return false;
        };
        (first.is_ascii_alphanumeric() || first == '_' || first == '(')
            && !["const", "override", "noexcept", "final"]
                .iter()
                .any(|word| starts_with_word(tail, word))
    })
}

fn starts_with_word(text: &str, word: &str) -> bool {
    text.strip_prefix(word).is_some_and(|tail| {
        tail.chars()
            .next()
            .is_none_or(|character| !is_identifier(character))
    })
}

fn is_identifier(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn has_unsafe_c_string_call(line: &str) -> bool {
    if UNSAFE_C_STRING.captures_iter(line).any(|capture| {
        let Some(unsafe_call) = capture.get(0) else {
            return false;
        };
        let start = unsafe_call.start();
        line[..start]
            .chars()
            .rev()
            .find(|character| !character.is_whitespace())
            .is_none_or(|character| character != '.' && character != '>')
    }) {
        return true;
    }
    if MEMBER_GETS.is_match(line) {
        return false;
    }
    GETS_CALL.captures_iter(line).any(|capture| {
        capture
            .name("arguments")
            .is_some_and(|arguments| !arguments.as_str().contains(','))
    })
}

struct MacroCandidate<'a> {
    line: usize,
    name: &'a str,
    replacement: &'a str,
    has_parenthesis: bool,
}

fn macro_constants(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let (candidates, conditional_macros) = collect_macro_candidates(source);
        for candidate in candidates {
            if is_macro_constant(&candidate, &conditional_macros) {
                findings.push(finding(
                    "cpp-macro-constant",
                    path,
                    candidate.line,
                    "macro constant used",
                ));
            }
        }
    }
    findings
}

fn collect_macro_candidates<'a>(source: &'a str) -> (Vec<MacroCandidate<'a>>, BTreeSet<&'a str>) {
    let mut candidates = Vec::new();
    let mut conditional_macros = BTreeSet::new();
    for (index, line) in source.split('\n').enumerate() {
        if let Some(name) = CONDITIONAL_MACRO
            .captures(line)
            .and_then(|capture| capture.get(1))
            .map(|matched| matched.as_str())
        {
            conditional_macros.insert(name);
        }
        if let Some(candidate) = parse_macro_candidate(line, index + 1) {
            candidates.push(candidate);
        }
    }
    (candidates, conditional_macros)
}

fn parse_macro_candidate(line: &str, line_number: usize) -> Option<MacroCandidate<'_>> {
    let definition = DEFINE.captures(line.trim())?;
    Some(MacroCandidate {
        line: line_number,
        name: definition.get(1)?.as_str(),
        replacement: definition.get(2)?.as_str().trim_start(),
        has_parenthesis: line.contains('('),
    })
}

fn is_macro_constant(candidate: &MacroCandidate<'_>, conditional_macros: &BTreeSet<&str>) -> bool {
    !candidate.replacement.is_empty()
        && !candidate.replacement.starts_with("//")
        && !candidate.replacement.starts_with("/*")
        && CONSTANT_REPLACEMENT.is_match(candidate.replacement)
        && !candidate.has_parenthesis
        && !conditional_macros.contains(candidate.name)
}

fn raw_owning_new(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let qt_owned_types = qt_owned_types(sources);
    let mut findings = Vec::new();
    for (path, source) in sources {
        let lines = source.split('\n').collect::<Vec<_>>();
        let mut emscripten_brace_depth = 0isize;
        for (index, line) in lines.iter().enumerate() {
            if emscripten_brace_depth > 0 {
                emscripten_brace_depth += brace_delta(line);
                emscripten_brace_depth = emscripten_brace_depth.max(0);
                continue;
            }
            if let Some(emscripten) = EMSCRIPTEN_MACRO.find(line) {
                emscripten_brace_depth = brace_delta(&line[emscripten.start()..]);
                continue;
            }
            if !RAW_NEW_ALLOCATION.is_match(line)
                || has_explicit_qt_parent(line, &qt_owned_types)
                || is_immediately_transferred(&lines, index)
            {
                continue;
            }
            findings.push(finding(
                "cpp-raw-owning-new",
                path,
                index + 1,
                "raw new expression used",
            ));
        }
    }
    findings
}

#[derive(Default)]
struct InheritedClassQualifications {
    bases_by_class: BTreeMap<String, BTreeSet<String>>,
    qualified: BTreeSet<String>,
}

impl InheritedClassQualifications {
    fn record(&mut self, name: String, bases: BTreeSet<String>, qualified: bool) {
        if qualified {
            self.qualified.insert(name.clone());
        }
        self.bases_by_class.insert(name, bases);
    }

    fn qualify_classes_with_external_bases(&mut self) {
        for (name, bases) in &self.bases_by_class {
            if bases
                .iter()
                .any(|base| !self.bases_by_class.contains_key(base))
            {
                self.qualified.insert(name.clone());
            }
        }
    }

    fn resolve_inherited(mut self) -> BTreeSet<String> {
        let mut changed = true;
        while changed {
            changed = false;
            for (name, bases) in &self.bases_by_class {
                if !self.qualified.contains(name)
                    && bases.iter().any(|base| self.qualified.contains(base))
                {
                    changed |= self.qualified.insert(name.clone());
                }
            }
        }
        self.qualified
    }
}

fn qt_owned_types(sources: &BTreeMap<&str, &str>) -> BTreeSet<String> {
    let mut qualifications = InheritedClassQualifications::default();
    for source in sources.values() {
        let lines = source.split('\n').collect::<Vec<_>>();
        for index in 0..lines.len() {
            if is_class_declaration_start(lines[index]) {
                record_qt_owned_class(&lines, index, &mut qualifications);
            }
        }
    }
    qualifications.resolve_inherited()
}

fn record_qt_owned_class(
    lines: &[&str],
    index: usize,
    qualifications: &mut InheritedClassQualifications,
) {
    let declaration = class_declaration(lines, index);
    let Some(name) = CLASS_DECLARATION_NAME
        .captures(&declaration)
        .map(|capture| capture[1].to_owned())
    else {
        return;
    };
    let bases = base_names_from_declaration(&declaration);
    let is_qt_owned = bases.iter().any(|base| starts_with_qt_type(base))
        || class_contains_qobject_macro(lines, index);
    qualifications.record(name, bases, is_qt_owned);
}

fn is_class_declaration_start(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("class ") || line.starts_with("struct ")
}

fn starts_with_qt_type(name: &str) -> bool {
    let mut characters = name.chars();
    characters.next() == Some('Q')
        && characters
            .next()
            .is_some_and(|value| value.is_ascii_uppercase())
}

fn class_contains_qobject_macro(lines: &[&str], start: usize) -> bool {
    let mut depth = 0isize;
    let mut opened = false;
    for line in lines.iter().skip(start) {
        if line.contains("Q_OBJECT") {
            return true;
        }
        let delta = brace_delta(line);
        if line.contains('{') {
            opened = true;
        }
        depth += delta;
        if opened && depth <= 0 {
            break;
        }
        if !opened && line.contains(';') {
            break;
        }
    }
    false
}

fn has_explicit_qt_parent(line: &str, qt_owned_types: &BTreeSet<String>) -> bool {
    let Some(construction) = NEW_CONSTRUCTION.captures(line) else {
        return false;
    };
    if !PARENT_ARGUMENT.is_match(&construction[2]) {
        return false;
    }
    let type_name = construction[1].rsplit("::").next().unwrap();
    starts_with_qt_type(type_name) || qt_owned_types.contains(type_name)
}

fn is_immediately_transferred(lines: &[&str], index: usize) -> bool {
    let Some(assignment) = ASSIGNED_QT_NAME.captures(lines[index]) else {
        return false;
    };
    let name = &assignment[1];
    for candidate in lines
        .iter()
        .take((index + 4).min(lines.len()))
        .skip(index + 1)
        .map(|line| line.trim())
    {
        if candidate.is_empty() || candidate.starts_with("//") {
            continue;
        }
        let Some(call) = OWNING_SETTER.captures(candidate) else {
            return false;
        };
        return call[1].trim() == name;
    }
    false
}

fn virtual_without_destructor(sources: &BTreeMap<&str, &str>) -> Vec<Finding> {
    let safe_or_unknown = classes_with_safe_or_unknown_destructors(sources);
    let mut findings = Vec::new();
    for (path, source) in sources {
        let lines = source.split('\n').collect::<Vec<_>>();
        for index in 0..lines.len() {
            let line = lines[index].trim();
            if !line.starts_with("class ") && !line.starts_with("struct ") {
                continue;
            }
            let body = class_body(&lines, index);
            let name = class_name(&lines, index);
            if body
                .iter()
                .any(|value| value.trim().starts_with("virtual "))
                && !body.iter().any(|line| declares_virtual_destructor(line))
                && name
                    .as_ref()
                    .is_none_or(|name| !safe_or_unknown.contains(name))
            {
                findings.push(finding(
                    "cpp-virtual-no-destructor",
                    path,
                    index + 1,
                    "class has virtual methods but no virtual destructor",
                ));
            }
        }
    }
    findings
}

fn classes_with_safe_or_unknown_destructors(sources: &BTreeMap<&str, &str>) -> BTreeSet<String> {
    let mut qualifications = InheritedClassQualifications::default();
    for source in sources.values() {
        let lines = source.split('\n').collect::<Vec<_>>();
        for index in 0..lines.len() {
            if is_class_declaration_start(lines[index]) {
                record_destructor_qualification(&lines, index, &mut qualifications);
            }
        }
    }
    qualifications.qualify_classes_with_external_bases();
    qualifications.resolve_inherited()
}

fn record_destructor_qualification(
    lines: &[&str],
    index: usize,
    qualifications: &mut InheritedClassQualifications,
) {
    let declaration = class_declaration(lines, index);
    let Some(name) = class_name_from_declaration(&declaration) else {
        return;
    };
    let has_virtual_destructor = class_body(lines, index)
        .iter()
        .any(|line| declares_virtual_destructor(line));
    let bases = base_names_from_declaration(&declaration);
    qualifications.record(name, bases, has_virtual_destructor);
}

fn declares_virtual_destructor(line: &str) -> bool {
    line.contains("virtual ~") || (line.contains('~') && line.contains("override"))
}

fn class_name(lines: &[&str], start: usize) -> Option<String> {
    class_name_from_declaration(&class_declaration(lines, start))
}

fn class_name_from_declaration(declaration: &str) -> Option<String> {
    let captures = CLASS_NAME.captures(declaration)?;
    let tokens = captures[1].split_whitespace().collect::<Vec<_>>();
    let index = if tokens.last() == Some(&"final") {
        tokens.len().checked_sub(2)?
    } else {
        tokens.len().checked_sub(1)?
    };
    Some(tokens[index].to_owned())
}

fn base_names_from_declaration(declaration: &str) -> BTreeSet<String> {
    let Some(colon) = declaration.find(':') else {
        return BTreeSet::new();
    };
    let Some(brace) = declaration.find('{') else {
        return BTreeSet::new();
    };
    if brace < colon {
        return BTreeSet::new();
    }
    declaration[colon + 1..brace]
        .split(',')
        .map(|base| ACCESS_SPECIFIER.replace_all(base, "").trim().to_owned())
        .map(|base| base.rsplit("::").next().unwrap_or("").to_owned())
        .map(|base| base.split('<').next().unwrap_or("").trim().to_owned())
        .filter(|base| !base.is_empty())
        .collect()
}

fn class_declaration(lines: &[&str], start: usize) -> String {
    let mut declaration = String::new();
    for line in lines.iter().skip(start).take(8) {
        if !declaration.is_empty() {
            declaration.push(' ');
        }
        declaration.push_str(line.trim());
        if line.contains('{') || line.contains(';') {
            break;
        }
    }
    declaration
}

#[derive(Default)]
struct ClassBoundaryParser {
    body_start: Option<usize>,
    depth: isize,
}

enum ClassBoundaryEvent {
    Continue,
    Closed,
    NoBody,
}

impl ClassBoundaryParser {
    fn find(lines: &[&str], start: usize) -> Option<std::ops::Range<usize>> {
        let remaining = lines.get(start..)?;
        let mut parser = Self::default();
        for (offset, line) in remaining.iter().enumerate() {
            let line_index = start + offset;
            match parser.advance(line, line_index) {
                ClassBoundaryEvent::Continue => {}
                ClassBoundaryEvent::Closed => return parser.body_range(line_index + 1),
                ClassBoundaryEvent::NoBody => return None,
            }
        }
        parser.body_range(lines.len())
    }

    fn advance(&mut self, line: &str, line_index: usize) -> ClassBoundaryEvent {
        if self.body_start.is_none() && line.contains(';') && !line.contains('{') {
            return ClassBoundaryEvent::NoBody;
        }
        for character in line.chars() {
            self.consume_brace(character, line_index);
        }
        if self.body_start.is_some() && self.depth == 0 {
            ClassBoundaryEvent::Closed
        } else {
            ClassBoundaryEvent::Continue
        }
    }

    fn consume_brace(&mut self, character: char, line_index: usize) {
        match character {
            '{' => {
                self.body_start.get_or_insert(line_index);
                self.depth += 1;
            }
            '}' if self.body_start.is_some() => self.depth -= 1,
            _ => {}
        }
    }

    fn body_range(&self, end: usize) -> Option<std::ops::Range<usize>> {
        self.body_start.map(|start| start..end)
    }
}

fn class_body<'lines, 'source>(
    lines: &'lines [&'source str],
    start: usize,
) -> &'lines [&'source str] {
    let Some(range) = ClassBoundaryParser::find(lines, start) else {
        return &[];
    };
    &lines[range]
}

#[derive(Clone, Copy)]
enum BraceLexicalState {
    Code,
    Quoted(char),
    Escaped(char),
}

struct BraceLexicalScanner {
    state: BraceLexicalState,
    delta: isize,
}

impl BraceLexicalScanner {
    fn scan(line: &str) -> isize {
        let mut scanner = Self {
            state: BraceLexicalState::Code,
            delta: 0,
        };
        let mut characters = line.chars().peekable();
        while let Some(character) = characters.next() {
            if !scanner.advance(character, characters.peek().copied()) {
                break;
            }
        }
        scanner.delta
    }

    fn advance(&mut self, character: char, next: Option<char>) -> bool {
        match self.state {
            BraceLexicalState::Code => self.advance_code(character, next),
            BraceLexicalState::Quoted(delimiter) => {
                self.advance_quoted(character, delimiter);
                true
            }
            BraceLexicalState::Escaped(delimiter) => {
                self.state = BraceLexicalState::Quoted(delimiter);
                true
            }
        }
    }

    fn advance_code(&mut self, character: char, next: Option<char>) -> bool {
        match character {
            '"' | '\'' | '`' => self.state = BraceLexicalState::Quoted(character),
            '/' if next == Some('/') => return false,
            '{' => self.delta += 1,
            '}' => self.delta -= 1,
            _ => {}
        }
        true
    }

    fn advance_quoted(&mut self, character: char, delimiter: char) {
        self.state = if character == '\\' {
            BraceLexicalState::Escaped(delimiter)
        } else if character == delimiter {
            BraceLexicalState::Code
        } else {
            BraceLexicalState::Quoted(delimiter)
        };
    }
}

fn brace_delta(line: &str) -> isize {
    BraceLexicalScanner::scan(line)
}

#[derive(Clone, Copy)]
enum MaskState {
    Code,
    Quoted { delimiter: char, escaped: bool },
    BlockComment,
}

enum MaskAction {
    Copy,
    Mask,
    MaskPair,
    Stop,
}

fn mask_non_code(line: &str, in_block_comment: &mut bool) -> String {
    let mut result = String::new();
    let characters = line.chars().collect::<Vec<_>>();
    let mut state = if *in_block_comment {
        MaskState::BlockComment
    } else {
        MaskState::Code
    };
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        let (next_state, action) = mask_transition(state, character, next);
        state = next_state;
        match action {
            MaskAction::Copy => result.push(character),
            MaskAction::Mask => result.push(' '),
            MaskAction::MaskPair => {
                result.push(' ');
                index += 1;
            }
            MaskAction::Stop => break,
        }
        index += 1;
    }
    *in_block_comment = matches!(state, MaskState::BlockComment);
    result
}

fn mask_transition(
    state: MaskState,
    character: char,
    next: Option<char>,
) -> (MaskState, MaskAction) {
    match state {
        MaskState::Code => code_mask_transition(character, next),
        MaskState::Quoted { delimiter, escaped } => {
            quoted_mask_transition(character, delimiter, escaped)
        }
        MaskState::BlockComment => block_comment_mask_transition(character, next),
    }
}

fn code_mask_transition(character: char, next: Option<char>) -> (MaskState, MaskAction) {
    match (character, next) {
        ('"' | '\'' | '`', _) => (
            MaskState::Quoted {
                delimiter: character,
                escaped: false,
            },
            MaskAction::Mask,
        ),
        ('/', Some('*')) => (MaskState::BlockComment, MaskAction::MaskPair),
        ('/', Some('/')) => (MaskState::Code, MaskAction::Stop),
        _ => (MaskState::Code, MaskAction::Copy),
    }
}

fn quoted_mask_transition(
    character: char,
    delimiter: char,
    escaped: bool,
) -> (MaskState, MaskAction) {
    let state = if escaped {
        MaskState::Quoted {
            delimiter,
            escaped: false,
        }
    } else if character == '\\' {
        MaskState::Quoted {
            delimiter,
            escaped: true,
        }
    } else if character == delimiter {
        MaskState::Code
    } else {
        MaskState::Quoted {
            delimiter,
            escaped: false,
        }
    };
    (state, MaskAction::Mask)
}

fn block_comment_mask_transition(character: char, next: Option<char>) -> (MaskState, MaskAction) {
    if character == '*' && next == Some('/') {
        (MaskState::Code, MaskAction::MaskPair)
    } else {
        (MaskState::BlockComment, MaskAction::Mask)
    }
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("C++ rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message: message.to_owned(),
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static USING_NAMESPACE_STD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*using namespace std;\s*$").unwrap());
static RAW_NEW_ALLOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:=\s*new\s|^\s*new\s)").unwrap());
static NEW_CONSTRUCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bnew\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)(?:\s*<[^;{}()]*>)?\s*\(([^;{}]*)\)")
        .unwrap()
});
static PARENT_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|,)\s*(?:this|parent\w*)\s*(?:,|$)").unwrap());
static ASSIGNED_QT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*new\s+Q[A-Z]\w*").unwrap());
static OWNING_SETTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:setCentralWidget|setCheckBox|setLayout|setMenuBar|setStatusBar|setViewport|setWidget)\s*\(\s*([^)]*?)\s*\)").unwrap()
});
static EMSCRIPTEN_MACRO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[A-Z_]*EM_ASM[A-Z_]*|EM_JS)\s*\(").unwrap());
static MANUAL_DELETE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bdelete(?:\[\])?\s+").unwrap());
static C_STYLE_CAST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\((?:int|float|double|char\s*\*|void\s*\*)\)\s*").unwrap());
static OBJECTIVE_C_PARAMETER_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r":\s*\((?:int|float|double|char\s*\*|void\s*\*)\)\s*[A-Za-z_]\w*\b").unwrap()
});
static CPP_NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bNULL\b").unwrap());
static CPP_GOTO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|\s)goto\s+").unwrap());
static NON_CONST_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:void|int|bool|auto)\b[^=;{}]*\([^;{}]*&\s+[A-Za-z_]\w*").unwrap()
});
static CONST_REFERENCE_EXCLUSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bconst(?:\s|&)").unwrap());
static CPP_ALLOCATION_API: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:malloc|calloc|realloc|free)\s*\(").unwrap());
static UNSAFE_C_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(").unwrap());
static MEMBER_GETS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.|->|::)\s*gets\s*\(").unwrap());
static GETS_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgets\s*\(\s*(?P<arguments>[^)]*)\)").unwrap());
static CPP_RAND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:srand\s*\(|rand\s*\(\s*\))").unwrap());
static CONST_CAST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bconst_cast\s*<").unwrap());
static REINTERPRET_CAST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\breinterpret_cast\s*<").unwrap());
static MEMSET_ZERO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bmemset\s*\([^,]+,\s*0\s*,").unwrap());
static CONDITIONAL_MACRO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*#\s*if(?:n?def)?\s+([A-Za-z_]\w*)").unwrap());
static DEFINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#define\s+([A-Za-z_]\w*)\s+(.*)$").unwrap());
static CONSTANT_REPLACEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:[-+]?(?:0[xX][0-9A-Fa-f']+|0[bB][01']+|\d[\d']*(?:\.\d[\d']*)?)|true\b|false\b|nullptr\b|NULL\b|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#).unwrap()
});
static CLASS_DECLARATION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:class|struct)\s+([A-Za-z_]\w*)").unwrap());
static CLASS_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:class|struct)\s+(.+?)(?:\s*:\s*|\s*\{)").unwrap());
static ACCESS_SPECIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:public|protected|private|virtual)\b").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::analyze;
    use crate::source_analysis_context::SourceAnalysisContext;

    #[test]
    fn reports_every_cpp_rule_with_stable_contracts() {
        let sources = BTreeMap::from([(
            "main.cpp".to_owned(),
            "using namespace std;\n\
#define BUFFER_SIZE 4096\n\
class Interface {\n\
 public:\n\
  virtual void draw();\n\
};\n\
void mutate(int& value) {\n\
  int converted = (int)value;\n\
  void* memory = malloc(16);\n\
  strcpy((char*)memory, input);\n\
  memset(memory, 0, 16);\n\
  auto random = rand();\n\
  auto immutable = const_cast<int*>(source);\n\
  auto raw = reinterpret_cast<char*>(memory);\n\
  Widget* widget = new Widget();\n\
  delete widget;\n\
  if (memory == NULL) goto cleanup;\n\
cleanup: free(memory);\n\
}"
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let mut findings = analyze(&context);
        findings.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.line.cmp(&right.line))
        });
        assert!(findings.iter().all(|finding| {
            finding.path == "main.cpp"
                && finding.end_line == 0
                && finding.confidence == "medium"
                && finding.why == "This construct weakens C++ type, lifetime, or interface safety."
                && finding.suggestion
                    == "Use the safer typed C++ alternative described by the rule."
        }));
        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.line,
                    finding.severity.as_str(),
                    finding.message.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("cpp-cast", 8, "info", "C-style cast used"),
                ("cpp-cast", 10, "info", "C-style cast used"),
                ("cpp-const-cast", 13, "warn", "const_cast used"),
                ("cpp-goto", 17, "warn", "goto statement used"),
                ("cpp-macro-constant", 2, "info", "macro constant used"),
                (
                    "cpp-malloc-free",
                    9,
                    "warn",
                    "C allocation API used in C++ code",
                ),
                (
                    "cpp-malloc-free",
                    18,
                    "warn",
                    "C allocation API used in C++ code",
                ),
                ("cpp-manual-delete", 16, "warn", "manual delete used"),
                (
                    "cpp-memset-zero",
                    11,
                    "info",
                    "memset used for zero-initialization",
                ),
                (
                    "cpp-non-const-ref-param",
                    7,
                    "info",
                    "non-const reference parameter may hide mutation",
                ),
                ("cpp-null", 17, "info", "NULL used instead of nullptr"),
                ("cpp-rand", 12, "info", "C rand/srand used"),
                ("cpp-raw-owning-new", 15, "warn", "raw new expression used",),
                ("cpp-reinterpret-cast", 14, "warn", "reinterpret_cast used",),
                (
                    "cpp-unsafe-c-string",
                    10,
                    "warn",
                    "unsafe C string/buffer API used",
                ),
                (
                    "cpp-using-namespace-std",
                    1,
                    "info",
                    "using namespace std used",
                ),
                (
                    "cpp-virtual-no-destructor",
                    3,
                    "warn",
                    "class has virtual methods but no virtual destructor",
                ),
            ]
        );
    }

    #[test]
    fn excludes_c_only_sources_and_ambiguous_headers() {
        let sources = BTreeMap::from([
            ("legacy.c".to_owned(), "void* value = malloc(4);".to_owned()),
            ("legacy.h".to_owned(), "#define BUFFER_SIZE 4096".to_owned()),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn applies_source_pattern_exclusions_after_lexical_masking() {
        let sources = BTreeMap::from([(
            "main.mm".to_owned(),
            "- (void)setValue:(int)value;\n\
int primitive = (int)value;\n\
void read(const int& value);\n\
void move(int&& value);\n\
auto seeded = rand(seed);\n\
object.strcpy(dst, src);\n\
pointer->sprintf(dst, \"%s\", src);\n\
std::sprintf(dst, \"%s\", src);\n\
gets(buffer);\n\
reader.gets(buffer);\n\
gets(buffer, size);\n\
const char* text = \"goto NULL malloc(\";\n\
// delete value\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("cpp-cast".to_owned(), 2),
                ("cpp-unsafe-c-string".to_owned(), 8),
                ("cpp-unsafe-c-string".to_owned(), 9),
            ]
        );
    }

    #[test]
    fn reports_only_literal_object_like_macros_not_used_as_conditionals() {
        let sources = BTreeMap::from([(
            "constants.hpp".to_owned(),
            "#define FUNCTION(value) 1\n\
#define PARENTHESIZED (1)\n\
#define EMPTY // no value\n\
#define FEATURE 1\n\
#define VALUE 42\n\
#define NAME \"code-buster\"\n\
#define EXPRESSION value\n\
#define TRUTH true\n\
#ifdef FEATURE\n\
#endif\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("cpp-macro-constant".to_owned(), 5),
                ("cpp-macro-constant".to_owned(), 6),
                ("cpp-macro-constant".to_owned(), 8),
            ]
        );
    }

    #[test]
    fn recognizes_qt_parenting_transfers_custom_types_and_emscripten_regions() {
        let sources = BTreeMap::from([
            (
                "adapter.hpp".to_owned(),
                "class Adapter : public QObject {\n\
  Q_OBJECT\n\
};\n\
class DerivedAdapter : public Adapter {};\n\
class Unknown {};\n"
                    .to_owned(),
            ),
            (
                "window.cpp".to_owned(),
                "Adapter* adapter = new Adapter(parent);\n\
DerivedAdapter* derived = new DerivedAdapter(this);\n\
Unknown* unknown = new Unknown(parent);\n\
QLabel* label = new QLabel();\n\
setWidget(label);\n\
Widget* widget = new Widget();\n\
EM_JS(void, makeWidget, (), { Widget* hidden = new Widget(); });\n\
EM_ASM({\n\
  Widget* embedded = new Widget();\n\
});\n\
Widget* visible = new Widget();\n"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .filter(|finding| finding.code == "cpp-raw-owning-new")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("window.cpp".to_owned(), 3),
                ("window.cpp".to_owned(), 6),
                ("window.cpp".to_owned(), 11),
            ]
        );
    }

    #[test]
    fn inherits_virtual_destructor_safety_and_scans_complete_class_bodies() {
        let mut long_body = String::from("class Large {\npublic:\n  virtual void run();\n");
        for index in 0..90 {
            long_body.push_str(&format!("  int field{index};\n"));
        }
        long_body.push_str("  virtual ~Large();\n};\n");
        let sources = BTreeMap::from([
            (
                "interfaces.hpp".to_owned(),
                "class Safe {\n\
 public:\n\
  virtual void run();\n\
  virtual ~Safe();\n\
};\n\
class Child : public Safe {\n\
 public:\n\
  virtual void child();\n\
};\n\
class External : public std::streambuf {\n\
 public:\n\
  virtual void read();\n\
};\n\
class Bad {\n\
 public:\n\
  virtual void fail();\n\
};\n"
                    .to_owned(),
            ),
            ("large.hpp".to_owned(), long_body),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .filter(|finding| finding.code == "cpp-virtual-no-destructor")
            .map(|finding| (finding.path, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(findings, vec![("interfaces.hpp".to_owned(), 14)]);
    }

    #[test]
    fn excludes_ambiguous_headers_when_c_and_cpp_sources_are_mixed() {
        let sources = BTreeMap::from([
            ("legacy.c".to_owned(), "void* value = malloc(4);".to_owned()),
            ("shared.h".to_owned(), "void* value = malloc(4);".to_owned()),
            (
                "modern.cpp".to_owned(),
                "void* value = malloc(4);".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .filter(|finding| finding.code == "cpp-malloc-free")
            .map(|finding| finding.path)
            .collect::<Vec<_>>();

        assert_eq!(findings, vec!["modern.cpp"]);
    }

    #[test]
    fn skips_incomplete_pattern_captures_without_changing_valid_findings() {
        let sources = BTreeMap::from([(
            "malformed.cpp".to_owned(),
            "int missing_cast = (int\n\
strcpy\n\
gets(buffer\n\
int value = (int)input;\n\
strcpy(output, input);\n\
gets(buffer);\n"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context)
            .into_iter()
            .map(|finding| (finding.code, finding.line, finding.message))
            .collect::<Vec<_>>();

        assert_eq!(
            findings,
            vec![
                ("cpp-cast".to_owned(), 4, "C-style cast used".to_owned(),),
                (
                    "cpp-unsafe-c-string".to_owned(),
                    5,
                    "unsafe C string/buffer API used".to_owned(),
                ),
                (
                    "cpp-unsafe-c-string".to_owned(),
                    6,
                    "unsafe C string/buffer API used".to_owned(),
                ),
            ]
        );
    }
}
