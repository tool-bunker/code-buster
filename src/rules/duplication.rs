use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use super::standalone_template_scope;
use crate::findings::{Finding, Severity};
use crate::rust_rules::function_lexical_facts;

const MAX_GROUPS: usize = 50;
const MAX_OCCURRENCES_PER_GROUP: usize = 32;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Location {
    path: String,
    line: usize,
    index: usize,
}

#[derive(Clone, Debug)]
struct NormalizedLine {
    number: usize,
    text: String,
}

#[derive(Clone, Debug)]
struct DuplicateSpan {
    path: String,
    start_line: usize,
    end_line: usize,
    start_index: usize,
    end_index: usize,
}

#[derive(Clone, Copy, Debug)]
struct LineRange {
    start: usize,
    end: usize,
}

pub fn exact_group_count(sources: &BTreeMap<String, String>, min_lines: i64) -> usize {
    exact_duplicates(sources, min_lines, false).0
}

pub fn exact_findings(sources: &BTreeMap<String, String>, min_lines: i64) -> Vec<Finding> {
    exact_duplicates(sources, min_lines, true).1
}

fn exact_duplicates(
    sources: &BTreeMap<String, String>,
    min_lines: i64,
    collect_findings: bool,
) -> (usize, Vec<Finding>) {
    let window = min_lines.max(3) as usize;
    let (occurrences, normalized_by_path) = collect_duplicate_windows(sources, window);
    let candidates = ordered_duplicate_candidates(occurrences);
    let mut occupied: BTreeMap<String, Vec<LineRange>> = BTreeMap::new();
    let mut groups = 0;
    let mut findings = Vec::new();

    for (_, candidate_key, candidate_locations) in candidates {
        if groups >= MAX_GROUPS {
            break;
        }
        let Some(locations) = select_duplicate_locations(
            candidate_locations,
            window,
            sources,
            &normalized_by_path,
            &occupied,
        ) else {
            continue;
        };
        let (backward, forward) =
            duplicate_span_extensions(&locations, window, &normalized_by_path);
        let spans = duplicate_spans(&locations, window, backward, forward, &normalized_by_path);
        if spans_overlap_each_other(&spans) || spans_overlap_occupied(&spans, &occupied) {
            continue;
        }
        let first = &spans[0];
        let maximal_lines = normalized_by_path[&first.path][first.start_index..=first.end_index]
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>();
        if mostly_literal_data(&maximal_lines) || mostly_case_labels(&maximal_lines) {
            continue;
        }
        groups += 1;
        if collect_findings {
            findings.push(duplicate_finding(&candidate_key, &spans, &maximal_lines));
        }
        occupy_duplicate_spans(spans, &mut occupied);
    }
    (groups, findings)
}

struct DuplicateOccurrence {
    insertion_order: usize,
    locations: Vec<Location>,
}

type DuplicateOccurrences = HashMap<String, DuplicateOccurrence>;
type NormalizedSources = BTreeMap<String, Vec<NormalizedLine>>;

fn collect_duplicate_windows(
    sources: &BTreeMap<String, String>,
    window: usize,
) -> (DuplicateOccurrences, NormalizedSources) {
    let mut occurrences = HashMap::new();
    let mut normalized_by_path = BTreeMap::new();
    for (path, source) in sources {
        record_source_duplicate_windows(
            path,
            source,
            window,
            &mut occurrences,
            &mut normalized_by_path,
        );
    }
    (occurrences, normalized_by_path)
}

fn record_source_duplicate_windows(
    path: &str,
    source: &str,
    window: usize,
    occurrences: &mut DuplicateOccurrences,
    normalized_by_path: &mut NormalizedSources,
) {
    if historical_sql(path) {
        return;
    }
    let lines = normalized_lines(source, path);
    if lines.len() >= window {
        let language_key = duplicate_language_key(path);
        let scope = standalone_template_scope(path);
        for start in 0..=lines.len() - window {
            let key = duplicate_window_key(&language_key, scope, &lines[start..start + window]);
            let insertion_order = occurrences.len();
            let occurrence = occurrences
                .entry(key)
                .or_insert_with(|| DuplicateOccurrence {
                    insertion_order,
                    locations: Vec::new(),
                });
            if occurrence.locations.len() < MAX_OCCURRENCES_PER_GROUP {
                occurrence.locations.push(Location {
                    path: path.to_owned(),
                    line: lines[start].number,
                    index: start,
                });
            }
        }
    }
    normalized_by_path.insert(path.to_owned(), lines);
}

fn duplicate_language_key(path: &str) -> String {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .map_or_else(String::new, |value| format!(".{value}"));
    if extension == ".luau" {
        ".lua".to_owned()
    } else {
        extension
    }
}

fn duplicate_window_key(language_key: &str, scope: &str, lines: &[NormalizedLine]) -> String {
    let mut key = String::with_capacity(
        language_key.len()
            + scope.len()
            + 2
            + lines.iter().map(|line| line.text.len() + 1).sum::<usize>(),
    );
    key.push_str(language_key);
    key.push('\n');
    key.push_str(scope);
    key.push('\n');
    for (offset, line) in lines.iter().enumerate() {
        if offset > 0 {
            key.push('\n');
        }
        key.push_str(&line.text);
    }
    key
}

fn ordered_duplicate_candidates(
    occurrences: DuplicateOccurrences,
) -> Vec<(usize, String, Vec<Location>)> {
    let mut candidates = occurrences
        .into_iter()
        .filter(|(_, occurrence)| occurrence.locations.len() > 1)
        .map(|(key, occurrence)| (occurrence.insertion_order, key, occurrence.locations))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        let left_earliest =
            earliest(&left.2).map(|location| (location.path.as_str(), location.line));
        let right_earliest =
            earliest(&right.2).map(|location| (location.path.as_str(), location.line));
        left_earliest
            .cmp(&right_earliest)
            .then_with(|| left.0.cmp(&right.0))
    });
    candidates
}

fn select_duplicate_locations(
    candidate_locations: Vec<Location>,
    window: usize,
    sources: &BTreeMap<String, String>,
    normalized_by_path: &NormalizedSources,
    occupied: &BTreeMap<String, Vec<LineRange>>,
) -> Option<Vec<Location>> {
    let mut ordered_locations = candidate_locations
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ordered_locations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
    });
    let mut locations: Vec<Location> = Vec::new();
    for location in ordered_locations {
        if locations.iter().any(|selected| {
            selected.path == location.path && selected.index.abs_diff(location.index) < window
        }) {
            continue;
        }
        locations.push(location);
    }
    if locations.len() < 2 {
        return None;
    }
    if locations.len() == 2
        && mutually_exclusive_go_builds(
            &locations[0].path,
            &sources[&locations[0].path],
            &locations[1].path,
            &sources[&locations[1].path],
        )
    {
        return None;
    }
    if locations.iter().any(|location| {
        let lines = &normalized_by_path[&location.path];
        overlaps(
            occupied.get(&location.path).map_or(&[], Vec::as_slice),
            LineRange {
                start: lines[location.index].number,
                end: lines[location.index + window - 1].number,
            },
        )
    }) {
        return None;
    }
    Some(locations)
}

fn duplicate_span_extensions(
    locations: &[Location],
    window: usize,
    normalized_by_path: &NormalizedSources,
) -> (usize, usize) {
    let mut backward = 0;
    while locations.iter().all(|location| location.index > backward) {
        let previous = locations
            .iter()
            .map(|location| {
                normalized_by_path[&location.path][location.index - backward - 1]
                    .text
                    .as_str()
            })
            .collect::<BTreeSet<_>>();
        if previous.len() != 1 {
            break;
        }
        backward += 1;
    }
    let mut forward = 0;
    while locations.iter().all(|location| {
        location.index + window + forward < normalized_by_path[&location.path].len()
    }) {
        let next = locations
            .iter()
            .map(|location| {
                normalized_by_path[&location.path][location.index + window + forward]
                    .text
                    .as_str()
            })
            .collect::<BTreeSet<_>>();
        if next.len() != 1 {
            break;
        }
        forward += 1;
    }
    (backward, forward)
}

fn duplicate_spans(
    locations: &[Location],
    window: usize,
    backward: usize,
    forward: usize,
    normalized_by_path: &NormalizedSources,
) -> Vec<DuplicateSpan> {
    locations
        .iter()
        .map(|location| {
            let lines = &normalized_by_path[&location.path];
            let start_index = location.index - backward;
            let end_index = location.index + window + forward - 1;
            DuplicateSpan {
                path: location.path.clone(),
                start_line: lines[start_index].number,
                end_line: lines[end_index].number,
                start_index,
                end_index,
            }
        })
        .collect()
}

fn spans_overlap_each_other(spans: &[DuplicateSpan]) -> bool {
    spans.iter().enumerate().any(|(index, left)| {
        spans[index + 1..].iter().any(|right| {
            left.path == right.path
                && left.start_index <= right.end_index
                && right.start_index <= left.end_index
        })
    })
}

fn spans_overlap_occupied(
    spans: &[DuplicateSpan],
    occupied: &BTreeMap<String, Vec<LineRange>>,
) -> bool {
    spans.iter().any(|span| {
        overlaps(
            occupied.get(&span.path).map_or(&[], Vec::as_slice),
            LineRange {
                start: span.start_line,
                end: span.end_line,
            },
        )
    })
}

fn duplicate_finding(
    candidate_key: &str,
    spans: &[DuplicateSpan],
    maximal_lines: &[&str],
) -> Finding {
    let language_key = candidate_key
        .split_once('\n')
        .map_or(candidate_key, |(key, _)| key);
    let mut fingerprint_material = String::from(language_key);
    fingerprint_material.push('\n');
    fingerprint_material.push_str(&maximal_lines.join("\n"));
    let digest = Sha256::digest(fingerprint_material.as_bytes());
    let fingerprint = format!("{digest:X}")[..12].to_owned();
    let snippet = maximal_lines
        .iter()
        .take(3)
        .map(|line| format!("    {}", line.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    let first = &spans[0];
    Finding {
        code: "duplicate-block".to_owned(),
        severity: Severity::Warn,
        path: first.path.clone(),
        line: first.start_line,
        end_line: first.end_line,
        message: format!(
            "duplicate block of {} lines fingerprint={fingerprint}",
            maximal_lines.len()
        ),
        confidence: "high".to_owned(),
        why: "The same normalized code block appears in more than one location.".to_owned(),
        suggestion: "Extract shared logic or raise min_duplication_lines if the duplication is intentional/noisy.".to_owned(),
        related_files: spans
            .iter()
            .skip(1)
            .map(|span| format!("{}:{}-{}", span.path, span.start_line, span.end_line))
            .collect(),
        snippet,
        code_flow: Vec::new(),
    }
}

fn occupy_duplicate_spans(
    spans: Vec<DuplicateSpan>,
    occupied: &mut BTreeMap<String, Vec<LineRange>>,
) {
    for span in spans {
        occupied.entry(span.path).or_default().push(LineRange {
            start: span.start_line,
            end: span.end_line,
        });
    }
}

#[derive(Debug)]
struct ConditionOccurrence {
    path: String,
    line: usize,
    source: String,
}

type ConditionIndex = BTreeMap<String, Vec<ConditionOccurrence>>;

pub fn repeated_condition_findings(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    qualified_repeated_conditions(&index_repeated_conditions(sources))
        .take(20)
        .map(repeated_condition_finding)
        .collect()
}

fn index_repeated_conditions(sources: &BTreeMap<String, String>) -> ConditionIndex {
    let mut occurrences = BTreeMap::new();
    for (path, source) in sources {
        for (index, line) in source.split('\n').enumerate() {
            let Some((normalized, condition)) = qualified_condition(line.trim()) else {
                continue;
            };
            occurrences
                .entry(format!("{path} | {normalized}"))
                .or_insert_with(Vec::new)
                .push(ConditionOccurrence {
                    path: path.clone(),
                    line: index + 1,
                    source: condition,
                });
        }
    }
    occurrences
}

fn qualified_condition(raw: &str) -> Option<(String, String)> {
    let is_condition = ["if ", "elif ", "elseif ", "else if ", "while "]
        .iter()
        .any(|prefix| raw.starts_with(prefix));
    if !is_condition {
        return None;
    }
    let condition = condition_source(raw);
    let has_compound_operator = [" and ", " or ", "&&", "||"]
        .iter()
        .any(|operator| condition.contains(operator));
    if mechanical_scanner_condition(&condition)
        || !has_compound_operator
        || structural_tokens(&condition).len() < 8
    {
        return None;
    }
    let normalized = WHITESPACE.replace_all(&condition, " ").trim().to_owned();
    Some((normalized, condition))
}

fn qualified_repeated_conditions(
    occurrences: &ConditionIndex,
) -> impl Iterator<Item = &[ConditionOccurrence]> {
    occurrences
        .values()
        .filter(|locations| locations.len() >= 3)
        .map(Vec::as_slice)
}

fn repeated_condition_finding(locations: &[ConditionOccurrence]) -> Finding {
    let first = &locations[0];
    Finding {
        code: "repeated-condition".to_owned(),
        severity: Severity::Info,
        path: first.path.clone(),
        line: first.line,
        end_line: first.line,
        message: format!(
            "complex condition is repeated in {} locations",
            locations.len()
        ),
        confidence: "medium".to_owned(),
        why: "Repeated policy conditions can drift when one copy changes without the others."
            .to_owned(),
        suggestion: "Consider a named predicate if these checks express the same business rule and should evolve together.".to_owned(),
        related_files: locations
            .iter()
            .skip(1)
            .map(|location| format!("{}:{}", location.path, location.line))
            .collect(),
        snippet: first.source.clone(),
        code_flow: Vec::new(),
    }
}

fn mechanical_scanner_condition(condition: &str) -> bool {
    let byte_access = condition.contains("bytes[")
        || condition.contains("bytes.get(")
        || condition.contains("bytes.len()")
        || condition.contains("*byte");
    byte_access
        && (condition.contains("cursor")
            || condition.contains("index")
            || condition.contains("*byte"))
}

pub(crate) fn structural_tokens(source: &str) -> Vec<String> {
    let no_strings = STRING_LITERAL.replace_all(source, " STR ");
    let raw: Vec<&str> = STRUCTURAL_TOKEN
        .find_iter(&no_strings)
        .map(|token| token.as_str())
        .collect();
    raw.iter()
        .enumerate()
        .map(|(index, token)| {
            if token.starts_with(|character: char| character.is_ascii_digit()) {
                return "NUM".to_owned();
            }
            if token
                .starts_with(|character: char| character.is_ascii_alphabetic() || character == '_')
            {
                let lower = token.to_ascii_lowercase();
                let call = raw.get(index + 1).is_some_and(|next| *next == "(");
                let member = index > 0 && raw[index - 1] == ".";
                if structural_keyword(&lower) || call || member {
                    return lower;
                }
                return "ID".to_owned();
            }
            (*token).to_owned()
        })
        .collect()
}

pub(crate) fn structural_keyword(value: &str) -> bool {
    matches!(
        value,
        "if" | "else"
            | "elif"
            | "elseif"
            | "then"
            | "for"
            | "while"
            | "case"
            | "switch"
            | "of"
            | "return"
            | "yield"
            | "break"
            | "continue"
            | "try"
            | "except"
            | "catch"
            | "finally"
            | "raise"
            | "throw"
            | "and"
            | "or"
            | "not"
            | "in"
            | "is"
            | "as"
            | "new"
            | "await"
            | "async"
            | "true"
            | "false"
            | "nil"
            | "null"
    )
}

fn condition_source(value: &str) -> String {
    let mut result = value;
    for prefix in ["else if ", "elseif ", "elif ", "if ", "while "] {
        if let Some(rest) = result.strip_prefix(prefix) {
            result = rest;
            break;
        }
    }
    if result.starts_with('(') && result.ends_with(") {") {
        result = &result[1..result.len() - 2];
    } else if let Some(stripped) = result.strip_suffix(" then") {
        result = stripped;
    } else if let Some(stripped) = result.strip_suffix(" {") {
        result = stripped;
    } else if let Some(stripped) = result.strip_suffix(':') {
        result = stripped;
    }
    result.trim().to_owned()
}

fn earliest(locations: &[Location]) -> Option<&Location> {
    locations.iter().min_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
    })
}

enum LineTreatment {
    Skip,
    Unique(String),
    Normalize,
}

struct NormalizationExclusions<'a> {
    source_path: &'a str,
    dart_forwarding: &'a BTreeSet<usize>,
    rust_tests: Option<&'a BTreeSet<usize>>,
    rust_masked_lines: Option<&'a [&'a str]>,
}

impl NormalizationExclusions<'_> {
    fn line_treatment(&self, index: usize, raw_line: &str) -> LineTreatment {
        let number = index + 1;
        if self.dart_forwarding.contains(&number) {
            return LineTreatment::Unique(format!(
                "__code_buster_dart_forwarding_constructor__{}:{number}",
                self.source_path
            ));
        }
        if self.rust_tests.is_some_and(|tests| tests.contains(&index)) {
            return LineTreatment::Skip;
        }
        if self.rust_masked_lines.is_some_and(|lines| {
            normalize_line(lines[index]).is_empty() && !normalize_line(raw_line).is_empty()
        }) {
            return LineTreatment::Unique(format!(
                "__code_buster_rust_literal__{}:{number}",
                self.source_path
            ));
        }
        LineTreatment::Normalize
    }
}

struct NormalizationPolicy {
    hash_comments: bool,
    lua_comments: bool,
    python: bool,
}

impl NormalizationPolicy {
    fn for_path(source_path: &str) -> Self {
        let lowercase_path = source_path.to_ascii_lowercase();
        let python = lowercase_path.ends_with(".py") || lowercase_path.ends_with(".pyw");
        Self {
            hash_comments: python,
            lua_comments: lowercase_path.ends_with(".lua") || lowercase_path.ends_with(".luau"),
            python,
        }
    }

    fn normalize(
        &self,
        raw_line: &str,
        comment_state: &mut CommentNormalizationState,
    ) -> Option<String> {
        if self.python
            && masks_python_standalone_string(raw_line, &mut comment_state.python_triple_quote)
        {
            return None;
        }
        if self.hash_comments && raw_line.trim_start().starts_with('#') {
            return None;
        }
        let mut line = raw_line.to_owned();
        if self.lua_comments {
            line = without_lua_long_comments(&line, &mut comment_state.lua_end);
        }
        line = without_block_comments(line, &mut comment_state.in_block_comment)?;
        let normalized = normalize_line(&line);
        (!normalized.is_empty()).then_some(normalized)
    }
}

#[derive(Default)]
struct CommentNormalizationState {
    lua_end: Option<String>,
    in_block_comment: bool,
    python_triple_quote: Option<&'static str>,
}

fn masks_python_standalone_string(line: &str, active_delimiter: &mut Option<&'static str>) -> bool {
    if let Some(delimiter) = active_delimiter {
        if line.contains(*delimiter) {
            *active_delimiter = None;
        }
        return true;
    }
    let trimmed = line.trim_start();
    let prefix_length = trimmed
        .bytes()
        .take_while(|byte| matches!(byte, b'b' | b'B' | b'f' | b'F' | b'r' | b'R' | b'u' | b'U'))
        .count();
    if prefix_length > 2 {
        return false;
    }
    let quoted = &trimmed[prefix_length..];
    let delimiter = if quoted.starts_with("\"\"\"") {
        "\"\"\""
    } else if quoted.starts_with("'''") {
        "'''"
    } else {
        return false;
    };
    if !quoted[delimiter.len()..].contains(delimiter) {
        *active_delimiter = Some(delimiter);
    }
    true
}

fn without_block_comments(mut line: String, in_block_comment: &mut bool) -> Option<String> {
    if *in_block_comment {
        let end = line.find("*/")?;
        line = line[end + 2..].to_owned();
        *in_block_comment = false;
    }
    if let Some(comment_start) = line.find("/*") {
        if let Some(relative_end) = line[comment_start + 2..].find("*/") {
            let comment_end = comment_start + 2 + relative_end;
            line = format!("{} {}", &line[..comment_start], &line[comment_end + 2..]);
        } else {
            line.truncate(comment_start);
            *in_block_comment = true;
        }
    }
    Some(line)
}

fn normalized_lines(source: &str, source_path: &str) -> Vec<NormalizedLine> {
    let raw_lines: Vec<&str> = source.split('\n').collect();
    let dart_forwarding = dart_forwarding_constructor_lines(&raw_lines, source_path);
    let rust_facts = source_path
        .ends_with(".rs")
        .then(|| function_lexical_facts(source));
    let rust_masked_lines = rust_facts
        .as_ref()
        .map(|(masked, _)| masked.split('\n').collect::<Vec<_>>());
    let exclusions = NormalizationExclusions {
        source_path,
        dart_forwarding: &dart_forwarding,
        rust_tests: rust_facts.as_ref().map(|(_, tests)| tests),
        rust_masked_lines: rust_masked_lines.as_deref(),
    };
    let policy = NormalizationPolicy::for_path(source_path);
    let mut comment_state = CommentNormalizationState::default();
    let mut result = Vec::new();
    for (index, raw_line) in raw_lines.iter().enumerate() {
        let text = match exclusions.line_treatment(index, raw_line) {
            LineTreatment::Skip => continue,
            LineTreatment::Unique(text) => text,
            LineTreatment::Normalize => {
                let Some(text) = policy.normalize(raw_line, &mut comment_state) else {
                    continue;
                };
                text
            }
        };
        result.push(NormalizedLine {
            number: index + 1,
            text,
        });
    }
    result
}

fn normalize_line(line: &str) -> String {
    let normalized = WHITESPACE.replace_all(line.trim(), " ").into_owned();
    if normalized.is_empty()
        || normalized.starts_with("--")
        || normalized.starts_with("//")
        || normalized.starts_with("using ")
        || normalized.starts_with("namespace ")
        || normalized.starts_with("#nullable")
        || normalized.starts_with("#pragma")
        || ["{", "}", "{}"].contains(&normalized.as_str())
    {
        String::new()
    } else {
        normalized
    }
}

fn dart_forwarding_constructor_lines(lines: &[&str], source_path: &str) -> BTreeSet<usize> {
    if !source_path.to_ascii_lowercase().ends_with(".dart") {
        return BTreeSet::new();
    }
    let classes = dart_class_names(lines);
    let mut excluded = BTreeSet::new();
    let mut index = 0;
    while index < lines.len() {
        if !is_dart_constructor_candidate(lines[index], &classes) {
            index += 1;
            continue;
        }
        let start = index;
        let (declaration, end) = dart_constructor_declaration(lines, start);
        if is_dart_forwarding_constructor(&declaration) {
            excluded.extend(start + 1..=end + 1);
        }
        index = end + 1;
    }
    excluded
}

fn dart_class_names(lines: &[&str]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| DART_CLASS.captures(line))
        .map(|captures| captures[1].to_owned())
        .collect()
}

fn is_dart_constructor_candidate(line: &str, classes: &[String]) -> bool {
    let trimmed = line.trim_start();
    let constructor = ["const ", "factory ", "external "]
        .into_iter()
        .find_map(|modifier| trimmed.strip_prefix(modifier))
        .unwrap_or(trimmed);
    classes
        .iter()
        .any(|class_name| dart_constructor_start(constructor, class_name))
}

#[derive(Default)]
struct ParenthesisBalance {
    depth: isize,
    saw_open: bool,
}

impl ParenthesisBalance {
    fn observe(&mut self, line: &str) {
        for character in line.chars() {
            match character {
                '(' => {
                    self.depth += 1;
                    self.saw_open = true;
                }
                ')' => self.depth -= 1,
                _ => {}
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.saw_open && self.depth == 0
    }
}

fn dart_constructor_declaration(lines: &[&str], start: usize) -> (String, usize) {
    let mut declaration = String::new();
    let mut balance = ParenthesisBalance::default();
    for (offset, line) in lines[start..].iter().enumerate() {
        declaration.push_str(line.trim());
        declaration.push(' ');
        balance.observe(line);
        if balance.is_closed() || offset > 30 {
            return (declaration, start + offset);
        }
    }
    (declaration, lines.len())
}

fn is_dart_forwarding_constructor(declaration: &str) -> bool {
    let Some(open) = declaration.find('(') else {
        return false;
    };
    let Some(close) = declaration.rfind(')').filter(|close| *close > open) else {
        return false;
    };
    let parameters = &declaration[open + 1..close];
    let trailing = declaration[close + 1..].trim();
    !parameters.trim().is_empty()
        && trailing.starts_with(';')
        && split_parameters(parameters).iter().all(|parameter| {
            let parameter = parameter.trim();
            parameter.contains("this.") || parameter.contains("super.")
        })
}

fn dart_constructor_start(source: &str, class_name: &str) -> bool {
    let Some(remainder) = source.strip_prefix(class_name) else {
        return false;
    };
    if remainder.starts_with('(') {
        return true;
    }
    let Some(named) = remainder.strip_prefix('.') else {
        return false;
    };
    let name_end = named
        .find(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .unwrap_or(named.len());
    name_end > 0 && named[name_end..].trim_start().starts_with('(')
}

fn split_parameters(parameters: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0isize;
    for character in parameters.chars() {
        match character {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                result.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(character);
    }
    result.push(current);
    result
}

fn without_lua_long_comments(line: &str, state: &mut Option<String>) -> String {
    let mut result = line.to_owned();
    let mut search_from = 0;
    if let Some(end_marker) = state.as_ref() {
        let Some(end) = result.find(end_marker) else {
            return String::new();
        };
        result = result[end + end_marker.len()..].to_owned();
        *state = None;
    }
    loop {
        let Some(captures) = LUA_LONG_COMMENT.captures(&result[search_from..]) else {
            return result;
        };
        let matched = captures.get(0).expect("Lua comment match must exist");
        let start_index = search_from + matched.start();
        if inside_lua_string(&result, start_index) {
            search_from += matched.end();
            continue;
        }
        let equals = captures.get(1).map_or("", |value| value.as_str());
        let end_marker = format!("]{equals}]");
        let content_start = search_from + matched.end();
        if let Some(relative_end) = result[content_start..].find(&end_marker) {
            let end_index = content_start + relative_end;
            result.replace_range(start_index..end_index + end_marker.len(), "");
            search_from = start_index;
        } else {
            result.truncate(start_index);
            *state = Some(end_marker);
            return result;
        }
    }
}

#[derive(Clone, Copy)]
enum LuaLexicalState {
    Code,
    Quoted(u8),
    LongString(usize),
}

fn inside_lua_string(line: &str, end: usize) -> bool {
    let bytes = line.as_bytes();
    let mut state = LuaLexicalState::Code;
    let mut index = 0;
    while index < end {
        (state, index) = lua_lexical_transition(bytes, state, index, end);
    }
    !matches!(state, LuaLexicalState::Code)
}

fn lua_lexical_transition(
    bytes: &[u8],
    state: LuaLexicalState,
    index: usize,
    end: usize,
) -> (LuaLexicalState, usize) {
    match state {
        LuaLexicalState::Code => lua_code_transition(bytes, index, end),
        LuaLexicalState::Quoted(quote) => lua_quoted_transition(bytes, index, quote),
        LuaLexicalState::LongString(equals) => lua_long_string_transition(bytes, index, equals),
    }
}

fn lua_code_transition(bytes: &[u8], index: usize, end: usize) -> (LuaLexicalState, usize) {
    let character = bytes[index];
    if b"\"'`".contains(&character) {
        return (LuaLexicalState::Quoted(character), index + 1);
    }
    if let Some(equals) = lua_long_string_opener(bytes, index, end) {
        return (LuaLexicalState::LongString(equals), index + equals + 2);
    }
    (LuaLexicalState::Code, index + 1)
}

fn lua_quoted_transition(bytes: &[u8], index: usize, quote: u8) -> (LuaLexicalState, usize) {
    match bytes[index] {
        b'\\' => (LuaLexicalState::Quoted(quote), index + 2),
        character if character == quote => (LuaLexicalState::Code, index + 1),
        _ => (LuaLexicalState::Quoted(quote), index + 1),
    }
}

fn lua_long_string_transition(
    bytes: &[u8],
    index: usize,
    equals: usize,
) -> (LuaLexicalState, usize) {
    if lua_long_string_closes(bytes, index, equals) {
        (LuaLexicalState::Code, index + equals + 2)
    } else {
        (LuaLexicalState::LongString(equals), index + 1)
    }
}

fn lua_long_string_opener(bytes: &[u8], index: usize, end: usize) -> Option<usize> {
    if bytes[index] != b'[' {
        return None;
    }
    let mut delimiter_end = index + 1;
    while delimiter_end < end && bytes[delimiter_end] == b'=' {
        delimiter_end += 1;
    }
    (delimiter_end < end && bytes[delimiter_end] == b'[').then_some(delimiter_end - index - 1)
}

fn lua_long_string_closes(bytes: &[u8], index: usize, equals: usize) -> bool {
    bytes.get(index) == Some(&b']')
        && bytes.get(index + equals + 1) == Some(&b']')
        && bytes[index + 1..index + equals + 1]
            .iter()
            .all(|character| *character == b'=')
}

fn mostly_literal_data(lines: &[&str]) -> bool {
    if lines.len() < 10 {
        return false;
    }
    let literal_lines = lines
        .iter()
        .filter(|line| {
            LITERAL_LINE.is_match(line) || SQL_TUPLE.is_match(line) || SQL_INSERT.is_match(line)
        })
        .count();
    literal_lines * 5 >= lines.len() * 4
}

fn mostly_case_labels(lines: &[&str]) -> bool {
    lines.len() >= 10
        && lines
            .iter()
            .filter(|line| CASE_LABEL.is_match(line))
            .count()
            * 5
            >= lines.len() * 4
}

fn historical_sql(source_path: &str) -> bool {
    let normalized = source_path.replace('\\', "/").to_ascii_lowercase();
    normalized.ends_with(".sql") && HISTORICAL_SQL.is_match(&normalized)
}

fn overlaps(ranges: &[LineRange], candidate: LineRange) -> bool {
    ranges
        .iter()
        .any(|range| candidate.start <= range.end && candidate.end >= range.start)
}

fn mutually_exclusive_go_builds(
    left_path: &str,
    left_source: &str,
    right_path: &str,
    right_source: &str,
) -> bool {
    if !left_path.ends_with(".go") || !right_path.ends_with(".go") {
        return false;
    }
    let constraint = |source: &str| {
        source
            .split('\n')
            .take(20)
            .find_map(|line| GO_BUILD.captures(line))
            .map(|captures| format!("{}{}", &captures[1], &captures[2]))
    };
    let (Some(left), Some(right)) = (constraint(left_source), constraint(right_source)) else {
        return false;
    };
    left == format!("!{right}") || right == format!("!{left}")
}

static WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("whitespace regex must compile"));
static STRING_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#).expect("string literal regex must compile")
});
static STRUCTURAL_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||[-+*/%<>{}()\[\].,:=]")
        .expect("structural token regex must compile")
});
static HISTORICAL_SQL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(?:migrations?|archive)(/|$)").expect("historical SQL regex must compile")
});
static DART_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bclass\s+([A-Za-z_$][\w$]*)").expect("Dart class regex must compile")
});
static LUA_LONG_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"--\[(=*)\[").expect("Lua long comment regex must compile"));
static LITERAL_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^(?:(?:r)?[\"'].*[\"'],?|(?:(?:null|nullptr|nil|none|true|false)\s*,?|(?:[\{\[]\s*)?(?:[-+]?(?:0x[0-9a-f]+|0b[01]+|\d+(?:\.\d*)?(?:e[-+]?\d+)?)[ulf]*)(?:\s*,\s*[-+]?(?:0x[0-9a-f]+|0b[01]+|\d+(?:\.\d*)?(?:e[-+]?\d+)?)[ulf]*)*(?:\s*[\}\]])?,?))\s*(?://.*|/\*.*\*/)?$"#)
        .expect("literal line regex must compile")
});
static SQL_TUPLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^\(\s*(?:(?:N)?'(?:''|[^'])*'|null|[-+]?\d+(?:\.\d*)?(?:e[-+]?\d+)?)(?:\s*,\s*(?:(?:N)?'(?:''|[^'])*'|null|[-+]?\d+(?:\.\d*)?(?:e[-+]?\d+)?))*\s*\)[,;]?$"#)
        .expect("SQL tuple regex must compile")
});
static SQL_INSERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^insert\s+into\s+.+\s+values\s*$").expect("SQL insert regex must compile")
});
static CASE_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:case\s+.+|default):$").expect("case label regex must compile")
});
static GO_BUILD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*//go:build\s+(!?)([A-Za-z_]\w*)\s*$").expect("Go build regex must compile")
});

#[cfg(test)]
mod tests {
    use super::{
        dart_forwarding_constructor_lines, earliest, exact_findings, exact_group_count,
        repeated_condition_findings,
    };
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn empty_duplicate_group_has_no_representative() {
        assert!(earliest(&[]).is_none());
    }

    #[test]
    fn counts_maximal_non_overlapping_duplicate_groups() {
        let block = "one();\ntwo();\nthree();\nfour();\n";
        let sources = BTreeMap::from([
            ("a.rs".to_owned(), block.to_owned()),
            ("b.rs".to_owned(), block.to_owned()),
        ]);
        assert_eq!(exact_group_count(&sources, 3), 1);
    }

    #[test]
    fn ignores_repeated_python_docstrings() {
        let documentation = (0..16)
            .map(|line| format!("Shared API documentation line {line}."))
            .collect::<Vec<_>>()
            .join("\n");
        let sources = BTreeMap::from([
            (
                "alpha.py".to_owned(),
                format!(
                    "def alpha():\n    \"\"\"{documentation}\n    \"\"\"\n    return alpha_value\n"
                ),
            ),
            (
                "beta.py".to_owned(),
                format!(
                    "def beta():\n    \"\"\"{documentation}\n    \"\"\"\n    return beta_value\n"
                ),
            ),
        ]);

        assert!(exact_findings(&sources, 5).is_empty());
    }

    #[test]
    fn keeps_standalone_scaffold_templates_in_separate_duplicate_domains() {
        let block = "one();\ntwo();\nthree();\nfour();\n";
        let sources = BTreeMap::from([
            (
                "packages/create-app/template-react/src/main.ts".to_owned(),
                block.to_owned(),
            ),
            (
                "packages/create-app/template-react-ts/src/main.ts".to_owned(),
                block.to_owned(),
            ),
        ]);

        assert_eq!(exact_group_count(&sources, 3), 0);
    }

    #[test]
    fn reports_maximal_duplicate_span_with_related_location() {
        let sources = BTreeMap::from([
            (
                "a.rs".to_owned(),
                "before_a();\none();\ntwo();\nthree();\nfour();\nafter_a();".to_owned(),
            ),
            (
                "b.rs".to_owned(),
                "before_b();\none();\ntwo();\nthree();\nfour();\nafter_b();".to_owned(),
            ),
        ]);

        let findings = exact_findings(&sources, 3);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            (
                findings[0].path.as_str(),
                findings[0].line,
                findings[0].end_line
            ),
            ("a.rs", 2, 5)
        );
        assert_eq!(findings[0].related_files, ["b.rs:2-5"]);
        assert!(
            findings[0]
                .message
                .starts_with("duplicate block of 4 lines")
        );
    }

    #[test]
    fn excludes_rust_test_blocks_with_raw_string_braces() {
        let source = r##"#[cfg(test)]
mod tests {
 const DOC: &str = r#"}"#;
 fn first() {
  one();
  two();
  three();
 }
 fn second() {
  one();
  two();
  three();
 }
}
"##;
        let sources = BTreeMap::from([("lib.rs".to_owned(), source.to_owned())]);
        assert_eq!(exact_group_count(&sources, 3), 0);
    }

    #[test]
    fn ignores_rust_multiline_string_content_in_duplicate_windows() {
        let source = r####"
fn first() -> &'static str {
    r#"
shared documentation line one
shared documentation line two
shared documentation line three
"#
}
fn second() -> &'static str {
    r#"
shared documentation line one
shared documentation line two
shared documentation line three
"#
}
"####;
        let sources = BTreeMap::from([("lib.rs".to_owned(), source.to_owned())]);

        assert_eq!(exact_group_count(&sources, 3), 0);
    }

    #[test]
    fn ignores_non_constructor_declarations_with_reversed_parentheses() {
        let lines = [
            "class Result {}",
            "Result get value => previous)",
            "    ? Result(",
            "        buildValue;",
            "class ActivityNotifier {}",
            "final provider = Factory(",
            "  ActivityNotifier.new,",
            ");",
        ];

        assert_eq!(
            dart_forwarding_constructor_lines(&lines, "lib/result.dart"),
            BTreeSet::new()
        );
    }
    #[test]
    fn distinguishes_forwarding_declarations_from_calls_and_tearoffs() {
        let lines = [
            "class CounterDisplay extends Widget {",
            "  void build() {",
            "    const CounterDisplay(),",
            "    register(CounterDisplay.new);",
            "  }",
            "  const CounterDisplay({super.key});",
            "}",
        ];

        assert_eq!(
            dart_forwarding_constructor_lines(&lines, "lib/widget.dart"),
            BTreeSet::from([6])
        );
    }
    #[test]
    fn repeated_conditions_ignore_lexical_scanner_mechanics() {
        let source = r#"fn scan_first(bytes: &[u8], mut index: usize) {
    while index < bytes.len() && bytes[index] != b'\n' { index += 1; }
}
fn scan_second(bytes: &[u8], mut index: usize) {
    while index < bytes.len() && bytes[index] != b'\n' { index += 1; }
}
fn scan_third(bytes: &[u8], mut index: usize) {
    while index < bytes.len() && bytes[index] != b'\n' { index += 1; }
}
fn first(user: User) {
    if user.is_active() && user.has_permission() { run(); }
}
fn second(user: User) {
    if user.is_active() && user.has_permission() { run(); }
}
fn third(user: User) {
    if user.is_active() && user.has_permission() { run(); }
}"#;
        let findings = repeated_condition_findings(&BTreeMap::from([(
            "src/lib.rs".to_owned(),
            source.to_owned(),
        )]));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "repeated-condition");
        assert_eq!(findings[0].line, 11);
    }
}
