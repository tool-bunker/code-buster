use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::{Captures, Regex};

use super::standalone_template_scope;
use crate::dart_null_assertion::dart_source_with_interpolations;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let dart_code = dart_code_sources(context);
    let mut findings = Vec::new();
    findings.extend(css_duplicate_declaration_sets(context));
    findings.extend(css_design_token_drift(context));
    findings.extend(flutter_repeated_inline_styles(context));
    findings.extend(flutter_theme_bypasses(&dart_code));
    findings.extend(flutter_parallel_controls(&dart_code));
    findings.extend(flutter_shared_component_bypasses(context));
    findings.extend(html_parallel_controls(context));
    findings
}

fn dart_code_sources<'a>(context: &'a SourceAnalysisContext<'_>) -> BTreeMap<&'a str, String> {
    context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".dart"))
        .map(|(path, source)| {
            let strings_masked = context.masked_lines(path).join("\n");
            (
                path.as_str(),
                dart_source_with_interpolations(source, &strings_masked),
            )
        })
        .collect()
}

#[derive(Clone)]
struct CssBlock {
    path: String,
    line: usize,
    selector: String,
    declarations: Vec<(String, String)>,
}

struct CssBlockScanner {
    blocks: Vec<CssBlock>,
}

impl CssBlockScanner {
    fn scan(sources: &BTreeMap<String, String>) -> Vec<CssBlock> {
        let mut scanner = Self { blocks: Vec::new() };
        for (path, original) in sources {
            scanner.scan_source(path, original);
        }
        scanner.blocks
    }

    fn scan_source(&mut self, path: &str, original: &str) {
        if !path.ends_with(".css") {
            return;
        }
        let source = without_css_comments(original);
        self.blocks.extend(
            CSS_BLOCK
                .captures_iter(&source)
                .filter_map(|captures| css_block(path, &source, &captures)),
        );
    }
}

fn css_duplicate_declaration_sets(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut by_signature = Vec::<(String, String, Vec<CssBlock>)>::new();
    for block in css_blocks(context.sources()) {
        if block.declarations.len() < 4 {
            continue;
        }
        let signature = declaration_signature(&block.declarations);
        let scope = standalone_template_scope(&block.path);
        if let Some((_, _, matches)) = by_signature
            .iter_mut()
            .find(|(existing, existing_scope, _)| existing == &signature && existing_scope == scope)
        {
            matches.push(block);
        } else {
            by_signature.push((signature, scope.to_owned(), vec![block]));
        }
    }
    let mut findings = Vec::new();
    for (_, _, matches) in by_signature {
        if matches.len() < 2 {
            continue;
        }
        let first = &matches[0];
        for duplicate in matches.iter().skip(1) {
            findings.push(finding(
                "css-duplicate-declaration-set",
                &duplicate.path,
                duplicate.line,
                format!(
                    "`{}` duplicates {} declarations from `{}`",
                    duplicate.selector,
                    duplicate.declarations.len(),
                    first.selector
                ),
                "high",
                vec![format!("{}:{}", first.path, first.line)],
            ));
        }
    }
    findings
}

struct CssTokenSource<'a> {
    path: &'a str,
    source: String,
}

struct CssTokenCandidate {
    source: usize,
    line: usize,
    property: std::ops::Range<usize>,
    value: std::ops::Range<usize>,
}

struct CssTokenCandidates<'a> {
    sources: Vec<CssTokenSource<'a>>,
    definitions: Vec<CssTokenCandidate>,
    usages: Vec<CssTokenCandidate>,
}

struct CssToken<'a> {
    name: &'a str,
    path: &'a str,
    line: usize,
}

struct CssTokenUsage<'a> {
    property: String,
    value: String,
    path: &'a str,
    scope: &'a str,
    line: usize,
}

struct GroupedCssTokens<'a> {
    definitions: BTreeMap<&'a str, BTreeMap<String, CssToken<'a>>>,
    usages: Vec<CssTokenUsage<'a>>,
}

fn css_design_token_drift(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let candidates = extract_css_token_candidates(context.sources());
    let grouped = group_css_token_candidates(&candidates);
    css_token_drift_findings(grouped)
}

fn extract_css_token_candidates<'a>(
    sources: &'a BTreeMap<String, String>,
) -> CssTokenCandidates<'a> {
    let mut extracted = CssTokenCandidates {
        sources: Vec::new(),
        definitions: Vec::new(),
        usages: Vec::new(),
    };
    for (path, original) in sources {
        if !path.ends_with(".css") {
            continue;
        }
        let source = without_css_comments(original);
        let source_index = extracted.sources.len();
        extract_css_token_definitions(source_index, original, &source, &mut extracted.definitions);
        extract_css_token_usages(source_index, &source, &mut extracted.usages);
        extracted.sources.push(CssTokenSource {
            path: path.as_str(),
            source,
        });
    }
    extracted
}

fn extract_css_token_definitions(
    source_index: usize,
    original: &str,
    source: &str,
    definitions: &mut Vec<CssTokenCandidate>,
) {
    for declaration in CSS_DECLARATION.captures_iter(source) {
        let Some(property) = declaration.get(1) else {
            continue;
        };
        if !property.as_str().trim().starts_with("--") {
            continue;
        }
        let (Some(value), Some(whole)) = (declaration.get(2), declaration.get(0)) else {
            continue;
        };
        definitions.push(CssTokenCandidate {
            source: source_index,
            line: line_at(original, whole.start()),
            property: property.start()..property.end(),
            value: value.start()..value.end(),
        });
    }
}

fn extract_css_token_usages(
    source_index: usize,
    source: &str,
    usages: &mut Vec<CssTokenCandidate>,
) {
    for block in CSS_BLOCK.captures_iter(source) {
        let (Some(selector), Some(body), Some(whole)) = (block.get(1), block.get(2), block.get(0))
        else {
            continue;
        };
        let selector = selector.as_str().trim();
        if selector.starts_with('@') || selector.is_empty() {
            continue;
        }
        let selector_offset = whole.as_str().find(selector).unwrap_or(0);
        let line = line_at(source, whole.start() + selector_offset);
        let first_usage = usages.len();
        for declaration in CSS_DECLARATION.captures_iter(body.as_str()) {
            let (Some(property), Some(value)) = (declaration.get(1), declaration.get(2)) else {
                continue;
            };
            let property_range = body.start() + property.start()..body.start() + property.end();
            let value_range = body.start() + value.start()..body.start() + value.end();
            if let Some(existing) = usages[first_usage..].iter_mut().find(|candidate| {
                source[candidate.property.clone()].eq_ignore_ascii_case(property.as_str())
            }) {
                existing.value = value_range;
            } else {
                usages.push(CssTokenCandidate {
                    source: source_index,
                    line,
                    property: property_range,
                    value: value_range,
                });
            }
        }
    }
}

fn group_css_token_candidates<'a>(candidates: &'a CssTokenCandidates<'a>) -> GroupedCssTokens<'a> {
    let mut definitions = BTreeMap::<&str, BTreeMap<String, CssToken<'_>>>::new();
    for candidate in &candidates.definitions {
        let source = &candidates.sources[candidate.source];
        let value = normalize_css_value(&source.source[candidate.value.clone()]);
        if !useful_token_value(&value) {
            continue;
        }
        definitions
            .entry(standalone_template_scope(source.path))
            .or_default()
            .entry(value)
            .or_insert_with(|| CssToken {
                name: source.source[candidate.property.clone()].trim(),
                path: source.path,
                line: candidate.line,
            });
    }
    let usages = candidates
        .usages
        .iter()
        .map(|candidate| {
            let source = &candidates.sources[candidate.source];
            CssTokenUsage {
                property: source.source[candidate.property.clone()].to_ascii_lowercase(),
                value: normalize_css_value(&source.source[candidate.value.clone()]),
                path: source.path,
                scope: standalone_template_scope(source.path),
                line: candidate.line,
            }
        })
        .collect();
    GroupedCssTokens {
        definitions,
        usages,
    }
}

fn css_token_drift_findings(grouped: GroupedCssTokens<'_>) -> Vec<Finding> {
    grouped
        .usages
        .into_iter()
        .filter_map(|usage| {
            if usage.property.starts_with("--") || usage.value.contains("var(") {
                return None;
            }
            let token = grouped.definitions.get(usage.scope)?.get(&usage.value)?;
            Some(finding(
                "css-design-token-drift",
                usage.path,
                usage.line,
                format!(
                    "`{}` repeats `{}` instead of `{}`",
                    usage.property, usage.value, token.name
                ),
                "high",
                vec![format!("{}:{}", token.path, token.line)],
            ))
        })
        .collect()
}

fn css_blocks(sources: &BTreeMap<String, String>) -> Vec<CssBlock> {
    CssBlockScanner::scan(sources)
}

fn css_block(path: &str, source: &str, block: &Captures<'_>) -> Option<CssBlock> {
    let selector = block.get(1)?.as_str().trim();
    if selector.starts_with('@') || selector.is_empty() {
        return None;
    }
    let declarations = css_block_declarations(block.get(2)?.as_str());
    if declarations.is_empty() {
        return None;
    }
    let whole = block.get(0)?;
    let selector_offset = whole.as_str().find(selector).unwrap_or(0);
    Some(CssBlock {
        path: path.to_owned(),
        line: line_at(source, whole.start() + selector_offset),
        selector: selector.to_owned(),
        declarations,
    })
}

fn css_block_declarations(body: &str) -> Vec<(String, String)> {
    let mut declarations = Vec::<(String, String)>::new();
    for declaration in CSS_DECLARATION.captures_iter(body) {
        let (Some(property), Some(value)) = (declaration.get(1), declaration.get(2)) else {
            continue;
        };
        let property = property.as_str().to_ascii_lowercase();
        let value = normalize_css_value(value.as_str());
        if let Some(existing) = declarations
            .iter_mut()
            .find(|(existing, _)| existing == &property)
        {
            existing.1 = value;
        } else {
            declarations.push((property, value));
        }
    }
    declarations
}

fn declaration_signature(declarations: &[(String, String)]) -> String {
    let mut pairs = declarations
        .iter()
        .map(|(property, value)| format!("{property}:{value}"))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join(";")
}

fn without_css_comments(source: &str) -> String {
    CSS_COMMENT
        .replace_all(source, |captures: &Captures<'_>| {
            let Some(comment) = captures.get(0) else {
                return String::new();
            };
            " ".repeat(comment.as_str().len())
        })
        .into_owned()
}

fn normalize_css_value(value: &str) -> String {
    let mut normalized = value.trim().to_ascii_lowercase();
    normalized = WHITESPACE.replace_all(&normalized, " ").into_owned();
    normalized = CSS_PUNCTUATION_SPACE
        .replace_all(&normalized, |_: &Captures<'_>| "$1")
        .into_owned();
    normalized = CSS_ZERO_UNIT.replace_all(&normalized, "0").into_owned();
    CSS_SIX_DIGIT_HEX
        .replace_all(&normalized, |captures: &Captures<'_>| {
            let Some(matched) = captures.get(0) else {
                return String::new();
            };
            let Some(hex) = captures.get(1).map(|capture| capture.as_str().as_bytes()) else {
                return matched.as_str().to_owned();
            };
            let [first, second, third, fourth, fifth, sixth] = hex else {
                return matched.as_str().to_owned();
            };
            if first == second && third == fourth && fifth == sixth {
                format!("#{}{}{}", *first as char, *third as char, *fifth as char)
            } else {
                matched.as_str().to_owned()
            }
        })
        .into_owned()
}

fn useful_token_value(value: &str) -> bool {
    value.len() >= 3
        && ![
            "0",
            "none",
            "auto",
            "inherit",
            "initial",
            "unset",
            "transparent",
        ]
        .contains(&value)
}

#[derive(Clone)]
struct StyleOccurrence {
    path: String,
    line: usize,
    constructor: String,
    signature: String,
}

fn flutter_repeated_inline_styles(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut groups = BTreeMap::<String, Vec<StyleOccurrence>>::new();
    for (path, source) in context.sources() {
        if !path.ends_with(".dart") {
            continue;
        }
        for style in flutter_styles(path, source) {
            groups
                .entry(style.signature.clone())
                .or_default()
                .push(style);
        }
    }
    let mut findings = Vec::new();
    for matches in groups.into_values() {
        if matches
            .iter()
            .map(|item| item.path.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            < 2
        {
            continue;
        }
        let first = &matches[0];
        for duplicate in matches.iter().skip(1) {
            if duplicate.path == first.path {
                continue;
            }
            findings.push(finding(
                "flutter-repeated-inline-style",
                &duplicate.path,
                duplicate.line,
                format!(
                    "`{}` repeats an inline style from `{}`",
                    duplicate.constructor, first.path
                ),
                "high",
                vec![format!("{}:{}", first.path, first.line)],
            ));
        }
    }
    findings
}

fn flutter_styles(path: &str, source: &str) -> Vec<StyleOccurrence> {
    let mut styles = Vec::new();
    for constructor in STYLE_CONSTRUCTOR.captures_iter(source) {
        let whole = constructor.get(0).unwrap();
        let open = whole.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        let body = &source[open + 1..close];
        if NAMED_ARGUMENT.find_iter(body).count() < 3 {
            continue;
        }
        let name = constructor.get(1).unwrap().as_str();
        styles.push(StyleOccurrence {
            path: path.to_owned(),
            line: line_at(source, whole.start()),
            constructor: name.to_owned(),
            signature: format!("{name}:{}", normalize_dart(body)),
        });
    }
    styles
}

#[derive(Clone)]
struct FlutterToken {
    name: String,
    path: String,
    line: usize,
}

fn flutter_theme_bypasses(sources: &BTreeMap<&str, String>) -> Vec<Finding> {
    let mut tokens = BTreeMap::<String, FlutterToken>::new();
    let mut declaration_locations = BTreeSet::new();
    for (&path, source) in sources {
        for declaration in TOKEN_DECLARATION.captures_iter(source) {
            let expression_match = declaration.get(2).unwrap();
            let expression = normalize_dart(expression_match.as_str());
            if expression == "Colors.transparent" {
                continue;
            }
            let whole = declaration.get(0).unwrap();
            let line = line_at(source, whole.start());
            tokens.entry(expression).or_insert_with(|| FlutterToken {
                name: declaration.get(1).unwrap().as_str().to_owned(),
                path: path.to_owned(),
                line,
            });
            declaration_locations.insert((path, expression_match.start()));
        }
    }
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (&path, source) in sources {
        for expression in COLOR_EXPRESSION.find_iter(source) {
            if declaration_locations.contains(&(path, expression.start())) {
                continue;
            }
            let Some(token) = tokens.get(&normalize_dart(expression.as_str())) else {
                continue;
            };
            findings.push(finding(
                "flutter-theme-bypass",
                path,
                line_at(source, expression.start()),
                format!(
                    "raw `{}` duplicates project color token `{}`",
                    expression.as_str(),
                    token.name
                ),
                "high",
                vec![format!("{}:{}", token.path, token.line)],
            ));
        }
    }
    findings
}

#[derive(Clone, Eq, PartialEq)]
struct Location {
    path: String,
    line: usize,
}

fn flutter_parallel_controls(sources: &BTreeMap<&str, String>) -> Vec<Finding> {
    let mut semantic = None;
    let mut pointer_controls = Vec::new();
    for (&path, source) in sources {
        if semantic.is_none() {
            semantic = first_location(path, source, &SEMANTIC_BUTTON);
        }
        for pointer in POINTER_CONTROL.find_iter(source) {
            let open = pointer.end() - 1;
            let Some(close) = matching_delimiter(source, open, b'(', b')') else {
                continue;
            };
            let tree = &source[pointer.start()..=close];
            if CONTAINER.is_match(tree) && TEXT_WIDGET.is_match(tree) {
                pointer_controls.push(Location {
                    path: path.to_owned(),
                    line: line_at(source, pointer.start()),
                });
            }
        }
    }
    let Some(semantic) = semantic else {
        return Vec::new();
    };
    pointer_controls
        .into_iter()
        .map(|pointer| {
            finding(
                "flutter-parallel-control-component",
                &pointer.path,
                pointer.line,
                "button-like pointer tree exists alongside semantic Flutter buttons".to_owned(),
                "medium",
                vec![format!("{}:{}", semantic.path, semantic.line)],
            )
        })
        .collect()
}

#[derive(Clone)]
struct SharedWidget {
    name: String,
    framework_control: String,
    path: String,
    line: usize,
    start: usize,
    end: usize,
}

struct EstablishedWidget {
    wrapper: SharedWidget,
    usages: Vec<Location>,
}

fn flutter_shared_component_bypasses(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let wrappers = shared_flutter_widgets(context);
    let established = established_flutter_widgets(context, &wrappers);
    let mut findings = Vec::new();
    for (control, conventions) in widgets_by_framework_control(established) {
        findings.extend(control_bypass_findings(
            context,
            &wrappers,
            &control,
            conventions,
        ));
    }
    findings
}

fn shared_flutter_widgets(context: &SourceAnalysisContext<'_>) -> Vec<SharedWidget> {
    let mut wrappers = Vec::new();
    for (path, source) in context.sources() {
        if !is_dart_ui_source(path) {
            continue;
        }
        for declaration in WIDGET_CLASS.captures_iter(source) {
            let whole = declaration.get(0).unwrap();
            let open = whole.end() - 1;
            let Some(close) = matching_delimiter(source, open, b'{', b'}') else {
                continue;
            };
            let Some(control) = FRAMEWORK_CONTROL.captures(&source[open + 1..close]) else {
                continue;
            };
            wrappers.push(SharedWidget {
                name: declaration.get(1).unwrap().as_str().to_owned(),
                framework_control: control.get(1).unwrap().as_str().to_owned(),
                path: path.clone(),
                line: line_at(source, whole.start()),
                start: whole.start(),
                end: close,
            });
        }
    }
    wrappers
}

fn established_flutter_widgets(
    context: &SourceAnalysisContext<'_>,
    wrappers: &[SharedWidget],
) -> Vec<EstablishedWidget> {
    wrappers
        .iter()
        .filter_map(|wrapper| {
            let usages = widget_usages(context, wrapper);
            established_usage(&usages).then(|| EstablishedWidget {
                wrapper: wrapper.clone(),
                usages,
            })
        })
        .collect()
}

fn widget_usages(context: &SourceAnalysisContext<'_>, wrapper: &SharedWidget) -> Vec<Location> {
    let pattern = Regex::new(&format!(r"\b{}\s*\(", regex::escape(&wrapper.name))).unwrap();
    let mut usages = Vec::new();
    for (path, source) in context.sources() {
        if !is_dart_ui_source(path) {
            continue;
        }
        usages.extend(
            pattern
                .find_iter(source)
                .filter(|usage| !inside_shared_widget(path, usage.start(), wrapper))
                .map(|usage| Location {
                    path: path.clone(),
                    line: line_at(source, usage.start()),
                }),
        );
    }
    usages
}

fn established_usage(usages: &[Location]) -> bool {
    usages.len() >= 3
        && usages
            .iter()
            .map(|usage| usage.path.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            >= 2
}

fn inside_shared_widget(path: &str, offset: usize, wrapper: &SharedWidget) -> bool {
    path == wrapper.path && offset >= wrapper.start && offset <= wrapper.end
}

fn widgets_by_framework_control(
    established: Vec<EstablishedWidget>,
) -> BTreeMap<String, Vec<EstablishedWidget>> {
    let mut by_control = BTreeMap::<String, Vec<EstablishedWidget>>::new();
    for widget in established {
        by_control
            .entry(widget.wrapper.framework_control.clone())
            .or_default()
            .push(widget);
    }
    by_control
}

fn control_bypass_findings(
    context: &SourceAnalysisContext<'_>,
    wrappers: &[SharedWidget],
    control: &str,
    mut conventions: Vec<EstablishedWidget>,
) -> Vec<Finding> {
    conventions.sort_by_key(|widget| std::cmp::Reverse(widget.usages.len()));
    if has_tied_conventions(&conventions) {
        return Vec::new();
    }
    let convention = &conventions[0];
    let direct_usages = direct_control_usages(context, wrappers, control);
    if direct_usages.len() >= convention.usages.len() {
        return Vec::new();
    }
    let related = convention_locations(convention);
    direct_usages
        .into_iter()
        .map(|usage| {
            finding(
                "flutter-shared-component-bypass",
                &usage.path,
                usage.line,
                format!(
                    "direct `{control}` bypasses established `{}` used {} times",
                    convention.wrapper.name,
                    convention.usages.len()
                ),
                "medium",
                related.clone(),
            )
        })
        .collect()
}

fn has_tied_conventions(conventions: &[EstablishedWidget]) -> bool {
    conventions.len() > 1 && conventions[0].usages.len() == conventions[1].usages.len()
}

fn direct_control_usages(
    context: &SourceAnalysisContext<'_>,
    wrappers: &[SharedWidget],
    control: &str,
) -> Vec<Location> {
    let direct = Regex::new(&format!(r"\b{}\s*\(", regex::escape(control))).unwrap();
    let mut usages = Vec::new();
    for (path, source) in context.sources() {
        if !is_dart_ui_source(path) {
            continue;
        }
        usages.extend(
            direct
                .find_iter(source)
                .filter(|usage| {
                    !wrappers
                        .iter()
                        .any(|wrapper| inside_shared_widget(path, usage.start(), wrapper))
                })
                .map(|usage| Location {
                    path: path.clone(),
                    line: line_at(source, usage.start()),
                }),
        );
    }
    usages
}

fn convention_locations(convention: &EstablishedWidget) -> Vec<String> {
    std::iter::once(format!(
        "{}:{}",
        convention.wrapper.path, convention.wrapper.line
    ))
    .chain(
        convention
            .usages
            .iter()
            .take(3)
            .map(|usage| format!("{}:{}", usage.path, usage.line)),
    )
    .collect()
}

fn html_parallel_controls(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut native = None;
    let mut alternatives = Vec::new();
    for (path, source) in context.sources() {
        if !path.ends_with(".html") && !path.ends_with(".htm") {
            continue;
        }
        if native.is_none() {
            native = first_location(path, source, &NATIVE_BUTTON);
        }
        alternatives.extend(
            ALTERNATIVE_BUTTON
                .find_iter(source)
                .map(|alternative| Location {
                    path: path.clone(),
                    line: line_at(source, alternative.start()),
                }),
        );
    }
    let Some(native) = native else {
        return Vec::new();
    };
    alternatives
        .into_iter()
        .map(|alternative| {
            finding(
                "html-parallel-control-pattern",
                &alternative.path,
                alternative.line,
                "button-like non-button element exists alongside native buttons".to_owned(),
                "high",
                vec![format!("{}:{}", native.path, native.line)],
            )
        })
        .collect()
}

enum DelimiterTransition {
    Advance,
    SkipEscapedByte,
    Matched,
}

struct QuoteAwareDelimiterScan {
    opening: u8,
    closing: u8,
    depth: usize,
    quote: Option<u8>,
}

impl QuoteAwareDelimiterScan {
    fn new(opening: u8, closing: u8) -> Self {
        Self {
            opening,
            closing,
            depth: 0,
            quote: None,
        }
    }

    fn transition(&mut self, byte: u8, has_following_byte: bool) -> DelimiterTransition {
        match self.quote {
            Some(current_quote) => {
                self.transition_within_quote(byte, current_quote, has_following_byte)
            }
            None => self.transition_outside_quote(byte),
        }
    }

    fn transition_within_quote(
        &mut self,
        byte: u8,
        current_quote: u8,
        has_following_byte: bool,
    ) -> DelimiterTransition {
        if byte == b'\\' && has_following_byte {
            return DelimiterTransition::SkipEscapedByte;
        }
        if byte == current_quote {
            self.quote = None;
        }
        DelimiterTransition::Advance
    }

    fn transition_outside_quote(&mut self, byte: u8) -> DelimiterTransition {
        match byte {
            b'"' | b'\'' => self.quote = Some(byte),
            byte if byte == self.opening => self.depth += 1,
            byte if byte == self.closing => {
                self.depth -= 1;
                if self.depth == 0 {
                    return DelimiterTransition::Matched;
                }
            }
            _ => {}
        }
        DelimiterTransition::Advance
    }
}

fn matching_delimiter(source: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut scan = QuoteAwareDelimiterScan::new(opening, closing);
    let mut index = open;
    while index < bytes.len() {
        match scan.transition(bytes[index], index + 1 < bytes.len()) {
            DelimiterTransition::Advance => index += 1,
            DelimiterTransition::SkipEscapedByte => index += 2,
            DelimiterTransition::Matched => return Some(index),
        }
    }
    None
}

fn normalize_dart(source: &str) -> String {
    let uncommented = DART_COMMENT.replace_all(source, "");
    WHITESPACE.replace_all(&uncommented, "").into_owned()
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn first_location(path: &str, source: &str, pattern: &Regex) -> Option<Location> {
    pattern.find(source).map(|found| Location {
        path: path.to_owned(),
        line: line_at(source, found.start()),
    })
}

fn is_dart_ui_source(path: &str) -> bool {
    path.ends_with(".dart") && !is_ui_auxiliary_path(path)
}

fn is_ui_auxiliary_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.ends_with(".g.dart") || UI_AUXILIARY_PATH.is_match(&normalized)
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("UI consistency metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("UI consistency rule severity must be valid"),
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

static CSS_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)([^{}]+)\{([^{}]+)\}").unwrap());
static CSS_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([\w-]+)\s*:\s*([^;{}]+)\s*;").unwrap());
static CSS_COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static CSS_PUNCTUATION_SPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s*([,()/])\s*").unwrap());
static CSS_ZERO_UNIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0(?:px|em|rem|%|s|ms)\b").unwrap());
static CSS_SIX_DIGIT_HEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"#([0-9a-f]{6})\b").unwrap());
static STYLE_CONSTRUCTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(TextStyle|ButtonStyle|BoxDecoration|InputDecoration|ElevatedButton\.styleFrom)\s*\(",
    )
    .unwrap()
});
static NAMED_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\s*:").unwrap());
static DART_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?ms)//.*?$|/\*.*?\*/").unwrap());
static TOKEN_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:static\s+)?const\s+(?:Color\s+)?([A-Za-z_]\w*)\s*=\s*(Color\s*\(\s*0x[0-9A-Fa-f]+\s*\)|Colors\.[A-Za-z_]\w*)\s*;").unwrap()
});
static COLOR_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Color\s*\(\s*0x[0-9A-Fa-f]+\s*\)|Colors\.[A-Za-z_]\w*").unwrap());
static SEMANTIC_BUTTON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:ElevatedButton|FilledButton|TextButton|OutlinedButton|IconButton)\s*\(")
        .unwrap()
});
static POINTER_CONTROL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:GestureDetector|InkWell)\s*\(").unwrap());
static CONTAINER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bContainer\s*\(").unwrap());
static TEXT_WIDGET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bText\s*\(").unwrap());
static WIDGET_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bclass\s+([A-Za-z_]\w*)\s+extends\s+(?:StatelessWidget|StatefulWidget)\b[^{]*\{")
        .unwrap()
});
static FRAMEWORK_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(ElevatedButton|FilledButton|TextButton|OutlinedButton|IconButton|TextField|TextFormField|AlertDialog|Card|Scaffold|Checkbox)\s*\(").unwrap()
});
static NATIVE_BUTTON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<button\b").unwrap());
static ALTERNATIVE_BUTTON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<(?:a|div|span)\b[^>]*(?:role\s*=\s*[\"']button[\"']|on(?:click|keydown)\s*=)[^>]*>"#).unwrap()
});
static UI_AUXILIARY_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(?:test|tests|example|examples|fixture|fixtures|generated)(?:/|$)").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_duplicate_css_declaration_sets() {
        let fixture = Fixture::new([
            (
                "primary.css",
                ".primary {\n  color: #fff;\n  background: #369;\n  padding: 12px 24px;\n  border-radius: 6px;\n}",
            ),
            (
                "confirm.css",
                ".confirm {\n  border-radius: 6px;\n  padding: 12px 24px;\n  background: #369;\n  color: #ffffff;\n}",
            ),
        ]);
        let findings = css_duplicate_declaration_sets(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "css-duplicate-declaration-set");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].related_files.len(), 1);
    }

    #[test]
    fn keeps_standalone_scaffold_templates_in_separate_css_domains() {
        let fixture = Fixture::new([
            (
                "packages/create-app/template-react/src/index.css",
                ":root { --brand: #369; }\n.primary { color: #fff; background: #123; padding: 12px 24px; border-radius: 6px; }",
            ),
            (
                "packages/create-app/template-react-ts/src/index.css",
                ".primary { color: #fff; background: #123; padding: 12px 24px; border-radius: 6px; }\n.accent { color: #369; }",
            ),
        ]);
        let context = fixture.context();

        assert!(css_duplicate_declaration_sets(&context).is_empty());
        assert!(css_design_token_drift(&context).is_empty());
    }

    #[test]
    fn preserves_first_seen_css_signature_group_order() {
        let fixture = Fixture::new([(
            "components.css",
            ".z-source { zeta-a: 1; zeta-b: 2; zeta-c: 3; zeta-d: 4; }\n\
             .z-copy { zeta-d: 4; zeta-c: 3; zeta-b: 2; zeta-a: 1; }\n\
             .a-source { alpha-a: 1; alpha-b: 2; alpha-c: 3; alpha-d: 4; }\n\
             .a-copy { alpha-d: 4; alpha-c: 3; alpha-b: 2; alpha-a: 1; }",
        )]);

        let findings = css_duplicate_declaration_sets(&fixture.context());

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            [
                "`.z-copy` duplicates 4 declarations from `.z-source`",
                "`.a-copy` duplicates 4 declarations from `.a-source`",
            ]
        );
    }

    #[test]
    fn reports_raw_css_values_matching_a_token() {
        let fixture = Fixture::new([
            ("tokens.css", ":root { --color-primary: #336699; }"),
            ("card.css", ".card { color: #369; }"),
        ]);
        let findings = css_design_token_drift(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("--color-primary"));
    }

    #[test]
    fn preserves_css_declaration_order_for_token_drift_findings() {
        let fixture = Fixture::new([
            (
                "tokens.css",
                ":root { --space-wide: 0.75rem; --space-narrow: 0.25rem; }",
            ),
            (
                "button.css",
                ".button { padding-right: 0.75rem; border-radius: 0.25rem; padding-left: 0.75rem; }",
            ),
        ]);

        let findings = css_design_token_drift(&fixture.context());

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            [
                "`padding-right` repeats `0.75rem` instead of `--space-wide`",
                "`border-radius` repeats `0.25rem` instead of `--space-narrow`",
                "`padding-left` repeats `0.75rem` instead of `--space-wide`",
            ]
        );
    }
    #[test]
    fn matches_dart_css_punctuation_normalization() {
        let fixture = Fixture::new([
            (
                "tokens.css",
                ":root { --color-secondary: hsl(240, 6%, 97%); }",
            ),
            (
                "theme.css",
                ".surface { background-color: hsl(240,6%,97%); }",
            ),
        ]);
        let findings = css_design_token_drift(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "`background-color` repeats `hsl$1240$16%$197%$1` instead of `--color-secondary`"
        );
    }

    #[test]
    fn ignores_incomplete_css_without_losing_valid_findings() {
        let fixture = Fixture::new([(
            "components.css",
            ".source { color: #fff; background: #369; padding: 12px; margin: 6px; }\n\
             .copy { margin: 6px; padding: 12px; background: #336699; color: #ffffff; }\n\
             .incomplete { color: #12345;\n\
             /* unterminated comment",
        )]);

        let findings = analyze(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "css-duplicate-declaration-set");
        assert_eq!(findings[0].line, 2);
        assert_eq!(
            findings[0].message,
            "`.copy` duplicates 4 declarations from `.source`"
        );
    }

    #[test]
    fn reports_repeated_substantial_flutter_inline_styles() {
        let style = "TextStyle(\n  color: Colors.white,\n  fontSize: 16,\n  fontWeight: FontWeight.w600,\n)";
        let fixture = Fixture::new([
            ("lib/save.dart", &format!("final saveStyle = {style};")),
            (
                "lib/confirm.dart",
                &format!("final confirmStyle = {style};"),
            ),
        ]);
        let findings = flutter_repeated_inline_styles(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "flutter-repeated-inline-style");
        assert_eq!(findings[0].related_files.len(), 1);
    }

    #[test]
    fn reports_flutter_color_values_bypassing_a_project_token() {
        let fixture = Fixture::new([
            (
                "lib/theme.dart",
                "abstract final class AppColors { static const primary = Color(0xff336699); }",
            ),
            (
                "lib/button.dart",
                "final button = Container(color: const Color(0xff336699));",
            ),
        ]);
        let context = fixture.context();
        let dart_code = dart_code_sources(&context);
        let findings = flutter_theme_bypasses(&dart_code);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("primary"));

        let transparent = Fixture::new([
            (
                "lib/theme.dart",
                "abstract final class AppColors { static const clear = Colors.transparent; }",
            ),
            (
                "lib/button.dart",
                "final ring = isFocused ? Colors.blue : Colors.transparent;",
            ),
        ]);
        let context = transparent.context();
        let dart_code = dart_code_sources(&context);
        assert!(flutter_theme_bypasses(&dart_code).is_empty());
    }

    #[test]
    fn reports_button_like_flutter_pointer_trees_beside_buttons() {
        let fixture = Fixture::new([
            (
                "lib/save.dart",
                "final save = ElevatedButton(onPressed: save, child: Text('Save'));",
            ),
            (
                "lib/confirm.dart",
                "final confirm = GestureDetector(\n  onTap: confirmAction,\n  child: Container(child: Text('Confirm')),\n);",
            ),
        ]);
        let context = fixture.context();
        let dart_code = dart_code_sources(&context);
        let findings = flutter_parallel_controls(&dart_code);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "flutter-parallel-control-component");
        assert_eq!(findings[0].related_files, vec!["lib/save.dart:1"]);
    }

    #[test]
    fn ignores_flutter_controls_and_colors_inside_dart_fixture_strings() {
        let fixture = Fixture::new([(
            "test/ui_rules_test.dart",
            r#"
const themeFixture = '''
abstract final class AppColors { static const primary = Color(0xff336699); }
final button = Container(color: const Color(0xff336699));
''';
const controlFixture = '''
final save = ElevatedButton(onPressed: save, child: Text('Save'));
final confirm = GestureDetector(
  onTap: confirmAction,
  child: Container(child: Text('Confirm')),
);
''';
"#,
        )]);

        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "flutter-theme-bypass" | "flutter-parallel-control-component"
                )
            })
            .collect::<Vec<_>>();

        assert!(findings.is_empty());
    }

    #[test]
    fn reports_direct_controls_bypassing_an_established_widget() {
        let fixture = Fixture::new([
            (
                "lib/app_button.dart",
                "class AppButton extends StatelessWidget {\n  Widget build(BuildContext context) {\n    return ElevatedButton(onPressed: save, child: Text('Save'));\n  }\n}",
            ),
            (
                "lib/profile.dart",
                "final a = AppButton(); final b = AppButton();",
            ),
            ("lib/checkout.dart", "final c = AppButton();"),
            (
                "lib/settings.dart",
                "final submit = ElevatedButton(onPressed: save, child: Text('Submit'));",
            ),
        ]);
        let findings = flutter_shared_component_bypasses(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/settings.dart");
        assert!(findings[0].message.contains("AppButton"));
        assert!(findings[0].message.contains("used 3 times"));
        assert_eq!(findings[0].related_files[0], "lib/app_button.dart:1");
    }

    #[test]
    fn requires_a_shared_widget_to_dominate_direct_controls() {
        let fixture = Fixture::new([
            (
                "lib/search.dart",
                "class SearchField extends StatelessWidget {\n  Widget build(BuildContext context) {\n    return TextFormField(\n      decoration: InputDecoration(\n        suffixIcon: IconButton(onPressed: clear, icon: Icon(Icons.clear)),\n      ),\n    );\n  }\n}",
            ),
            (
                "lib/a.dart",
                "final a = SearchField(); final b = SearchField();",
            ),
            ("lib/b.dart", "final c = SearchField();"),
            (
                "lib/actions.dart",
                "final one = IconButton(onPressed: save, icon: Icon(Icons.save));\nfinal two = IconButton(onPressed: close, icon: Icon(Icons.close));\nfinal three = IconButton(onPressed: add, icon: Icon(Icons.add));",
            ),
        ]);

        assert!(flutter_shared_component_bypasses(&fixture.context()).is_empty());
    }

    #[test]
    fn reports_button_like_html_elements_beside_native_buttons() {
        let fixture = Fixture::new([
            ("save.html", "<button type=\"button\">Save</button>"),
            ("confirm.html", "<a href=\"#\" role=\"button\">Confirm</a>"),
        ]);
        let findings = html_parallel_controls(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "html-parallel-control-pattern");
        assert_eq!(findings[0].related_files, vec!["save.html:1"]);
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
