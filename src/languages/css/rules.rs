use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, original) in sources
        .iter()
        .filter(|(path, _)| path.to_ascii_lowercase().ends_with(".css"))
    {
        analyze_file(path, original, &mut findings);
    }
    findings
}
pub(crate) fn analyze_svelte_styles(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources
        .iter()
        .filter(|(path, _)| path.to_ascii_lowercase().ends_with(".svelte"))
    {
        for capture in SVELTE_STYLE_BLOCK.captures_iter(source) {
            let (Some(attributes), Some(body)) = (capture.get(1), capture.get(2)) else {
                continue;
            };
            if SVELTE_STYLE_LANGUAGE
                .captures(attributes.as_str())
                .and_then(|capture| capture.get(1).or_else(|| capture.get(2)))
                .is_some_and(|language| !language.as_str().eq_ignore_ascii_case("css"))
            {
                continue;
            }
            let css = mask_css_comments(body.as_str());
            let line_offset = source.as_bytes()[..body.start()]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count();
            analyze_structured_css(path, &css, line_offset, &mut findings);
        }
    }
    findings
}

fn analyze_file(path: &str, original: &str, findings: &mut Vec<Finding>) {
    let source = mask_css_comments(original);
    let lower_source = source.to_ascii_lowercase();
    let lines = source.split('\n').collect::<Vec<_>>();
    let saw_reduced_motion = lower_source.contains("prefers-reduced-motion");
    analyze_structured_css(path, &source, 0, findings);
    let mut state = CssBlockState::default();

    for (index, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        let line_number = index + 1;
        analyze_selector(path, line, line_number, &lines, index, &mut state, findings);
        analyze_important(path, &lower, line_number, findings);
        analyze_z_index(path, &lower, line_number, findings);
        analyze_fixed_font(path, &lower, line_number, &mut state, findings);
        analyze_vendor_prefix(path, &lower, &lower_source, line_number, findings);
        analyze_duplicate_property(path, &lower, line_number, &mut state, findings);
        analyze_motion(
            path,
            &lower,
            line_number,
            saw_reduced_motion,
            &mut state,
            findings,
        );
        if line.contains('}') {
            state.in_block = false;
            state.in_tailwind_utility = false;
        }
    }
}

#[derive(Default)]
struct CssBlockState {
    in_block: bool,
    properties: BTreeMap<String, String>,
    previous_property: Option<String>,
    in_tailwind_utility: bool,
    fixed_font_reported: bool,
    motion_reported_in_block: bool,
}

fn analyze_selector(
    path: &str,
    line: &str,
    line_number: usize,
    lines: &[&str],
    index: usize,
    state: &mut CssBlockState,
    findings: &mut Vec<Finding>,
) {
    if !line.contains('{') {
        return;
    }
    state.in_block = true;
    state.properties.clear();
    state.previous_property = None;
    state.motion_reported_in_block = false;
    state.in_tailwind_utility = line.starts_with("@utility ");
    let selector = line.split('{').next().unwrap_or_default().trim();
    if selector.starts_with('@') {
        return;
    }
    if selector_list(selector)
        .into_iter()
        .any(|part| selector_depth(part) > 4)
    {
        findings.push(finding(
            "css-selector-depth",
            path,
            line_number,
            "deep CSS selector",
        ));
    }
    if has_universal_selector_token(selector)
        && !is_universal_box_sizing_reset(selector, lines, index)
    {
        findings.push(finding(
            "css-universal-selector",
            path,
            line_number,
            "universal selector used",
        ));
    }
}

fn analyze_important(path: &str, lower: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if lower.contains("!important") {
        findings.push(finding(
            "css-important",
            path,
            line_number,
            "!important used",
        ));
    }
}

fn analyze_z_index(path: &str, lower: &str, line_number: usize, findings: &mut Vec<Finding>) {
    let excessive = Z_INDEX
        .captures(lower)
        .and_then(|capture| capture.get(1))
        .and_then(|value| value.as_str().parse::<u64>().ok())
        .is_some_and(|value| value > 1000);
    if excessive {
        findings.push(finding(
            "css-high-z-index",
            path,
            line_number,
            "very high z-index",
        ));
    }
}

fn analyze_fixed_font(
    path: &str,
    lower: &str,
    line_number: usize,
    state: &mut CssBlockState,
    findings: &mut Vec<Finding>,
) {
    if !state.fixed_font_reported && FIXED_FONT_PX.is_match(lower) {
        findings.push(finding(
            "css-fixed-font-px",
            path,
            line_number,
            "font size uses px",
        ));
        state.fixed_font_reported = true;
    }
}

fn analyze_vendor_prefix(
    path: &str,
    lower: &str,
    lower_source: &str,
    line_number: usize,
    findings: &mut Vec<Finding>,
) {
    let Some(prefixed) = PREFIXED_PROPERTY.captures(lower) else {
        return;
    };
    let standard = prefixed.get(1).unwrap().as_str();
    if VENDOR_ONLY_PROPERTIES.contains(&standard)
        || standard_property_exists(lower_source, standard)
    {
        return;
    }
    findings.push(finding(
        "css-vendor-prefix-only",
        path,
        line_number,
        "vendor-prefixed property",
    ));
}

fn analyze_duplicate_property(
    path: &str,
    lower: &str,
    line_number: usize,
    state: &mut CssBlockState,
    findings: &mut Vec<Finding>,
) {
    if !state.in_block {
        return;
    }
    let Some(declaration) = DECLARATION.captures(lower) else {
        return;
    };
    let property = declaration.get(1).unwrap().as_str().to_owned();
    let value = declaration.get(2).unwrap().as_str().trim().to_owned();
    if let Some(previous) = state.properties.get(&property)
        && !compatible_duplicate_property(state, &property, previous, &value)
    {
        findings.push(finding(
            "css-duplicate-property",
            path,
            line_number,
            &format!("duplicate CSS property: {property}"),
        ));
    }
    state.properties.insert(property.clone(), value);
    state.previous_property = Some(property);
}

fn compatible_duplicate_property(
    state: &CssBlockState,
    property: &str,
    previous: &str,
    current: &str,
) -> bool {
    state.previous_property.as_deref() == Some(property)
        && (is_compatibility_value_fallback(property, previous, current)
            || state.in_tailwind_utility
                && property.starts_with("--")
                && are_disjoint_tailwind_value_overloads(previous, current))
}

fn analyze_motion(
    path: &str,
    lower: &str,
    line_number: usize,
    saw_reduced_motion: bool,
    state: &mut CssBlockState,
    findings: &mut Vec<Finding>,
) {
    if has_motion_declaration(lower) && !saw_reduced_motion && !state.motion_reported_in_block {
        state.motion_reported_in_block = true;
        findings.push(finding(
            "css-animation-no-reduced-motion",
            path,
            line_number,
            "motion without reduced-motion guard",
        ));
    }
}

#[derive(Clone, Copy)]
enum CssCommentMaskState {
    Code,
    Quoted(u8),
    Comment,
}

struct CssCommentMasker {
    bytes: Vec<u8>,
    state: CssCommentMaskState,
    index: usize,
}

impl CssCommentMasker {
    fn new(source: &str) -> Self {
        Self {
            bytes: source.as_bytes().to_vec(),
            state: CssCommentMaskState::Code,
            index: 0,
        }
    }

    fn mask(mut self) -> String {
        while self.index < self.bytes.len() {
            match self.state {
                CssCommentMaskState::Code => self.consume_code_byte(),
                CssCommentMaskState::Quoted(delimiter) => {
                    self.consume_quoted_byte(delimiter);
                }
                CssCommentMaskState::Comment => self.consume_comment_byte(),
            }
        }

        // The input and ASCII-only replacements preserve UTF-8. If that
        // invariant is ever broken, avoid analyzing corrupted selectors.
        String::from_utf8(self.bytes).unwrap_or_else(|_| String::new())
    }

    fn consume_code_byte(&mut self) {
        match (
            self.bytes[self.index],
            self.bytes.get(self.index + 1).copied(),
        ) {
            (delimiter @ (b'"' | b'\''), _) => {
                self.state = CssCommentMaskState::Quoted(delimiter);
                self.index += 1;
            }
            (b'/', Some(b'*')) => {
                self.mask_comment_delimiter();
                self.state = CssCommentMaskState::Comment;
            }
            _ => self.index += 1,
        }
    }

    fn consume_quoted_byte(&mut self, delimiter: u8) {
        match (
            self.bytes[self.index],
            self.bytes.get(self.index + 1).copied(),
        ) {
            (b'\\', Some(_)) => self.index += 2,
            (byte, _) if byte == delimiter => {
                self.state = CssCommentMaskState::Code;
                self.index += 1;
            }
            _ => self.index += 1,
        }
    }

    fn consume_comment_byte(&mut self) {
        match (
            self.bytes[self.index],
            self.bytes.get(self.index + 1).copied(),
        ) {
            (b'*', Some(b'/')) => {
                self.mask_comment_delimiter();
                self.state = CssCommentMaskState::Code;
            }
            (b'\n', _) => self.index += 1,
            _ => {
                self.bytes[self.index] = b' ';
                self.index += 1;
            }
        }
    }

    fn mask_comment_delimiter(&mut self) {
        self.bytes[self.index..self.index + 2].fill(b' ');
        self.index += 2;
    }
}

fn mask_css_comments(source: &str) -> String {
    CssCommentMasker::new(source).mask()
}
#[derive(Clone, Copy)]
struct CssDeclaration {
    property_start: usize,
    property_end: usize,
    value_start: usize,
    value_end: usize,
    line: usize,
}

struct CssRuleBlock {
    header_start: usize,
    header_end: usize,
    declarations: Vec<CssDeclaration>,
    in_keyframes: bool,
}

#[derive(Clone, Copy)]
enum CssStructureState {
    Code,
    Quoted(u8),
}

struct CssStructureScanner<'a> {
    source: &'a str,
    bytes: &'a [u8],
    index: usize,
    parentheses: usize,
    line: usize,
    statement_start: usize,
    statement_line: usize,
    state: CssStructureState,
    stack: Vec<CssRuleBlock>,
    blocks: Vec<CssRuleBlock>,
}

impl<'a> CssStructureScanner<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            index: 0,
            parentheses: 0,
            line: 1,
            statement_start: 0,
            statement_line: 1,
            state: CssStructureState::Code,
            stack: Vec::new(),
            blocks: Vec::new(),
        }
    }

    fn scan(mut self) -> Vec<CssRuleBlock> {
        while let Some(&byte) = self.bytes.get(self.index) {
            match self.state {
                CssStructureState::Code => self.consume_code(byte),
                CssStructureState::Quoted(delimiter) => self.consume_quoted(byte, delimiter),
            }
            if byte == b'\n' {
                self.line += 1;
            }
            self.index += 1;
        }
        self.blocks
    }

    fn consume_code(&mut self, byte: u8) {
        match byte {
            delimiter @ (b'"' | b'\'') => {
                self.state = CssStructureState::Quoted(delimiter);
            }
            b'(' => self.parentheses += 1,
            b')' => self.parentheses = self.parentheses.saturating_sub(1),
            b'{' if self.parentheses == 0 => self.open_block(),
            b';' if self.parentheses == 0 => self.finish_declaration(),
            b'}' if self.parentheses == 0 => self.close_block(),
            _ => {}
        }
    }

    fn consume_quoted(&mut self, byte: u8, delimiter: u8) {
        if byte == b'\\' {
            self.index += usize::from(self.index + 1 < self.bytes.len());
        } else if byte == delimiter {
            self.state = CssStructureState::Code;
        }
    }

    fn open_block(&mut self) {
        let (header_start, header_end) =
            trim_css_range(self.bytes, self.statement_start, self.index);
        let header = &self.source[header_start..header_end];
        let in_keyframes = self.stack.last().is_some_and(|block| block.in_keyframes)
            || is_keyframes_header(header);
        self.stack.push(CssRuleBlock {
            header_start,
            header_end,
            declarations: Vec::new(),
            in_keyframes,
        });
        self.advance_statement();
    }

    fn finish_declaration(&mut self) {
        self.record_declaration(self.index);
        self.advance_statement();
    }

    fn close_block(&mut self) {
        self.record_declaration(self.index);
        if let Some(block) = self.stack.pop() {
            self.blocks.push(block);
        }
        self.advance_statement();
    }

    fn record_declaration(&mut self, end: usize) {
        let Some(block) = self.stack.last_mut() else {
            return;
        };
        let Some((property_start, property_end, value_start, value_end)) =
            parse_css_declaration(self.bytes, self.statement_start, end)
        else {
            return;
        };
        let line = self.statement_line
            + self.source[self.statement_start..property_start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
        block.declarations.push(CssDeclaration {
            property_start,
            property_end,
            value_start,
            value_end,
            line,
        });
    }

    fn advance_statement(&mut self) {
        self.statement_start = self.index + 1;
        self.statement_line = self.line;
    }
}

fn trim_css_range(bytes: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && is_css_whitespace(bytes[start]) {
        start += 1;
    }
    while end > start && is_css_whitespace(bytes[end - 1]) {
        end -= 1;
    }
    (start, end)
}

fn parse_css_declaration(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Option<(usize, usize, usize, usize)> {
    let (start, end) = trim_css_range(bytes, start, end);
    let colon = bytes[start..end]
        .iter()
        .position(|byte| *byte == b':')
        .map(|offset| start + offset)?;
    let (property_start, property_end) = trim_css_range(bytes, start, colon);
    let (value_start, value_end) = trim_css_range(bytes, colon + 1, end);
    let property = std::str::from_utf8(&bytes[property_start..property_end]).ok()?;
    if property.is_empty()
        || property.starts_with("--")
        || !property
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'-')
    {
        return None;
    }
    Some((property_start, property_end, value_start, value_end))
}

fn is_keyframes_header(header: &str) -> bool {
    let header = header.trim();
    header
        .get(.."@keyframes".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("@keyframes"))
        || header
            .get(.."@-webkit-keyframes".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("@-webkit-keyframes"))
}

fn analyze_structured_css(
    path: &str,
    source: &str,
    line_offset: usize,
    findings: &mut Vec<Finding>,
) {
    let blocks = CssStructureScanner::new(source).scan();
    let focus_indicators = focus_indicator_targets(source, &blocks);
    for block in &blocks {
        analyze_transition_declarations(path, source, block, line_offset, findings);
        analyze_focus_indicator(
            path,
            source,
            block,
            line_offset,
            &focus_indicators,
            findings,
        );
    }
}

fn analyze_transition_declarations(
    path: &str,
    source: &str,
    block: &CssRuleBlock,
    line_offset: usize,
    findings: &mut Vec<Finding>,
) {
    for declaration in &block.declarations {
        let property = &source[declaration.property_start..declaration.property_end];
        let value = &source[declaration.value_start..declaration.value_end];
        if is_transition_property(property) {
            if TRANSITION_ALL_VALUE.is_match(value) {
                findings.push(finding(
                    "css-transition-all",
                    path,
                    declaration.line + line_offset,
                    "transition applies to every property",
                ));
            }
            if let Some(layout_property) = LAYOUT_TRANSITION_PROPERTY
                .captures(value)
                .and_then(|capture| capture.get(1))
            {
                findings.push(finding(
                    "css-layout-property-animation",
                    path,
                    declaration.line + line_offset,
                    &format!(
                        "transition animates layout property: {}",
                        layout_property.as_str()
                    ),
                ));
            }
        } else if block.in_keyframes && is_layout_property(property) {
            findings.push(finding(
                "css-layout-property-animation",
                path,
                declaration.line + line_offset,
                &format!("keyframes animate layout property: {property}"),
            ));
        }
    }
}

fn is_transition_property(property: &str) -> bool {
    property.eq_ignore_ascii_case("transition")
        || property.eq_ignore_ascii_case("transition-property")
        || property.eq_ignore_ascii_case("-webkit-transition")
        || property.eq_ignore_ascii_case("-webkit-transition-property")
}

fn is_layout_property(property: &str) -> bool {
    [
        "width",
        "height",
        "top",
        "right",
        "bottom",
        "left",
        "inset",
        "inset-block",
        "inset-block-start",
        "inset-block-end",
        "inset-inline",
        "inset-inline-start",
        "inset-inline-end",
        "flex-basis",
        "grid-template-columns",
        "grid-template-rows",
    ]
    .iter()
    .any(|candidate| property.eq_ignore_ascii_case(candidate))
}

fn focus_indicator_targets(source: &str, blocks: &[CssRuleBlock]) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for block in blocks {
        if block.in_keyframes
            || !block.declarations.iter().any(|declaration| {
                let property = &source[declaration.property_start..declaration.property_end];
                let value = &source[declaration.value_start..declaration.value_end];
                supplies_focus_indicator(property, value)
            })
        {
            continue;
        }
        let selector = &source[block.header_start..block.header_end];
        targets.extend(focus_targets(selector));
    }
    targets
}

fn analyze_focus_indicator(
    path: &str,
    source: &str,
    block: &CssRuleBlock,
    line_offset: usize,
    focus_indicators: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    if block.in_keyframes {
        return;
    }
    let selector = &source[block.header_start..block.header_end];
    let targets = focus_targets(selector);
    if targets.is_empty() {
        return;
    }
    let suppressed = block.declarations.iter().find(|declaration| {
        let property = &source[declaration.property_start..declaration.property_end];
        let value = &source[declaration.value_start..declaration.value_end];
        suppresses_outline(property, value)
    });
    if let Some(suppressed) = suppressed
        && !targets
            .iter()
            .all(|target| focus_indicators.contains(target))
    {
        findings.push(finding(
            "css-focus-indicator-suppressed",
            path,
            suppressed.line + line_offset,
            "focus indicator is removed without a visible replacement",
        ));
    }
}

fn focus_targets(selector: &str) -> BTreeSet<String> {
    selector_list(selector)
        .into_iter()
        .filter(|part| {
            FOCUS_PSEUDO.is_match(part)
                && !MOUSE_ONLY_FOCUS_SELECTOR.is_match(part)
                && !NON_INTERACTIVE_ANCHOR_FOCUS.is_match(part)
        })
        .map(normalize_focus_target)
        .collect()
}

fn normalize_focus_target(selector: &str) -> String {
    FOCUS_PSEUDO
        .replace_all(selector, "$after")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn suppresses_outline(property: &str, value: &str) -> bool {
    (property.eq_ignore_ascii_case("outline") || property.eq_ignore_ascii_case("outline-style"))
        && OUTLINE_NONE_VALUE.is_match(value)
        || property.eq_ignore_ascii_case("outline-width") && ZERO_CSS_VALUE.is_match(value)
}

fn supplies_focus_indicator(property: &str, value: &str) -> bool {
    if (property.eq_ignore_ascii_case("outline") || property.eq_ignore_ascii_case("outline-style"))
        && !OUTLINE_NONE_VALUE.is_match(value)
        || property.eq_ignore_ascii_case("box-shadow") && !NONE_CSS_VALUE.is_match(value)
    {
        return true;
    }
    (property.eq_ignore_ascii_case("background")
        || property.eq_ignore_ascii_case("background-color")
        || property.eq_ignore_ascii_case("border")
        || property
            .get(.."border-".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("border-")))
        && !INVISIBLE_FOCUS_VALUE.is_match(value)
}

fn is_universal_box_sizing_reset(selector: &str, lines: &[&str], start: usize) -> bool {
    if selector.trim() != "*" {
        return false;
    }
    let mut declarations = Vec::new();
    for raw in lines.iter().skip(start + 1) {
        let line = raw.trim();
        if line.contains('}') {
            break;
        }
        if !line.is_empty() {
            declarations.push(line);
        }
    }
    !declarations.is_empty()
        && declarations
            .into_iter()
            .all(|line| BOX_SIZING_RESET.is_match(line))
}

#[derive(Clone, Copy)]
enum UniversalSelectorLexicalState {
    Selector,
    Quoted(u8),
}

struct UniversalSelectorScanner<'a> {
    bytes: &'a [u8],
    index: usize,
    brackets: usize,
    state: UniversalSelectorLexicalState,
}

impl<'a> UniversalSelectorScanner<'a> {
    fn new(selector: &'a str) -> Self {
        Self {
            bytes: selector.as_bytes(),
            index: 0,
            brackets: 0,
            state: UniversalSelectorLexicalState::Selector,
        }
    }

    fn consume_selector_byte(&mut self, byte: u8) -> bool {
        match byte {
            delimiter @ (b'"' | b'\'') => {
                self.state = UniversalSelectorLexicalState::Quoted(delimiter);
            }
            b'[' => self.brackets += 1,
            b']' => self.brackets = self.brackets.saturating_sub(1),
            b'*' => return self.brackets == 0,
            _ => {}
        }
        false
    }

    fn consume_quoted_byte(&mut self, byte: u8, delimiter: u8) {
        if byte == b'\\' && self.index < self.bytes.len() {
            self.index += 1;
        } else if byte == delimiter {
            self.state = UniversalSelectorLexicalState::Selector;
        }
    }
}

impl Iterator for UniversalSelectorScanner<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&byte) = self.bytes.get(self.index) {
            let index = self.index;
            self.index += 1;
            match self.state {
                UniversalSelectorLexicalState::Selector => {
                    if self.consume_selector_byte(byte) {
                        return Some(index);
                    }
                }
                UniversalSelectorLexicalState::Quoted(delimiter) => {
                    self.consume_quoted_byte(byte, delimiter);
                }
            }
        }
        None
    }
}

fn qualifies_as_universal_selector(bytes: &[u8], index: usize) -> bool {
    index == 0
        || matches!(
            bytes[index - 1],
            b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'+' | b'~' | b',' | b'(' | b'|'
        )
}

fn has_universal_selector_token(selector: &str) -> bool {
    let bytes = selector.as_bytes();
    UniversalSelectorScanner::new(selector)
        .any(|index| qualifies_as_universal_selector(bytes, index))
}

fn selector_list(selector: &str) -> Vec<&str> {
    let bytes = selector.as_bytes();
    let mut parentheses = 0usize;
    let mut brackets = 0usize;
    let mut start = 0usize;
    let mut result = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' => parentheses += 1,
            b')' => parentheses = parentheses.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b',' if parentheses == 0 && brackets == 0 => {
                result.push(selector[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    result.push(selector[start..].trim());
    result
}

#[derive(Clone, Copy)]
enum SelectorDepthToken {
    ExplicitCombinator,
    Whitespace {
        preceding: Option<u8>,
        following: Option<u8>,
    },
}

impl SelectorDepthToken {
    fn increases_depth(self) -> bool {
        match self {
            Self::ExplicitCombinator => true,
            Self::Whitespace {
                preceding,
                following,
            } => {
                preceding.is_some_and(is_compound_selector_edge)
                    && following.is_some_and(is_compound_selector_edge)
            }
        }
    }
}

fn is_compound_selector_edge(byte: u8) -> bool {
    !is_css_combinator(byte) && byte != b','
}

struct SelectorDepthScanner<'a> {
    bytes: &'a [u8],
    index: usize,
    parentheses: usize,
    brackets: usize,
}

impl<'a> SelectorDepthScanner<'a> {
    fn new(selector: &'a str) -> Self {
        Self {
            bytes: selector.as_bytes(),
            index: 0,
            parentheses: 0,
            brackets: 0,
        }
    }

    fn consume_nested_byte(&mut self, byte: u8) -> bool {
        if self.brackets > 0 {
            if byte == b']' {
                self.brackets -= 1;
            }
            return true;
        }
        if self.parentheses > 0 {
            match byte {
                b'(' => self.parentheses += 1,
                b')' => self.parentheses -= 1,
                b'[' => self.brackets += 1,
                _ => {}
            }
            return true;
        }
        match byte {
            b'(' => self.parentheses += 1,
            b'[' => self.brackets += 1,
            _ => return false,
        }
        true
    }

    fn consume_whitespace(&mut self, start: usize) -> SelectorDepthToken {
        while self
            .bytes
            .get(self.index)
            .is_some_and(|byte| is_css_whitespace(*byte))
        {
            self.index += 1;
        }
        SelectorDepthToken::Whitespace {
            preceding: start.checked_sub(1).map(|index| self.bytes[index]),
            following: self.bytes.get(self.index).copied(),
        }
    }
}

impl Iterator for SelectorDepthScanner<'_> {
    type Item = SelectorDepthToken;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&byte) = self.bytes.get(self.index) {
            let index = self.index;
            self.index += 1;
            if self.consume_nested_byte(byte) {
                continue;
            }
            if is_css_combinator(byte) {
                return Some(SelectorDepthToken::ExplicitCombinator);
            }
            if is_css_whitespace(byte) {
                return Some(self.consume_whitespace(index));
            }
        }
        None
    }
}

fn selector_depth(selector: &str) -> usize {
    SelectorDepthScanner::new(selector)
        .filter(|token| token.increases_depth())
        .count()
}

fn is_css_whitespace(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_css_combinator(byte: u8) -> bool {
    matches!(byte, b'+' | b'>' | b'~')
}

fn standard_property_exists(source: &str, property: &str) -> bool {
    Regex::new(&format!(r"(?:^|[;{{])\s*{}\s*:", regex::escape(property)))
        .unwrap()
        .is_match(source)
}

fn is_compatibility_value_fallback(property: &str, previous: &str, current: &str) -> bool {
    previous != current
        && (is_standard_to_vendor_value_fallback(previous, current)
            || is_logical_text_align_fallback(property, previous, current)
            || is_equivalent_alpha_color_fallback(previous, current)
            || (["''", "\"\""].contains(&previous) && current == "none"))
}

fn are_disjoint_tailwind_value_overloads(previous: &str, current: &str) -> bool {
    fn signatures(value: &str) -> Option<BTreeSet<&str>> {
        let capture = TAILWIND_VALUE.captures(value)?;
        Some(
            capture
                .get(1)?
                .as_str()
                .split(',')
                .map(str::trim)
                .filter(|signature| !signature.is_empty())
                .collect(),
        )
    }
    let Some(previous) = signatures(previous) else {
        return false;
    };
    let Some(current) = signatures(current) else {
        return false;
    };
    previous.is_disjoint(&current)
}

fn is_logical_text_align_fallback(property: &str, previous: &str, current: &str) -> bool {
    property == "text-align"
        && ["left", "right"].contains(&previous)
        && ["start", "end"].contains(&current)
}

fn is_standard_to_vendor_value_fallback(previous: &str, current: &str) -> bool {
    has_vendor_compatibility_value(previous) != has_vendor_compatibility_value(current)
}

fn has_vendor_compatibility_value(value: &str) -> bool {
    VENDOR_VALUE.is_match(value) || MICROSOFT_GRADIENT.is_match(value)
}

fn is_equivalent_alpha_color_fallback(previous: &str, current: &str) -> bool {
    let Some(hex) = HEX_COLOR.captures(previous) else {
        return false;
    };
    let Some(rgba) = RGBA_COLOR.captures(current) else {
        return false;
    };
    let (Some(digits), Some(rgba_red), Some(rgba_green), Some(rgba_blue)) =
        (hex.get(1), rgba.get(1), rgba.get(2), rgba.get(3))
    else {
        return false;
    };
    let digits = digits.as_str();
    let Ok(color) = u32::from_str_radix(digits, 16) else {
        return false;
    };
    let (red, green, blue) = if digits.len() == 3 {
        (
            ((color >> 8) & 0xf) * 17,
            ((color >> 4) & 0xf) * 17,
            (color & 0xf) * 17,
        )
    } else {
        ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff)
    };
    let (Ok(rgba_red), Ok(rgba_green), Ok(rgba_blue)) = (
        rgba_red.as_str().parse::<u32>(),
        rgba_green.as_str().parse::<u32>(),
        rgba_blue.as_str().parse::<u32>(),
    ) else {
        return false;
    };
    red == rgba_red && green == rgba_green && blue == rgba_blue
}

fn has_motion_declaration(line: &str) -> bool {
    let Some(declaration) = MOTION_DECLARATION.captures(line) else {
        return false;
    };
    let property = declaration.get(1).unwrap().as_str();
    let Some(value) = declaration.get(2).map(|value| value.as_str().trim()) else {
        return false;
    };
    if [
        "none",
        "initial",
        "inherit",
        "unset",
        "revert",
        "revert-layer",
    ]
    .contains(&value)
    {
        return false;
    }
    if property == "transition" && changes_only_non_motion_properties(value) {
        return false;
    }
    if value.contains("var(") || value.contains("calc(") {
        return true;
    }
    MOTION_DURATION.captures_iter(value).any(|capture| {
        capture
            .get(1)
            .and_then(|duration| duration.as_str().parse::<f64>().ok())
            .is_some_and(|duration| duration > 0.0)
    })
}

fn changes_only_non_motion_properties(value: &str) -> bool {
    value.split(',').all(|transition| {
        transition
            .split_ascii_whitespace()
            .next()
            .is_some_and(|property| NON_MOTION_TRANSITION_PROPERTIES.contains(&property))
    })
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("CSS rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const VENDOR_ONLY_PROPERTIES: [&str; 9] = [
    "box-orient",
    "font-smoothing",
    "osx-font-smoothing",
    "overflow-scrolling",
    "overflow-style",
    "tap-highlight-color",
    "text-fill-color",
    "text-stroke",
    "touch-callout",
];
const NON_MOTION_TRANSITION_PROPERTIES: &[&str] = &[
    "background-color",
    "border-bottom-color",
    "border-color",
    "border-left-color",
    "border-right-color",
    "border-top-color",
    "box-shadow",
    "color",
    "column-rule-color",
    "opacity",
    "outline-color",
    "text-decoration-color",
    "text-shadow",
];

static BOX_SIZING_RESET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:-webkit-|-moz-)?box-sizing\s*:\s*border-box\s*;$").unwrap()
});
static Z_INDEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"z-index\s*:\s*(\d+)").unwrap());
static FIXED_FONT_PX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"font-size\s*:[^;]*\dpx").unwrap());
static PREFIXED_PROPERTY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-(?:webkit|moz|ms|o)-([a-z-]+)\s*:").unwrap());
static DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([a-z-]+)\s*:\s*([^;}]+)").unwrap());
static TAILWIND_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"--value\(([^)]+)\)").unwrap());
static VENDOR_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-(?:webkit|moz|ms|o)-").unwrap());
static MICROSOFT_GRADIENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"progid\s*:\s*dximagetransform\.microsoft\.gradient\s*\(").unwrap()
});
static HEX_COLOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#([0-9a-f]{3}|[0-9a-f]{6})$").unwrap());
static RGBA_COLOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^rgba\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,").unwrap()
});
static MOTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:-(?:webkit|moz|ms|o)-)?(animation|transition)\s*:\s*([^;}]+)").unwrap()
});
static MOTION_DURATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d*\.?\d+)(?:ms|s)\b").unwrap());
static TRANSITION_ALL_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[\s,])all(?:$|[\s,])").unwrap());
static LAYOUT_TRANSITION_PROPERTY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[^a-z0-9_-])(width|height|top|right|bottom|left|inset(?:-(?:block|inline)(?:-(?:start|end))?)?|flex-basis|grid-template-(?:columns|rows))(?:$|[^a-z0-9_-])",
    )
    .unwrap()
});
static FOCUS_PSEUDO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i):focus(?:-visible)?(?P<after>[^a-z0-9_-]|$)").unwrap());
static MOUSE_ONLY_FOCUS_SELECTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i):focus\s*:\s*not\(\s*:focus-visible\s*\)").unwrap());
static NON_INTERACTIVE_ANCHOR_FOCUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s>+~,])a\s*:not\(\s*\[\s*href\s*\]\s*\).*:focus").unwrap()
});
static OUTLINE_NONE_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:none|0(?:[a-z%]+)?(?:\s+[^!]+)?)(?:\s*!important)?\s*$").unwrap()
});
static ZERO_CSS_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*0(?:[a-z%]+)?(?:\s*!important)?\s*$").unwrap());
static NONE_CSS_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(?:none|initial|unset)(?:\s*!important)?\s*$").unwrap());
static INVISIBLE_FOCUS_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^\s*(?:none|transparent|initial|inherit|unset|revert|0(?:[a-z%]+)?)(?:\s*!important)?\s*$",
    )
    .unwrap()
});
static SVELTE_STYLE_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<style\b([^>]*)>(.*?)</style\s*>").unwrap());
static SVELTE_STYLE_LANGUAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\blang\s*=\s*(?:"([^"]+)"|'([^']+)')"#).unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(source: &str) -> Vec<Finding> {
        analyze(&BTreeMap::from([(
            "style.css".to_owned(),
            source.to_owned(),
        )]))
    }

    #[test]
    fn reports_complete_css_source_rule_family() {
        let source = r#"* .a .b .c .d > span {
  color: red;
  color: blue !important;
  font-size: 12px;
  z-index: 9999;
  animation: pulse 1s;
  -webkit-transform: scale(1);
}"#;
        assert_eq!(
            findings(source)
                .into_iter()
                .map(|finding| finding.code)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "css-animation-no-reduced-motion".to_owned(),
                "css-duplicate-property".to_owned(),
                "css-fixed-font-px".to_owned(),
                "css-high-z-index".to_owned(),
                "css-important".to_owned(),
                "css-selector-depth".to_owned(),
                "css-universal-selector".to_owned(),
                "css-vendor-prefix-only".to_owned(),
            ])
        );
    }

    #[test]
    fn groups_fixed_pixel_font_evidence_per_file() {
        let selected = findings(
            ".title { font-size: 18px; }\n.subtitle { font-size: 14px; }\nbody { font-size: 1rem; }",
        )
        .into_iter()
        .filter(|finding| finding.code == "css-fixed-font-px")
        .collect::<Vec<_>>();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].line, 1);
    }

    #[test]
    fn accepts_compatibility_accessibility_and_reset_contracts() {
        let source = r#"* {
  box-sizing: border-box;
}
.item {
  display: -webkit-flex;
  display: flex;
  transition: none;
  -webkit-transform: scale(1);
  transform: scale(1);
}
@media (prefers-reduced-motion: reduce) {
  .item { animation: pulse 1s; }
}"#;
        let codes = findings(source)
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();
        assert!(!codes.contains("css-universal-selector"));
        assert!(!codes.contains("css-duplicate-property"));
        assert!(!codes.contains("css-animation-no-reduced-motion"));
        assert!(!codes.contains("css-vendor-prefix-only"));
    }

    #[test]
    fn ignores_cosmetic_transitions_but_reports_spatial_motion() {
        let source = r#".button {
  transition: border-color 0.3s, box-shadow 0.3s;
}
.panel {
  transition: transform 0.3s;
}"#;
        let motion = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "css-animation-no-reduced-motion")
            .collect::<Vec<_>>();

        assert_eq!(motion.len(), 1);
        assert_eq!(motion[0].line, 5);
    }

    #[test]
    fn groups_vendor_and_standard_motion_declarations_per_block() {
        let source = r#".cursor {
  -webkit-animation: blink 1s infinite;
  animation: blink 1s infinite;
}
.panel {
  transition: transform 0.3s;
}"#;
        let motion = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "css-animation-no-reduced-motion")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();

        assert_eq!(motion, [2, 6]);
    }

    #[test]
    fn reports_explicit_and_layout_transitions_and_suppressed_focus() {
        let source = r#".button:focus-visible {
  outline:
    none;
  transition:
    all 200ms ease;
}
.panel {
  transition-property:
    width,
    opacity;
}
@keyframes expand {
  from { height: 0; }
  to { height: 10rem; }
}"#;
        let found = findings(source);
        let lines = |code: &str| {
            found
                .iter()
                .filter(|finding| finding.code == code)
                .map(|finding| finding.line)
                .collect::<Vec<_>>()
        };

        assert_eq!(lines("css-transition-all"), vec![4]);
        assert_eq!(lines("css-layout-property-animation"), vec![8, 13, 14]);
        assert_eq!(lines("css-focus-indicator-suppressed"), vec![2]);
    }

    #[test]
    fn accepts_composited_motion_and_visible_focus_contracts() {
        let source = r#".button:focus {
  outline: none;
}
.button:focus-visible {
  outline: 2px solid currentColor;
}
.link:focus-visible {
  outline: 0;
  box-shadow: 0 0 0 3px currentColor;
}
.summary:focus {
  box-shadow: 0 0 0 3px currentColor;
}
.summary:focus-visible {
  outline: none;
}
.close:hover,
.close:focus-visible {
  outline: none;
  border-color: currentColor;
}
.menu:hover,
.menu:focus-visible {
  outline: none;
  background-color: CanvasText;
}
.mouse-only:focus:not(:focus-visible) {
  outline: none;
}
a:not([href]):focus {
  outline: none;
}
.panel {
  transition: transform 200ms ease, opacity 200ms ease;
}
@keyframes enter {
  from { transform: translateY(1rem); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}"#;
        let codes = findings(source)
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();

        assert!(!codes.contains("css-transition-all"));
        assert!(!codes.contains("css-layout-property-animation"));
        assert!(!codes.contains("css-focus-indicator-suppressed"));
    }

    #[test]
    fn analyzes_plain_css_inside_svelte_style_blocks() {
        let source = r#"<script>
  const example = "transition: all 1s";
</script>
<style>
  .panel { transition: all 200ms; }
  @keyframes grow { to { height: 10rem; } }
</style>
<style lang="scss">
  .ignored { transition: all 1s; }
</style>"#;
        let found = analyze_svelte_styles(&BTreeMap::from([(
            "Component.svelte".to_owned(),
            source.to_owned(),
        )]));
        let evidence = found
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<Vec<_>>();

        assert_eq!(
            evidence,
            vec![
                ("css-transition-all".to_owned(), 5),
                ("css-layout-property-animation".to_owned(), 6),
            ]
        );
    }

    #[test]
    fn ignores_new_css_rule_text_inside_comments_and_strings() {
        let source = r#"/* .fake:focus-visible { outline: none; transition: all 1s; } */
.real::before {
  content: ".fake { transition: width 1s; }";
}"#;
        let codes = findings(source)
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();

        assert!(!codes.contains("css-transition-all"));
        assert!(!codes.contains("css-layout-property-animation"));
        assert!(!codes.contains("css-focus-indicator-suppressed"));
    }

    #[test]
    fn masks_comments_without_masking_comment_tokens_in_strings() {
        let source = r#"/* .fake { color: red !important; } */
.real::before {
  content: "/* !important */";
}"#;
        let important = findings(source)
            .into_iter()
            .filter(|finding| finding.code == "css-important")
            .collect::<Vec<_>>();
        assert_eq!(important.len(), 1);
        assert_eq!(important[0].line, 3);
    }

    #[test]
    fn handles_valid_and_malformed_alpha_color_fallbacks() {
        assert!(is_equivalent_alpha_color_fallback(
            "#fff",
            "rgba(255, 255, 255, 0.5)"
        ));
        assert!(is_equivalent_alpha_color_fallback(
            "#123456",
            "rgba(18, 52, 86, 0.25)"
        ));
        assert!(!is_equivalent_alpha_color_fallback(
            "#12xz56",
            "rgba(18, 52, 86, 0.25)"
        ));
        assert!(!is_equivalent_alpha_color_fallback(
            "#123456",
            "rgba(18, nope, 86, 0.25)"
        ));
    }

    #[test]
    fn ignores_malformed_motion_duration_values() {
        assert!(!has_motion_declaration("animation: pulse .s"));
        assert!(!has_motion_declaration("transition: opacity ms"));
    }
}
