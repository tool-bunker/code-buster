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

fn analyze_file(path: &str, original: &str, findings: &mut Vec<Finding>) {
    let source = mask_css_comments(original);
    let lower_source = source.to_ascii_lowercase();
    let lines = source.split('\n').collect::<Vec<_>>();
    let saw_reduced_motion = lower_source.contains("prefers-reduced-motion");
    let mut state = CssBlockState::default();

    for (index, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        let line_number = index + 1;
        analyze_selector(path, line, line_number, &lines, index, &mut state, findings);
        analyze_important(path, &lower, line_number, findings);
        analyze_z_index(path, &lower, line_number, findings);
        analyze_fixed_font(path, &lower, line_number, findings);
        analyze_vendor_prefix(path, &lower, &lower_source, line_number, findings);
        analyze_duplicate_property(path, &lower, line_number, &mut state, findings);
        analyze_motion(path, &lower, line_number, saw_reduced_motion, findings);
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

fn analyze_fixed_font(path: &str, lower: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if FIXED_FONT_PX.is_match(lower) {
        findings.push(finding(
            "css-fixed-font-px",
            path,
            line_number,
            "font size uses px",
        ));
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
    findings: &mut Vec<Finding>,
) {
    if has_motion_declaration(lower) && !saw_reduced_motion {
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
    let Some(value) = declaration.get(1).map(|value| value.as_str().trim()) else {
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
    Regex::new(r"^(?:-(?:webkit|moz|ms|o)-)?(?:animation|transition)\s*:\s*([^;}]+)").unwrap()
});
static MOTION_DURATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d*\.?\d+)(?:ms|s)\b").unwrap());

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
