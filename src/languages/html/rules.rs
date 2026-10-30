use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources.iter().filter(|(path, _)| is_markup_path(path)) {
        analyze_file(path, source, &mut findings);
    }
    findings
}

fn is_markup_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.ends_with(".html") || path.ends_with(".htm") || path.ends_with(".svelte")
}

fn analyze_file(path: &str, source: &str, findings: &mut Vec<Finding>) {
    let markup = mask_html_comments(source);
    let semantic_markup = mask_html_raw_text(&markup);
    let is_svelte = path.to_ascii_lowercase().ends_with(".svelte");
    analyze_media_accessibility(path, &semantic_markup, is_svelte, findings);
    let lines = source.split('\n').collect::<Vec<_>>();
    let masked_lines = markup.split('\n').collect::<Vec<_>>();
    let input_label_lines = inputs_without_label(&markup);

    {
        let mut analyzer = HtmlLineAnalyzer {
            path,
            is_svelte,
            inline_scripts: executable_inline_script_lines(&markup),
            blank_targets: blank_targets_without_rel(&markup),
            images_without_alt: start_tags_without_attribute(&markup, &IMG_TAG, &HAS_ALT),
            inputs_without_label: input_label_lines,
            forms_without_method: forms_without_native_method(&markup),
            template_conditions: template_conditions(&lines),
            ids: BTreeMap::new(),
            findings,
        };
        for (index, raw) in lines.iter().enumerate() {
            analyzer.analyze_line(index, raw, masked_lines[index]);
        }
    }

    report_document_findings(path, source, &markup, findings);
}

struct HtmlLineAnalyzer<'a> {
    path: &'a str,
    is_svelte: bool,
    inline_scripts: BTreeSet<usize>,
    blank_targets: BTreeSet<usize>,
    images_without_alt: BTreeSet<usize>,
    inputs_without_label: BTreeSet<usize>,
    forms_without_method: BTreeSet<usize>,
    template_conditions: Vec<BTreeSet<String>>,
    ids: BTreeMap<String, Vec<BTreeSet<String>>>,
    findings: &'a mut Vec<Finding>,
}

impl HtmlLineAnalyzer<'_> {
    fn analyze_line(&mut self, index: usize, raw: &str, masked: &str) {
        let lower = raw.trim().to_ascii_lowercase();
        let active_lower = masked.trim().to_ascii_lowercase();
        let line = index + 1;

        self.report_inline_script(line);
        self.report_inline_event(line, &lower);
        self.report_blank_target(line);
        self.report_missing_alt(line);
        self.report_insecure_resource(line, &active_lower);
        self.track_id(index, line, masked);
        self.report_missing_input_label(line);
        self.report_missing_form_method(line);
    }

    fn report_inline_script(&mut self, line: usize) {
        if !self.is_svelte && self.inline_scripts.contains(&line) {
            self.findings.push(finding(
                "html-inline-script",
                self.path,
                line,
                "inline script block",
            ));
        }
    }

    fn report_inline_event(&mut self, line: usize, lower: &str) {
        if !self.is_svelte && INLINE_EVENT.is_match(lower) {
            self.findings.push(finding(
                "html-inline-event",
                self.path,
                line,
                "inline event handler",
            ));
        }
    }

    fn report_blank_target(&mut self, line: usize) {
        if self.blank_targets.contains(&line) {
            self.findings.push(finding(
                "html-blank-no-rel",
                self.path,
                line,
                "target blank link lacks rel",
            ));
        }
    }

    fn report_missing_alt(&mut self, line: usize) {
        if self.images_without_alt.contains(&line) {
            self.findings.push(finding(
                "html-img-alt",
                self.path,
                line,
                "image missing alt text",
            ));
        }
    }

    fn report_insecure_resource(&mut self, line: usize, active_lower: &str) {
        if has_insecure_http_resource(active_lower) {
            self.findings.push(finding(
                "html-http-resource",
                self.path,
                line,
                "insecure HTTP resource",
            ));
        }
    }

    fn track_id(&mut self, index: usize, line: usize, masked: &str) {
        let id = attribute(masked, "id");
        if id.is_empty() {
            return;
        }

        let previous = self.ids.entry(id.to_owned()).or_default();
        if previous
            .iter()
            .any(|conditions| !mutually_exclusive(conditions, &self.template_conditions[index]))
        {
            self.findings.push(finding(
                "html-duplicate-id",
                self.path,
                line,
                &format!("duplicate id attribute: {id}"),
            ));
        }
        previous.push(self.template_conditions[index].clone());
    }

    fn report_missing_input_label(&mut self, line: usize) {
        if self.inputs_without_label.contains(&line) {
            self.findings.push(finding(
                "html-input-label",
                self.path,
                line,
                "input lacks obvious label",
            ));
        }
    }

    fn report_missing_form_method(&mut self, line: usize) {
        if self.forms_without_method.contains(&line) {
            self.findings.push(finding(
                "html-form-method",
                self.path,
                line,
                "form has no explicit method",
            ));
        }
    }
}

fn report_document_findings(path: &str, source: &str, markup: &str, findings: &mut Vec<Finding>) {
    let document = markup.to_ascii_lowercase();
    let is_document = HTML_START.is_match(markup);
    let has_templated_head = has_markup_template_in_head(source);
    let has_templated_title = has_templated_head || has_jekyll_seo_tag_in_head(source);
    let has_lang = HTML_WITH_LANG.is_match(markup);
    let has_viewport = has_start_tag_with_attribute_value(markup, &META_TAG, "name", "viewport");
    let has_title = TITLE_CONTENT.is_match(&document);

    if is_document && !has_lang {
        findings.push(finding(
            "html-missing-lang",
            path,
            1,
            "html document missing lang",
        ));
    }
    if is_document && !has_viewport && !has_templated_head {
        findings.push(finding(
            "html-missing-viewport",
            path,
            1,
            "missing viewport meta",
        ));
    }
    if is_document && !has_title && !has_templated_title {
        findings.push(finding(
            "html-missing-title",
            path,
            1,
            "document missing title",
        ));
    }
}

fn mask_html_comments(source: &str) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for comment in HTML_COMMENT.find_iter(source) {
        for byte in &mut bytes[comment.start()..comment.end()] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("masked HTML must remain UTF-8")
}
fn mask_html_raw_text(source: &str) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for capture in RAW_TEXT_ELEMENT.captures_iter(source) {
        let Some(content) = capture.get(1) else {
            continue;
        };
        for byte in &mut bytes[content.start()..content.end()] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("masked HTML raw text must remain UTF-8")
}

struct MarkupTag<'a> {
    raw: &'a str,
    name: &'a str,
    start: usize,
    end: usize,
    closing: bool,
    self_closing: bool,
}

struct MarkupTagScanner<'a> {
    source: &'a str,
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> MarkupTagScanner<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            cursor: 0,
        }
    }

    fn tag_end(&self, mut index: usize) -> Option<usize> {
        let mut braces = 0usize;
        let mut quoted = None;
        while let Some(&byte) = self.bytes.get(index) {
            if let Some(delimiter) = quoted {
                if byte == b'\\' {
                    index += usize::from(index + 1 < self.bytes.len());
                } else if byte == delimiter {
                    quoted = None;
                }
            } else {
                match byte {
                    delimiter @ (b'"' | b'\'' | b'`') => quoted = Some(delimiter),
                    b'{' => braces += 1,
                    b'}' => braces = braces.saturating_sub(1),
                    b'>' if braces == 0 => return Some(index + 1),
                    _ => {}
                }
            }
            index += 1;
        }
        None
    }
}

impl<'a> Iterator for MarkupTagScanner<'a> {
    type Item = MarkupTag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(relative) = self.bytes[self.cursor..]
            .iter()
            .position(|byte| *byte == b'<')
        {
            let start = self.cursor + relative;
            let mut index = start + 1;
            let closing = self.bytes.get(index) == Some(&b'/');
            index += usize::from(closing);
            let name_start = index;
            if !self.bytes.get(index).is_some_and(u8::is_ascii_alphabetic) {
                self.cursor = index.saturating_add(1);
                continue;
            }
            while self
                .bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':'))
            {
                index += 1;
            }
            let name_end = index;
            let Some(end) = self.tag_end(index) else {
                self.cursor = index;
                continue;
            };
            self.cursor = end;
            let self_closing = self.bytes[start..end - 1]
                .iter()
                .rev()
                .find(|byte| !byte.is_ascii_whitespace())
                == Some(&b'/');
            return Some(MarkupTag {
                raw: &self.source[start..end],
                name: &self.source[name_start..name_end],
                start,
                end,
                closing,
                self_closing,
            });
        }
        None
    }
}

fn analyze_media_accessibility(
    path: &str,
    source: &str,
    is_svelte: bool,
    findings: &mut Vec<Finding>,
) {
    let mut stack = Vec::<HtmlAncestor<'_>>::new();
    for tag in MarkupTagScanner::new(source) {
        if tag.closing {
            close_ancestor(&mut stack, tag.name, is_svelte);
            continue;
        }
        analyze_open_media_tag(path, source, is_svelte, &tag, &stack, findings);
        if !tag.self_closing && !is_void_html_element(tag.name) {
            stack.push(HtmlAncestor {
                name: tag.name,
                accessible_context: has_accessible_context(tag.raw, tag.name, is_svelte),
            });
        }
    }
}

fn close_ancestor<'a>(stack: &mut Vec<HtmlAncestor<'a>>, closing_name: &str, is_svelte: bool) {
    if let Some(index) = stack
        .iter()
        .rposition(|ancestor| same_markup_name(ancestor.name, closing_name, is_svelte))
    {
        stack.truncate(index);
    }
}

fn analyze_open_media_tag(
    path: &str,
    source: &str,
    is_svelte: bool,
    tag: &MarkupTag<'_>,
    ancestors: &[HtmlAncestor<'_>],
    findings: &mut Vec<Finding>,
) {
    let line = line_at(source, tag.start);
    if is_native_markup_tag(tag.name, "video", is_svelte)
        && AUTOPLAY_ATTRIBUTE.is_match(tag.raw)
        && !MUTED_ATTRIBUTE.is_match(tag.raw)
    {
        findings.push(finding(
            "html-video-autoplay-unmuted",
            path,
            line,
            "autoplay video is not muted",
        ));
    }
    if (is_native_markup_tag(tag.name, "svg", is_svelte)
        || is_native_markup_tag(tag.name, "canvas", is_svelte))
        && !graphic_is_accessible(
            source,
            tag.end,
            tag.name,
            tag.raw,
            tag.self_closing,
            is_svelte,
            ancestors,
        )
    {
        findings.push(finding(
            "html-graphic-accessibility-name",
            path,
            line,
            &format!("<{}> has no accessible name or decorative role", tag.name),
        ));
    }
}

fn is_native_markup_tag(name: &str, expected: &str, is_svelte: bool) -> bool {
    if is_svelte {
        name == expected
    } else {
        name.eq_ignore_ascii_case(expected)
    }
}

fn same_markup_name(left: &str, right: &str, is_svelte: bool) -> bool {
    if is_svelte {
        left == right
    } else {
        left.eq_ignore_ascii_case(right)
    }
}

struct HtmlAncestor<'a> {
    name: &'a str,
    accessible_context: bool,
}

fn graphic_is_accessible(
    source: &str,
    end: usize,
    name: &str,
    tag: &str,
    self_closing: bool,
    is_svelte: bool,
    ancestors: &[HtmlAncestor<'_>],
) -> bool {
    is_explicitly_hidden(tag)
        || has_accessible_name(tag)
        || has_decorative_role(tag)
        || is_svelte && SVELTE_SPREAD_ATTRIBUTE.is_match(tag)
        || ancestors.iter().any(|ancestor| ancestor.accessible_context)
        || !self_closing && graphic_has_fallback(source, end, name)
}

fn has_accessible_context(tag: &str, name: &str, is_svelte: bool) -> bool {
    is_explicitly_hidden(tag)
        || has_accessible_name(tag)
        || (!attribute(tag, "title").trim().is_empty()
            && (["a", "button"]
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
                || is_svelte && name.as_bytes().first().is_some_and(u8::is_ascii_uppercase)))
}

fn is_explicitly_hidden(tag: &str) -> bool {
    attribute(tag, "aria-hidden").eq_ignore_ascii_case("true")
        || HIDDEN_ATTRIBUTE.is_match(tag)
        || INLINE_HIDDEN_STYLE.is_match(tag)
}

fn has_accessible_name(tag: &str) -> bool {
    !attribute(tag, "aria-label").trim().is_empty()
        || !attribute(tag, "aria-labelledby").trim().is_empty()
        || DYNAMIC_ARIA_LABEL.is_match(tag)
}

fn has_decorative_role(tag: &str) -> bool {
    ["none", "presentation"]
        .iter()
        .any(|role| attribute(tag, "role").eq_ignore_ascii_case(role))
}

fn graphic_has_fallback(source: &str, end: usize, name: &str) -> bool {
    let remainder = &source[end..];
    if name.eq_ignore_ascii_case("svg") {
        let Some(closing) = SVG_CLOSE.find(remainder) else {
            return false;
        };
        let body = &remainder[..closing.start()];
        SVG_TITLE_CONTENT.is_match(body) || SVG_DEFINITION.is_match(body)
    } else {
        let Some(closing) = CANVAS_CLOSE.find(remainder) else {
            return false;
        };
        has_visible_fallback_text(&remainder[..closing.start()])
    }
}

fn has_visible_fallback_text(source: &str) -> bool {
    let mut in_tag = false;
    for character in source.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag && !character.is_whitespace() && !matches!(character, '{' | '}') => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_void_html_element(name: &str) -> bool {
    [
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

#[derive(Default)]
struct LabelIndex<'a> {
    targets: BTreeSet<&'a str>,
    bound_targets: BTreeSet<&'a str>,
}

fn index_labels(source: &str) -> LabelIndex<'_> {
    let mut index = LabelIndex::default();
    for label in LABEL_TAG.find_iter(source) {
        let tag = label.as_str();
        let target = attribute(tag, "for");
        if !target.is_empty() {
            index.targets.insert(target);
        }
        let bound_target = bound_attribute(tag, "for");
        if !bound_target.is_empty() {
            index.bound_targets.insert(bound_target);
        }
    }
    index
}

fn inputs_without_label(source: &str) -> BTreeSet<usize> {
    let labels = index_labels(source);
    INPUT_TAG
        .find_iter(source)
        .filter_map(|input| {
            qualify_unlabelled_input(source, input.as_str(), input.start(), &labels)
        })
        .map(|offset| line_at(source, offset))
        .collect()
}

fn qualify_unlabelled_input(
    source: &str,
    tag: &str,
    offset: usize,
    labels: &LabelIndex<'_>,
) -> Option<usize> {
    if input_does_not_require_label(tag) || input_has_label(source, tag, offset, labels) {
        return None;
    }
    Some(offset)
}

fn input_does_not_require_label(tag: &str) -> bool {
    let input_type = attribute(tag, "type");
    ["hidden", "submit", "button", "reset"]
        .iter()
        .any(|candidate| input_type.eq_ignore_ascii_case(candidate))
        || HIDDEN_ATTRIBUTE.is_match(tag)
        || input_type.eq_ignore_ascii_case("image") && !attribute(tag, "alt").is_empty()
        || !attribute(tag, "is").is_empty() && !attribute(tag, "label").is_empty()
        || ARIA_LABEL.is_match(tag)
}

fn input_has_label(source: &str, tag: &str, offset: usize, labels: &LabelIndex<'_>) -> bool {
    let id = attribute(tag, "id");
    let bound_id = bound_attribute(tag, "id");
    !id.is_empty() && labels.targets.contains(id)
        || !bound_id.is_empty() && labels.bound_targets.contains(bound_id)
        || is_inside_label(source, offset)
}

fn is_inside_label(source: &str, offset: usize) -> bool {
    let prefix = &source[..offset];
    let opening = LABEL_TAG
        .find_iter(prefix)
        .last()
        .map_or(usize::MAX, |matched| matched.start());
    let closing = LABEL_CLOSE
        .find_iter(prefix)
        .last()
        .map_or(usize::MAX, |matched| matched.start());
    match (opening, closing) {
        (usize::MAX, _) => false,
        (_, usize::MAX) => true,
        _ => opening > closing,
    }
}

fn start_tags_without_attribute(
    source: &str,
    tag: &Regex,
    attribute_pattern: &Regex,
) -> BTreeSet<usize> {
    tag.find_iter(source)
        .filter(|matched| !attribute_pattern.is_match(matched.as_str()))
        .map(|matched| line_at(source, matched.start()))
        .collect()
}

fn has_start_tag_with_attribute_value(
    source: &str,
    tag: &Regex,
    attribute_name: &str,
    attribute_value: &str,
) -> bool {
    tag.find_iter(source).any(|matched| {
        attribute(matched.as_str(), attribute_name).eq_ignore_ascii_case(attribute_value)
    })
}

fn forms_without_native_method(source: &str) -> BTreeSet<usize> {
    FORM_TAG
        .find_iter(source)
        .filter(|matched| {
            let tag = matched.as_str();
            !METHOD_ATTRIBUTE.is_match(tag) && !prevents_native_form_submission(tag)
        })
        .map(|matched| line_at(source, matched.start()))
        .collect()
}

fn prevents_native_form_submission(tag: &str) -> bool {
    FORM_PREVENT_MODIFIER.is_match(tag)
        || ON_SUBMIT.is_match(tag) && (PREVENT_DEFAULT.is_match(tag) || RETURN_FALSE.is_match(tag))
}

fn blank_targets_without_rel(source: &str) -> BTreeSet<usize> {
    let mut result = BTreeSet::new();
    for anchor in ANCHOR_TAG.find_iter(source) {
        let tag = anchor.as_str();
        let Some(target) = BLANK_TARGET.find(tag) else {
            continue;
        };
        if REL_ATTRIBUTE.is_match(tag) {
            continue;
        }
        result.insert(line_at(source, anchor.start() + target.start()));
    }
    result
}

fn executable_inline_script_lines(source: &str) -> BTreeSet<usize> {
    let mut result = BTreeSet::new();
    let mut cursor = 0usize;
    while cursor < source.len() {
        let Some(opening) = SCRIPT_TAG.find(&source[cursor..]) else {
            break;
        };
        let opening_start = cursor + opening.start();
        let opening_end = cursor + opening.end();
        let tag = &source[opening_start..opening_end];
        if is_executable_inline_script_tag(tag) {
            result.insert(line_at(source, opening_start));
        }
        let Some(closing) = SCRIPT_CLOSE.find(&source[opening_end..]) else {
            break;
        };
        cursor = opening_end + closing.end();
    }
    result
}

fn is_executable_inline_script_tag(tag: &str) -> bool {
    if SRC_ATTRIBUTE.is_match(tag) || NONCE_ATTRIBUTE.is_match(tag) {
        return false;
    }
    let script_type = attribute(tag, "type");
    script_type.is_empty()
        || ["module", "text/javascript", "application/javascript"]
            .iter()
            .any(|value| script_type.eq_ignore_ascii_case(value))
}

fn has_insecure_http_resource(line: &str) -> bool {
    if HTTP_SOURCE.is_match(line) || HTTP_BASE_OR_USE.is_match(line) {
        return true;
    }
    LINK_TAG.find_iter(line).any(|matched| {
        let tag = matched.as_str();
        HTTP_HREF.is_match(tag) && attribute(tag, "rel").trim() != "profile"
    })
}

fn attribute<'a>(tag: &'a str, name: &str) -> &'a str {
    ATTRIBUTE
        .captures_iter(tag)
        .find_map(|capture| {
            let attribute = capture.get(1)?;
            if !attribute.as_str().eq_ignore_ascii_case(name) {
                return None;
            }
            capture
                .get(2)
                .or_else(|| capture.get(3))
                .map(|value| value.as_str())
        })
        .unwrap_or("")
}

fn bound_attribute<'a>(tag: &'a str, name: &str) -> &'a str {
    BOUND_ATTRIBUTE
        .captures_iter(tag)
        .find_map(|capture| {
            let attribute = capture.get(1)?;
            if !attribute.as_str().eq_ignore_ascii_case(name) {
                return None;
            }
            capture
                .get(2)
                .or_else(|| capture.get(3))
                .map(|value| value.as_str().trim())
        })
        .unwrap_or("")
}

fn template_conditions(lines: &[&str]) -> Vec<BTreeSet<String>> {
    let doxygen = doxygen_conditions(lines);
    let svelte = svelte_conditions(lines);
    doxygen
        .into_iter()
        .zip(svelte)
        .map(|(mut left, right)| {
            left.extend(right);
            left
        })
        .collect()
}

fn doxygen_conditions(lines: &[&str]) -> Vec<BTreeSet<String>> {
    let mut active = Vec::<String>::new();
    let mut result = Vec::with_capacity(lines.len());
    for line in lines {
        let mut conditions = active.iter().cloned().collect::<BTreeSet<_>>();
        for capture in DOXYGEN_MARKER.captures_iter(line) {
            let kind = capture.get(1).unwrap().as_str().to_ascii_uppercase();
            let condition = capture.get(2).unwrap().as_str().to_ascii_uppercase();
            if kind == "BEGIN" {
                active.push(condition.clone());
                conditions.insert(condition);
            } else if let Some(index) = active.iter().rposition(|value| value == &condition) {
                active.remove(index);
            }
        }
        result.push(conditions);
    }
    result
}

// code-buster-ignore complex-function: Svelte branch tracking is one small stack machine with shared active state.
fn svelte_conditions(lines: &[&str]) -> Vec<BTreeSet<String>> {
    let mut active = Vec::<(usize, usize)>::new();
    let mut result = Vec::with_capacity(lines.len());
    let mut next_group = 0usize;
    for line in lines {
        let mut conditions = active
            .iter()
            .map(|(branch, group)| format!("@svelte:{group}:{branch}"))
            .collect::<BTreeSet<_>>();
        for capture in SVELTE_MARKER.captures_iter(line) {
            let kind = capture.get(1).unwrap().as_str();
            if kind == "#if" {
                let value = (0, next_group);
                next_group += 1;
                active.push(value);
                conditions.insert(format!("@svelte:{}:{}", value.1, value.0));
            } else if kind.starts_with(":else") {
                if let Some(previous) = active.pop() {
                    conditions.remove(&format!("@svelte:{}:{}", previous.1, previous.0));
                    let value = (previous.0 + 1, previous.1);
                    active.push(value);
                    conditions.insert(format!("@svelte:{}:{}", value.1, value.0));
                }
            } else if kind == "/if" {
                active.pop();
            }
        }
        result.push(conditions);
    }
    result
}

fn mutually_exclusive(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|condition| {
        let opposite = condition
            .strip_prefix('!')
            .map_or_else(|| format!("!{condition}"), str::to_owned);
        right.contains(&opposite)
            || condition
                .strip_prefix("@svelte:")
                .and_then(|body| body.rfind(':'))
                .is_some_and(|separator| {
                    let separator = "@svelte:".len() + separator;
                    let group = &condition[..=separator];
                    right
                        .iter()
                        .any(|candidate| candidate.starts_with(group) && candidate != condition)
                })
    })
}

fn has_markup_template_in_head(source: &str) -> bool {
    if HEAD_INCLUDE.is_match(source) {
        return true;
    }
    HEAD_BLOCK
        .captures(source)
        .and_then(|capture| capture.get(1))
        .is_some_and(|head| HEAD_TEMPLATE.is_match(head.as_str()))
}

fn has_jekyll_seo_tag_in_head(source: &str) -> bool {
    HEAD_BLOCK
        .captures(source)
        .and_then(|capture| capture.get(1))
        .is_some_and(|head| JEKYLL_SEO.is_match(head.as_str()))
}

fn line_at(source: &str, offset: usize) -> usize {
    source.as_bytes()[..offset.min(source.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("HTML rule metadata must exist");
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

static HTML_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<!--.*?(?:-->|$)").unwrap());
static HTML_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<html\b").unwrap());
static HTML_WITH_LANG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<html\b[^>]*\blang\s*=").unwrap());
static TITLE_CONTENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<title(?:\s[^>]*)?>\s*[^<\s]").unwrap());
static INLINE_EVENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\son(?:click|load|change|submit|error)\s*=").unwrap());
static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:^|\s)([A-Za-z_][A-Za-z0-9_:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap()
});
static BOUND_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^|\s)(?::|v-bind:)([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
    )
    .unwrap()
});
static LABEL_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<label\b[^>]*>").unwrap());
static LABEL_CLOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)</label\s*>").unwrap());
static INPUT_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<input\b[^>]*>").unwrap());
static IMG_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<img\b[^>]*>").unwrap());
static META_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
static FORM_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<form\b[^>]*>").unwrap());
static ANCHOR_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<a\b[^>]*>").unwrap());
static LINK_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<link\b[^>]*>").unwrap());
static SCRIPT_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<script\b[^>]*>").unwrap());
static SCRIPT_CLOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)</script\s*>").unwrap());
static HAS_ALT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\balt\s*=").unwrap());
static HIDDEN_ATTRIBUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|\s)hidden(?:\s|/?>|=)").unwrap());
static ARIA_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\baria-label(?:ledby)?\s*=").unwrap());
static METHOD_ATTRIBUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bmethod\s*=").unwrap());
static FORM_PREVENT_MODIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:@|v-on:)submit(?:\.[\w-]+)*\.prevent(?:\.[\w-]+)*\s*=").unwrap()
});
static ON_SUBMIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bonsubmit\b").unwrap());
static PREVENT_DEFAULT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bpreventdefault\s*\(").unwrap());
static RETURN_FALSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\breturn\s+false\b").unwrap());
static BLANK_TARGET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)target\s*=\s*["']_blank["']"#).unwrap());
static REL_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\brel\s*=").unwrap());
static SRC_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bsrc\s*=").unwrap());
static NONCE_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\bnonce\s*=|\{\{[^}]*\bnonce(?:_?attribute)?\b[^}]*\}\})").unwrap()
});
static HTTP_SOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\s(?:src|srcset)\s*=\s*["']http://"#).unwrap());
static HTTP_BASE_OR_USE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<(?:base|use)\b[^>]*\shref\s*=\s*["']http://"#).unwrap());
static HTTP_HREF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\shref\s*=\s*["']http://"#).unwrap());
static DOXYGEN_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<!--\s*(BEGIN|END)\s+(!?[A-Z0-9_]+)\s*-->").unwrap());
static SVELTE_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{(#if\b|:else if\b|:else\b|/if\b)").unwrap());
static HEAD_INCLUDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\{%\s*include\s+["']?(?:[^"'%\s]+[/\\])?head(?:\.[a-z0-9_-]+)?["']?\s*%\}"#)
        .unwrap()
});
static HEAD_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<head\b[^>]*>(.*?)</head>").unwrap());
static HEAD_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<%-|\{\{\{\s*|\{\{\s*>|\{%\s*include\b|<\?(?:php)?\s*(?:include|require)\b")
        .unwrap()
});
static JEKYLL_SEO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\{%\s*seo\b[^%]*%\}").unwrap());
static RAW_TEXT_ELEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<(?:script|style)\b[^>]*>(.*?)</(?:script|style)\s*>").unwrap()
});
static AUTOPLAY_ATTRIBUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|\s)autoplay(?:\s|=|/?>)").unwrap());
static MUTED_ATTRIBUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|\s)muted(?:\s|=|/?>)").unwrap());
static DYNAMIC_ARIA_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^|\s)(?::|v-bind:)?aria-label(?:ledby)?\s*=\s*(?:\{[^}]+\}|["'][^"']+["'])"#,
    )
    .unwrap()
});
static SVELTE_SPREAD_ATTRIBUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\s*\.\.\.[^}]+\}").unwrap());
static INLINE_HIDDEN_STYLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)"#)
        .unwrap()
});
static SVG_CLOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)</svg\s*>").unwrap());
static CANVAS_CLOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)</canvas\s*>").unwrap());
static SVG_TITLE_CONTENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title\b[^>]*>\s*[^<\s]").unwrap());
static SVG_DEFINITION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<symbol\b").unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(source: &str) -> BTreeSet<String> {
        analyze(&BTreeMap::from([(
            "index.html".to_owned(),
            source.to_owned(),
        )]))
        .into_iter()
        .map(|finding| finding.code)
        .collect()
    }

    #[test]
    fn reports_complete_html_source_rule_family() {
        let source = r#"<html>
<head><script>alert(1)</script></head>
<body onclick="run()">
<a target="_blank">open</a>
<img src="http://example.test/image.png">
<input id="name">
<div id="same"></div>
<span id="same"></span>
<form></form>
</body></html>"#;
        assert_eq!(
            codes(source),
            BTreeSet::from([
                "html-blank-no-rel".to_owned(),
                "html-duplicate-id".to_owned(),
                "html-form-method".to_owned(),
                "html-http-resource".to_owned(),
                "html-img-alt".to_owned(),
                "html-inline-event".to_owned(),
                "html-inline-script".to_owned(),
                "html-input-label".to_owned(),
                "html-missing-lang".to_owned(),
                "html-missing-title".to_owned(),
                "html-missing-viewport".to_owned(),
            ])
        );
    }

    #[test]
    fn accepts_accessible_secure_document_contracts() {
        let source = r#"<!doctype html>
<html lang="en">
<head>
  <title>Account</title>
  <meta name="viewport" content="width=device-width">
  <script src="app.js"></script>
</head>
<body>
  <a target="_blank" rel="noopener">open</a>
  <img src="https://example.test/logo.png" alt="Logo">
  <label for="name">Name</label><input id="name">
  <input is="emby-input" label="Server">
  <form method="post"></form>
</body>
</html>"#;
        assert!(codes(source).is_empty());
    }

    #[test]
    fn handles_multiline_tags_templates_and_svelte_branches() {
        let source = r#"<html
 lang="en">
<head>{% seo %}<meta
 name="viewport"
 content="width=device-width"></head>
<body>
<label
 for="name">Name</label>
<input
 id="name">
<a
 target="_blank"
 rel="noopener">open</a>
</body></html>"#;
        let findings = analyze(&BTreeMap::from([(
            "index.html".to_owned(),
            source.to_owned(),
        )]));
        assert!(findings.is_empty());

        let svelte = r#"{#if first}<section id="panel"></section>
{:else}<section id="panel"></section>{/if}"#;
        assert!(
            analyze(&BTreeMap::from([(
                "component.svelte".to_owned(),
                svelte.to_owned()
            )]))
            .into_iter()
            .all(|finding| finding.code != "html-duplicate-id")
        );
    }

    #[test]
    fn reports_unmuted_autoplay_and_unlabelled_graphics() {
        let source = r#"<video
  autoplay
  src="intro.mp4"></video>
<svg>
  <path d="M0 0h10v10z"></path>
</svg>
<canvas></canvas>"#;
        let findings = analyze(&BTreeMap::from([(
            "index.html".to_owned(),
            source.to_owned(),
        )]));
        let lines = |code: &str| {
            findings
                .iter()
                .filter(|finding| finding.code == code)
                .map(|finding| finding.line)
                .collect::<Vec<_>>()
        };

        assert_eq!(lines("html-video-autoplay-unmuted"), vec![1]);
        assert_eq!(lines("html-graphic-accessibility-name"), vec![4, 7]);
    }

    #[test]
    fn accepts_muted_video_and_accessible_or_decorative_graphics() {
        let source = r#"<video autoplay muted src="intro.mp4"></video>
<video controls src="interview.mp4"></video>
<svg aria-hidden="true"><path></path></svg>
<svg role="presentation"><path></path></svg>
<svg><title>Quarterly sales</title><path></path></svg>
<button aria-label="Save"><svg><path></path></svg></button>
<canvas>Quarterly sales chart</canvas>
<svg><symbol id="check"><path></path></symbol></svg>
<script>const sample = '<video autoplay><svg></svg>';</script>
<!-- <video autoplay></video><canvas></canvas> -->"#;
        let new_codes = codes(source)
            .into_iter()
            .filter(|code| {
                code == "html-video-autoplay-unmuted" || code == "html-graphic-accessibility-name"
            })
            .collect::<BTreeSet<_>>();

        assert!(new_codes.is_empty());
    }

    #[test]
    fn accepts_dynamic_svelte_media_accessibility_bindings_and_components() {
        let source = r#"<video autoplay={start} muted={silent}></video>
<svg aria-label={iconName}><path></path></svg>
<svg onmousemove={(event) => { point = event.clientX; }} role="presentation"></svg>
<svg {...restProps}><path></path></svg>
<Button title="Toggle theme"><svg><path></path></svg></Button>
<Video autoplay></Video>
<Canvas></Canvas>"#;
        let findings = analyze(&BTreeMap::from([(
            "component.svelte".to_owned(),
            source.to_owned(),
        )]));

        assert!(findings.into_iter().all(|finding| {
            finding.code != "html-video-autoplay-unmuted"
                && finding.code != "html-graphic-accessibility-name"
        }));
    }

    #[test]
    fn skips_malformed_attribute_and_branch_structures() {
        assert_eq!(attribute(r#"<div id="panel">"#, "id"), "panel");
        assert_eq!(attribute("<div id=panel>", "id"), "");
        assert_eq!(bound_attribute(r#"<input :id="'panel'">"#, "id"), "'panel'");
        assert_eq!(bound_attribute("<input :id=panel>", "id"), "");

        let malformed = BTreeSet::from(["@svelte:branch".to_owned()]);
        let valid = BTreeSet::from(["@svelte:branch:1".to_owned()]);
        assert!(!mutually_exclusive(&malformed, &valid));

        let source = r#"{:else}<div id="panel"></div>
<div id="panel"></div>{/if}"#;
        assert!(codes(source).contains("html-duplicate-id"));
    }

    #[test]
    fn incomplete_head_does_not_hide_valid_document_findings() {
        let source = r#"<html lang="en">
<head>{% seo %}
<body><img src="https://example.test/image.png"></body></html>"#;

        assert!(!has_markup_template_in_head(source));
        assert!(!has_jekyll_seo_tag_in_head(source));
        assert_eq!(
            codes(source),
            BTreeSet::from([
                "html-img-alt".to_owned(),
                "html-missing-title".to_owned(),
                "html-missing-viewport".to_owned(),
            ])
        );
    }
}
