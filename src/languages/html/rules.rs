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
    let lines = source.split('\n').collect::<Vec<_>>();
    let masked_lines = markup.split('\n').collect::<Vec<_>>();
    let is_svelte = path.to_ascii_lowercase().ends_with(".svelte");
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
