use std::sync::LazyLock;

use regex::Regex;

use crate::dart_core_rules::mask_comments;
use crate::dart_null_assertion::dart_source_with_interpolations;
use crate::dart_reliability::unguarded_context_uses;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let sources = dart_sources(context);
    let mut findings = Vec::new();
    findings.extend(missing_const_constructors(&sources));
    findings.extend(large_list_views(&sources));
    findings.extend(image_cache_bypasses(context, &sources));
    findings.extend(missing_widget_keys(&sources));
    findings.extend(build_matches(
        &sources,
        &SET_STATE,
        "flutter-setstate-in-build",
        "build calls setState directly",
    ));
    findings.extend(context_after_await(&sources));
    findings.extend(build_matches(
        &sources,
        &CONTROLLER_CREATION,
        "flutter-controller-created-in-build",
        "build creates a controller or focus node",
    ));
    findings.extend(unlocalized_text(context, &sources));
    findings.extend(missing_assets(context, &sources));
    findings.extend(forms_without_validation(&sources));
    findings.extend(bloc_builder_effects(&sources));
    findings.extend(get_it_widgets(&sources));
    findings.extend(platform_branches(&sources));
    findings.extend(provider_watch_in_callbacks(&sources));
    findings.extend(repeated_sized_box_spacing(&sources));
    findings
}

struct DartSource<'a> {
    path: &'a str,
    raw: &'a str,
    masked: String,
}

impl DartSource<'_> {
    fn line_at(&self, offset: usize) -> usize {
        self.masked.as_bytes()[..offset.min(self.masked.len())]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1
    }
}

struct ClassBlock<'a> {
    name: &'a str,
    header: &'a str,
    body: &'a str,
    line: usize,
}

struct FunctionBlock<'a> {
    name: &'a str,
    body: &'a str,
    line: usize,
}

fn dart_sources<'a>(context: &'a SourceAnalysisContext<'_>) -> Vec<DartSource<'a>> {
    context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".dart"))
        .map(|(path, source)| {
            let masked =
                dart_source_with_interpolations(source, &context.masked_lines(path).join("\n"));
            let lines = masked.split('\n').map(str::to_owned).collect::<Vec<_>>();
            DartSource {
                path,
                raw: source,
                masked: mask_comments(&lines).join("\n"),
            }
        })
        .collect()
}

fn classes<'a>(source: &'a DartSource<'_>) -> Vec<ClassBlock<'a>> {
    CLASS_START
        .captures_iter(&source.masked)
        .filter_map(|capture| {
            let matched = capture.get(0).unwrap();
            let name = capture.get(1)?.as_str();
            let end = matching_delimiter(&source.masked, matched.end() - 1, b'{', b'}')?;
            Some(ClassBlock {
                name,
                header: matched.as_str(),
                body: &source.masked[matched.start()..=end],
                line: source.line_at(matched.start()),
            })
        })
        .collect()
}

fn functions<'a>(source: &'a DartSource<'_>) -> Vec<FunctionBlock<'a>> {
    FUNCTION_DECLARATION
        .captures_iter(&source.masked)
        .filter_map(|capture| {
            let matched = capture.get(0).unwrap();
            let name = capture.get(1)?.as_str();
            let brace = source.masked[matched.start()..]
                .find('{')
                .map(|offset| matched.start() + offset)?;
            let end = matching_delimiter(&source.masked, brace, b'{', b'}')?;
            Some(FunctionBlock {
                name,
                body: &source.masked[matched.start()..=end],
                line: source.line_at(matched.start()),
            })
        })
        .collect()
}

fn missing_const_constructors(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for block in classes(source) {
            if !block.header.contains("extends StatelessWidget") {
                continue;
            }
            let constructor = Regex::new(&format!(
                r"(?:^|\n)\s*(const\s+)?{}\s*\(",
                regex::escape(block.name)
            ))
            .unwrap();
            let Some(capture) = constructor.captures(block.body) else {
                continue;
            };
            if capture.get(1).is_some() || has_mutable_instance_field(block.body) {
                continue;
            }
            findings.push(quality_finding(
                "flutter-widget-missing-const-constructor",
                source.path,
                block.line,
                format!(
                    "{} is immutable but its constructor is not const",
                    block.name
                ),
            ));
        }
    }
    findings
}

fn has_mutable_instance_field(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        !["static", "final", "const"]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix) && word_boundary(trimmed, prefix.len()))
            && MUTABLE_FIELD.is_match(trimmed)
    })
}

fn word_boundary(value: &str, offset: usize) -> bool {
    value
        .as_bytes()
        .get(offset)
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'_' | b'$'))
}

fn large_list_views(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for start in LIST_VIEW.find_iter(&source.masked) {
            let stop = start.start().saturating_add(3000).min(source.masked.len());
            let tail = &source.masked[start.start()..stop];
            if LIST_CHILDREN.captures(tail).is_some_and(|capture| {
                capture
                    .get(1)
                    .is_some_and(|children| children.as_str().matches(',').count() >= 12)
            }) {
                findings.push(quality_finding(
                    "flutter-listview-large-children",
                    source.path,
                    source.line_at(start.start()),
                    "ListView eagerly builds a large children literal".to_owned(),
                ));
            }
        }
    }
    findings
}

fn image_cache_bypasses(
    context: &SourceAnalysisContext<'_>,
    sources: &[DartSource<'_>],
) -> Vec<Finding> {
    let mut established = context
        .auxiliary_files()
        .get("pubspec.yaml")
        .is_some_and(|pubspec| pubspec.contains("cached_network_image:"));
    let mut direct = Vec::new();
    for source in sources {
        if source.masked.contains("CachedNetworkImage(")
            || source.masked.contains("CachedNetworkImageProvider(")
        {
            established = true;
        }
        direct.extend(
            IMAGE_NETWORK
                .find_iter(&source.masked)
                .map(|matched| (source.path, source.line_at(matched.start()))),
        );
    }
    if !established || direct.len() < 3 {
        return Vec::new();
    }
    vec![quality_finding(
        "flutter-image-cache-bypass",
        direct[0].0,
        direct[0].1,
        format!(
            "{} direct Image.network calls bypass the established cache",
            direct.len()
        ),
    )]
}

fn missing_widget_keys(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for block in classes(source) {
            if !block.header.contains("extends StatefulWidget") || block.name.starts_with('_') {
                continue;
            }
            let constructor =
                Regex::new(&format!(r"{}\s*\(([^)]*)\)", regex::escape(block.name))).unwrap();
            let Some(capture) = constructor.captures(block.body) else {
                continue;
            };
            let Some(arguments) = capture.get(1) else {
                continue;
            };
            if WIDGET_KEY.is_match(arguments.as_str()) {
                continue;
            }
            findings.push(quality_finding(
                "flutter-missing-widget-key",
                source.path,
                block.line,
                format!("{} does not expose a widget key", block.name),
            ));
        }
    }
    findings
}

fn build_matches(
    sources: &[DartSource<'_>],
    pattern: &Regex,
    code: &str,
    message: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for build in functions(source)
            .into_iter()
            .filter(|function| function.name == "build")
        {
            if pattern.is_match(build.body) {
                findings.push(quality_finding(
                    code,
                    source.path,
                    build.line,
                    message.to_owned(),
                ));
            }
        }
    }
    findings
}

fn context_after_await(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for context_use in unguarded_context_uses(&source.masked) {
            findings.push(quality_finding(
                "flutter-context-after-await",
                source.path,
                source.line_at(context_use.start),
                format!(
                    "{} uses BuildContext after await without a mounted guard",
                    context_use.name
                ),
            ));
        }
    }
    findings
}

fn unlocalized_text(
    context: &SourceAnalysisContext<'_>,
    sources: &[DartSource<'_>],
) -> Vec<Finding> {
    let localized = context.auxiliary_files().contains_key("l10n.yaml")
        || context
            .auxiliary_files()
            .get("pubspec.yaml")
            .is_some_and(|pubspec| pubspec.contains("generate: true"))
        || context
            .sources()
            .values()
            .any(|source| source.contains("AppLocalizations"));
    if !localized {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for source in sources {
        for capture in USER_TEXT.captures_iter(source.raw) {
            let matched = capture.get(0).unwrap();
            let text = capture.get(1).unwrap().as_str().trim();
            if NON_WORD_TEXT.is_match(text) {
                continue;
            }
            findings.push(quality_finding(
                "flutter-unlocalized-user-text",
                source.path,
                source.line_at(matched.start()),
                format!("user-visible literal `{text}` bypasses localization"),
            ));
        }
    }
    findings
}

fn missing_assets(context: &SourceAnalysisContext<'_>, sources: &[DartSource<'_>]) -> Vec<Finding> {
    let pubspec = context
        .auxiliary_files()
        .get("pubspec.yaml")
        .map_or("", String::as_str);
    let mut findings = Vec::new();
    for source in sources {
        for capture in ASSET_REFERENCE.captures_iter(source.raw) {
            let matched = capture.get(0).unwrap();
            let asset = capture.get(1).unwrap().as_str();
            let declared = pubspec.contains(asset) || declared_asset_directory(pubspec, asset);
            let exists = context
                .auxiliary_files()
                .get(&format!("@exists/{asset}"))
                .is_some_and(|value| value == "true");
            if declared && exists {
                continue;
            }
            findings.push(quality_finding(
                "flutter-asset-reference-missing",
                source.path,
                source.line_at(matched.start()),
                format!(
                    "asset `{asset}` is {}",
                    if declared {
                        "missing on disk"
                    } else {
                        "not declared"
                    }
                ),
            ));
        }
    }
    findings
}

fn declared_asset_directory(pubspec: &str, asset: &str) -> bool {
    let segments = asset.split('/').collect::<Vec<_>>();
    (1..segments.len())
        .rev()
        .any(|length| pubspec.contains(&format!("{}/", segments[..length].join("/"))))
}

fn forms_without_validation(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        if source.masked.contains("Form(")
            && source.masked.contains("TextFormField(")
            && FORM_SUBMISSION.is_match(&source.masked)
            && !FORM_VALIDATION.is_match(&source.masked)
        {
            findings.push(quality_finding(
                "flutter-form-without-validation",
                source.path,
                1,
                "submitted Form has editable fields but no validation path".to_owned(),
            ));
        }
    }
    findings
}

fn bloc_builder_effects(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for matched in BLOC_BUILDER.find_iter(&source.masked) {
            let stop = matched
                .start()
                .saturating_add(3000)
                .min(source.masked.len());
            if BLOC_SIDE_EFFECT.is_match(&source.masked[matched.start()..stop]) {
                findings.push(quality_finding(
                    "flutter-bloc-side-effect-in-builder",
                    source.path,
                    source.line_at(matched.start()),
                    "BlocBuilder performs a navigation, UI, telemetry, or persistence side effect"
                        .to_owned(),
                ));
            }
        }
    }
    findings
}

fn get_it_widgets(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for block in classes(source) {
            if WIDGET_CLASS.is_match(block.header) && GET_IT.is_match(block.body) {
                findings.push(quality_finding(
                    "flutter-getit-lookup-in-widget",
                    source.path,
                    block.line,
                    format!("{} resolves a dependency through GetIt", block.name),
                ));
            }
        }
    }
    findings
}

fn platform_branches(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for build in functions(source)
            .into_iter()
            .filter(|function| function.name == "build")
        {
            if PLATFORM_CHECK.is_match(build.body)
                && ADAPTABLE_CONTROL.is_match(build.body)
                && !build.body.contains(".adaptive(")
                && !build.body.contains("Cupertino")
            {
                findings.push(quality_finding(
                    "flutter-platform-branch-without-adaptation",
                    source.path,
                    build.line,
                    "build branches by platform around a control without using an adaptive widget"
                        .to_owned(),
                ));
            }
        }
    }
    findings
}

#[derive(Clone, Copy)]
struct FunctionExpression {
    start: usize,
    body_start: usize,
    end: usize,
}

fn provider_watch_in_callbacks(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        let expressions = function_expressions(&source.masked);
        for capture in PROVIDER_WATCH.captures_iter(&source.masked) {
            let matched = capture.get(0).unwrap();
            let nearest = expressions
                .iter()
                .filter(|expression| {
                    expression.body_start <= matched.start() && matched.start() < expression.end
                })
                .min_by_key(|expression| expression.end - expression.start);
            let Some(expression) = nearest else {
                continue;
            };
            let mut prefix_start = expression.start.saturating_sub(80);
            while !source.masked.is_char_boundary(prefix_start) {
                prefix_start -= 1;
            }
            if !EVENT_CALLBACK.is_match(&source.masked[prefix_start..expression.start]) {
                continue;
            }
            findings.push(range_finding(
                "flutter-provider-watch-in-callback",
                source.path,
                source.line_at(matched.start()),
                source.line_at(matched.end()),
                format!(
                    "`{}.watch` is used inside an event callback",
                    capture.get(1).unwrap().as_str()
                ),
                "high",
            ));
        }
    }
    findings
}

fn function_expressions(source: &str) -> Vec<FunctionExpression> {
    let pairs = parenthesis_pairs(source);
    let mut expressions = Vec::new();
    scan_parenthesized_expressions(source, pairs, &mut expressions);
    scan_single_parameter_expressions(source, &mut expressions);
    expressions
}

fn parenthesis_pairs(source: &str) -> Vec<(usize, usize)> {
    let mut stack = Vec::new();
    let mut pairs = Vec::new();
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'(' {
            stack.push(index);
        } else if byte == b')'
            && let Some(open) = stack.pop()
        {
            pairs.push((open, index));
        }
    }
    pairs.sort_unstable_by_key(|(open, _)| *open);
    pairs
}

fn scan_parenthesized_expressions(
    source: &str,
    pairs: Vec<(usize, usize)>,
    expressions: &mut Vec<FunctionExpression>,
) {
    for (open, close) in pairs {
        if let Some(expression) = parenthesized_expression(source, open, close) {
            expressions.push(expression);
        }
    }
}

fn parenthesized_expression(source: &str, open: usize, close: usize) -> Option<FunctionExpression> {
    let previous = preceding_identifier(source, open);
    if matches!(
        previous,
        Some("if" | "for" | "while" | "switch" | "catch" | "assert")
    ) {
        return None;
    }

    let marker = closure_body_marker(source, close);
    if source.as_bytes().get(marker) == Some(&b'{') {
        return Some(FunctionExpression {
            start: open,
            body_start: marker + 1,
            end: matching_delimiter(source, marker, b'{', b'}')?,
        });
    }
    source[marker..]
        .starts_with("=>")
        .then(|| FunctionExpression {
            start: open,
            body_start: marker + 2,
            end: expression_end(source, marker + 2),
        })
}

fn closure_body_marker(source: &str, close: usize) -> usize {
    let marker = skip_whitespace(source, close + 1);
    if source[marker..].starts_with("async") && word_boundary(&source[marker..], "async".len()) {
        skip_whitespace(source, marker + "async".len())
    } else {
        marker
    }
}

fn scan_single_parameter_expressions(source: &str, expressions: &mut Vec<FunctionExpression>) {
    for capture in SINGLE_PARAMETER_CLOSURE.captures_iter(source) {
        let matched = capture.get(0).unwrap();
        let marker = capture.name("marker").unwrap();
        expressions.push(FunctionExpression {
            start: matched.start(),
            body_start: marker.end(),
            end: expression_end(source, marker.end()),
        });
    }
}

fn preceding_identifier(source: &str, offset: usize) -> Option<&str> {
    let prefix = source[..offset].trim_end();
    let end = prefix.len();
    let start = prefix
        .char_indices()
        .rev()
        .take_while(|(_, character)| character.is_alphanumeric() || matches!(character, '_' | '$'))
        .last()
        .map_or(end, |(index, _)| index);
    (start < end).then(|| &prefix[start..end])
}

struct LayoutSpacingCandidate<'a> {
    layout: &'a str,
    dimension: &'static str,
    elements: Vec<&'a str>,
    start: usize,
    end: usize,
}

struct SpacingGroup<'a> {
    value: &'a str,
    count: usize,
}

fn repeated_sized_box_spacing(sources: &[DartSource<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        for capture in LAYOUT_CALL.captures_iter(&source.masked) {
            let Some(candidate) = extract_layout_spacing(&source.masked, capture) else {
                continue;
            };
            let Some(group) = group_repeated_spacing(&candidate.elements, candidate.dimension)
            else {
                continue;
            };
            findings.push(emit_repeated_spacing(source, &candidate, group));
        }
    }
    findings
}

fn extract_layout_spacing<'a>(
    source: &'a str,
    capture: regex::Captures<'a>,
) -> Option<LayoutSpacingCandidate<'a>> {
    let matched = capture.get(0)?;
    if source[..matched.start()].trim_end().ends_with('.') {
        return None;
    }
    let open = matched.end() - 1;
    let close = matching_delimiter(source, open, b'(', b')')?;
    let layout = capture.get(1)?.as_str();
    let arguments = split_top_level(&source[open + 1..close], b',');
    if named_argument(&arguments, "spacing").is_some() {
        return None;
    }
    let children = named_argument(&arguments, "children")?.trim();
    if !children.starts_with('[') {
        return None;
    }
    let list_close = matching_delimiter(children, 0, b'[', b']')?;
    if !children[list_close + 1..].trim().is_empty() {
        return None;
    }
    let elements = split_top_level(&children[1..list_close], b',')
        .into_iter()
        .map(str::trim)
        .filter(|element| !element.is_empty())
        .collect::<Vec<_>>();
    if elements.len() < 5 || elements.iter().any(|element| collection_element(element)) {
        return None;
    }
    Some(LayoutSpacingCandidate {
        layout,
        dimension: if layout == "Column" {
            "height"
        } else {
            "width"
        },
        elements,
        start: matched.start(),
        end: close + 1,
    })
}

fn group_repeated_spacing<'a>(elements: &[&'a str], dimension: &str) -> Option<SpacingGroup<'a>> {
    let mut spacing = None;
    let mut spacer_count = 0usize;
    for (index, element) in elements.iter().enumerate() {
        let current = spacing_expression(element, dimension);
        if index % 2 == 0 {
            if current.is_some() {
                return None;
            }
            continue;
        }
        let current = current?;
        if spacing.is_some_and(|spacing| spacing != current) {
            return None;
        }
        spacing = Some(current);
        spacer_count += 1;
    }
    spacing
        .filter(|_| spacer_count >= 2)
        .map(|value| SpacingGroup {
            value,
            count: spacer_count,
        })
}

fn emit_repeated_spacing(
    source: &DartSource<'_>,
    candidate: &LayoutSpacingCandidate<'_>,
    group: SpacingGroup<'_>,
) -> Finding {
    range_finding(
        "flutter-repeated-sizedbox-spacing",
        source.path,
        source.line_at(candidate.start),
        source.line_at(candidate.end),
        format!(
            "{} identical {} {} spacers can use {}.spacing",
            group.count,
            group.value,
            if candidate.dimension == "height" {
                "vertical"
            } else {
                "horizontal"
            },
            candidate.layout
        ),
        "high",
    )
}

fn named_argument<'a>(arguments: &[&'a str], name: &str) -> Option<&'a str> {
    arguments.iter().find_map(|argument| {
        let colon = top_level_colon(argument)?;
        (argument[..colon].trim() == name).then(|| &argument[colon + 1..])
    })
}

fn top_level_colon(source: &str) -> Option<usize> {
    let mut depth = [0usize; 3];
    for (index, byte) in source.bytes().enumerate() {
        match byte {
            b'(' => depth[0] += 1,
            b')' => depth[0] = depth[0].saturating_sub(1),
            b'[' => depth[1] += 1,
            b']' => depth[1] = depth[1].saturating_sub(1),
            b'{' => depth[2] += 1,
            b'}' => depth[2] = depth[2].saturating_sub(1),
            b':' if depth == [0, 0, 0] => return Some(index),
            _ => {}
        }
    }
    None
}

fn collection_element(element: &str) -> bool {
    let element = element.trim_start();
    element.starts_with("...")
        || ["if", "for"]
            .iter()
            .any(|keyword| element.starts_with(keyword) && word_boundary(element, keyword.len()))
}

fn spacing_expression<'a>(expression: &'a str, dimension: &str) -> Option<&'a str> {
    let capture = SIZED_BOX.captures(expression.trim())?;
    let arguments = split_top_level(capture.get(1)?.as_str(), b',')
        .into_iter()
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    if arguments.len() != 1 {
        return None;
    }
    let colon = top_level_colon(arguments[0])?;
    if arguments[0][..colon].trim() != dimension {
        return None;
    }
    let value = arguments[0][colon + 1..].trim();
    STABLE_SPACING.is_match(value).then_some(value)
}

fn split_top_level(source: &str, separator: u8) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut depth = [0usize; 3];
    for (index, byte) in source.bytes().enumerate() {
        match byte {
            b'(' => depth[0] += 1,
            b')' => depth[0] = depth[0].saturating_sub(1),
            b'[' => depth[1] += 1,
            b']' => depth[1] = depth[1].saturating_sub(1),
            b'{' => depth[2] += 1,
            b'}' => depth[2] = depth[2].saturating_sub(1),
            value if value == separator && depth == [0, 0, 0] => {
                result.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    result.push(&source[start..]);
    result
}

fn skip_whitespace(source: &str, mut offset: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    offset
}

fn expression_end(source: &str, start: usize) -> usize {
    let mut depth = [0usize; 3];
    for (index, byte) in source.bytes().enumerate().skip(start) {
        match byte {
            b'(' => depth[0] += 1,
            b')' if depth[0] > 0 => depth[0] -= 1,
            b'[' => depth[1] += 1,
            b']' if depth[1] > 0 => depth[1] -= 1,
            b'{' => depth[2] += 1,
            b'}' if depth[2] > 0 => depth[2] -= 1,
            b',' | b';' if depth == [0, 0, 0] => return index,
            _ => {}
        }
    }
    source.len()
}

fn matching_delimiter(source: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    if source.as_bytes().get(open) != Some(&opening) {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in source.bytes().enumerate().skip(open) {
        if byte == opening {
            depth += 1;
        } else if byte == closing {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn quality_finding(code: &str, path: &str, line: usize, message: String) -> Finding {
    range_finding(code, path, line, 0, message, "high")
}

fn range_finding(
    code: &str,
    path: &str,
    line: usize,
    end_line: usize,
    message: String,
    confidence: &str,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Flutter quality metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line,
        message,
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+([A-Za-z_$]\w*)[^\{]*\{").unwrap());
static FUNCTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|\n)\s*(?:@[\w.()]+\s*)*(?:(?:Future<[^>]+>|Future|Widget|void|dynamic|[A-Za-z_$]\w*)\s+)([A-Za-z_$]\w*)\s*\([^;]*\)\s*(?:async\s*)?\{").unwrap()
});
static MUTABLE_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$<>?,.\[\]]*\s+\w+\s*(?:=|;)").unwrap());
static LIST_VIEW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bListView\s*\(").unwrap());
static LIST_CHILDREN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"children\s*:\s*\[([\s\S]*?)\]").unwrap());
static IMAGE_NETWORK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bImage\.network\s*\(").unwrap());
static WIDGET_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:super\.key|Key\??\s+key)\b").unwrap());
static SET_STATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bsetState\s*\(").unwrap());
static CONTROLLER_CREATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:TextEditingController|AnimationController|ScrollController|PageController|TabController|FocusNode)\s*\(").unwrap()
});
static USER_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\b(?:Text|Tooltip)\s*\(\s*['\"]([^'\"$]{4,})['\"]"#).unwrap());
static NON_WORD_TEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\d\W_]+$").unwrap());
static ASSET_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:Image\.asset|AssetImage)\s*\(\s*['\"](assets/[^'\"]+)['\"]"#).unwrap()
});
static FORM_SUBMISSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bon(?:Pressed|FieldSubmitted|EditingComplete)\s*:").unwrap());
static FORM_VALIDATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bvalidator\s*:|\.validate\s*\(").unwrap());
static BLOC_BUILDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bBlocBuilder(?:<[^>]+>)?\s*\(").unwrap());
static BLOC_SIDE_EFFECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Navigator\.|showDialog\s*\(|ScaffoldMessenger\.|analytics\.|repository\.|\.save\s*\()").unwrap()
});
static WIDGET_CLASS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"extends\s+(?:StatelessWidget|StatefulWidget|State<)").unwrap());
static GET_IT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:GetIt\.I|getIt)(?:\.get)?\s*(?:<|\()").unwrap());
static PLATFORM_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Platform\.is(?:IOS|Android|MacOS|Windows)|defaultTargetPlatform)\b").unwrap()
});
static ADAPTABLE_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Switch|Slider|CircularProgressIndicator|RefreshIndicator)\s*\(").unwrap()
});
static PROVIDER_WATCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(context|ref)\s*\.\s*watch\s*(?:<[^>]+>)?\s*\(").unwrap());
static EVENT_CALLBACK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:on[A-Z]\w*|listener|callback)\s*:\s*$").unwrap());
static SINGLE_PARAMETER_CLOSURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_$]\w*\s*(?:async\s*)?(?P<marker>=>)").unwrap());
static LAYOUT_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(Row|Column)\s*\(").unwrap());
static SIZED_BOX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:const\s+)?SizedBox\s*\(([\s\S]*)\)$").unwrap());
static STABLE_SPACING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:\d+(?:\.\d*)?|[A-Za-z_$]\w*(?:\.[A-Za-z_$]\w*)?)$").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    struct Fixture {
        sources: BTreeMap<String, String>,
        auxiliary: BTreeMap<String, String>,
    }

    impl Fixture {
        fn analyze(&self) -> Vec<Finding> {
            let base = BTreeMap::new();
            let changed = BTreeSet::new();
            let context = SourceAnalysisContext::with_auxiliary(
                &self.sources,
                &base,
                &changed,
                false,
                &self.auxiliary,
            );
            analyze(&context)
        }
    }

    #[test]
    fn reports_complete_quality_rule_family() {
        let children = (0..13)
            .map(|index| format!("Text(\"{index}\"),"))
            .collect::<String>();
        let source = format!(
            r#"class UserCard extends StatelessWidget {{
 final String name;
 UserCard({{required this.name}});
}}
class Editor extends StatefulWidget {{ const Editor(); }}
class Page extends StatelessWidget {{
 Widget build(BuildContext context) {{
  setState(() {{}});
  final controller = TextEditingController();
  if (Platform.isIOS) return Switch(value: true, onChanged: update);
  return BlocBuilder<AppBloc, AppState>(builder: (context, state) {{ Navigator.of(context).pop(); return Form(child: TextFormField(onFieldSubmitted: submit)); }});
 }}
 Widget services() => Text(GetIt.I.get<User>().name);
}}
Future<void> submit(BuildContext context) async {{
 await save();
 Navigator.of(context).pop();
}}
Widget list() => ListView(children: [{children}]);
Widget images() => Column(children: [Image.network(a), Image.network(b), Image.network(c)]);
Widget label() => const Text('Save changes');
Widget asset() => Image.asset('assets/logo.png');
Widget action(Ref ref) => GestureDetector(onTap: () {{ ref.watch(selectionProvider); }});
Widget spaced() => Column(children: [Header(), SizedBox(height: 12), Content(), SizedBox(height: 12), Footer()]);
"#
        );
        let fixture = Fixture {
            sources: BTreeMap::from([("lib/page.dart".to_owned(), source)]),
            auxiliary: BTreeMap::from([
                (
                    "pubspec.yaml".to_owned(),
                    "flutter:\n  generate: true\ndependencies:\n  cached_network_image: ^3.0.0\n  assets:\n    - assets/logo.png"
                        .to_owned(),
                ),
                ("@exists/assets/logo.png".to_owned(), "false".to_owned()),
            ]),
        };
        let codes = fixture
            .analyze()
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            codes,
            BTreeSet::from([
                "flutter-asset-reference-missing".to_owned(),
                "flutter-bloc-side-effect-in-builder".to_owned(),
                "flutter-context-after-await".to_owned(),
                "flutter-controller-created-in-build".to_owned(),
                "flutter-form-without-validation".to_owned(),
                "flutter-getit-lookup-in-widget".to_owned(),
                "flutter-image-cache-bypass".to_owned(),
                "flutter-listview-large-children".to_owned(),
                "flutter-missing-widget-key".to_owned(),
                "flutter-platform-branch-without-adaptation".to_owned(),
                "flutter-provider-watch-in-callback".to_owned(),
                "flutter-repeated-sizedbox-spacing".to_owned(),
                "flutter-setstate-in-build".to_owned(),
                "flutter-unlocalized-user-text".to_owned(),
                "flutter-widget-missing-const-constructor".to_owned(),
            ])
        );
    }

    #[test]
    fn accepts_safe_quality_contracts_and_exception_shapes() {
        let fixture = Fixture {
            sources: BTreeMap::from([(
                "lib/page.dart".to_owned(),
                r#"class Card extends StatelessWidget {
 final String name;
 const Card({required this.name});
}
class Editor extends StatefulWidget { const Editor({super.key}); }
Future<void> submit(BuildContext context) async {
 await save();
 if (!context.mounted) return;
 Navigator.of(context).pop();
}
Widget build(BuildContext context, Ref ref) {
 final controller = retainedController;
 ref.watch(selectionProvider);
 return Form(child: TextFormField(validator: validate));
}
Widget action(Ref ref) => GestureDetector(onTap: () { ref.read(selectionProvider); });
Widget spaced() => Column(spacing: 12, children: [Header(), Content(), Footer()]);
Widget asset() => Image.asset('assets/logo.png');
"#
                .to_owned(),
            )]),
            auxiliary: BTreeMap::from([
                (
                    "pubspec.yaml".to_owned(),
                    "flutter:\n  assets:\n    - assets/".to_owned(),
                ),
                ("@exists/assets/logo.png".to_owned(), "true".to_owned()),
            ]),
        };
        assert!(fixture.analyze().is_empty());
    }
    #[test]
    fn reports_context_only_after_completed_unguarded_async_gaps() {
        let fixture = Fixture {
            sources: BTreeMap::from([(
                "lib/navigation.dart".to_owned(),
                r#"Future<void> submit(BuildContext context) async {
  await save();
  Navigator.of(context).pop();
}
Future<void> start(BuildContext context) async {
  await context.push('/next');
}
Future<void> guarded(BuildContext context) async {
  await save();
  if (!context.mounted) return;
  Navigator.of(context).pop();
}
void register() {
  callback((context) async {
    await save();
    Navigator.of(context).pop();
  });
}
Future<void> reportFailure() async {
  await callback();
  FlutterErrorDetails(context: ErrorDescription('callback failed'));
}"#
                .to_owned(),
            )]),
            auxiliary: BTreeMap::new(),
        };

        let findings = fixture
            .analyze()
            .into_iter()
            .filter(|finding| finding.code == "flutter-context-after-await")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        assert_eq!(findings, [1, 14]);
    }

    #[test]
    fn masks_commented_callbacks_at_utf8_boundaries() {
        let fixture = Fixture {
            sources: BTreeMap::from([(
                "lib/page.dart".to_owned(),
                "class Commented {\n  Widget build(BuildContext context) {\n    // café setState(() {});\n    return const Placeholder();\n  }\n}\nclass Active {\n  Widget build(BuildContext context) {\n    setState(() {});\n    return const Placeholder();\n  }\n}\n".to_owned(),
            )]),
            auxiliary: BTreeMap::new(),
        };
        let set_state_lines = fixture
            .analyze()
            .into_iter()
            .filter(|finding| finding.code == "flutter-setstate-in-build")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();

        assert_eq!(set_state_lines, vec![7]);
    }
    #[test]
    fn skips_incomplete_widgets_without_losing_later_valid_findings() {
        let fixture = Fixture {
            sources: BTreeMap::from([(
                "lib/page.dart".to_owned(),
                r#"class Broken extends StatelessWidget {
  Widget build(BuildContext context) {
    setState(() {});
class Card extends StatelessWidget {
  final String name;
  Card({required this.name});
}
class Page extends StatelessWidget {
  Widget build(BuildContext context) {
    setState(() {});
    return const Placeholder();
  }
}"#
                .to_owned(),
            )]),
            auxiliary: BTreeMap::new(),
        };

        let findings = fixture
            .analyze()
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "flutter-setstate-in-build" | "flutter-widget-missing-const-constructor"
                )
            })
            .map(|finding| (finding.code, finding.line))
            .collect::<BTreeSet<_>>();

        assert_eq!(
            findings,
            BTreeSet::from([
                ("flutter-setstate-in-build".to_owned(), 8),
                ("flutter-widget-missing-const-constructor".to_owned(), 4),
            ])
        );
    }
}
