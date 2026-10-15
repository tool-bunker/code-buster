use std::sync::LazyLock;

use regex::Regex;

use crate::dart_core_rules::mask_comments;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{index::DartSourceIndex, matching_delimiter};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        let source = mask_comments(index.masked_lines(path)).join("\n");
        for method in build_methods(&source) {
            findings.extend(analyze_build(path, &source, &method));
        }
    }
    findings
}

#[derive(Debug)]
struct BuildMethod {
    body_start: usize,
    body_end: usize,
    line: usize,
    end_line: usize,
}

fn build_methods(source: &str) -> Vec<BuildMethod> {
    let mut result = Vec::new();
    for class in CLASS_START.find_iter(source) {
        let class_open = class.end() - 1;
        let Some(class_close) = matching_delimiter(source, class_open, b'{', b'}') else {
            continue;
        };
        let class_body = &source[class_open + 1..class_close];
        for declaration in BUILD_METHOD.find_iter(class_body) {
            let absolute = class_open + 1 + declaration.start();
            if brace_depth(source, class_open + 1, absolute) != 0 {
                continue;
            }
            let marker = class_open + 1 + declaration.end();
            let body_marker = source.as_bytes()[marker - 1];
            let (body_start, body_end) = if body_marker == b'{' {
                let open = marker - 1;
                let Some(close) = matching_delimiter(source, open, b'{', b'}') else {
                    continue;
                };
                (open + 1, close)
            } else {
                let start = marker;
                let Some(end) = statement_end(source, start, class_close) else {
                    continue;
                };
                (start, end)
            };
            result.push(BuildMethod {
                body_start,
                body_end,
                line: line_at(source, annotated_declaration_start(source, absolute)),
                end_line: line_at(source, body_end),
            });
        }
    }
    result
}

fn analyze_build(path: &str, source: &str, method: &BuildMethod) -> Vec<Finding> {
    BuildAnalysis::new(path, source, method).findings()
}

struct BuildAnalysis<'a> {
    path: &'a str,
    source: &'a str,
    method: &'a BuildMethod,
    body: &'a str,
    nodes: Vec<WidgetNode>,
}

impl<'a> BuildAnalysis<'a> {
    fn new(path: &'a str, source: &'a str, method: &'a BuildMethod) -> Self {
        Self {
            path,
            source,
            method,
            body: &source[method.body_start..method.body_end],
            nodes: widget_nodes(source, method),
        }
    }

    fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.collect_async_source_findings(&mut findings);
        self.collect_global_key_findings(&mut findings);
        self.collect_widget_findings(&mut findings);
        findings
    }

    fn collect_async_source_findings(&self, findings: &mut Vec<Finding>) {
        for captures in FUTURE_ARGUMENT.captures_iter(self.body) {
            let call = captures.get(1).unwrap().as_str();
            if call != "Future" {
                findings.push(self.build_finding(
                    "flutter-future-created-in-build",
                    &format!("Future `{call}()` is created during build"),
                ));
            }
        }
        if STREAM_CREATION.is_match(self.body) || STREAM_ARGUMENT.is_match(self.body) {
            findings.push(self.build_finding(
                "flutter-stream-created-in-build",
                "a Stream or subscription source is created during build",
            ));
        }
    }

    fn collect_global_key_findings(&self, findings: &mut Vec<Finding>) {
        if self.has_eager_global_key() {
            findings.push(self.build_finding(
                "flutter-global-key-created-in-build",
                "GlobalKey is created during build",
            ));
        }
    }

    fn has_eager_global_key(&self) -> bool {
        let mut global_keys = self
            .nodes
            .iter()
            .filter(|node| node.type_name == "GlobalKey");
        let Some(first) = global_keys.next() else {
            return false;
        };
        let parsed_closures = closures(self.body);
        std::iter::once(first)
            .chain(global_keys)
            .any(|node| !deferred_creation(&parsed_closures, node.start - self.method.body_start))
    }

    fn collect_widget_findings(&self, findings: &mut Vec<Finding>) {
        for (index, node) in self.nodes.iter().enumerate() {
            let parent = nearest_parent(&self.nodes, index);
            let node_source = &self.source[node.start..=node.end];
            findings.extend(
                [
                    self.unbounded_scrollable_finding(node, parent, node_source),
                    self.gesture_semantic_finding(index, node, node_source),
                    self.expanded_parent_finding(node, parent),
                    self.network_image_finding(node, node_source),
                ]
                .into_iter()
                .flatten(),
            );
        }
    }

    fn unbounded_scrollable_finding(
        &self,
        node: &WidgetNode,
        parent: Option<&str>,
        node_source: &str,
    ) -> Option<Finding> {
        (matches!(node.type_name.as_str(), "ListView" | "GridView")
            && parent.is_some_and(|name| matches!(name, "Column" | "Row" | "Flex"))
            && !SHRINK_WRAP.is_match(node_source))
        .then(|| {
            self.node_finding(
                "flutter-unbounded-scrollable",
                node,
                "a scrollable may be unbounded inside a flex layout",
            )
        })
    }

    fn gesture_semantic_finding(
        &self,
        index: usize,
        node: &WidgetNode,
        node_source: &str,
    ) -> Option<Finding> {
        (node.type_name == "Listener"
            && POINTER_DOWN_OR_UP.is_match(node_source)
            && !POINTER_MOVE.is_match(node_source)
            && !has_semantic_ancestor(&self.nodes, index))
        .then(|| {
            self.node_finding(
                "flutter-gesture-semantic-gap",
                node,
                "a raw pointer target is built without semantic context",
            )
        })
    }

    fn expanded_parent_finding(&self, node: &WidgetNode, parent: Option<&str>) -> Option<Finding> {
        (node.type_name == "Expanded"
            && parent.is_some_and(|name| {
                matches!(
                    name,
                    "Align"
                        | "Center"
                        | "ColoredBox"
                        | "Container"
                        | "DecoratedBox"
                        | "Padding"
                        | "SizedBox"
                        | "Stack"
                )
            }))
        .then(|| {
            self.node_finding(
                "flutter-expanded-outside-flex",
                node,
                "Expanded is built without a surrounding Flex, Row, or Column",
            )
        })
    }

    fn network_image_finding(&self, node: &WidgetNode, node_source: &str) -> Option<Finding> {
        (node.type_name == "Image"
            && node.constructor.as_deref() == Some("network")
            && !ERROR_BUILDER.is_match(node_source))
        .then(|| {
            self.build_finding(
                "flutter-image-network-no-error-builder",
                "Image.network has no errorBuilder fallback",
            )
        })
    }

    fn build_finding(&self, code: &str, message: &str) -> Finding {
        finding(
            code,
            self.path,
            self.method.line,
            self.method.end_line,
            message,
        )
    }

    fn node_finding(&self, code: &str, node: &WidgetNode, message: &str) -> Finding {
        finding(
            code,
            self.path,
            line_at(self.source, node.start),
            line_at(self.source, node.end),
            message,
        )
    }
}

#[derive(Debug)]
struct WidgetNode {
    type_name: String,
    constructor: Option<String>,
    start: usize,
    end: usize,
}

fn widget_nodes(source: &str, method: &BuildMethod) -> Vec<WidgetNode> {
    let text = &source[method.body_start..method.body_end];
    let mut nodes = Vec::new();
    for captures in WIDGET_CALL.captures_iter(text) {
        let whole = captures.get(0).unwrap();
        let open = method.body_start + whole.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        if close > method.body_end {
            continue;
        }
        nodes.push(WidgetNode {
            type_name: captures.name("type").unwrap().as_str().to_owned(),
            constructor: captures
                .name("constructor")
                .map(|value| value.as_str().to_owned()),
            start: method.body_start + whole.start(),
            end: close,
        });
    }
    nodes.sort_by_key(|node| (node.start, node.end));
    nodes
}

fn nearest_parent(nodes: &[WidgetNode], child: usize) -> Option<&str> {
    let child = &nodes[child];
    nodes
        .iter()
        .filter(|candidate| candidate.start < child.start && child.end < candidate.end)
        .min_by_key(|candidate| candidate.end - candidate.start)
        .map(|candidate| candidate.type_name.as_str())
}

fn has_semantic_ancestor(nodes: &[WidgetNode], child: usize) -> bool {
    let child = &nodes[child];
    nodes.iter().any(|candidate| {
        candidate.start < child.start
            && child.end < candidate.end
            && matches!(candidate.type_name.as_str(), "Semantics" | "Tooltip")
    })
}

#[derive(Debug)]
struct Closure {
    start: usize,
    end: usize,
    deferred: bool,
}

fn deferred_creation(parsed_closures: &[Closure], creation: usize) -> bool {
    parsed_closures
        .iter()
        .filter(|closure| closure.start < creation && creation < closure.end)
        .max_by_key(|closure| closure.start)
        .is_some_and(|closure| closure.deferred)
}

fn closures(source: &str) -> Vec<Closure> {
    let mut closures = Vec::new();
    for captures in CLOSURE_START.captures_iter(source) {
        let marker = captures.name("marker").unwrap();
        let body_start = marker.end();
        let end = if marker.as_str() == "{" {
            matching_delimiter(source, marker.start(), b'{', b'}').unwrap_or(source.len())
        } else {
            arrow_expression_end(source, body_start)
        };
        let Some(prefix) = captures.name("prefix") else {
            continue;
        };
        let prefix = &source[..prefix.end()];
        closures.push(Closure {
            start: body_start,
            end,
            deferred: deferred_parent(prefix),
        });
    }
    closures
}

fn deferred_parent(prefix: &str) -> bool {
    let prefix = prefix.trim_end();
    if prefix.ends_with(':') || prefix.ends_with('=') {
        return true;
    }
    let Some(invocation) = TRAILING_INVOCATION.captures(prefix) else {
        return prefix.ends_with(',');
    };
    let name = invocation.get(1).unwrap().as_str();
    name != "hooks.useMemoized"
}

fn arrow_expression_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depths = [0usize; 3];
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        match *byte {
            b'(' => depths[0] += 1,
            b')' if depths[0] > 0 => depths[0] -= 1,
            b'[' => depths[1] += 1,
            b']' if depths[1] > 0 => depths[1] -= 1,
            b'{' => depths[2] += 1,
            b'}' if depths[2] > 0 => depths[2] -= 1,
            b',' | b';' if depths == [0, 0, 0] => return index,
            _ => {}
        }
    }
    source.len()
}

fn brace_depth(source: &str, start: usize, end: usize) -> usize {
    source.as_bytes()[start..end]
        .iter()
        .fold(0usize, |depth, byte| match *byte {
            b'{' => depth + 1,
            b'}' => depth.saturating_sub(1),
            _ => depth,
        })
}

fn statement_end(source: &str, start: usize, limit: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depths = [0usize; 3];
    for (index, byte) in bytes.iter().enumerate().take(limit).skip(start) {
        match *byte {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'[' => depths[1] += 1,
            b']' => depths[1] = depths[1].saturating_sub(1),
            b'{' => depths[2] += 1,
            b'}' => depths[2] = depths[2].saturating_sub(1),
            b';' if depths == [0, 0, 0] => return Some(index),
            _ => {}
        }
    }
    None
}

fn annotated_declaration_start(source: &str, offset: usize) -> usize {
    let mut start = source[..offset].rfind('\n').map_or(0, |index| index + 1);
    while start > 0 {
        let previous_end = start - 1;
        let previous_start = source[..previous_end]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        if !source[previous_start..previous_end]
            .trim_start()
            .starts_with('@')
        {
            break;
        }
        start = previous_start;
    }
    start
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding(code: &str, path: &str, line: usize, end_line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Flutter build metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Flutter build severity must be valid"),
        path: path.to_owned(),
        line,
        end_line,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+[A-Za-z_]\w*[^\{;]*\{").unwrap());
static BUILD_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[A-Za-z_]\w*(?:<[^>{}]+>)?\s+)?build\s*\([^;{}]*?\)\s*(?:async\s*)?(?:\{|=>)")
        .unwrap()
});
static FUTURE_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfuture\s*:\s*([A-Za-z_]\w*)\s*\(").unwrap());
static STREAM_CREATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bStream(?:Controller)?(?:<[^>]+>)?\s*\(").unwrap());
static STREAM_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bstream\s*:\s*[A-Za-z_]\w*\s*\(").unwrap());
static WIDGET_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?P<type>[A-Z][A-Za-z0-9_]*)(?:<[^>()]+>)?(?:\.(?P<constructor>[A-Za-z_]\w*))?\s*\(",
    )
    .unwrap()
});
static SHRINK_WRAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bshrinkWrap\s*:\s*true\b").unwrap());
static POINTER_DOWN_OR_UP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bonPointer(?:Down|Up)\s*:").unwrap());
static POINTER_MOVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bonPointerMove\s*:").unwrap());
static ERROR_BUILDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\berrorBuilder\s*:").unwrap());
static CLOSURE_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)(?P<prefix>^|[(:,=\[\{])\s*\([^)]*\)\s*(?P<marker>=>|\{)").unwrap()
});
static TRAILING_INVOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\(\s*$").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn finds_async_values_and_direct_global_keys_created_in_build() {
        let fixture = Fixture::new([(
            "lib/advanced.dart",
            "class RiskyState {\n  @override\n  Widget build(BuildContext context) {\n    final key = GlobalKey();\n    final stream = StreamController<int>();\n    return FutureBuilder(future: fetch(), builder: buildResult);\n  }\n}",
        )]);

        assert_eq!(
            code_lines(&fixture),
            vec![
                ("flutter-future-created-in-build".to_owned(), 2),
                ("flutter-global-key-created-in-build".to_owned(), 2),
                ("flutter-stream-created-in-build".to_owned(), 2),
            ]
        );
    }

    #[test]
    fn allows_deferred_global_keys_but_rejects_targeted_memoization() {
        let fixture = Fixture::new([
            (
                "lib/direct.dart",
                "class Direct { Widget build(BuildContext context) { final key = GlobalKey<FormState>(); return Form(key: key); } }",
            ),
            (
                "lib/memoized.dart",
                "class Memoized { Widget build(BuildContext context) { final key = useMemoized(() => GlobalKey<FormState>()); return Form(key: key); } }",
            ),
            (
                "lib/event.dart",
                "class Event { Widget build(BuildContext context) => Button(onTap: () => Dialog(formKey: GlobalKey<FormState>())); }",
            ),
            (
                "lib/assigned.dart",
                "class Assigned { Widget build(BuildContext context) { final open = () => Dialog(formKey: GlobalKey<FormState>()); return Button(onTap: open); } }",
            ),
            (
                "lib/positional.dart",
                "class Positional { Widget build(BuildContext context) => CallbackHost(() => Form(key: GlobalKey<FormState>())); }",
            ),
            (
                "lib/unrelated.dart",
                "class Unrelated { Widget build(BuildContext context) { final key = hooks.useMemoized(() => GlobalKey<FormState>()); return Form(key: key); } }",
            ),
        ]);
        let paths = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "flutter-global-key-created-in-build")
            .map(|finding| finding.path)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            paths,
            BTreeSet::from([
                "lib/direct.dart".to_owned(),
                "lib/unrelated.dart".to_owned(),
            ])
        );
    }

    #[test]
    fn finds_unbounded_scrollables_and_pointer_only_controls() {
        let risky = Fixture::new([(
            "lib/risky.dart",
            "class Risky { Widget build(BuildContext context) => Column(children: [ ListView(children: const []), Listener(onPointerUp: activate, child: const Text('Run')), ]); }",
        )]);
        let safe = Fixture::new([(
            "lib/safe.dart",
            "class Safe { Widget build(BuildContext context) => Column(children: [ Expanded(child: ListView(children: const [])), Semantics(child: Listener(onPointerUp: activate, child: const Text('Run'))), Listener(onPointerDown: track, onPointerMove: track, child: const Text('Track')), ]); }",
        )]);

        assert_eq!(
            codes(&risky),
            BTreeSet::from([
                "flutter-gesture-semantic-gap".to_owned(),
                "flutter-unbounded-scrollable".to_owned(),
            ])
        );
        assert!(codes(&safe).is_empty());
    }

    #[test]
    fn validates_expanded_parents_and_network_image_fallbacks() {
        let risky = Fixture::new([(
            "lib/risky.dart",
            "class Risky { Widget build(BuildContext context) => Container(child: Expanded(child: Image.network('url', frameBuilder: frame))); }",
        )]);
        let safe = Fixture::new([
            (
                "lib/safe.dart",
                "class Safe { Widget build(BuildContext context) => Column(children: [ Expanded(child: Image.network('url', errorBuilder: imageError)), ]); }",
            ),
            (
                "lib/custom.dart",
                "class Custom { Widget build(BuildContext context) => Padding(child: FlowyOptionTile.text(content: Expanded(child: Text('Create')))); }",
            ),
        ]);

        assert_eq!(
            codes(&risky),
            BTreeSet::from([
                "flutter-expanded-outside-flex".to_owned(),
                "flutter-image-network-no-error-builder".to_owned(),
            ])
        );
        assert!(codes(&safe).is_empty());
    }

    #[test]
    fn accepts_stable_future_and_stream_arguments() {
        let fixture = Fixture::new([(
            "lib/stable.dart",
            "class Stable { Widget build(BuildContext context) => Column(children: [ FutureBuilder(future: Future.value(result), builder: buildFuture), StreamBuilder(stream: retainedStream, builder: buildStream), ]); }",
        )]);

        assert!(codes(&fixture).is_empty());
    }

    fn codes(fixture: &Fixture) -> BTreeSet<String> {
        analyze(&fixture.context())
            .into_iter()
            .map(|finding| finding.code)
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
