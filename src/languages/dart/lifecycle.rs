use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::dart_core_rules::mask_comments;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
#[cfg(test)]
use crate::source_analysis_context::SourceAnalysisContext;

use super::{attached_documentation_line, index::DartSourceIndex, matching_delimiter};

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in index.paths() {
        let source = mask_comments(index.masked_lines(path)).join("\n");
        let original = index.source(path);
        for class in classes(&source) {
            findings.extend(owned_resource_findings(path, &source, original, &class));
            findings.extend(listener_findings(path, &source, &class));
        }
    }
    findings
}

#[derive(Debug)]
struct Class<'a> {
    name: &'a str,
    start: usize,
    body_start: usize,
    end: usize,
    fields: Vec<Field>,
}

#[derive(Debug)]
struct Field {
    type_name: String,
    name: String,
    initializer: Option<String>,
    line: usize,
}

fn classes(source: &str) -> Vec<Class<'_>> {
    let mut result = Vec::new();
    for captures in CLASS_START.captures_iter(source) {
        let whole = captures.get(0).unwrap();
        let open = whole.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'{', b'}') else {
            continue;
        };
        result.push(Class {
            name: captures.get(1).unwrap().as_str(),
            start: whole.start(),
            body_start: open + 1,
            end: close,
            fields: class_fields(source, open + 1, close),
        });
    }
    result
}

fn class_fields(source: &str, start: usize, end: usize) -> Vec<Field> {
    let mut fields = Vec::new();
    let bytes = source.as_bytes();
    let mut braces = 0usize;
    let mut member_start = start;
    let mut index = start;
    while index < end {
        match bytes[index] {
            b'{' => braces += 1,
            b'}' => {
                braces = braces.saturating_sub(1);
                if braces == 0 {
                    member_start = index + 1;
                }
            }
            b';' if braces == 0 => {
                fields.extend(parse_field_segment(source, member_start, index + 1));
                member_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    fields
}

fn parse_field_segment(source: &str, start: usize, end: usize) -> Vec<Field> {
    let segment = &source[start..end];
    let Some(captures) = FIELD_DECLARATION.captures(segment) else {
        return Vec::new();
    };
    let whole = captures.get(0).unwrap();
    if !segment[..whole.start()].trim().is_empty() {
        return Vec::new();
    }
    let type_name = captures.name("type").unwrap().as_str().to_owned();
    let variables = captures.name("variables").unwrap();
    if variables.as_str().find('(').is_some_and(|parenthesis| {
        variables
            .as_str()
            .find('=')
            .is_none_or(|assignment| parenthesis < assignment)
    }) {
        return Vec::new();
    }
    split_top_level(variables.as_str(), b',')
        .into_iter()
        .filter_map(|(offset, variable)| {
            let captures = FIELD_VARIABLE.captures(variable.trim())?;
            let name = captures.get(1)?;
            let initializer = captures
                .get(2)
                .map(|value| value.as_str().trim().to_owned());
            let relative = variable.find(name.as_str())?;
            let absolute = start + variables.start() + offset + relative;
            Some(Field {
                type_name: type_name.clone(),
                name: name.as_str().to_owned(),
                initializer,
                line: line_at(source, absolute),
            })
        })
        .collect()
}

fn owned_resource_findings(
    path: &str,
    source: &str,
    original: &str,
    class: &Class<'_>,
) -> Vec<Finding> {
    let text = &source[class.start..=class.end];
    let mut findings = Vec::new();
    for field in &class.fields {
        let type_name = field.type_name.trim_end_matches('?');
        if CONTROLLER_TYPES.contains(&type_name)
            && field.name.starts_with('_')
            && constructs_controller(text, &field.name, type_name)
            && !calls_action(text, &field.name, "dispose")
        {
            findings.push(finding(
                "dart-controller-not-disposed",
                path,
                field.line,
                &format!("owned controller `{}` is not disposed", field.name),
            ));
        }

        let Some(resource) = resource(type_name) else {
            continue;
        };
        if type_name == class.name
            || field.initializer.is_none() && !assigns_field(text, &field.name)
            || closes_resource(text, &field.name, resource.action)
        {
            continue;
        }
        let mut issue = finding(
            resource.code,
            path,
            attached_documentation_line(original, line_at(source, class.start)),
            &format!(
                "owned {} `{}` is not {}d",
                resource.kind, field.name, resource.action
            ),
        );
        issue.end_line = line_at(source, class.end);
        findings.push(issue);
    }
    findings
}

struct Resource {
    code: &'static str,
    kind: &'static str,
    action: &'static str,
}

fn resource(type_name: &str) -> Option<Resource> {
    let resource = match type_name {
        "Timer" => Resource {
            code: "dart-timer-not-cancelled",
            kind: "timer",
            action: "cancel",
        },
        "IOSink" => Resource {
            code: "dart-iosink-not-closed",
            kind: "sink",
            action: "close",
        },
        "HttpClient" | "http.Client" => Resource {
            code: "dart-http-client-not-closed",
            kind: "HTTP client",
            action: "close",
        },
        "Isolate" => Resource {
            code: "dart-isolate-not-terminated",
            kind: "isolate",
            action: "kill",
        },
        "ReceivePort" => Resource {
            code: "dart-receive-port-not-closed",
            kind: "receive port",
            action: "close",
        },
        "RandomAccessFile" => Resource {
            code: "dart-random-access-file-not-closed",
            kind: "random-access file",
            action: "close",
        },
        _ if type_name.starts_with("StreamSink<") => Resource {
            code: "dart-iosink-not-closed",
            kind: "sink",
            action: "close",
        },
        _ => return None,
    };
    Some(resource)
}

fn constructs_controller(text: &str, field: &str, type_name: &str) -> bool {
    let Ok(pattern) = Regex::new(&format!(
        r"\b{}\s*(?:\?\?=|=)\s*(?:const\s+)?{}(?:\s*\.\s*\w+)?\s*\(",
        regex::escape(field),
        regex::escape(type_name)
    )) else {
        return false;
    };
    pattern.is_match(text)
}

fn assigns_field(text: &str, field: &str) -> bool {
    let Ok(pattern) = Regex::new(&format!(r"\b{}\s*(?:\?\?=|=)", regex::escape(field))) else {
        return false;
    };
    pattern.is_match(text)
}

fn calls_action(text: &str, field: &str, action: &str) -> bool {
    let Ok(pattern) = Regex::new(&format!(
        r"\b{}[!?]?\s*\.\s*{}\s*\(",
        regex::escape(field),
        regex::escape(action)
    )) else {
        return false;
    };
    pattern.is_match(text)
}

fn closes_resource(text: &str, field: &str, action: &str) -> bool {
    if calls_action(text, field, action) {
        return true;
    }
    let Ok(alias) = Regex::new(&format!(
        r"\b(?:final|var)\s+(\w+)\s*=\s*{}\s*;",
        regex::escape(field)
    )) else {
        return false;
    };
    alias.captures_iter(text).any(|captures| {
        let Some((matched, alias_name)) = captures.get(0).zip(captures.get(1)) else {
            return false;
        };
        calls_action(&text[matched.end()..], alias_name.as_str(), action)
    })
}

#[derive(Debug)]
struct ListenerCall {
    target: String,
    callback: String,
    method: &'static str,
    start: usize,
    line: usize,
    end_line: usize,
    scope: usize,
}

fn listener_findings(path: &str, source: &str, class: &Class<'_>) -> Vec<Finding> {
    let text = &source[class.body_start..class.end];
    let calls = listener_calls(source, class, text);
    let disposed_targets = calls
        .iter()
        .filter(|call| call.method == "dispose")
        .map(|call| call.target.clone())
        .collect::<BTreeSet<_>>();
    let removed_targets = calls
        .iter()
        .filter(|call| call.method == "removeListener")
        .map(|call| call.target.clone())
        .collect::<BTreeSet<_>>();
    let removed_callbacks = calls
        .iter()
        .filter(|call| call.method == "removeListener" && !call.callback.is_empty())
        .map(|call| (call.scope, call.callback.clone()))
        .collect::<BTreeSet<_>>();
    let disposed_animations = class
        .fields
        .iter()
        .filter(|field| field.type_name.starts_with("Animation"))
        .filter(|field| {
            field.initializer.as_ref().is_some_and(|initializer| {
                disposed_targets
                    .iter()
                    .any(|target| contains_identifier(initializer, target))
            })
        })
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();

    let mut registrations = BTreeMap::new();
    for call in calls.iter().filter(|call| call.method == "addListener") {
        registrations.entry(call.target.clone()).or_insert(call);
    }
    registrations
        .into_iter()
        .filter_map(|(target, registration)| {
            if removed_targets.contains(&target)
                || removed_callbacks.contains(&(registration.scope, registration.callback.clone()))
                || disposed_targets.contains(&target)
                || disposed_animations.contains(&target)
                || disposed_targets
                    .iter()
                    .any(|disposed| target.contains(disposed))
                || hook_owned_listener(text, registration, &target)
            {
                return None;
            }
            Some(range_finding(
                "flutter-listener-without-remove",
                path,
                registration.line,
                registration.end_line,
                &format!("listener registered on `{target}` is never removed"),
            ))
        })
        .collect()
}

fn listener_calls(source: &str, class: &Class<'_>, text: &str) -> Vec<ListenerCall> {
    let scopes = method_scopes(source, class);
    let mut calls = Vec::new();
    for captures in LISTENER_CALL.captures_iter(text) {
        let Some(target) = captures.name("target") else {
            continue;
        };
        if let Some(call) = listener_call(
            source,
            class,
            &scopes,
            &captures,
            normalize_target(target.as_str()),
        ) {
            calls.push(call);
        }
    }
    for captures in CASCADE_LISTENER.captures_iter(text) {
        let Some(target) = captures.name("target") else {
            continue;
        };
        if let Some(call) = listener_call(
            source,
            class,
            &scopes,
            &captures,
            target.as_str().to_owned(),
        ) {
            calls.push(call);
        }
    }
    calls.sort_by_key(|call| call.start);
    calls
}

fn listener_call(
    source: &str,
    class: &Class<'_>,
    scopes: &[(usize, usize)],
    captures: &Captures<'_>,
    target: String,
) -> Option<ListenerCall> {
    let whole = captures.get(0)?;
    let method = captures.name("method")?;
    let absolute = class.body_start + whole.start();
    Some(ListenerCall {
        target,
        callback: captures
            .name("arguments")
            .map_or("", |arguments| arguments.as_str())
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned(),
        method: method_name(method.as_str()),
        start: absolute,
        line: line_at(source, absolute),
        end_line: listener_call_end_line(
            source,
            class.body_start + method.end(),
            class.body_start + whole.end(),
        ),
        scope: scope_at(scopes, absolute),
    })
}

fn listener_call_end_line(source: &str, mut offset: usize, fallback: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    let end = if source.as_bytes().get(offset) == Some(&b'(') {
        matching_delimiter(source, offset, b'(', b')').unwrap_or(fallback)
    } else {
        fallback
    };
    line_at(source, end)
}

fn method_scopes(source: &str, class: &Class<'_>) -> Vec<(usize, usize)> {
    let text = &source[class.body_start..class.end];
    METHOD_START
        .find_iter(text)
        .filter_map(|matched| {
            let open = class.body_start + matched.end() - 1;
            matching_delimiter(source, open, b'{', b'}').map(|close| (open, close))
        })
        .collect()
}

fn scope_at(scopes: &[(usize, usize)], offset: usize) -> usize {
    scopes
        .iter()
        .filter(|(start, end)| *start < offset && offset < *end)
        .min_by_key(|(start, end)| end - start)
        .map_or(usize::MAX, |(start, _)| *start)
}

fn hook_owned_listener(text: &str, registration: &ListenerCall, target: &str) -> bool {
    let Some(entry) = target.strip_suffix(".value") else {
        return false;
    };
    let Ok(loop_pattern) = Regex::new(&format!(
        r"for\s*\(\s*final\s+{}\s+in\s+([A-Za-z_]\w*)\.entries\s*\)",
        regex::escape(entry)
    )) else {
        return false;
    };
    let Some(loop_match) = loop_pattern.captures(text) else {
        return false;
    };
    let Some(collection) = loop_match.get(1).map(|matched| matched.as_str()) else {
        return false;
    };
    let Ok(collection_pattern) = Regex::new(&format!(
        r"(?s)(?:final|var)\s+{}\s*=\s*<[^;]+use(?:FocusNode|AnimationController|ValueNotifier)\s*\(",
        regex::escape(collection)
    )) else {
        return false;
    };
    registration.scope != usize::MAX && collection_pattern.is_match(text)
}

fn normalize_target(target: &str) -> String {
    target
        .trim()
        .strip_prefix("this.")
        .unwrap_or(target.trim())
        .trim_end_matches(['!', '?'])
        .to_owned()
}

fn method_name(value: &str) -> &'static str {
    match value {
        "addListener" => "addListener",
        "removeListener" => "removeListener",
        "dispose" => "dispose",
        _ => unreachable!("listener call regex limits method names"),
    }
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    let Ok(pattern) = Regex::new(&format!(r"\b{}\b", regex::escape(identifier))) else {
        return false;
    };
    pattern.is_match(source)
}

fn split_top_level(source: &str, separator: u8) -> Vec<(usize, &str)> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut depths = [0usize; 3];
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'(' => depths[0] += 1,
            b')' => depths[0] = depths[0].saturating_sub(1),
            b'[' => depths[1] += 1,
            b']' => depths[1] = depths[1].saturating_sub(1),
            b'{' => depths[2] += 1,
            b'}' => depths[2] = depths[2].saturating_sub(1),
            value if value == separator && depths == [0, 0, 0] => {
                result.push((start, &source[start..index]));
                start = index + 1;
            }
            _ => {}
        }
    }
    result.push((start, &source[start..]));
    result
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn range_finding(code: &str, path: &str, line: usize, end_line: usize, message: &str) -> Finding {
    let mut finding = finding(code, path, line, message);
    finding.end_line = end_line;
    finding
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Dart lifecycle metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart lifecycle severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const CONTROLLER_TYPES: [&str; 6] = [
    "AnimationController",
    "PageController",
    "ScrollController",
    "TabController",
    "TextEditingController",
    "FocusNode",
];

static CLASS_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+([A-Za-z_$][\w$]*)[^\{;]*\{").unwrap());
static FIELD_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^\s*(?:(?:static|late|final|const|covariant)\s+)*(?P<type>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:<[^;=]+>)?\??)\s+(?P<variables>[^;]+);\s*$").unwrap()
});
static FIELD_VARIABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^([A-Za-z_]\w*)\s*(?:=\s*(.+))?$").unwrap());
static LISTENER_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<target>(?:this\.)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)[!?]?\s*\.\s*(?P<method>addListener|removeListener|dispose)\s*\((?P<arguments>[^)]*)\)").unwrap()
});
static CASCADE_LISTENER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)(?P<target>[A-Za-z_]\w*)\s*=\s*[A-Z]\w*(?:<[^>]+>)?(?:\.\w+)?\s*\([^;]*?\.\.(?P<method>addListener|removeListener|dispose)\s*\((?P<arguments>[^)]*)\)").unwrap()
});
static METHOD_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\)|\b(?:get|set)\s+[A-Za-z_]\w*)\s*(?:async\s*)?\{").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn finds_owned_controller_and_operating_system_resources() {
        let fixture = Fixture::new([(
            "lib/resources.dart",
            "class Resources {\n  final TextEditingController _controller = TextEditingController();\n  Timer timer = Timer.run(tick);\n  IOSink sink = openSink();\n  HttpClient client = HttpClient();\n  Isolate isolate = spawnWorker();\n  ReceivePort port = ReceivePort();\n  RandomAccessFile file = openFile();\n  StreamSink<int> events = openEvents();\n}",
        )]);
        let codes = lifecycle_codes(&fixture);

        assert_eq!(
            codes,
            vec![
                "dart-controller-not-disposed",
                "dart-http-client-not-closed",
                "dart-iosink-not-closed",
                "dart-iosink-not-closed",
                "dart-isolate-not-terminated",
                "dart-random-access-file-not-closed",
                "dart-receive-port-not-closed",
                "dart-timer-not-cancelled",
            ]
        );
    }

    #[test]
    fn limits_findings_to_owned_fields_and_accepts_cleanup_aliases() {
        let fixture = Fixture::new([(
            "lib/safe.dart",
            "class HttpClient {\n  static HttpClient? _instance;\n  Timer? timer;\n  TextEditingController? _borrowed;\n  IOSink? _sink;\n\n  void attach(TextEditingController controller) {\n    _borrowed = controller;\n  }\n  void open(File file) {\n    _sink = file.openWrite();\n  }\n  Future<void> close() async {\n    final sink = _sink;\n    _sink = null;\n    await sink?.close();\n  }\n}\nclass Lifecycle {\n  AnimationController? _controller;\n  ReceivePort? receiver;\n  void init() { _controller = AnimationController(); }\n  void dispose() { _controller?.dispose(); }\n}",
        )]);

        assert!(lifecycle_codes(&fixture).is_empty());
    }

    #[test]
    fn reports_only_controllers_constructed_by_the_class() {
        let fixture = Fixture::new([(
            "lib/controllers.dart",
            "class Borrowed {\n  TextEditingController? _controller;\n  void attach(TextEditingController controller) { _controller = controller; }\n}\nclass Owned {\n  TextEditingController? _controller;\n  void init() { _controller = TextEditingController(); }\n}",
        )]);
        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "dart-controller-not-disposed")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 6);
    }

    #[test]
    fn pairs_listener_cleanup_by_receiver_callback_and_disposed_owner() {
        let fixture = Fixture::new([(
            "lib/listeners.dart",
            "class ListenerState {\n  final source = Source();\n  final other = Source();\n  final AnimationController controller = AnimationController();\n  late final Animation<double> animation = controller.drive(tween);\n  late AnimationController cascadedController;\n  late FocusNode focusNode;\n\n  void initState() {\n    this.source.addListener(_changed);\n    other.addListener(_changed);\n    animation.addListener(_changed);\n    cascadedController = AnimationController.unbounded()\n      ..addListener(_changed);\n    focusNode = FocusNode()..addListener(_changed);\n  }\n  void replaceSource(Source oldValue, Source value) {\n    oldValue.removeListener(_moved);\n    value.addListener(_moved);\n  }\n  void dispose() {\n    source.removeListener(_changed);\n    controller.dispose();\n    cascadedController.dispose();\n    focusNode.dispose();\n  }\n}",
        )]);
        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "flutter-listener-without-remove")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 11);
        assert!(findings[0].message.contains("`other`"));
    }

    #[test]
    fn accepts_listeners_on_hook_owned_collection_values() {
        let fixture = Fixture::new([(
            "lib/hooks.dart",
            "class Dialog extends HookWidget {\n  Widget build(BuildContext context) {\n    final nodes = <String, FocusNode>{\n      'terms': useFocusNode(),\n      'privacy': useFocusNode(),\n    };\n    useEffect(() {\n      for (final entry in nodes.entries) {\n        entry.value.addListener(() => update(entry.key));\n      }\n      return null;\n    }, []);\n  }\n}",
        )]);

        assert!(
            analyze(&fixture.context())
                .into_iter()
                .all(|finding| finding.code != "flutter-listener-without-remove")
        );
    }

    #[test]
    fn supports_dollar_class_names_and_multiline_listener_ranges() {
        let fixture = Fixture::new([(
            "lib/generated.dart",
            "class _$GeneratedState {\n  final source = Source();\n\n  void initState() {\n    source.addListener(\n      _changed,\n    );\n  }\n}\n",
        )]);
        let findings = analyze(&fixture.context())
            .into_iter()
            .filter(|finding| finding.code == "flutter-listener-without-remove")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!((findings[0].line, findings[0].end_line), (5, 7));
        assert!(findings[0].message.contains("`source`"));
    }

    #[test]
    fn malformed_dart_does_not_interrupt_lifecycle_findings() {
        let fixture = Fixture::new([(
            "lib/malformed.dart",
            "class Broken {\n  Timer timer = Timer.run(tick), = invalid;\n  IOSink sink = openSink();\n  HttpClient client = HttpClient();\n\n  void initState() {\n    final nodes = <String, FocusNode>{'entry': useFocusNode()};\n    for (final entry in nodes.entries) {\n      entry.value.addListener(_changed);\n    }\n  }\n\n  void dispose() {\n    final sinkAlias = sink;\n    sinkAlias.close();\n  }\n\n  void brokenListener() {\n    source.addListener(\n  }\n}\n\nclass Unclosed {\n  Timer ignored = Timer.run(tick);\n",
        )]);
        let findings = analyze(&fixture.context());
        let actual = findings
            .iter()
            .map(|finding| {
                (
                    finding.code.as_str(),
                    finding.line,
                    finding.message.as_str(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                (
                    "dart-timer-not-cancelled",
                    1,
                    "owned timer `timer` is not canceld",
                ),
                (
                    "dart-http-client-not-closed",
                    1,
                    "owned HTTP client `client` is not closed",
                ),
            ]
        );
    }

    fn lifecycle_codes(fixture: &Fixture) -> Vec<String> {
        let mut codes = analyze(&fixture.context())
            .into_iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        codes.sort();
        codes
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
