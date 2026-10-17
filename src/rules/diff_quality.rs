use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::{NoExpand, Regex};
use serde_json::{Map, Value};

use crate::findings::{Finding, Severity};
use crate::generic_rules::mask_generic_rule_strings;
use crate::rule_catalog;
use crate::semantic_diff::{SemanticDiff, SemanticFileDiff, SemanticLine};
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let Some(change) = focused_diff(context) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    findings.extend(broad_refactors(context, &change));
    findings.extend(style_drift(context, &change));
    findings.extend(changed_behavior_without_test(context, &change));
    findings.extend(stale_contract_references(context, &change));
    findings.extend(risky_changes_without_test(context, &change));
    findings.extend(changed_duplicate_implementations(context, &change));
    findings.extend(optional_feature_bundles(context, &change));
    findings.extend(abstraction_cost_exceeds_use(context, &change));
    findings.extend(new_unused_declarations(context, &change));
    findings.extend(single_caller_wrappers(context, &change));
    findings.extend(unrelated_symbol_churn(context, &change));
    findings.extend(boolean_option_explosions(context, &change));
    findings.extend(caller_side_guard_duplication(context, &change));
    findings.extend(thin_dependencies(context, &change));
    findings
}

fn focused_diff(context: &SourceAnalysisContext<'_>) -> Option<SemanticDiff> {
    if !context.has_changed_base() || context.base_sources().is_empty() {
        return None;
    }
    let change = SemanticDiff::from_context(context);
    change.is_focused().then_some(change)
}

fn broad_refactors(_context: &SourceAnalysisContext<'_>, change: &SemanticDiff) -> Vec<Finding> {
    change
        .production_files()
        .filter_map(|file| {
            let style_edits = file.style_only_edits();
            (file.behavior_additions() >= 1 && style_edits >= 6).then(|| {
                finding(
                    "broad-refactor-in-focused-change",
                    &file.path,
                    file.added_lines[0].number,
                    format!(
                        "focused behavior change includes {style_edits} unrelated style-equivalent edits"
                    ),
                    "high",
                    Vec::new(),
                )
            })
        })
        .collect()
}

fn style_drift(_context: &SourceAnalysisContext<'_>, change: &SemanticDiff) -> Vec<Finding> {
    change
        .production_files()
        .filter_map(|file| {
            let style_edits = file.style_only_edits();
            (file.behavior_additions() >= 1 && style_edits >= 3).then(|| {
                finding(
                    "style-drift-in-diff",
                    &file.path,
                    file.added_lines[0].number,
                    format!("{style_edits} style-equivalent lines changed beside behavioral edits"),
                    "high",
                    Vec::new(),
                )
            })
        })
        .collect()
}

fn changed_behavior_without_test(
    _context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let tests = change.test_files().collect::<Vec<_>>();
    let mut findings = Vec::new();
    for file in change.production_files() {
        if file.behavior_additions() < 2 || has_related_changed_test(file, &tests) {
            continue;
        }
        let line = file
            .added_lines
            .iter()
            .find(|line| CHANGED_BEHAVIOR_LINE.is_match(&line.text))
            .unwrap_or(&file.added_lines[0]);
        findings.push(finding(
            "changed-behavior-without-test",
            &file.path,
            line.number,
            "changed behavior has no concept-related changed test".to_owned(),
            "medium",
            Vec::new(),
        ));
    }
    findings
}

fn stale_contract_references(
    context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for owner in change.production_files() {
        let old = public_declarations(&owner.before, &owner.path);
        let current = public_declarations(&owner.after, &owner.path);
        for name in old.difference(&current) {
            let Ok(reference) = Regex::new(&format!(r"\b{}\b", regex::escape(name))) else {
                continue;
            };
            for (path, source) in context.sources() {
                if path == &owner.path || TEST_SOURCE_PATH.is_match(path) {
                    continue;
                }
                let raw_lines = source.split('\n').map(str::to_owned).collect::<Vec<_>>();
                let strings_masked = mask_generic_rule_strings(&raw_lines, path);
                let masked = mask_comments(&strings_masked, path.ends_with(".py"));
                let Some(index) = masked.iter().position(|line| reference.is_match(line)) else {
                    continue;
                };
                findings.push(finding(
                    "stale-contract-reference",
                    path,
                    index + 1,
                    format!(
                        "`{}` removed public declaration `{name}`, but this file still references it",
                        owner.path
                    ),
                    "high",
                    vec![owner.path.clone()],
                ));
                break;
            }
        }
    }
    findings
}

fn risky_changes_without_test(
    _context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let tests = change.test_files().collect::<Vec<_>>();
    let mut findings = Vec::new();
    for file in change.production_files() {
        if has_related_changed_test(file, &tests) {
            continue;
        }
        let raw_lines = file
            .after
            .split('\n')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let masked = mask_generic_rule_strings(&raw_lines, &file.path);
        for line in &file.added_lines {
            let Some(category) = risk_category(&masked[line.number - 1]) else {
                continue;
            };
            findings.push(finding(
                "risky-change-without-test",
                &file.path,
                line.number,
                format!("changed {category} behavior has no concept-related changed test"),
                "medium",
                Vec::new(),
            ));
            break;
        }
    }
    findings
}

fn changed_duplicate_implementations(
    context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let index = duplicate_implementation_index(context, change);
    let mut findings = Vec::new();
    for file in change.production_files() {
        emit_changed_duplicate_findings(&mut findings, file, &index);
    }
    findings
}

fn duplicate_implementation_index(
    context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<ChangedFunction> {
    let mut index = Vec::new();
    for (path, source) in context.sources() {
        if !context.changed_paths().contains(path) && !TEST_SOURCE_PATH.is_match(path) {
            index.extend(one_line_functions(path, source));
        }
    }
    for file in change.production_files() {
        index.extend(one_line_functions(&file.path, &file.before));
    }
    index
}

fn emit_changed_duplicate_findings(
    findings: &mut Vec<Finding>,
    file: &SemanticFileDiff,
    index: &[ChangedFunction],
) {
    for added in changed_functions(file) {
        let Some(duplicate) = qualifying_duplicate(&added, &file.before, index) else {
            continue;
        };
        findings.push(changed_duplicate_finding(file, &added, duplicate));
    }
}

fn qualifying_duplicate<'a>(
    added: &ChangedFunction,
    before: &str,
    index: &'a [ChangedFunction],
) -> Option<&'a ChangedFunction> {
    let existing_occurrences = identifier_occurrences(before, &added.name)?;
    if added.body_shape.len() < 24
        || existing_occurrences > 0
        || OPERATION_TOKEN.find_iter(&added.body_shape).count() < 2
    {
        return None;
    }
    index
        .iter()
        .find(|candidate| candidate.name != added.name && candidate.body_shape == added.body_shape)
}

fn changed_duplicate_finding(
    file: &SemanticFileDiff,
    added: &ChangedFunction,
    duplicate: &ChangedFunction,
) -> Finding {
    finding(
        "changed-duplicate-implementation",
        &file.path,
        added.line,
        format!(
            "new `{}` repeats unchanged `{}` behavior",
            added.name, duplicate.name
        ),
        "high",
        vec![duplicate.path.clone()],
    )
}

fn optional_feature_bundles(
    _context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in change.production_files() {
        let options = file
            .added_lines
            .iter()
            .filter(|line| OPTIONAL_CONTROL.is_match(&line.text))
            .count();
        if options >= 3
            && file
                .added_lines
                .iter()
                .any(|line| SPECULATIVE_FEATURE.is_match(&line.text))
        {
            findings.push(finding(
                "optional-feature-bundle",
                &file.path,
                file.added_lines[0].number,
                format!(
                    "change adds {options} optional controls with speculative feature collaborators"
                ),
                "medium",
                Vec::new(),
            ));
        }
    }
    findings
}

fn abstraction_cost_exceeds_use(
    _context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    change
        .production_files()
        .filter(|file| file.declaration_additions() >= 3 && file.behavior_additions() <= 2)
        .map(|file| {
            finding(
                "abstraction-cost-exceeds-use",
                &file.path,
                file.added_lines[0].number,
                format!(
                    "change adds {} declarations for {} behavioral lines",
                    file.declaration_additions(),
                    file.behavior_additions()
                ),
                "medium",
                Vec::new(),
            )
        })
        .collect()
}

fn new_unused_declarations(
    context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let project_source = reference_source(context);
    let mut findings = Vec::new();
    for file in change.production_files() {
        for function in changed_functions(file) {
            if function.is_private
                && identifier_occurrences(&project_source, &function.name) == Some(1)
            {
                findings.push(finding(
                    "new-unused-declaration",
                    &file.path,
                    function.line,
                    format!(
                        "new private declaration `{}` has no references",
                        function.name
                    ),
                    "high",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

fn single_caller_wrappers(
    context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let project_source = reference_source(context);
    let mut findings = Vec::new();
    for file in change.production_files() {
        for function in changed_functions(file) {
            if function.is_private
                && function.is_forwarder
                && identifier_occurrences(&project_source, &function.name) == Some(2)
            {
                findings.push(finding(
                    "single-caller-wrapper",
                    &file.path,
                    function.line,
                    format!(
                        "new private forwarding wrapper `{}` has one caller",
                        function.name
                    ),
                    "high",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

fn unrelated_symbol_churn(
    _context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for functions in change
        .production_files()
        .filter_map(unrelated_symbol_candidates)
    {
        emit_unrelated_symbol_findings(&mut findings, &functions);
    }
    findings
}

fn unrelated_symbol_candidates(file: &SemanticFileDiff) -> Option<Vec<ChangedFunction>> {
    let functions = changed_functions(file);
    (functions.len() >= 4).then_some(functions)
}

fn emit_unrelated_symbol_findings(findings: &mut Vec<Finding>, functions: &[ChangedFunction]) {
    for function in functions {
        if changed_function_connection(function, functions) == Some(false) {
            findings.push(unrelated_symbol_finding(function, functions.len() - 1));
        }
    }
}

fn changed_function_connection(
    function: &ChangedFunction,
    functions: &[ChangedFunction],
) -> Option<bool> {
    for other in functions {
        if other.name == function.name {
            continue;
        }
        let forward_reference = contains_identifier(&function.source, &other.name)?;
        let reverse_reference = contains_identifier(&other.source, &function.name)?;
        if forward_reference || reverse_reference {
            return Some(true);
        }
    }
    Some(false)
}

fn unrelated_symbol_finding(function: &ChangedFunction, peer_count: usize) -> Finding {
    finding(
        "unrelated-symbol-churn",
        &function.path,
        function.line,
        format!(
            "changed symbol `{}` is disconnected from {peer_count} other changed functions",
            function.name
        ),
        "medium",
        Vec::new(),
    )
}

fn boolean_option_explosions(
    _context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in change.production_files() {
        for line in &file.added_lines {
            if !line.text.contains('(') || !line.text.contains(')') {
                continue;
            }
            let count = BOOLEAN_PARAMETER.find_iter(&line.text).count();
            if count >= 3 {
                findings.push(finding(
                    "boolean-option-explosion",
                    &file.path,
                    line.number,
                    format!("new API declares {count} Boolean options"),
                    "high",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

#[derive(Clone)]
struct GuardedCall {
    path: String,
    line: usize,
    callee: String,
}

fn caller_side_guard_duplication(
    context: &SourceAnalysisContext<'_>,
    change: &SemanticDiff,
) -> Vec<Finding> {
    let mut groups = Vec::<(String, Vec<GuardedCall>)>::new();
    for file in change.production_files() {
        let raw_lines = file
            .after
            .split('\n')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let masked = mask_generic_rule_strings(&raw_lines, &file.path);
        for line in &file.added_lines {
            let Some(matched) = GUARDED_CALL.captures(&masked[line.number - 1]) else {
                continue;
            };
            let (Some(guard), Some(callee), Some(argument)) = (
                matched.name("guard"),
                matched.name("callee"),
                matched.name("argument"),
            ) else {
                continue;
            };
            let (guard, callee, argument) = (guard.as_str(), callee.as_str(), argument.as_str());
            let Ok(argument_pattern) = Regex::new(&format!(r"\b{}\b", regex::escape(argument)))
            else {
                continue;
            };
            if !argument_pattern.is_match(guard)
                || !GUARD_EVIDENCE.is_match(guard)
                || !declares_project_function(context, callee)
            {
                continue;
            }
            let shape = WHITESPACE
                .replace_all(
                    &argument_pattern.replace_all(guard, NoExpand("$argument")),
                    "",
                )
                .into_owned();
            let key = format!("{callee}|{shape}");
            let call = GuardedCall {
                path: file.path.clone(),
                line: line.number,
                callee: callee.to_owned(),
            };
            if let Some((_, calls)) = groups.iter_mut().find(|(candidate, _)| *candidate == key) {
                calls.push(call);
            } else {
                groups.push((key, vec![call]));
            }
        }
    }
    let mut findings = Vec::new();
    for (_, calls) in groups {
        if calls.len() < 2 {
            continue;
        }
        findings.push(finding(
            "caller-side-guard-duplication",
            &calls[0].path,
            calls[0].line,
            format!(
                "{} callers add the same guard around `{}`",
                calls.len(),
                calls[0].callee
            ),
            "medium",
            Vec::new(),
        ));
    }
    findings
}

struct NativeCapability {
    package: &'static str,
    import_pattern: Regex,
    replacement: &'static str,
    minimum_node_major: Option<u64>,
}

fn thin_dependencies(context: &SourceAnalysisContext<'_>, change: &SemanticDiff) -> Vec<Finding> {
    if !context.changed_paths().contains("package.json") {
        return Vec::new();
    }
    let added = added_production_dependencies(context);
    let mut findings = Vec::new();
    for capability in NATIVE_CAPABILITIES.iter() {
        if !added.contains(capability.package)
            || capability
                .minimum_node_major
                .is_some_and(|minimum| !supports_node_global(context, minimum))
        {
            continue;
        }
        let mut uses = Vec::new();
        for file in change.production_files() {
            let Some(import) = capability.import_pattern.captures(&file.after) else {
                continue;
            };
            let (Some(complete), Some(binding)) = (import.get(0), import.name("binding")) else {
                continue;
            };
            let binding = binding.as_str();
            let raw_lines = file
                .after
                .split('\n')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let masked = mask_generic_rule_strings(&raw_lines, &file.path).join("\n");
            if identifier_occurrences(&masked, binding) == Some(2) {
                uses.push((file.path.clone(), complete.start(), binding.to_owned()));
            }
        }
        if uses.len() != 1 {
            continue;
        }
        let (path, offset, binding) = &uses[0];
        let source = &context.sources()[path];
        findings.push(finding(
            "thin-dependency-for-trivial-capability",
            path,
            1 + source[..*offset]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            format!(
                "new `{}` dependency is used once for `{binding}`; {} is native",
                capability.package, capability.replacement
            ),
            "high",
            Vec::new(),
        ));
    }
    findings
}

#[derive(Clone)]
struct ChangedFunction {
    path: String,
    name: String,
    line: usize,
    source: String,
    body_shape: String,
    is_private: bool,
    is_forwarder: bool,
}

fn changed_functions(file: &SemanticFileDiff) -> Vec<ChangedFunction> {
    functions_from_lines(&file.path, file.added_lines.iter())
}

fn one_line_functions(path: &str, source: &str) -> Vec<ChangedFunction> {
    let lines = source
        .split('\n')
        .enumerate()
        .map(|(index, text)| SemanticLine {
            number: index + 1,
            text: text.to_owned(),
        })
        .collect::<Vec<_>>();
    functions_from_lines(path, lines.iter())
}

fn functions_from_lines<'a>(
    path: &str,
    lines: impl IntoIterator<Item = &'a SemanticLine>,
) -> Vec<ChangedFunction> {
    let mut result = Vec::new();
    for line in lines {
        let Some(matched) = ONE_LINE_FUNCTION.captures(&line.text) else {
            continue;
        };
        let (Some(name), Some(parameters)) = (matched.name("name"), matched.name("parameters"))
        else {
            continue;
        };
        let (name, parameters) = (name.as_str(), parameters.as_str());
        let Some(body) = matched
            .name("expression")
            .or_else(|| matched.name("body"))
            .map(|value| value.as_str())
        else {
            continue;
        };
        let private = name.starts_with('_') || matched.name("private").is_some();
        let forwarder = FORWARDER.is_match(body.trim());
        let Some(body_shape) = function_body_shape(body, parameters) else {
            continue;
        };
        result.push(ChangedFunction {
            path: path.to_owned(),
            name: name.to_owned(),
            line: line.number,
            source: line.text.clone(),
            body_shape,
            is_private: private,
            is_forwarder: forwarder,
        });
    }
    result
}

fn function_body_shape(body: &str, parameters: &str) -> Option<String> {
    let mut result = body.to_owned();
    let mut names = Vec::new();
    for parameter in parameters.split(',') {
        let declaration = parameter.split('=').next().unwrap_or_default().trim();
        let identifiers = IDENTIFIER
            .find_iter(declaration)
            .map(|matched| matched.as_str())
            .collect::<Vec<_>>();
        if identifiers.is_empty() {
            continue;
        }
        names.push(if declaration.contains(':') {
            identifiers[0]
        } else {
            identifiers[identifiers.len() - 1]
        });
    }
    for (index, name) in names.iter().enumerate() {
        let pattern = Regex::new(&format!(r"\b{}\b", regex::escape(name))).ok()?;
        result = pattern
            .replace_all(&result, NoExpand(&format!("$arg{index}")))
            .into_owned();
    }
    Some(WHITESPACE.replace_all(&result, "").into_owned())
}

fn reference_source(context: &SourceAnalysisContext<'_>) -> String {
    context
        .sources()
        .keys()
        .flat_map(|path| context.masked_lines(path).iter().cloned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn has_related_changed_test(file: &SemanticFileDiff, tests: &[&SemanticFileDiff]) -> bool {
    let concepts = file.concepts();
    tests
        .iter()
        .any(|test| !test.concepts().is_disjoint(&concepts))
}

fn risk_category(line: &str) -> Option<&'static str> {
    if MONEY_TERM.is_match(line) && RISK_OPERATION.is_match(line) {
        Some("money")
    } else if TRUST_BOUNDARY_CALL.is_match(line)
        || (CREDENTIAL_TERM.is_match(line) && RISK_OPERATION.is_match(line))
    {
        Some("authentication or authorization")
    } else if PARSER_CALL.is_match(line) {
        Some("parser or deserialization")
    } else if PATH_BOUNDARY_CALL.is_match(line) {
        Some("path-boundary")
    } else if RECIPIENT_BOUNDARY.is_match(line) {
        Some("recipient privacy")
    } else {
        None
    }
}

// code-buster-ignore complex-function: language-specific public declaration patterns are a bounded dispatch table.
fn public_declarations(source: &str, path: &str) -> BTreeSet<String> {
    let raw_lines = source.split('\n').map(str::to_owned).collect::<Vec<_>>();
    let masked = mask_generic_rule_strings(&raw_lines, path).join("\n");
    let mut patterns = Vec::<&Regex>::new();
    if JS_PATH.is_match(path) {
        patterns.push(&JS_PUBLIC_DECLARATION);
    }
    if path.ends_with(".dart") {
        patterns.push(&DART_PUBLIC_TYPE);
        patterns.push(&DART_PUBLIC_FUNCTION);
    }
    if path.ends_with(".py") {
        patterns.push(&PYTHON_PUBLIC_DECLARATION);
    }
    if path.ends_with(".go") {
        patterns.push(&GO_PUBLIC_DECLARATION);
    }
    if path.ends_with(".rs") {
        patterns.push(&RUST_PUBLIC_DECLARATION);
    }
    if JVM_PATH.is_match(path) {
        patterns.push(&JVM_PUBLIC_DECLARATION);
    }
    let mut result = BTreeSet::new();
    for pattern in patterns {
        for matched in pattern.captures_iter(&masked) {
            let Some(name) = matched.name("name").map(|name| name.as_str()) else {
                continue;
            };
            if name.len() >= 3 && !name.starts_with('_') {
                result.insert(name.to_owned());
            }
        }
    }
    result
}

fn identifier_occurrences(source: &str, identifier: &str) -> Option<usize> {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .ok()
        .map(|pattern| pattern.find_iter(source).count())
}

fn contains_identifier(source: &str, identifier: &str) -> Option<bool> {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .ok()
        .map(|pattern| pattern.is_match(source))
}

fn declares_project_function(context: &SourceAnalysisContext<'_>, name: &str) -> bool {
    let escaped = regex::escape(name);
    let Ok(declaration) = Regex::new(&format!(
        r"(?:^|\n)\s*(?:(?:export|async|public|private|protected|static)\s+)*(?:(?:function|def|fun|fn)\s+{escaped}\s*\(|(?:[A-Za-z_][\w<>,?\[\].]*\s+)+{escaped}\s*\([^;\n]*\)\s*(?:\{{|=>|:))"
    )) else {
        return false;
    };
    if context
        .sources()
        .keys()
        .any(|path| declaration.is_match(&context.masked_lines(path).join("\n")))
    {
        return true;
    }
    let Ok(local_import) = Regex::new(&format!(
        r#"(?:^|\n)\s*(?:import\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}\s*from\s*["']\.|from\s+\.+[\w.]*\s+import\s+[^\n]*\b{escaped}\b)"#
    )) else {
        return false;
    };
    context
        .sources()
        .values()
        .any(|source| local_import.is_match(source))
}

fn added_production_dependencies(context: &SourceAnalysisContext<'_>) -> BTreeSet<String> {
    let current = json_object(context.auxiliary_files().get("package.json"));
    let previous = json_object(context.auxiliary_files().get("@base/package.json"));
    dependency_names(&current)
        .difference(&dependency_names(&previous))
        .cloned()
        .collect()
}

fn json_object(source: Option<&String>) -> Map<String, Value> {
    source
        .and_then(|source| serde_json::from_str::<Value>(source).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn dependency_names(manifest: &Map<String, Value>) -> BTreeSet<String> {
    manifest
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|dependencies| dependencies.keys().cloned().collect())
        .unwrap_or_default()
}

fn supports_node_global(context: &SourceAnalysisContext<'_>, minimum: u64) -> bool {
    let manifest = json_object(context.auxiliary_files().get("package.json"));
    let Some(node) = manifest
        .get("engines")
        .and_then(Value::as_object)
        .and_then(|engines| engines.get("node"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    NODE_LOWER_BOUND
        .captures(node)
        .and_then(|matched| matched.name("major"))
        .and_then(|major| major.as_str().parse::<u64>().ok())
        .is_some_and(|major| major >= minimum)
}

fn mask_comments(lines: &[String], hash_comments: bool) -> Vec<String> {
    CommentMasker::new(hash_comments).mask(lines)
}

struct CommentMasker {
    hash_comments: bool,
    block_depth: usize,
}

enum CommentTransition {
    Code,
    BlockComment,
    LineComment,
}

impl CommentMasker {
    fn new(hash_comments: bool) -> Self {
        Self {
            hash_comments,
            block_depth: 0,
        }
    }

    fn mask(mut self, lines: &[String]) -> Vec<String> {
        let mut masked = Vec::with_capacity(lines.len());
        for line in lines {
            masked.push(self.mask_line(line));
        }
        masked
    }

    fn mask_line(&mut self, line: &str) -> String {
        let bytes = line.as_bytes();
        let mut code = String::with_capacity(bytes.len());
        let mut code_start = (self.block_depth == 0).then_some(0);
        let mut index = 0;
        while index < bytes.len() {
            if self.block_depth > 0 {
                self.consume_block_comment(bytes, &mut index);
                if self.block_depth == 0 {
                    code_start = Some(index);
                }
                continue;
            }

            let code_end = index;
            match self.consume_code(bytes, &mut index) {
                CommentTransition::Code => {}
                CommentTransition::BlockComment => {
                    Self::append_code(&mut code, line, code_start.take(), code_end);
                }
                CommentTransition::LineComment => {
                    Self::append_code(&mut code, line, code_start, code_end);
                    return code;
                }
            }
        }
        Self::append_code(&mut code, line, code_start, line.len());
        code
    }

    fn consume_code(&mut self, bytes: &[u8], index: &mut usize) -> CommentTransition {
        if bytes[*index..].starts_with(b"//") || (self.hash_comments && bytes[*index] == b'#') {
            CommentTransition::LineComment
        } else if bytes[*index..].starts_with(b"/*") {
            self.block_depth = 1;
            *index += 2;
            CommentTransition::BlockComment
        } else {
            *index += 1;
            CommentTransition::Code
        }
    }

    fn consume_block_comment(&mut self, bytes: &[u8], index: &mut usize) {
        if bytes[*index..].starts_with(b"/*") {
            self.block_depth += 1;
            *index += 2;
        } else if bytes[*index..].starts_with(b"*/") {
            self.block_depth -= 1;
            *index += 2;
        } else {
            *index += 1;
        }
    }

    fn append_code(code: &mut String, line: &str, start: Option<usize>, end: usize) {
        if let Some(start) = start {
            code.push_str(&line[start..end]);
        }
    }
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("diff-quality rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("diff-quality severity must be valid"),
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

static CHANGED_BEHAVIOR_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:if|for|while|switch|return|throw|await)\b").unwrap());
static OPTIONAL_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:bool\??\s+\w+\s*=|\w+\s*:\s*(?:true|false)|\w+\s*=\s*(?:True|False))\b")
        .unwrap()
});
static SPECULATIVE_FEATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:cache|validator|validation|notify|notification|retry|callback|hook)\w*\b")
        .unwrap()
});
static BOOLEAN_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:bool(?:ean)?\??\s+[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*:\s*(?:bool|boolean))\b",
    )
    .unwrap()
});
static GUARDED_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bif\s*\(\s*(?P<guard>[^)]*?)\s*\)\s*(?:\{\s*)?(?:await\s+)?(?P<callee>[A-Za-z_$][\w$]*)\s*\(\s*(?P<argument>[A-Za-z_$][\w$]*)").unwrap()
});
static GUARD_EVIDENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:null|nil|None|isEmpty|isNotEmpty|length)\b").unwrap());
static ONE_LINE_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(?P<private>private)\s+)?(?:static\s+)?(?:[A-Za-z_$][\w$<>,?\[\].]*\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<parameters>[^;]*)\)\s*(?:=>\s*(?P<expression>.+);|\{\s*(?:return\s+)?(?P<body>.+);\s*})\s*$").unwrap()
});
static FORWARDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:await\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\s*\([^;]*\)$").unwrap()
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*").unwrap());
static OPERATION_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[.+\-*/%]|\w+\(").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static MONEY_TERM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:amount|balance|currency|fee|money|payment|price|refund|subtotal|tax|total)\b",
    )
    .unwrap()
});
static CREDENTIAL_TERM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:auth|credential|permission|signature|token)\w*\b").unwrap()
});
static RISK_OPERATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:[+\-*/%]=?|[=!<>]=|\b(?:return|throw)\b)").unwrap());
static TRUST_BOUNDARY_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:authenticate|authorize|checkPermission|validateSignature|verifySignature|verifyToken)\s*\(").unwrap()
});
static PARSER_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:decode|deserialize|fromJson|jsonDecode|parse|unmarshal)\s*\(").unwrap()
});
static PATH_BOUNDARY_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:canonicalize|normalize|realpath|resolve|resolveSymbolicLinks)\s*\(")
        .unwrap()
});
static RECIPIENT_BOUNDARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:send|mail)\w*\s*\([^;\n]*(?:bcc|cc|recipients?|to)\s*[:=]").unwrap()
});
static TEST_SOURCE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(?:test|tests|spec|specs|__tests__)(/|$)|(?:_test|\.test|\.spec)\.")
        .unwrap()
});
static JS_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$").unwrap());
static JVM_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(?:cs|java|kt|kts)$").unwrap());
static JS_PUBLIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)\s*export\s+(?:default\s+)?(?:(?:async\s+)?function|class|interface|type|enum|const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)").unwrap()
});
static DART_PUBLIC_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)(?:class|mixin|enum|typedef|extension\s+type)\s+(?P<name>[A-Za-z]\w*)")
        .unwrap()
});
static DART_PUBLIC_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)(?:[A-Za-z][\w<>,?.]*\s+)+(?P<name>[A-Za-z]\w*)\s*\([^;\n]*\)\s*(?:\{|=>)")
        .unwrap()
});
static PYTHON_PUBLIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)(?:async\s+def|def|class)\s+(?P<name>[A-Za-z]\w*)").unwrap()
});
static GO_PUBLIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)(?:func|type|const|var)\s+(?P<name>[A-Z][A-Za-z0-9_]*)").unwrap()
});
static RUST_PUBLIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)\s*pub(?:\([^)]*\))?\s+(?:async\s+)?(?:fn|struct|enum|trait|type|const|static)\s+(?P<name>[A-Za-z]\w*)").unwrap()
});
static JVM_PUBLIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\n)\s*public\s+(?:(?:static|final|abstract|sealed|suspend|async)\s+)*(?:(?:class|interface|enum|record)\s+)?(?:[A-Za-z][\w<>,?.\[\]]*\s+)?(?P<name>[A-Za-z]\w*)\s*(?:\(|\{|=)").unwrap()
});
static NODE_LOWER_BOUND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:[~^]|>=?)?\s*(?P<major>\d+)").unwrap());
static NATIVE_CAPABILITIES: LazyLock<Vec<NativeCapability>> = LazyLock::new(|| {
    [
        ("left-pad", "String.padStart", None),
        ("object-assign", "Object.assign", None),
        ("node-fetch", "global fetch", Some(18)),
        ("abort-controller", "global AbortController", Some(18)),
    ]
    .into_iter()
    .map(|(package, replacement, minimum_node_major)| NativeCapability {
        package,
        import_pattern: Regex::new(&format!(
            r#"(?:import\s+|(?:const|let|var)\s+)(?P<binding>[A-Za-z_$][\w$]*)\s*(?:from\s+|=\s*require\(\s*)["']{}["']"#,
            regex::escape(package)
        ))
        .unwrap(),
        replacement,
        minimum_node_major,
    })
    .collect()
});

include!("diff_quality/tests.rs");
