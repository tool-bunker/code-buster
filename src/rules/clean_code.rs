use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::generic_rules::mask_generic_rule_strings;
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(public_mutable_state(context));
    findings.extend(commented_out_code(context));
    findings.extend(placeholder_identifiers(context));
    findings.extend(mixed_boundary_responsibilities(context));
    findings.extend(repeated_policy_literals(context));
    findings.extend(inconsistent_peer_file_naming(context));
    findings.extend(changed_public_api_without_test(context));
    findings.extend(changed_complexity_regressions(context));
    findings
}

fn public_mutable_state(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in context
        .sources()
        .keys()
        .filter(|path| is_production_source(path))
    {
        let syntax = MutableStateSyntax::for_path(path);
        let mut scope = MutableStateScope::default();
        for (index, line) in context.masked_lines(path).iter().enumerate() {
            scope.observe_class_declaration(line, syntax);
            if let Some(name) = mutable_state_candidate(line, syntax, &scope)
                && !is_excluded_mutable_state(name)
                && scope.mark_current_type_reported()
            {
                findings.push(public_mutable_state_finding(path, index + 1, name));
            }
            scope.advance(line);
        }
    }
    findings
}

#[derive(Clone, Copy)]
enum MutableStateSyntax {
    Dart,
    Script,
    CSharp,
    Java,
    ExplicitOnly,
}

impl MutableStateSyntax {
    fn for_path(path: &str) -> Self {
        if path.ends_with(".dart") {
            Self::Dart
        } else if is_script_path(path) {
            Self::Script
        } else if path.ends_with(".cs") {
            Self::CSharp
        } else if path.ends_with(".java") {
            Self::Java
        } else {
            Self::ExplicitOnly
        }
    }
}

#[derive(Clone, Copy)]
struct MutableTypeScope {
    depth: isize,
    awaiting_body: bool,
    private_class: bool,
    intentionally_mutable_class: bool,
    externally_visible: bool,
    mutable_state_reported: bool,
}

#[derive(Default)]
struct MutableStateScope {
    depth: isize,
    parenthesis_depth: isize,
    type_scopes: Vec<MutableTypeScope>,
}

impl MutableStateScope {
    fn observe_class_declaration(&mut self, line: &str, syntax: MutableStateSyntax) {
        let Some(name) = CLASS_DECLARATION
            .captures(line)
            .and_then(|class| class.name("name"))
        else {
            return;
        };
        let opening_braces = count_byte(line, b'{');
        let parent_is_visible = self
            .type_scopes
            .last()
            .is_none_or(|scope| scope.externally_visible);
        self.type_scopes.push(MutableTypeScope {
            depth: self.depth + opening_braces.max(1),
            awaiting_body: opening_braces == 0,
            private_class: name.as_str().starts_with('_'),
            intentionally_mutable_class: intentionally_mutable_type(name.as_str()),
            externally_visible: !matches!(
                syntax,
                MutableStateSyntax::CSharp | MutableStateSyntax::Java
            ) || (parent_is_visible && contains_identifier(line, "public")),
            mutable_state_reported: false,
        });
    }

    fn is_direct_member(&self) -> bool {
        self.type_scopes.last().is_some_and(|scope| {
            !scope.awaiting_body && scope.depth == self.depth && self.parenthesis_depth == 0
        })
    }

    fn mark_current_type_reported(&mut self) -> bool {
        let Some(scope) = self.type_scopes.last_mut() else {
            return true;
        };
        if scope.mutable_state_reported {
            return false;
        }
        scope.mutable_state_reported = true;
        true
    }

    fn private_class(&self) -> bool {
        self.type_scopes
            .last()
            .is_some_and(|scope| scope.private_class)
    }

    fn intentionally_mutable_class(&self) -> bool {
        self.type_scopes
            .last()
            .is_some_and(|scope| scope.intentionally_mutable_class)
    }

    fn externally_visible(&self) -> bool {
        self.type_scopes
            .last()
            .is_some_and(|scope| scope.externally_visible)
    }

    fn advance(&mut self, line: &str) {
        let opening_braces = count_byte(line, b'{');
        self.depth += opening_braces - count_byte(line, b'}');
        self.parenthesis_depth += count_byte(line, b'(') - count_byte(line, b')');
        if opening_braces > 0
            && let Some(scope) = self
                .type_scopes
                .last_mut()
                .filter(|scope| scope.awaiting_body)
        {
            scope.depth = self.depth;
            scope.awaiting_body = false;
        }
        while self
            .type_scopes
            .last()
            .is_some_and(|scope| !scope.awaiting_body && self.depth < scope.depth)
        {
            self.type_scopes.pop();
        }
    }
}

fn mutable_state_candidate<'a>(
    line: &'a str,
    syntax: MutableStateSyntax,
    scope: &MutableStateScope,
) -> Option<&'a str> {
    if scope.intentionally_mutable_class() && scope.is_direct_member() {
        return None;
    }
    if let Some(name) = explicit_mutable_field(line) {
        if matches!(
            syntax,
            MutableStateSyntax::CSharp | MutableStateSyntax::Java
        ) && (!scope.is_direct_member() || !scope.externally_visible())
        {
            return None;
        }
        return Some(name);
    }
    if !scope.is_direct_member() {
        return None;
    }
    match syntax {
        MutableStateSyntax::Dart if !scope.private_class() => dart_mutable_field(line),
        MutableStateSyntax::Script => script_mutable_field(line),
        MutableStateSyntax::Dart
        | MutableStateSyntax::CSharp
        | MutableStateSyntax::Java
        | MutableStateSyntax::ExplicitOnly => None,
    }
}

fn is_excluded_mutable_state(name: &str) -> bool {
    name.starts_with('_')
}

fn intentionally_mutable_type(name: &str) -> bool {
    name.strip_prefix("Mutable")
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(char::is_uppercase)
        || ["Config", "Configuration", "Options", "Settings"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn public_mutable_state_finding(path: &str, line: usize, name: &str) -> Finding {
    finding(
        "public-mutable-state",
        path,
        line,
        format!("public mutable field `{name}` exposes writable state"),
        "high",
        Vec::new(),
    )
}

fn explicit_mutable_field(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let remainder = trimmed.strip_prefix("public")?.trim_start();
    let qualifiers = remainder
        .strip_prefix("static")
        .map(str::trim_start)
        .unwrap_or(remainder);
    if ["const", "event", "final", "readonly"]
        .iter()
        .any(|keyword| starts_keyword(qualifiers, keyword))
    {
        return None;
    }
    PUBLIC_FIELD
        .captures(line)
        .and_then(|captures| captures.name("name"))
        .filter(|name| name.as_str() != "operator")
        .map(|name| name.as_str())
}

fn dart_mutable_field(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if starts_keyword(trimmed, "final")
        || starts_keyword(trimmed, "const")
        || trimmed
            .strip_prefix("late")
            .map(str::trim_start)
            .is_some_and(|tail| starts_keyword(tail, "final"))
    {
        return None;
    }
    DART_FIELD
        .captures(line)
        .and_then(|captures| captures.name("name"))
        .map(|name| name.as_str())
}

fn script_mutable_field(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if ["private", "protected", "readonly", "static", "declare"]
        .iter()
        .any(|keyword| starts_keyword(trimmed, keyword))
        || trimmed.starts_with('#')
    {
        return None;
    }
    SCRIPT_FIELD
        .captures(line)
        .and_then(|captures| captures.name("name"))
        .map(|name| name.as_str())
}

fn commented_out_code(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| is_production_source(path))
    {
        let lines = source.split('\n').collect::<Vec<_>>();
        let supports_hash = matches!(extension(path).as_str(), ".mojo" | ".nim" | ".php" | ".py");
        if let Some(candidate) = comment_candidates(&lines, supports_hash)
            .find(|candidate| is_commented_code_candidate(&lines, candidate))
        {
            findings.push(commented_code_finding(path, candidate.line_index + 1));
        }
    }
    findings
}

struct CommentCandidate<'a> {
    line_index: usize,
    body: &'a str,
}

fn comment_candidates<'a>(
    lines: &'a [&'a str],
    supports_hash: bool,
) -> impl Iterator<Item = CommentCandidate<'a>> + 'a {
    lines
        .iter()
        .enumerate()
        .filter_map(move |(line_index, line)| {
            let comment = if supports_hash {
                HASH_OR_SLASH_COMMENT.captures(line)
            } else {
                SLASH_COMMENT.captures(line)
            };
            comment
                .and_then(|captures| captures.name("body"))
                .map(|body| CommentCandidate {
                    line_index,
                    body: body.as_str().trim(),
                })
        })
}

fn is_commented_code_candidate(lines: &[&str], candidate: &CommentCandidate<'_>) -> bool {
    candidate.body.len() >= 8
        && COMMENTED_CODE.is_match(candidate.body)
        && !MEMBER_ACCESS_PROSE.is_match(candidate.body)
        && !DIRECTIVE.is_match(candidate.body)
        && !DOCUMENTATION_PLACEHOLDER.is_match(candidate.body)
        && !LATEX_MATH.is_match(candidate.body)
        && !is_documented_example(lines, candidate.line_index)
        && !is_inline_syntax_example(lines, candidate)
}

fn commented_code_finding(path: &str, line: usize) -> Finding {
    finding(
        "commented-out-code",
        path,
        line,
        "comment contains disabled source code".to_owned(),
        "high",
        Vec::new(),
    )
}

fn is_documented_example(lines: &[&str], line_index: usize) -> bool {
    for index in (0..=line_index).rev() {
        let Some(comment) = HASH_OR_SLASH_COMMENT.captures(lines[index]) else {
            return false;
        };
        if DOCUMENTATION_EXAMPLE.is_match(comment.name("body").unwrap().as_str()) {
            return true;
        }
    }
    false
}

fn is_inline_syntax_example(lines: &[&str], candidate: &CommentCandidate<'_>) -> bool {
    if MULTIPLE_EXAMPLE_STATEMENTS.is_match(candidate.body) {
        return true;
    }
    COMMENTED_DECLARATION.is_match(candidate.body)
        && lines[candidate.line_index + 1..]
            .iter()
            .map(|line| line.trim())
            .find(|line| !line.is_empty() && !HASH_OR_SLASH_COMMENT.is_match(line))
            .is_some_and(|line| OBJECT_PROPERTY.is_match(line))
}

const PLACEHOLDER_NAMES: [&str; 8] = [
    "asdf", "bar", "baz", "dummy", "foo", "stuff", "thing", "whatever",
];

struct PlaceholderIdentifierCandidate<'a> {
    name: &'a str,
    declaration_line: &'a str,
    line: usize,
    scope_depth: isize,
}

fn placeholder_identifiers(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in context
        .sources()
        .keys()
        .filter(|path| is_production_source(path))
    {
        let lines = context.masked_lines(path);
        let candidates = placeholder_identifier_candidates(path, lines);
        findings.extend(
            candidates
                .into_iter()
                .filter(|candidate| qualifies_placeholder_identifier(candidate, lines))
                .map(|candidate| placeholder_identifier_finding(path, candidate)),
        );
    }
    findings
}

fn placeholder_identifier_candidates<'a>(
    path: &str,
    lines: &'a [String],
) -> Vec<PlaceholderIdentifierCandidate<'a>> {
    let comment_only = comment_only_lines(lines, extension(path) == ".py");
    let mut depth = 0;
    let mut candidates = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !comment_only[index] {
            candidates.extend(
                PLACEHOLDER_DECLARATION
                    .captures_iter(line)
                    .map(|declaration| {
                        let complete = declaration.get(0).unwrap();
                        PlaceholderIdentifierCandidate {
                            name: declaration.name("name").unwrap().as_str(),
                            declaration_line: line,
                            line: index + 1,
                            scope_depth: depth + brace_delta(&line[..complete.start()]),
                        }
                    }),
            );
        }
        depth += brace_delta(line);
    }
    candidates
}

fn comment_only_lines(lines: &[String], supports_hash: bool) -> Vec<bool> {
    let mut in_block = false;
    lines
        .iter()
        .map(|line| {
            let trimmed = line.trim_start();
            if in_block {
                if trimmed.contains("*/") {
                    in_block = false;
                }
                return true;
            }
            if trimmed.starts_with("/*") {
                in_block = !trimmed.contains("*/");
                return true;
            }
            trimmed.starts_with("//") || (supports_hash && trimmed.starts_with('#'))
        })
        .collect()
}

fn brace_delta(source: &str) -> isize {
    count_byte(source, b'{') - count_byte(source, b'}')
}

fn qualifies_placeholder_identifier(
    candidate: &PlaceholderIdentifierCandidate<'_>,
    lines: &[String],
) -> bool {
    let normalized = TRAILING_DIGITS.replace(candidate.name, "");
    if !PLACEHOLDER_NAMES
        .iter()
        .any(|name| normalized.eq_ignore_ascii_case(name))
    {
        return false;
    }
    EXPOSED.is_match(candidate.declaration_line)
        || placeholder_identifier_use_count(candidate, lines) >= 3
}

fn placeholder_identifier_use_count(
    candidate: &PlaceholderIdentifierCandidate<'_>,
    lines: &[String],
) -> usize {
    let identifier = Regex::new(&format!(r"\b{}\b", regex::escape(candidate.name))).unwrap();
    let mut depth = lines[..candidate.line - 1]
        .iter()
        .map(|line| brace_delta(line))
        .sum::<isize>();
    let mut uses = 0;
    for line in &lines[candidate.line - 1..] {
        uses += identifier.find_iter(line).count();
        depth += brace_delta(line);
        if candidate.scope_depth > 0 && depth < candidate.scope_depth {
            break;
        }
    }
    uses
}

fn placeholder_identifier_finding(
    path: &str,
    candidate: PlaceholderIdentifierCandidate<'_>,
) -> Finding {
    finding(
        "placeholder-identifier",
        path,
        candidate.line,
        format!(
            "`{}` is a placeholder name used beyond a tiny local scope",
            candidate.name
        ),
        "high",
        Vec::new(),
    )
}

fn mixed_boundary_responsibilities(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context.sources() {
        if !is_production_source(path) {
            continue;
        }
        for function in function_blocks(source) {
            if function.lines < 8 || ORCHESTRATOR_NAME.is_match(&function.name) {
                continue;
            }
            let boundaries = BOUNDARIES
                .iter()
                .filter_map(|(name, pattern)| pattern.is_match(&function.body).then_some(*name))
                .collect::<Vec<_>>();
            if boundaries.len() >= 3 {
                findings.push(finding(
                    "mixed-boundary-responsibility",
                    path,
                    function.line,
                    format!(
                        "{} directly coordinates {} boundaries",
                        function.name,
                        boundaries.join(", ")
                    ),
                    "medium",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

#[derive(Clone, Copy)]
struct PolicyLiteral<'a> {
    concept: &'a str,
    literal: &'a str,
    path: &'a str,
    line: usize,
}

#[derive(Clone, Copy)]
struct PolicyConcept<'a> {
    name: &'a str,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct CapturedPolicyConcept<'a> {
    concept: PolicyConcept<'a>,
    comparison: bool,
    named: bool,
}

#[derive(Clone, Copy)]
struct PolicyLocation<'a> {
    path: &'a str,
    line: usize,
}

struct PolicyGroup<'a> {
    first_seen: usize,
    locations: Vec<PolicyLocation<'a>>,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct PolicyKey<'a> {
    concept: String,
    literal: &'a str,
}

type PolicyGroups<'a> = BTreeMap<PolicyKey<'a>, PolicyGroup<'a>>;

struct QualifiedPolicy<'groups, 'source> {
    concept: &'groups str,
    literal: &'source str,
    group: &'groups PolicyGroup<'source>,
    primary: &'groups PolicyLocation<'source>,
}

fn repeated_policy_literals(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let literals = collect_policy_literals(context);
    let groups = group_policy_literals(literals);
    emit_repeated_policy_literals(qualify_policy_groups(&groups))
}

fn collect_policy_literals<'a>(context: &'a SourceAnalysisContext<'_>) -> Vec<PolicyLiteral<'a>> {
    let mut literals = Vec::new();
    for path in context
        .sources()
        .keys()
        .filter(|path| is_production_source(path))
    {
        for (index, line) in context.masked_lines(path).iter().enumerate() {
            collect_line_policy_literals(line, path, index + 1, &mut literals);
        }
    }
    literals
}

fn collect_line_policy_literals<'a>(
    line: &'a str,
    path: &'a str,
    line_number: usize,
    literals: &mut Vec<PolicyLiteral<'a>>,
) {
    let first_line_literal = literals.len();
    let mut named = Vec::new();
    let mut comparison_concept: Option<PolicyConcept<'a>> = None;
    let mut named_concepts = Vec::new();

    for captures in POLICY_TOKEN.captures_iter(line) {
        if let Some(literal) = captures.name("literal") {
            if let Some(concept) = comparison_concept.take()
                && is_policy_comparison(&line[concept.end..literal.start()])
            {
                push_line_policy_literal(
                    literals,
                    first_line_literal,
                    concept.name,
                    literal.as_str(),
                    path,
                    line_number,
                );
            }
            collect_named_policy_match(
                line,
                literal.start(),
                literal.as_str(),
                &mut named_concepts,
                &mut named,
            );
            continue;
        }

        let Some(captured) = captured_policy_concept(&captures) else {
            continue;
        };
        if let Some((start, literal)) =
            embedded_policy_literal(line, captured.concept.start, captured.concept.name)
        {
            collect_named_policy_match(line, start, literal, &mut named_concepts, &mut named);
        }
        comparison_concept = captured.comparison.then_some(captured.concept);
        if captured.named {
            named_concepts.push(captured.concept);
        }
    }

    for (concept, literal) in named {
        push_line_policy_literal(
            literals,
            first_line_literal,
            concept,
            literal,
            path,
            line_number,
        );
    }
}

fn captured_policy_concept<'a>(
    captures: &regex::Captures<'a>,
) -> Option<CapturedPolicyConcept<'a>> {
    let (matched, comparison, named) = if let Some(matched) = captures.name("named_comparison") {
        (matched, true, true)
    } else if let Some(matched) = captures.name("comparison") {
        (matched, true, false)
    } else {
        (captures.name("named_only")?, false, true)
    };
    Some(CapturedPolicyConcept {
        concept: PolicyConcept {
            name: matched.as_str(),
            start: matched.start(),
            end: matched.end(),
        },
        comparison,
        named,
    })
}

fn collect_named_policy_match<'a>(
    line: &str,
    literal_start: usize,
    literal: &'a str,
    concepts: &mut Vec<PolicyConcept<'a>>,
    matches: &mut Vec<(&'a str, &'a str)>,
) {
    if let Some(concept) = concepts
        .iter()
        .find(|concept| is_named_policy_gap(&line[concept.end..literal_start]))
    {
        matches.push((concept.name, literal));
    }
    concepts.clear();
}

fn embedded_policy_literal<'a>(
    line: &'a str,
    token_start: usize,
    token: &str,
) -> Option<(usize, &'a str)> {
    let offset = token
        .as_bytes()
        .iter()
        .position(|byte| byte.is_ascii_digit())?;
    let start = token_start + offset;
    let remainder = line.get(start..)?;
    let mut length = remainder
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if remainder.as_bytes().get(length) == Some(&b'.') {
        let fractional_digits = remainder
            .as_bytes()
            .get(length + 1..)
            .map_or(0, |fraction| {
                fraction
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count()
            });
        if fractional_digits > 0 {
            length += fractional_digits + 1;
        }
    }
    line.get(start..start + length)
        .map(|literal| (start, literal))
}

fn push_line_policy_literal<'a>(
    literals: &mut Vec<PolicyLiteral<'a>>,
    first_line_literal: usize,
    concept: &'a str,
    literal: &'a str,
    path: &'a str,
    line: usize,
) {
    if is_excluded_policy_literal(concept, literal)
        || literals[first_line_literal..].iter().any(|existing| {
            existing.concept.eq_ignore_ascii_case(concept) && existing.literal == literal
        })
    {
        return;
    }
    literals.push(PolicyLiteral {
        concept,
        literal,
        path,
        line,
    });
}

fn is_policy_comparison(gap: &str) -> bool {
    matches!(gap.trim(), "<" | "<=" | ">" | ">=" | "==" | "!=")
}

fn is_named_policy_gap(gap: &str) -> bool {
    !gap.contains(';') && gap.chars().count() <= 40
}

fn is_excluded_policy_literal(concept: &str, literal: &str) -> bool {
    concept.eq_ignore_ascii_case("count")
        || matches!(literal, "-1" | "0" | "1" | "2" | "10" | "100")
}

fn group_policy_literals<'a>(literals: Vec<PolicyLiteral<'a>>) -> PolicyGroups<'a> {
    let mut groups = PolicyGroups::new();
    for (order, literal) in literals.into_iter().enumerate() {
        let group = groups
            .entry(PolicyKey {
                concept: literal.concept.to_ascii_lowercase(),
                literal: literal.literal,
            })
            .or_insert_with(|| PolicyGroup {
                first_seen: order,
                locations: Vec::new(),
            });
        group.locations.push(PolicyLocation {
            path: literal.path,
            line: literal.line,
        });
    }
    groups
}

fn qualify_policy_groups<'groups, 'source>(
    groups: &'groups PolicyGroups<'source>,
) -> Vec<QualifiedPolicy<'groups, 'source>> {
    let mut qualified = Vec::new();
    for (key, group) in groups {
        let Some(primary) = group.locations.first() else {
            continue;
        };
        if group
            .locations
            .iter()
            .any(|location| location.path != primary.path)
        {
            qualified.push(QualifiedPolicy {
                concept: &key.concept,
                literal: key.literal,
                group,
                primary,
            });
        }
    }
    qualified.sort_unstable_by_key(|policy| policy.group.first_seen);
    qualified
}

fn emit_repeated_policy_literals(policies: Vec<QualifiedPolicy<'_, '_>>) -> Vec<Finding> {
    policies
        .into_iter()
        .map(|policy| {
            finding(
                "repeated-policy-literal",
                policy.primary.path,
                policy.primary.line,
                format!(
                    "policy literal `{}` for `{}` appears {} times without a shared name",
                    policy.literal,
                    policy.concept,
                    policy.group.locations.len()
                ),
                "medium",
                related_policy_paths(&policy),
            )
        })
        .collect()
}

fn related_policy_paths(policy: &QualifiedPolicy<'_, '_>) -> Vec<String> {
    let mut related = Vec::new();
    for location in &policy.group.locations {
        if location.path != policy.primary.path
            && related
                .last()
                .is_none_or(|previous| previous != location.path)
        {
            related.push(location.path.to_owned());
        }
    }
    related
}

// code-buster-ignore complex-function: peer naming analysis requires one directory grouping and style-majority pass.
fn inconsistent_peer_file_naming(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut by_directory = BTreeMap::<String, Vec<String>>::new();
    for path in context.sources().keys().filter(|path| is_source(path)) {
        by_directory
            .entry(posix_directory(path).to_owned())
            .or_default()
            .push(path.clone());
    }
    let role_names = [
        "index",
        "main",
        "benchmark",
        "mod",
        "rules",
        "types",
        "package-info",
        "module-info",
    ];
    let mut findings = Vec::new();
    for peers in by_directory.values() {
        if peers.len() < 6 {
            continue;
        }
        let mut styles = Vec::<(String, Vec<String>)>::new();
        for peer in peers {
            let style = file_style(file_stem(peer));
            if let Some((_, paths)) = styles.iter_mut().find(|(name, _)| *name == style) {
                paths.push(peer.clone());
            } else {
                styles.push((style.to_owned(), vec![peer.clone()]));
            }
        }
        styles.sort_by_key(|entry| std::cmp::Reverse(entry.1.len()));
        if styles[0].1.len() < 5 {
            continue;
        }
        for (style, paths) in styles.iter().skip(1) {
            if !is_naming_outlier(style, paths, &styles[0].0, &role_names) {
                continue;
            }
            findings.push(finding(
                "inconsistent-peer-file-naming",
                &paths[0],
                1,
                format!(
                    "file name is the lone `{style}` outlier among `{}` peers",
                    styles[0].0
                ),
                "high",
                styles[0].1.iter().take(3).cloned().collect(),
            ));
        }
    }
    findings
}

fn is_naming_outlier(
    style: &str,
    paths: &[String],
    dominant_style: &str,
    role_names: &[&str],
) -> bool {
    if paths.len() != 1 || role_names.contains(&file_stem(&paths[0])) {
        return false;
    }
    let stem = file_stem(&paths[0]);
    if dominant_style == "PascalCase"
        && stem.starts_with(|character: char| character.is_ascii_uppercase())
        && stem.contains('_')
    {
        return false;
    }
    dominant_style != "lowercase" || !matches!(style, "snake_case" | "kebab-case")
}

fn changed_public_api_without_test(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    if !context.has_changed_base() || context.changed_paths().is_empty() {
        return Vec::new();
    }
    let changed_tests = context
        .changed_paths()
        .iter()
        .filter(|path| is_test(path))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    for path in context.sources().keys() {
        if !context.changed_paths().contains(path) || is_test(path) {
            continue;
        }
        let Some(index) = context
            .masked_lines(path)
            .iter()
            .position(|line| PUBLIC_API.is_match(line))
        else {
            continue;
        };
        let concepts = path_concepts(path);
        let related_test = changed_tests
            .iter()
            .any(|test| !path_concepts(test).is_disjoint(&concepts));
        if !related_test {
            findings.push(finding(
                "changed-public-api-without-test",
                path,
                index + 1,
                "changed public API has no concept-related changed test".to_owned(),
                "medium",
                Vec::new(),
            ));
        }
    }
    findings
}

fn changed_complexity_regressions(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    if !context.has_changed_base() || context.base_sources().is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (path, source) in context.sources() {
        let Some(before) = context.base_sources().get(path) else {
            continue;
        };
        let old_functions = function_blocks(before)
            .into_iter()
            .map(|function| (function.name.clone(), function))
            .collect::<BTreeMap<_, _>>();
        for current in function_blocks(source) {
            let Some(old) = old_functions.get(&current.name) else {
                continue;
            };
            let current_complexity = complexity(&current.body);
            let old_complexity = complexity(&old.body);
            if current_complexity >= 10 && current_complexity - old_complexity >= 4 {
                findings.push(finding(
                    "changed-complexity-regression",
                    path,
                    current.line,
                    format!(
                        "{} complexity increased from {old_complexity} to {current_complexity}",
                        current.name
                    ),
                    "high",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

#[derive(Clone)]
struct FunctionBlock {
    name: String,
    body: String,
    line: usize,
    lines: usize,
}

fn function_blocks(source: &str) -> Vec<FunctionBlock> {
    let raw_lines = source.split('\n').map(str::to_owned).collect::<Vec<_>>();
    let lines = mask_generic_rule_strings(&raw_lines, "");
    let mut result = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some(declaration) = FUNCTION_DECLARATION.captures(&lines[index]) else {
            index += 1;
            continue;
        };
        if lines[index].contains("=>") {
            index += 1;
            continue;
        }
        let mut depth = 0isize;
        let mut seen_brace = false;
        let mut body = String::new();
        let mut end = index;
        while end < lines.len() {
            let line = &lines[end];
            body.push_str(line);
            body.push('\n');
            let opens = count_byte(line, b'{');
            let closes = count_byte(line, b'}');
            if opens > 0 {
                seen_brace = true;
            }
            depth += opens - closes;
            if seen_brace && depth <= 0 {
                break;
            }
            end += 1;
        }
        if seen_brace {
            result.push(FunctionBlock {
                name: declaration.name("name").unwrap().as_str().to_owned(),
                body,
                line: index + 1,
                lines: end - index + 1,
            });
        }
        index = end + 1;
    }
    result
}

fn complexity(body: &str) -> usize {
    1 + COMPLEXITY_TOKEN.find_iter(body).count()
}

fn is_production_source(path: &str) -> bool {
    is_source(path) && !is_test(path)
}

fn is_source(path: &str) -> bool {
    matches!(
        extension(path).as_str(),
        ".c" | ".cc"
            | ".cpp"
            | ".cs"
            | ".dart"
            | ".go"
            | ".h"
            | ".hpp"
            | ".java"
            | ".js"
            | ".jsx"
            | ".kt"
            | ".kts"
            | ".lua"
            | ".m"
            | ".mm"
            | ".mojo"
            | ".nim"
            | ".php"
            | ".py"
            | ".rs"
            | ".swift"
            | ".ts"
            | ".tsx"
            | ".wren"
    )
}

fn is_test(path: &str) -> bool {
    TEST_PATH.is_match(&path.replace('\\', "/"))
}

fn extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{}", value.to_ascii_lowercase()))
        .unwrap_or_default()
}

fn starts_keyword(source: &str, keyword: &str) -> bool {
    source == keyword
        || source
            .strip_prefix(keyword)
            .and_then(|tail| tail.chars().next())
            .is_some_and(char::is_whitespace)
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    source
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|candidate| candidate == identifier)
}

fn is_script_path(path: &str) -> bool {
    matches!(extension(path).as_str(), ".js" | ".jsx" | ".ts" | ".tsx")
}

fn count_byte(source: &str, byte: u8) -> isize {
    source
        .bytes()
        .filter(|candidate| *candidate == byte)
        .count() as isize
}

fn posix_directory(path: &str) -> &str {
    path.rsplit_once('/')
        .map_or(".", |(directory, _)| directory)
}

fn file_stem(path: &str) -> &str {
    let basename = path.rsplit('/').next().unwrap_or(path);
    basename.rsplit_once('.').map_or(basename, |(stem, _)| stem)
}

fn file_style(name: &str) -> &'static str {
    if name.contains('_') {
        "snake_case"
    } else if name.contains('-') {
        "kebab-case"
    } else if name.starts_with(|character: char| character.is_ascii_uppercase()) {
        "PascalCase"
    } else if name.chars().any(|character| character.is_ascii_uppercase()) {
        "camelCase"
    } else {
        "lowercase"
    }
}

fn path_concepts(path: &str) -> BTreeSet<String> {
    let ignored = ["src", "lib", "test", "tests", "spec", "index", "main"];
    file_stem(path)
        .to_ascii_lowercase()
        .split(['_', '-', '.'])
        .filter(|part| part.len() >= 3 && !ignored.contains(part))
        .map(str::to_owned)
        .collect()
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("clean-code rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("clean-code rule severity must be valid"),
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

static CLASS_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:(?:abstract|declare|default|export|file|final|internal|partial|private|protected|public|readonly|ref|sealed|static|strictfp|unsafe)\s+)*(?:class|enum|struct|record(?:\s+(?:class|struct))?)\s+(?P<name>[A-Za-z_$]\w*)",
    )
    .unwrap()
});
static PUBLIC_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*public\s+(?:static\s+)?(?:[A-Za-z_$][\w$<>,?\[\].]*\s+)+(?P<name>\w+)\s*(?:;|=(?:[^>]|$))",
    )
    .unwrap()
});
static DART_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:late\s+)?(?:var|[A-Za-z_$][\w$<>,?\[\].]*)\s+(?P<name>[A-Za-z$][\w$]*)\s*(?:;|=(?:[^=>]|$))",
    )
    .unwrap()
});
static SCRIPT_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:public\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=;]+)?(?:=|;)").unwrap()
});
static HASH_OR_SLASH_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?://|#)\s?(?P<body>.*)$").unwrap());
static SLASH_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*//\s?(?P<body>.*)$").unwrap());
static COMMENTED_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\s*(?:public|private|protected|internal|static|final|const|var|let|def|class|interface|return|throw|if\s*\(|for\s*\(|while\s*\(|[A-Za-z_$]\w*\s*[.(\[]).*(?:[;{}]|=>)\s*)$").unwrap()
});
static MEMBER_ACCESS_PROSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$]\w*(?:\.[A-Za-z_$]\w*)+\s+[A-Za-z]").unwrap());
static DOCUMENTATION_EXAMPLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:examples?|e\.?g\.?|i\.?e\.?|snippets?|expands?\s+to|ends?\s+up\s+like|code\s+(?:like|such\s+as)|calls?\s+this\s+like|following\s+code|(?:may|would)\s+look\s+like|looks?\s+like(?:\s+this)?)\b").unwrap()
});
static DOCUMENTATION_PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[[a-z][a-z0-9]*(?:_[a-z0-9]+)+\]").unwrap());
static DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:include|define|pragma|region|ifn?def)\b").unwrap());
static LATEX_MATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\(?:approx|cdot|frac|geq|infty|leq|prod|sqrt|sum|times)\b|[_^]\{").unwrap()
});
static MULTIPLE_EXAMPLE_STATEMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r";\s*(?:new\s+|(?:const|let|return|throw|var)\s+|[A-Za-z_$]\w*\s*[.(])").unwrap()
});
static COMMENTED_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:const|let|var)\b.*;?\s*$").unwrap());
static OBJECT_PROPERTY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$]\w*\s*:").unwrap());
static PLACEHOLDER_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:export\s+|public\s+)?(?:class|interface|enum|struct|def|function|fn|proc|func|void|var|let|const|final|[A-Z][\w$<>,?\[\].]*)\s+(?P<name>[A-Za-z_$][\w$]*)").unwrap()
});
static TRAILING_DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+$").unwrap());
static EXPOSED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:export|public)\b").unwrap());
static ORCHESTRATOR_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:main|bootstrap|migrate|transaction)\b").unwrap());
static BOUNDARIES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("persistence", Regex::new(r"(?i)\b(?:(?:repository|database)\s*\.|(?:insert|update|delete|save|query|executeSql)\s*\()").unwrap()),
        ("network", Regex::new(r"(?i)\b(?:https?\s*\.|fetch\s*\(|request\s*\(|client\s*\.\s*(?:get|post|put|send)\s*\()").unwrap()),
        ("filesystem", Regex::new(r"(?i)\b(?:File|Directory)\s*\(|\b(?:readAs|writeAs|openSync|readFile|writeFile)\s*\(").unwrap()),
        ("process", Regex::new(r"(?i)\b(?:Process\s*\.\s*(?:run|start)|exec|spawn|subprocess)\s*\(").unwrap()),
        ("telemetry", Regex::new(r"(?i)\b(?:analytics|telemetry|metrics|track|logger?)\s*\.").unwrap()),
        ("navigation", Regex::new(r"(?i)\b(?:Navigator\s*\.|(?:redirect|navigate)\s*\()").unwrap()),
    ]
});
static POLICY_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\b(?:(?P<named_comparison>capacity|limit|max|min|retries|retry|threshold|timeout)\b|(?P<comparison>(?:attempts?|capacity|complexity|count|depth|files?|height|limit|lines?|max|min|retries|retry|score|size|threshold|timeout|width)\w*)|(?P<named_only>Duration)\b)|(?P<literal>-?\b\d+(?:\.\d+)?\b))").unwrap()
});
static PUBLIC_API: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:export\s+|public\s+|abstract\s+interface\s+class\s+|class\s+[A-Z])")
        .unwrap()
});
static FUNCTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(?:public|private|protected|internal|static|final|async|export)\s+)*(?:[A-Za-z_$][\w$<>,?\[\].]*\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:async\s*)?(?:=>|\{)").unwrap()
});
static COMPLEXITY_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?").unwrap());
static TEST_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(?:test|tests|spec|specs|__tests__)(/|$)|(?:_test|\.test|\.spec)\.")
        .unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_all_clean_code_rules_in_repository_order() {
        let sources = sources(&[
            ("lib/account.dart", "class Account {\n  int balance = 0;\n}"),
            ("lib/comment.dart", "// final result = legacy.load();"),
            ("lib/download.dart", "if (size >= 30) stop();"),
            (
                "lib/registration.dart",
                "void registerUser() {\n  validate();\n  database.save(user);\n  client.post(request);\n  File('audit').writeAsString(event);\n  normalize();\n  updateCache();\n  notifyUser();\n  finish();\n}",
            ),
            (
                "lib/decision.dart",
                "void decide() {\n  if (a) act();\n  if (b) act();\n  if (c) act();\n  if (d) act();\n  if (e) act();\n  if (f) act();\n  if (g) act();\n  if (h) act();\n  if (i) act();\n}",
            ),
            ("lib/upload.dart", "if (size > 30) reject();"),
            ("src/api.ts", "export class Foo {}"),
            ("lib/services/PaymentService.dart", ""),
            ("lib/services/audit_service.dart", ""),
            ("lib/services/cache_service.dart", ""),
            ("lib/services/mail_service.dart", ""),
            ("lib/services/order_service.dart", ""),
            ("lib/services/user_service.dart", ""),
        ]);
        let base = self::sources(&[("lib/decision.dart", "void decide() { act(); }")]);
        let changed = set(&["lib/account.dart"]);
        let context = SourceAnalysisContext::new(&sources, &base, &changed, true);
        let findings = analyze(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.severity.as_str(),
                    finding.path.as_str(),
                    finding.line,
                    finding.end_line,
                    finding.confidence.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "public-mutable-state",
                    "info",
                    "lib/account.dart",
                    2,
                    0,
                    "high",
                ),
                (
                    "commented-out-code",
                    "info",
                    "lib/comment.dart",
                    1,
                    0,
                    "high",
                ),
                ("placeholder-identifier", "info", "src/api.ts", 1, 0, "high",),
                (
                    "mixed-boundary-responsibility",
                    "info",
                    "lib/registration.dart",
                    1,
                    0,
                    "medium",
                ),
                (
                    "repeated-policy-literal",
                    "info",
                    "lib/download.dart",
                    1,
                    0,
                    "medium",
                ),
                (
                    "inconsistent-peer-file-naming",
                    "info",
                    "lib/services/PaymentService.dart",
                    1,
                    0,
                    "high",
                ),
                (
                    "changed-public-api-without-test",
                    "info",
                    "lib/account.dart",
                    1,
                    0,
                    "medium",
                ),
                (
                    "changed-complexity-regression",
                    "info",
                    "lib/decision.dart",
                    1,
                    0,
                    "high",
                ),
            ]
        );
        assert_eq!(
            findings[0].message,
            "public mutable field `balance` exposes writable state"
        );
        assert_eq!(
            findings[3].message,
            "registerUser directly coordinates persistence, network, filesystem boundaries"
        );
        assert_eq!(
            findings[4].message,
            "policy literal `30` for `size` appears 2 times without a shared name"
        );
        assert_eq!(
            findings[4].related_files,
            vec!["lib/upload.dart".to_owned()]
        );
        assert_eq!(
            findings[7].message,
            "decide complexity increased from 1 to 10"
        );
    }

    #[test]
    fn accepts_hidden_final_and_constructor_state() {
        let sources = sources(&[
            (
                "lib/account.dart",
                "class Account {\n  int balance = 0;\n  final String id = 'stable';\n  int _cached = 0;\n  bool operator ==(Object other) => identical(this, other);\n}\nclass _Scanner {\n  int offset = 0;\n}",
            ),
            (
                "src/User.java",
                "public class User {\n public String name;\n public String displayName;\n public final String id = \"stable\";\n private static class Hidden {\n  public String leaked;\n }\n}\nclass MutablePair {\n public Object left;\n public Object right;\n}\npublic class ServerOptions {\n public String host;\n public int port;\n}",
            ),
            (
                "src/session.ts",
                "class Session {\n token: string = '';\n readonly id: string = '';\n private secret: string = '';\n constructor(\n   kind: string,\n   options: { message?: string } = {}\n ) {}\n}",
            ),
            (
                "src/Signals.cs",
                "public partial class Signals\n{\n public int Mutable;\n public int AlsoMutable;\n public int Derived => Mutable;\n public event Action Changed;\n public static bool operator ==(Signals left, Signals right) => true;\n private class Hidden\n {\n  public int Leaked;\n }\n}\ninternal struct Native\n{\n public IntPtr Handle;\n}",
            ),
            (
                "src/imports.js",
                "/** A class of analyzer dependencies. */\nconst first = require('./first'),\n  CodePath = require('./code-path');",
            ),
        ]);
        let context = unchanged(&sources);
        let findings = public_mutable_state(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec![
                "public mutable field `balance` exposes writable state",
                "public mutable field `Mutable` exposes writable state",
                "public mutable field `name` exposes writable state",
                "public mutable field `token` exposes writable state",
            ]
        );
    }

    #[test]
    fn distinguishes_disabled_code_from_prose_and_documented_examples() {
        let sources = sources(&[
            (
                "lib/service.dart",
                "// final result = legacy.load();\n// Keep this ordering because the server requires it.\n// Example: call load before save.\n// finish(value);",
            ),
            (
                "src/generator.py",
                "# return legacy();\n# ContentType.toString already handles this;",
            ),
            (
                "middleware/example.go",
                "// A route may look like:\n\
// r.Get(\"/long\", handler)\n\
const route = true\n\
// e.g. foo.a = 0;\n\
const assignment = true\n\
// P[m, n] \\approx 1 - e^{-m^2/2n}\n\
const probability = true\n\
// run();\n\
// Here's a snippet for generated output:",
            ),
            (
                "src/visitor.js",
                "return {\n\
// var {x} = value;\n\
ObjectPattern: checkPattern,\n\
// var value = {x: 'y'}\n\
ObjectExpression: checkObject,\n\
}\n\
if (ready ||\n\
// new (a().b)(); new (a.b().c)();\n\
fallback) run();",
            ),
        ]);
        let context = unchanged(&sources);
        let findings = commented_out_code(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("lib/service.dart", 1), ("src/generator.py", 1)]
        );
    }

    #[test]
    fn groups_commented_code_per_file() {
        let sources = sources(&[(
            "src/legacy.cs",
            "// var first = legacy.Load();\n\
             // first.Run();\n\
             int active = 1;\n\
             // return legacy.Save();",
        )]);
        let context = unchanged(&sources);

        assert_eq!(
            commented_out_code(&context)
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn requires_placeholder_exposure_or_repeated_use() {
        let sources = sources(&[(
            "src/api.ts",
            "/// pub struct Foo {}\n/** public class Bar {} */\nexport class Foo {}\nfunction small() { const obj = make(); }\nfunction use() { let dummy = make(); return dummy + dummy; }",
        )]);
        let context = unchanged(&sources);
        let findings = placeholder_identifiers(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec![
                "`Foo` is a placeholder name used beyond a tiny local scope",
                "`dummy` is a placeholder name used beyond a tiny local scope",
            ]
        );
    }

    #[test]
    fn separates_policy_concepts_and_ignores_tests_and_common_literals() {
        let sources = sources(&[
            ("lib/a.dart", "if (size > 30) reject();"),
            ("lib/b.dart", "if (size >= 30) stop();"),
            ("lib/c.dart", "if (width > 30) wrap();"),
            ("lib/d.dart", "if (count > 30) count();"),
            ("lib/e.dart", "if (size > 10) allow();"),
            ("test/a_test.dart", "if (size > 30) test();"),
        ]);
        let context = unchanged(&sources);
        let findings = repeated_policy_literals(&context);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/a.dart");
        assert_eq!(findings[0].related_files, vec!["lib/b.dart".to_owned()]);
    }

    #[test]
    fn policy_literals_do_not_read_numeric_type_suffixes() {
        let sources = sources(&[
            (
                "src/a.rs",
                "let duration = value.parse::<f64>();\nlet retries = value.parse::<u64>();",
            ),
            (
                "src/b.rs",
                "let duration = other.parse::<f64>();\nlet retries = other.parse::<u64>();",
            ),
        ]);
        let context = unchanged(&sources);

        assert!(repeated_policy_literals(&context).is_empty());
    }

    #[test]
    fn skips_incomplete_policy_declarations_without_changing_valid_findings() {
        let sources = sources(&[
            (
                "lib/a.dart",
                "const timeout =;\nif (size >) reject();\nif (size > 30) reject();",
            ),
            ("lib/b.dart", "if (size >= 30) stop();"),
        ]);
        let context = unchanged(&sources);
        let findings = repeated_policy_literals(&context);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/a.dart");
        assert_eq!(findings[0].line, 3);
        assert_eq!(
            findings[0].message,
            "policy literal `30` for `size` appears 2 times without a shared name"
        );
        assert_eq!(findings[0].related_files, vec!["lib/b.dart".to_owned()]);
    }

    #[test]
    fn preserves_policy_order_when_named_and_comparison_syntax_overlap() {
        let sources = sources(&[
            (
                "lib/a.dart",
                "const timeout = size > 30; if (width > 40) wrap();",
            ),
            (
                "lib/b.dart",
                "const timeout = size > 30; if (width > 40) wrap();",
            ),
        ]);
        let context = unchanged(&sources);
        let findings = repeated_policy_literals(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec![
                "policy literal `30` for `size` appears 2 times without a shared name",
                "policy literal `40` for `width` appears 2 times without a shared name",
                "policy literal `30` for `timeout` appears 2 times without a shared name",
            ]
        );
    }

    #[test]
    fn accepts_role_based_naming_outliers() {
        let sources = sources(&[
            ("lib/services/audit_service.dart", ""),
            ("lib/services/cache_service.dart", ""),
            ("lib/services/mail_service.dart", ""),
            ("lib/services/order_service.dart", ""),
            ("lib/services/user_service.dart", ""),
            ("lib/services/rules.dart", ""),
        ]);
        let context = unchanged(&sources);
        assert!(inconsistent_peer_file_naming(&context).is_empty());
    }

    #[test]
    fn accepts_compound_separator_name_among_single_word_peers() {
        let sources = sources(&[
            ("src/commands/cache.rs", ""),
            ("src/commands/config.rs", ""),
            ("src/commands/fix.rs", ""),
            ("src/commands/graph.rs", ""),
            ("src/commands/rules.rs", ""),
            ("src/commands/repository_view.rs", ""),
        ]);
        let context = unchanged(&sources);

        assert!(inconsistent_peer_file_naming(&context).is_empty());
    }

    #[test]
    fn accepts_standard_java_metadata_file_names() {
        let sources = sources(&[
            ("src/main/java/example/Alpha.java", ""),
            ("src/main/java/example/Bravo.java", ""),
            ("src/main/java/example/Charlie.java", ""),
            ("src/main/java/example/Delta.java", ""),
            ("src/main/java/example/Echo.java", ""),
            ("src/main/java/example/package-info.java", ""),
        ]);
        let context = unchanged(&sources);

        assert!(inconsistent_peer_file_naming(&context).is_empty());
    }

    #[test]
    fn accepts_compound_pascal_name_among_pascal_peers() {
        let sources = sources(&[
            ("src/Parser.cs", ""),
            ("src/Lexer.cs", ""),
            ("src/Token.cs", ""),
            ("src/Syntax.cs", ""),
            ("src/Trivia.cs", ""),
            ("src/Parser_Async.cs", ""),
        ]);
        let context = unchanged(&sources);

        assert!(inconsistent_peer_file_naming(&context).is_empty());
    }
    #[test]
    fn changed_public_api_accepts_a_concept_related_changed_test() {
        let sources = sources(&[(
            "lib/user_service.dart",
            "class UserService { void save() {} }",
        )]);
        let base = BTreeMap::new();
        let uncovered_paths = set(&["lib/user_service.dart"]);
        let uncovered = SourceAnalysisContext::new(&sources, &base, &uncovered_paths, true);
        assert_eq!(changed_public_api_without_test(&uncovered).len(), 1);

        let covered_paths = set(&["lib/user_service.dart", "test/user_service_test.dart"]);
        let covered = SourceAnalysisContext::new(&sources, &base, &covered_paths, true);
        assert!(changed_public_api_without_test(&covered).is_empty());
    }

    #[test]
    fn complexity_regression_requires_a_large_threshold_crossing() {
        let sources = sources(&[
            (
                "lib/large.dart",
                "void decide() {\nif(a){}\nif(b){}\nif(c){}\nif(d){}\nif(e){}\nif(f){}\nif(g){}\nif(h){}\nif(i){}\n}",
            ),
            (
                "lib/small.dart",
                "void choose() {\nif(a){}\nif(b){}\nif(c){}\n}",
            ),
        ]);
        let base = self::sources(&[
            ("lib/large.dart", "void decide() { act(); }"),
            ("lib/small.dart", "void choose() { act(); }"),
        ]);
        let changed = BTreeSet::new();
        let context = SourceAnalysisContext::new(&sources, &base, &changed, true);

        let findings = changed_complexity_regressions(&context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/large.dart");
    }

    fn unchanged(sources: &BTreeMap<String, String>) -> SourceAnalysisContext<'_> {
        SourceAnalysisContext::unchanged(sources)
    }

    fn sources(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
            .collect()
    }

    fn set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }
}
