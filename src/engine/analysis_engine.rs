use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::dependency_graph::DependencyGraph;
use crate::discovery::{AnalysisProfile, PreparedPreview, RulePackTiming};
use crate::finding_controls;
use crate::findings::Finding;
use crate::function_sources::{self, FunctionSource};
use crate::languages::dart::index::DartSourceIndex;
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;
use crate::yagni_call_index::YagniCallIndex;

use super::execution_plan::ExecutionPlan;
use super::rule_packs::{RULE_PACKS, RulePack, RulePackContext, RulePackOutput, RulePackPhase};

pub struct AnalysisOutput {
    pub findings: Vec<Finding>,
    pub family_durations_milliseconds: BTreeMap<String, u128>,
    pub profile: AnalysisProfile,
    collect_timings: bool,
}

struct AnalysisResources<'source> {
    functions: Vec<FunctionSource>,
    dart_index: Option<DartSourceIndex<'source>>,
}

pub fn analyze<'source>(
    prepared: &PreparedPreview,
    context: &'source SourceAnalysisContext<'source>,
    graph: &DependencyGraph,
    plan: &ExecutionPlan<'_>,
    collect_timings: bool,
) -> Result<AnalysisOutput, String> {
    validate_duplication_mode(prepared)?;

    let sources = context.sources();
    let mut output = AnalysisOutput {
        findings: Vec::new(),
        family_durations_milliseconds: BTreeMap::new(),
        profile: AnalysisProfile::default(),
        collect_timings,
    };
    let resources = prepare_analysis_resources(prepared, context, sources, plan, &mut output);
    let yagni_call_index =
        prepare_yagni_call_index(prepared, plan, &resources.functions, &mut output);

    run_rule_pack_schedule(
        prepared,
        context,
        graph,
        plan,
        &resources,
        yagni_call_index.as_ref(),
        &mut output,
    )?;
    post_process_findings(prepared, context, sources, &mut output)?;
    Ok(output)
}

fn validate_duplication_mode(prepared: &PreparedPreview) -> Result<(), String> {
    let duplication_mode = prepared.config.duplication_mode.as_str();
    if matches!(duplication_mode, "exact" | "normalized" | "semantic") {
        Ok(())
    } else {
        Err(format!("unsupported duplication mode: {duplication_mode}"))
    }
}

fn prepare_analysis_resources<'source>(
    prepared: &PreparedPreview,
    context: &'source SourceAnalysisContext<'source>,
    sources: &BTreeMap<String, String>,
    plan: &ExecutionPlan<'_>,
    output: &mut AnalysisOutput,
) -> AnalysisResources<'source> {
    let collect_timings = output.collect_timings;
    let needs_functions = RULE_PACKS
        .iter()
        .any(|pack| pack_enabled(pack, prepared, plan) && pack.needs_functions);
    let functions = if needs_functions {
        let started = collect_timings.then(Instant::now);
        let functions = function_sources::extract(sources);
        if let Some(started) = started {
            record_shared_duration(output, "function-extraction", started.elapsed());
        }
        functions
    } else {
        Vec::new()
    };
    let dart_index = plan.selects_language("dart").then(|| {
        let started = collect_timings.then(Instant::now);
        let index = DartSourceIndex::new(context);
        if let Some(started) = started {
            record_shared_duration(output, "dart-index", started.elapsed());
        }
        index
    });
    AnalysisResources {
        functions,
        dart_index,
    }
}

fn prepare_yagni_call_index<'functions>(
    prepared: &PreparedPreview,
    plan: &ExecutionPlan<'_>,
    functions: &'functions [FunctionSource],
    output: &mut AnalysisOutput,
) -> Option<YagniCallIndex<'functions>> {
    let collect_timings = output.collect_timings;
    let needs_yagni_index = RULE_PACKS
        .iter()
        .any(|pack| pack_enabled(pack, prepared, plan) && pack.needs_yagni_index);
    needs_yagni_index.then(|| {
        let started = collect_timings.then(Instant::now);
        let index = YagniCallIndex::new(functions);
        if let Some(started) = started {
            record_shared_duration(output, "yagni-index", started.elapsed());
        }
        index
    })
}

fn run_rule_pack_schedule<'source, 'functions>(
    prepared: &PreparedPreview,
    context: &'source SourceAnalysisContext<'source>,
    graph: &DependencyGraph,
    plan: &ExecutionPlan<'_>,
    resources: &'functions AnalysisResources<'source>,
    yagni_call_index: Option<&YagniCallIndex<'functions>>,
    output: &mut AnalysisOutput,
) -> Result<(), String> {
    run_rule_packs(
        RulePackPhase::Main,
        prepared,
        context,
        graph,
        &resources.functions,
        resources.dart_index.as_ref(),
        yagni_call_index,
        plan,
        output,
    )?;
    run_rule_packs(
        RulePackPhase::AfterMain,
        prepared,
        context,
        graph,
        &resources.functions,
        resources.dart_index.as_ref(),
        yagni_call_index,
        plan,
        output,
    )
}

fn post_process_findings(
    prepared: &PreparedPreview,
    context: &SourceAnalysisContext<'_>,
    sources: &BTreeMap<String, String>,
    output: &mut AnalysisOutput,
) -> Result<(), String> {
    let started = output.collect_timings.then(Instant::now);
    let flutter = project_uses_flutter(context, sources);
    output
        .findings
        .retain(|finding| finding_is_enabled(finding, prepared, flutter));
    order_findings(&mut output.findings)?;
    if let Some(started) = started {
        record_shared_duration(output, "post-processing", started.elapsed());
    }
    Ok(())
}

fn project_uses_flutter(
    context: &SourceAnalysisContext<'_>,
    sources: &BTreeMap<String, String>,
) -> bool {
    context.auxiliary_files().iter().any(|(path, source)| {
        path.ends_with("pubspec.yaml")
            && source
                .lines()
                .any(|line| line.trim_start().starts_with("flutter:"))
    }) || sources
        .values()
        .any(|source| source.contains("package:flutter/"))
}

fn finding_is_enabled(finding: &Finding, prepared: &PreparedPreview, flutter: bool) -> bool {
    let group =
        rule_catalog::descriptor(&finding.code).map_or("security", |descriptor| descriptor.group);
    !prepared.config.disabled_rules.contains(&finding.code)
        && finding_controls::mode_for_code(&finding.code, &prepared.config, group) != "off"
        && rule_catalog::metadata(&finding.code).is_none_or(|metadata| {
            metadata.frameworks.is_empty()
                || metadata.frameworks.iter().all(|framework| {
                    prepared.config.frameworks.contains(*framework)
                        || *framework == "flutter" && flutter
                })
        })
}

fn order_findings(findings: &mut Vec<Finding>) -> Result<(), String> {
    findings.sort_by_key(|finding| finding_family_rank(&finding.code));
    let style_start = findings
        .iter()
        .position(|finding| finding_family_rank(&finding.code) == STYLE_FINDING_RANK)
        .unwrap_or(findings.len());
    order_legacy_style_input(&mut findings[style_start..]);
    sort_style_findings_like_dart(findings, style_start)?;
    findings.dedup_by(|left, right| duplicate_finding(left, right));
    Ok(())
}

fn pack_enabled(pack: &RulePack, prepared: &PreparedPreview, plan: &ExecutionPlan<'_>) -> bool {
    debug_assert!(!pack.id.is_empty(), "rule-pack IDs must not be empty");
    plan.allows(pack.family)
        && (pack.languages.is_empty()
            || pack
                .languages
                .iter()
                .any(|language| plan.selects_language(language)))
        && pack
            .framework
            .is_none_or(|framework| prepared.config.frameworks.contains(framework))
}

#[allow(clippy::too_many_arguments)]
fn run_rule_packs<'source, 'functions>(
    phase: RulePackPhase,
    prepared: &PreparedPreview,
    source_context: &'source SourceAnalysisContext<'source>,
    graph: &DependencyGraph,
    functions: &'functions [FunctionSource],
    dart_index: Option<&DartSourceIndex<'source>>,
    yagni_index: Option<&YagniCallIndex<'functions>>,
    plan: &ExecutionPlan<'_>,
    output: &mut AnalysisOutput,
) -> Result<(), String> {
    let collect_timings = output.collect_timings;
    for pack in RULE_PACKS
        .iter()
        .filter(|pack| pack.phase == phase && pack_enabled(pack, prepared, plan))
    {
        let started = collect_timings.then(Instant::now);
        let RulePackOutput {
            findings: pack_findings,
            shared_durations_microseconds,
            rule_durations_microseconds,
        } = (pack.analyze)(&RulePackContext {
            prepared,
            source_context,
            graph,
            functions,
            dart_index,
            yagni_index,
            prior_findings: &output.findings,
            collect_timings,
        })?;
        if let Some(started) = started {
            record_pack_duration(output, pack, started.elapsed());
            merge_detail_durations(
                &mut output.family_durations_milliseconds,
                &mut output.profile.shared_durations_microseconds,
                shared_durations_microseconds,
            );
            merge_detail_durations(
                &mut output.family_durations_milliseconds,
                &mut output.profile.rule_durations_microseconds,
                rule_durations_microseconds,
            );
        }
        output.findings.extend(pack_findings);
    }
    Ok(())
}

fn record_pack_duration(output: &mut AnalysisOutput, pack: &RulePack, elapsed: Duration) {
    record_family_duration(
        &mut output.family_durations_milliseconds,
        pack.family,
        elapsed,
    );
    output.profile.rule_packs.push(RulePackTiming {
        id: pack.id.to_owned(),
        family: pack.family.to_owned(),
        duration_microseconds: elapsed.as_micros(),
    });
}

fn record_shared_duration(output: &mut AnalysisOutput, name: &str, elapsed: Duration) {
    record_family_duration(&mut output.family_durations_milliseconds, name, elapsed);
    *output
        .profile
        .shared_durations_microseconds
        .entry(name.to_owned())
        .or_default() += elapsed.as_micros();
}

fn record_family_duration(durations: &mut BTreeMap<String, u128>, name: &str, elapsed: Duration) {
    *durations.entry(name.to_owned()).or_default() += elapsed.as_millis();
}

fn merge_detail_durations(
    family_durations: &mut BTreeMap<String, u128>,
    profile_durations: &mut BTreeMap<String, u128>,
    details: BTreeMap<String, u128>,
) {
    for (name, duration_microseconds) in details {
        *family_durations.entry(name.clone()).or_default() += duration_microseconds / 1_000;
        *profile_durations.entry(name).or_default() += duration_microseconds;
    }
}

fn duplicate_finding(left: &Finding, right: &Finding) -> bool {
    !matches!(
        left.code.as_str(),
        "dart-dynamic"
            | "dart-json-cast-without-validation"
            | "large-number-ungrouped"
            | "nim-distinct-serialization-asymmetry"
            | "placeholder-identifier"
            | "rust-blocking-call-in-async"
    ) && left.code == right.code
        && left.path == right.path
        && left.line == right.line
        && left.end_line == right.end_line
        && left.message == right.message
        && left.related_files == right.related_files
}

const STYLE_FINDING_RANK: usize = 15;

fn finding_family_rank(code: &str) -> usize {
    match code {
        "complex-function" | "long-function" => 0,
        "single-use-trivial-wrapper" => 1,
        "single-product-factory" => 2,
        "constant-argument-parameter" => 3,
        "unused-customization-hook" => 4,
        "unused-optional-parameter" => 5,
        "unused-configuration-option" => 6,
        "large-file" | "goto-statement" => 7,
        "cycle"
        | "architecture-forbidden-dependency"
        | "architecture-layer-cycle"
        | "mvvm-forbidden-dependency"
        | "dead-file" => 8,
        "duplicate-block" => 9,
        "near-duplicate-function" => 10,
        "parallel-contract-implementation" => 11,
        "repeated-condition" => 12,
        "feature-flag" => 13,
        _ if code.starts_with("structure-") => 14,
        _ => STYLE_FINDING_RANK,
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum LegacyStylePriority {
    Language(usize),
    Repository(usize),
    Unclassified,
}

fn order_legacy_style_input(findings: &mut [Finding]) {
    findings.sort_by(compare_legacy_style_input);
}

fn compare_legacy_style_input(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    let left_priority = legacy_style_priority(left);
    let right_priority = legacy_style_priority(right);
    left_priority
        .cmp(&right_priority)
        .then_with(|| compare_legacy_language_ties(left, right, left_priority, right_priority))
}

fn legacy_style_priority(finding: &Finding) -> LegacyStylePriority {
    if let Some(rank) = legacy_repository_rule_rank(&finding.code) {
        return LegacyStylePriority::Repository(rank);
    }
    match legacy_language_rule_rank(finding) {
        STYLE_FINDING_RANK => LegacyStylePriority::Unclassified,
        rank => LegacyStylePriority::Language(rank),
    }
}

fn compare_legacy_language_ties(
    left: &Finding,
    right: &Finding,
    left_priority: LegacyStylePriority,
    right_priority: LegacyStylePriority,
) -> std::cmp::Ordering {
    match (left_priority, right_priority) {
        (LegacyStylePriority::Language(3), LegacyStylePriority::Language(3)) => {
            legacy_language_code_order(&left.code, &right.code)
                .then_with(|| compare_nim_findings(left, right))
        }
        (LegacyStylePriority::Language(_), LegacyStylePriority::Language(_)) => {
            legacy_language_code_order(&left.code, &right.code)
        }
        _ => std::cmp::Ordering::Equal,
    }
}

fn legacy_language_rule_rank(finding: &Finding) -> usize {
    if finding.code.starts_with("oop-") {
        return legacy_oop_rule_rank(&finding.path);
    }

    const PREFIX_RANKS: &[(&str, usize)] = &[
        ("html-", 0),
        ("css-", 1),
        ("wren-", 2),
        ("nim-", 3),
        ("lua-", 4),
        ("mojo-", 5),
        ("ts-", 6),
        ("js-", 6),
        ("svelte-", 6),
        ("go-", 7),
        ("py-", 8),
        ("fastapi-", 8),
        ("sql-", 9),
        ("rust-", 10),
        ("cargo-", 10),
        ("cpp-", 11),
        ("cs-", 12),
        ("java-", 13),
        ("dart-", 14),
        ("flutter-", 14),
    ];
    PREFIX_RANKS
        .iter()
        .find_map(|&(prefix, rank)| finding.code.starts_with(prefix).then_some(rank))
        .unwrap_or(STYLE_FINDING_RANK)
}

fn legacy_oop_rule_rank(path: &str) -> usize {
    match std::path::Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
    {
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" => 6,
        "cs" => 12,
        "java" => 13,
        "dart" => 14,
        _ => STYLE_FINDING_RANK,
    }
}

fn legacy_language_code_order(left: &str, right: &str) -> std::cmp::Ordering {
    let family = |code: &str| usize::from(!code.starts_with("oop-"));
    family(left).cmp(&family(right)).then_with(|| {
        match (
            legacy_language_code_rank(left),
            legacy_language_code_rank(right),
        ) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left.cmp(right),
        }
    })
}

fn legacy_language_code_rank(code: &str) -> Option<usize> {
    const ORDERED_CODES: &[&str] = &[
        "mojo-deprecated-fn",
        "mojo-deprecated-let",
        "mojo-deprecated-alias",
        "mojo-parameter-decorator",
        "mojo-legacy-argument-convention",
        "mojo-legacy-stdlib-import",
        "mojo-string-index",
        "mojo-missing-raises",
        "rust-unwrap",
        "rust-expect",
        "rust-panic-macro",
        "rust-undocumented-unsafe-block",
        "rust-static-mut",
        "rust-raw-ownership-reconstruction",
        "rust-manual-send-sync-impl",
        "rust-mem-forget",
        "rust-dbg-macro",
        "rust-todo-macro",
        "rust-command-shell",
        "rust-panic-across-ffi-boundary",
        "rust-blocking-call-in-async",
        "rust-unbounded-channel",
        "dart-null-assertion",
        "dart-map-string-dynamic-boundary",
    ];
    ORDERED_CODES
        .iter()
        .position(|candidate| *candidate == code)
}

fn compare_nim_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    let project_finding =
        |finding: &Finding| finding.path == "." || finding.code == "nim-missing-test-for-module";
    project_finding(right)
        .cmp(&project_finding(left))
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| nim_finding_phase(&left.code).cmp(&nim_finding_phase(&right.code)))
        .then_with(|| left.line.cmp(&right.line))
        .then_with(|| nim_finding_tie_order(&left.code).cmp(&nim_finding_tie_order(&right.code)))
}

fn nim_finding_phase(code: &str) -> usize {
    match code {
        "nim-missing-test-for-module" | "nim-no-test-suite" => 0,
        "nim-exported-object-without-doc"
        | "nim-tuple-used-as-domain-type"
        | "nim-ref-object-inheritance"
        | "nim-missing-raises"
        | "nim-missing-doc"
        | "nim-broad-except" => 10,
        "nim-split-recursive-types" => 11,
        "nim-exported-template-missing-doc"
        | "nim-template-body-state-mutation"
        | "nim-state-restore-without-finally" => 20,
        "nim-average-openarray-risk"
        | "nim-divide-by-len-without-empty-check"
        | "nim-float-test-exact-equality" => 50,
        "nim-float-tests-missing-edge-cases" => 51,
        "nim-openarray-missing-empty-test" => 52,
        "nim-hook-overwrites-accumulator" => 80,
        "nim-distinct-serialization-asymmetry" => 81,
        "nim-update-blocking-io" | "nim-draw-loads-asset" => 100,
        "nim-input-in-draw" | "nim-per-frame-string-format" | "nim-sound-every-frame" => 110,
        "nim-render-state-not-restored" => 111,
        "nim-entity-access-after-destroy"
        | "nim-nil-component-access"
        | "nim-physics-variable-timestep"
        | "nim-draw-call-in-update"
        | "nim-hardcoded-screen-size"
        | "nim-debug-draw-not-gated" => 120,
        "nim-save-missing-version" => 121,
        "nim-camera-transform-leak" => 122,
        "nim-asset-loaded-not-freed" => 123,
        "nim-too-many-parameters" => 130,
        "nim-could-be-const" => 140,
        "nim-cast-usage" | "nim-return-instead-of-result" => 150,
        "nim-unordered-table-output" => 170,
        "nim-tainted-exec" => 171,
        "nim-exec-dynamic-command" => 172,
        "nim-std-import" | "nim-broad-import" | "nim-prefer-let" => 180,
        _ => 1000,
    }
}

fn nim_finding_tie_order(code: &str) -> usize {
    match code {
        "nim-exported-object-without-doc" | "nim-exported-template-missing-doc" => 0,
        "nim-tuple-used-as-domain-type" | "nim-template-body-state-mutation" => 1,
        "nim-ref-object-inheritance" | "nim-state-restore-without-finally" => 2,
        "nim-missing-raises" => 3,
        "nim-missing-doc" => 4,
        "nim-broad-except" => 5,
        _ => 1000,
    }
}

fn legacy_repository_rule_rank(code: &str) -> Option<usize> {
    const RULES: &[&str] = &[
        "tab-indent",
        "trailing-whitespace",
        "long-line",
        "todo-comment",
        "fixme-comment",
        "operation-on-same-value",
        "public-mutable-state",
        "commented-out-code",
        "placeholder-identifier",
        "mixed-boundary-responsibility",
        "repeated-policy-literal",
        "inconsistent-peer-file-naming",
        "changed-public-api-without-test",
        "changed-complexity-regression",
        "broad-refactor-in-focused-change",
        "style-drift-in-diff",
        "changed-behavior-without-test",
        "stale-contract-reference",
        "risky-change-without-test",
        "changed-duplicate-implementation",
        "optional-feature-bundle",
        "abstraction-cost-exceeds-use",
        "new-unused-declaration",
        "single-caller-wrapper",
        "unrelated-symbol-churn",
        "boolean-option-explosion",
        "caller-side-guard-duplication",
        "thin-dependency-for-trivial-capability",
        "excessive-comment-density",
        "narrating-implementation-comment",
        "trivial-comment-restatement",
        "single-method-delegating-class",
        "parallel-schema-definition",
        "suspicious-command-arg-space",
        "large-number-ungrouped",
        "large-inline-list",
        "needless-bool-branch",
        "css-duplicate-declaration-set",
        "css-design-token-drift",
        "html-parallel-control-pattern",
        "test-repeated-runtime-bootstrap",
        "sql-inline-string-concat",
        "ai-prompt-injection-instruction",
        "ai-untrusted-prompt-construction",
        "ai-model-output-execution",
        "rust-unpinned-git-dependency",
        "flutter-context-after-await",
    ];
    RULES.iter().position(|candidate| *candidate == code)
}

fn sort_style_findings_like_dart(findings: &mut Vec<Finding>, start: usize) -> Result<(), String> {
    if findings.len().saturating_sub(start) < 2 {
        return Ok(());
    }
    let mut order = (start..findings.len()).collect::<Vec<_>>();
    dart_sort_indices(&mut order, &|left, right| {
        let left = &findings[left];
        let right = &findings[right];
        if left.code.starts_with("nim-") && right.code.starts_with("nim-") {
            return compare_nim_findings(left, right);
        }
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| {
                let layout_rank = |code: &str| {
                    usize::from(!matches!(
                        code,
                        "tab-indent" | "trailing-whitespace" | "long-line"
                    ))
                };
                layout_rank(&left.code).cmp(&layout_rank(&right.code))
            })
    });
    let mut unsorted = findings.drain(start..).map(Some).collect::<Vec<_>>();
    for index in order {
        let Some(finding) = index
            .checked_sub(start)
            .and_then(|offset| unsorted.get_mut(offset))
            .and_then(Option::take)
        else {
            return Err("style finding scheduler produced an invalid permutation".to_owned());
        };
        findings.push(finding);
    }
    Ok(())
}

pub(crate) fn dart_sort_indices(
    values: &mut [usize],
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    if values.is_empty() {
        return;
    }
    dart_sort_range(values, 0, values.len() as isize - 1, compare);
}

fn dart_sort_range(
    values: &mut [usize],
    left: isize,
    right: isize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    if right - left <= 32 {
        dart_insertion_sort(values, left, right, compare);
        return;
    }

    let pivots = select_dart_pivots(values, left, right, compare);
    let (mut less, mut great) = if compare(pivots.first, pivots.second).is_eq() {
        partition_equal_dart_pivots(values, left, right, pivots.first, compare)
    } else {
        partition_distinct_dart_pivots(values, left, right, pivots.first, pivots.second, compare)
    };

    values[left as usize] = values[(less - 1) as usize];
    values[(less - 1) as usize] = pivots.first;
    values[right as usize] = values[(great + 1) as usize];
    values[(great + 1) as usize] = pivots.second;
    dart_sort_range(values, left, less - 2, compare);
    dart_sort_range(values, great + 2, right, compare);
    if compare(pivots.first, pivots.second).is_eq() {
        return;
    }

    group_equal_dart_pivots(values, &mut less, &mut great, &pivots, compare);
    dart_sort_range(values, less, great, compare);
}

fn dart_insertion_sort(
    values: &mut [usize],
    left: isize,
    right: isize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    for index in left + 1..=right {
        let element = values[index as usize];
        let mut target = index;
        while target > left && compare(values[(target - 1) as usize], element).is_gt() {
            values[target as usize] = values[(target - 1) as usize];
            target -= 1;
        }
        values[target as usize] = element;
    }
}

#[derive(Clone, Copy)]
struct DartPivots {
    first: usize,
    second: usize,
    outer_left: isize,
    outer_right: isize,
}

fn select_dart_pivots(
    values: &mut [usize],
    left: isize,
    right: isize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) -> DartPivots {
    let sixth = (right - left + 1) / 6;
    let index1 = left + sixth;
    let index5 = right - sixth;
    let index3 = (left + right) / 2;
    let index2 = index3 - sixth;
    let index4 = index3 + sixth;
    let mut element1 = values[index1 as usize];
    let mut element2 = values[index2 as usize];
    let mut element3 = values[index3 as usize];
    let mut element4 = values[index4 as usize];
    let mut element5 = values[index5 as usize];

    sort_dart_pair(&mut element1, &mut element2, compare);
    sort_dart_pair(&mut element4, &mut element5, compare);
    sort_dart_pair(&mut element1, &mut element3, compare);
    sort_dart_pair(&mut element2, &mut element3, compare);
    sort_dart_pair(&mut element1, &mut element4, compare);
    sort_dart_pair(&mut element3, &mut element4, compare);
    sort_dart_pair(&mut element2, &mut element5, compare);
    sort_dart_pair(&mut element2, &mut element3, compare);
    sort_dart_pair(&mut element4, &mut element5, compare);

    values[index1 as usize] = element1;
    values[index3 as usize] = element3;
    values[index5 as usize] = element5;
    values[index2 as usize] = values[left as usize];
    values[index4 as usize] = values[right as usize];
    DartPivots {
        first: element2,
        second: element4,
        outer_left: index1,
        outer_right: index5,
    }
}

fn sort_dart_pair(
    left: &mut usize,
    right: &mut usize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    if compare(*left, *right).is_gt() {
        std::mem::swap(left, right);
    }
}

fn partition_equal_dart_pivots(
    values: &mut [usize],
    left: isize,
    right: isize,
    pivot: usize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) -> (isize, isize) {
    let mut less = left + 1;
    let mut great = right - 1;
    let mut index = less;
    while index <= great {
        let element = values[index as usize];
        let order = compare(element, pivot);
        if order.is_lt() {
            move_before_dart_pivot(values, index, element, &mut less);
        } else if order.is_gt() {
            move_after_equal_dart_pivot(
                values, index, element, &mut less, &mut great, pivot, compare,
            );
        }
        index += 1;
    }
    (less, great)
}

fn partition_distinct_dart_pivots(
    values: &mut [usize],
    left: isize,
    right: isize,
    pivot1: usize,
    pivot2: usize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) -> (isize, isize) {
    let mut less = left + 1;
    let mut great = right - 1;
    let mut index = less;
    while index <= great {
        let element = values[index as usize];
        if compare(element, pivot1).is_lt() {
            move_before_dart_pivot(values, index, element, &mut less);
        } else if compare(element, pivot2).is_gt() {
            move_after_distinct_dart_pivot(
                values,
                index,
                element,
                &mut less,
                &mut great,
                (pivot1, pivot2),
                compare,
            );
        }
        index += 1;
    }
    (less, great)
}

fn move_before_dart_pivot(values: &mut [usize], index: isize, element: usize, less: &mut isize) {
    if index != *less {
        values[index as usize] = values[*less as usize];
        values[*less as usize] = element;
    }
    *less += 1;
}

fn move_after_equal_dart_pivot(
    values: &mut [usize],
    index: isize,
    element: usize,
    less: &mut isize,
    great: &mut isize,
    pivot: usize,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    loop {
        let order = compare(values[*great as usize], pivot);
        if order.is_gt() {
            *great -= 1;
            continue;
        }
        if order.is_lt() {
            values[index as usize] = values[*less as usize];
            values[*less as usize] = values[*great as usize];
            *less += 1;
        } else {
            values[index as usize] = values[*great as usize];
        }
        values[*great as usize] = element;
        *great -= 1;
        break;
    }
}

fn move_after_distinct_dart_pivot(
    values: &mut [usize],
    index: isize,
    element: usize,
    less: &mut isize,
    great: &mut isize,
    pivots: (usize, usize),
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    loop {
        let order = compare(values[*great as usize], pivots.1);
        if order.is_gt() {
            *great -= 1;
            if *great < index {
                break;
            }
            continue;
        }
        if compare(values[*great as usize], pivots.0).is_lt() {
            values[index as usize] = values[*less as usize];
            values[*less as usize] = values[*great as usize];
            *less += 1;
        } else {
            values[index as usize] = values[*great as usize];
        }
        values[*great as usize] = element;
        *great -= 1;
        break;
    }
}

fn group_equal_dart_pivots(
    values: &mut [usize],
    less: &mut isize,
    great: &mut isize,
    pivots: &DartPivots,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    if *less >= pivots.outer_left || *great <= pivots.outer_right {
        return;
    }
    while compare(values[*less as usize], pivots.first).is_eq() {
        *less += 1;
    }
    while compare(values[*great as usize], pivots.second).is_eq() {
        *great -= 1;
    }
    let mut index = *less;
    while index <= *great {
        let element = values[index as usize];
        if compare(element, pivots.first).is_eq() {
            move_before_dart_pivot(values, index, element, less);
        } else if compare(element, pivots.second).is_eq() {
            group_second_dart_pivot(values, index, element, less, great, pivots, compare);
        }
        index += 1;
    }
}

fn group_second_dart_pivot(
    values: &mut [usize],
    index: isize,
    element: usize,
    less: &mut isize,
    great: &mut isize,
    pivots: &DartPivots,
    compare: &impl Fn(usize, usize) -> std::cmp::Ordering,
) {
    loop {
        let order = compare(values[*great as usize], pivots.second);
        if order.is_eq() {
            *great -= 1;
            if *great < index {
                break;
            }
            continue;
        }
        if compare(values[*great as usize], pivots.first).is_lt() {
            values[index as usize] = values[*less as usize];
            values[*less as usize] = values[*great as usize];
            *less += 1;
        } else {
            values[index as usize] = values[*great as usize];
        }
        values[*great as usize] = element;
        *great -= 1;
        break;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dart_sort_preserves_and_orders_large_duplicate_sets() {
        for length in [0usize, 1, 33, 34, 64, 97] {
            let keys = (0..length)
                .map(|index| (index * 17 + index / 3) % 7)
                .collect::<Vec<_>>();
            let mut order = (0..length).rev().collect::<Vec<_>>();

            dart_sort_indices(&mut order, &|left, right| keys[left].cmp(&keys[right]));

            assert!(order.windows(2).all(|pair| keys[pair[0]] <= keys[pair[1]]));
            let mut preserved = order;
            preserved.sort_unstable();
            assert_eq!(preserved, (0..length).collect::<Vec<_>>());
        }

        let mut equal = (0..64).rev().collect::<Vec<_>>();
        dart_sort_indices(&mut equal, &|_, _| std::cmp::Ordering::Equal);
        equal.sort_unstable();
        assert_eq!(equal, (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn legacy_language_order_is_total_for_known_and_unknown_rules() {
        let mut codes = vec![
            "rust-zeta",
            "rust-static-mut",
            "rust-alpha",
            "rust-unwrap",
            "rust-expect",
        ];

        codes.sort_by(|left, right| legacy_language_code_order(left, right));

        assert_eq!(
            codes,
            [
                "rust-unwrap",
                "rust-expect",
                "rust-static-mut",
                "rust-alpha",
                "rust-zeta",
            ]
        );
    }

    #[test]
    fn keeps_findings_with_distinct_related_evidence() {
        let first = Finding::structure(
            "oop-template-workflow-candidate",
            "Base.java".to_owned(),
            "same rendered workflow".to_owned(),
            "review",
            vec!["first/Child.java".to_owned()],
        );
        let second = Finding::structure(
            "oop-template-workflow-candidate",
            "Base.java".to_owned(),
            "same rendered workflow".to_owned(),
            "review",
            vec!["second/Child.java".to_owned()],
        );

        assert!(!duplicate_finding(&first, &second));
        assert!(duplicate_finding(&first, &first.clone()));
    }
}
