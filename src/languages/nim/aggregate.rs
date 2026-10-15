#[allow(clippy::too_many_arguments)]
fn analyze_aggregate(
    path: &str,
    source: &str,
    lines: &[&str],
    is_test: bool,
    file_lower: &str,
    mentions_websocket: bool,
    state: &ScanState,
    facts: &FileFacts,
    findings: &mut Vec<Finding>,
) {
    analyze_module_size(path, facts, findings);
    analyze_test_name(path, findings);
    analyze_resource_balance(path, state, findings);
    analyze_parameter_clusters(path, &state.proc_parameters, findings);
    analyze_generic_contracts(path, state, findings);
    analyze_websocket_coverage(
        path,
        source,
        is_test,
        file_lower,
        mentions_websocket,
        findings,
    );
    analyze_distinct_serialization(path, state, findings);
    analyze_mutable_declarations(path, lines, facts, findings);
}

fn analyze_module_size(path: &str, facts: &FileFacts, findings: &mut Vec<Finding>) {
    if facts.import_count > 15 {
        push(
            findings,
            "nim-god-module",
            path,
            1,
            format!("module has {} import statements", facts.import_count),
            "medium",
            Some(Severity::Warn),
        );
    }
    if facts.export_count > 25 {
        push(
            findings,
            "nim-many-exports",
            path,
            1,
            format!("module exports {} symbols", facts.export_count),
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_test_name(path: &str, findings: &mut Vec<Finding>) {
    if !path.starts_with("tests/") {
        return;
    }
    let file_name = file_stem(path).unwrap_or("");
    if !file_name.starts_with("test_")
        && !file_name.starts_with("tests_")
        && !file_name.starts_with('t')
        && !["alltests", "testutils", "full_test_suite"].contains(&file_name)
    {
        push_str(
            findings,
            "nim-test-naming",
            path,
            1,
            "test file does not follow common t*.nim/test_*.nim/tests_*.nim convention",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_resource_balance(path: &str, state: &ScanState, findings: &mut Vec<Finding>) {
    if state.camera_modified && !state.camera_restored {
        push_str(
            findings,
            "nim-camera-transform-leak",
            path,
            state.camera_proc_line,
            "camera modified in draw proc but not restored",
            "medium",
            Some(Severity::Warn),
        );
    }
    if state.asset_load_count > 2 && state.asset_free_count == 0 {
        push_str(
            findings,
            "nim-asset-loaded-not-freed",
            path,
            1,
            "module loads assets but has no matching unload/free calls",
            "low",
            Some(Severity::Info),
        );
    }
    if state.render_begin_count > state.render_end_count {
        push_str(
            findings,
            "nim-render-state-not-restored",
            path,
            state.render_proc_line,
            "render state begin without matching restore",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_generic_contracts(path: &str, state: &ScanState, findings: &mut Vec<Finding>) {
    if state.generic_hook_count > 0 && state.has_import {
        push_str(
            findings,
            "nim-imported-hook-ambiguity-risk",
            path,
            1,
            "module imports dependencies and defines generic hook procs",
            "low",
            Some(Severity::Info),
        );
    }
    if state.generic_hook_count > 0 && state.has_generic_serialization_wrapper {
        push_str(
            findings,
            "nim-generic-hook-cross-module-call",
            path,
            1,
            "module defines generic hooks and an exported generic serialization wrapper",
            "low",
            Some(Severity::Info),
        );
    }
    if state.json_api_count >= 3 {
        push_str(
            findings,
            "nim-json-heavy-api",
            path,
            1,
            "public API exposes JSON/render value types in several places",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_websocket_coverage(
    path: &str,
    source: &str,
    is_test: bool,
    file_lower: &str,
    mentions_websocket: bool,
    findings: &mut Vec<Finding>,
) {
    if mentions_websocket
        && !is_test
        && !(file_lower.contains("keep-alive, upgrade") && source.contains("Upgrade"))
    {
        push_str(
            findings,
            "nim-websocket-tests-missing-header-variants",
            path,
            1,
            "WebSocket/protocol code has no obvious comma-separated/case-variant header coverage nearby",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_distinct_serialization(
    path: &str,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    for type_name in &state.distinct_types {
        let has_dump = state.dump_types.contains(type_name);
        let has_parse = state.parse_types.contains(type_name);
        if has_dump == has_parse {
            continue;
        }
        push_str(
            findings,
            "nim-distinct-serialization-asymmetry",
            path,
            1,
            if has_dump {
                "distinct type has dump/encode hook but no matching parse/decode hook"
            } else {
                "distinct type has parse/decode hook but no matching dump/encode hook"
            },
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_mutable_declarations(
    path: &str,
    lines: &[&str],
    facts: &FileFacts,
    findings: &mut Vec<Finding>,
) {
    for (name, declaration) in &facts.mutable_declarations {
        if lines
            .iter()
            .filter(|line| has_assignment(line, name))
            .count()
            <= 1
        {
            push_str(
                findings,
                "nim-prefer-let",
                path,
                declaration + 1,
                "review whether var can be let",
                "low",
                Some(Severity::Info),
            );
        }
    }
}

type ParameterPairCounts<'a> = BTreeMap<(&'a str, &'a str), usize>;

fn analyze_parameter_clusters(
    path: &str,
    procedures: &[(usize, BTreeSet<String>)],
    findings: &mut Vec<Finding>,
) {
    if procedures.len() < 3 {
        return;
    }
    let pair_counts = aggregate_parameter_pairs(procedures);
    emit_parameter_clusters(path, procedures, &pair_counts, findings);
}

fn aggregate_parameter_pairs(
    procedures: &[(usize, BTreeSet<String>)],
) -> ParameterPairCounts<'_> {
    let mut pair_counts = ParameterPairCounts::new();
    for (_, names) in procedures {
        for (left_index, left) in names.iter().enumerate() {
            for right in names.iter().skip(left_index + 1) {
                *pair_counts
                    .entry((left.as_str(), right.as_str()))
                    .or_default() += 1;
            }
        }
    }
    pair_counts
}

fn qualifies_as_parameter_cluster(
    names: &BTreeSet<String>,
    pair_counts: &ParameterPairCounts<'_>,
) -> bool {
    if names.len() < 4 {
        return false;
    }
    let mut shared_pairs = 0;
    for (left_index, left) in names.iter().enumerate() {
        for right in names.iter().skip(left_index + 1) {
            if pair_counts
                .get(&(left.as_str(), right.as_str()))
                .copied()
                .unwrap_or_default()
                >= 3
            {
                shared_pairs += 1;
            }
        }
    }
    shared_pairs >= 3
}

fn emit_parameter_clusters(
    path: &str,
    procedures: &[(usize, BTreeSet<String>)],
    pair_counts: &ParameterPairCounts<'_>,
    findings: &mut Vec<Finding>,
) {
    for (line, names) in procedures {
        if qualifies_as_parameter_cluster(names, pair_counts) {
            push_str(
                findings,
                "nim-parameter-cluster-spread",
                path,
                *line,
                "proc shares a parameter cluster with other procs in this module",
                "low",
                Some(Severity::Info),
            );
        }
    }
}

fn split_recursive_types(path: &str, lines: &[&str]) -> Vec<Finding> {
    let starts = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == "type").then_some(index))
        .collect::<Vec<_>>();
    for left in 0..starts.len().saturating_sub(1) {
        let left_text = lines[starts[left]..starts[left + 1]].join("\n");
        let left_names = type_names(&left_text);
        for right in left + 1..starts.len() {
            let right_end = starts.get(right + 1).copied().unwrap_or(lines.len());
            let right_text = lines[starts[right]..right_end].join("\n");
            let right_names = type_names(&right_text);
            if left_names.iter().any(|name| right_text.contains(name))
                && right_names.iter().any(|name| left_text.contains(name))
            {
                return vec![finding(
                    "nim-split-recursive-types",
                    path,
                    starts[right] + 1,
                    "mutually recursive types are split across type sections",
                    "medium",
                    Some(Severity::Warn),
                )];
            }
        }
    }
    Vec::new()
}

fn type_names(source: &str) -> BTreeSet<String> {
    TYPE_NAME
        .captures_iter(source)
        .map(|captures| captures[1].to_owned())
        .collect()
}
