#[test]
fn structure_reports_policy_violations_in_text_and_json() {
    let root = TempDirectory::new("cbr-structure");
    root.write(
        "code-buster.toml",
        br#"languages = ["rust"]

[structure]
source_roots = ["src"]
max_root_files = 1
required_directories = ["features"]
"#,
    );
    root.write("src/a.rs", b"pub fn a() {}\n");
    root.write("src/b.rs", b"pub fn b() {}\n");

    let text = run_structure(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✗ Code Buster structure — 2 actionable findings\n"));
    assert!(stdout.contains("  Files       2 analyzed"));
    assert!(stdout.contains(
        "Findings\n\n  WARN  structure-missing-required-dir\n        src/features:1\n        required source subdirectory is missing: src/features"
    ));
    assert!(stdout.contains(
        "  WARN  structure-top-level-file\n        src:1\n        source root has 2 top-level file(s), allowed 1"
    ));
    assert!(!stdout.contains("Scope\n"));

    let json = run_structure(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("structure JSON must parse");
    assert_eq!(report["schemaVersion"], 3);
    assert_eq!(report["command"], "structure");
    assert_eq!(report["files"], 2);
    assert_eq!(report["actionableFindingCount"], 2);
    assert_eq!(
        report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .map(|finding| finding["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["structure-missing-required-dir", "structure-top-level-file"]
    );
    assert_eq!(
        report["findings"][1]["related_files"],
        serde_json::json!(["src/a.rs", "src/b.rs"])
    );

    root.write(
        "baseline.json",
        br#"{"entries":[{"code":"structure-top-level-file","path":"src","message":"source root has 2 top-level file(s), allowed 1","status":"accepted","expiry":""}]}"#,
    );
    let baseline = root.path.join("baseline.json");
    let baseline_argument = baseline.to_str().expect("temporary path must be UTF-8");
    let suppressed = run_structure(
        &root.path,
        &["--format", "json", "--baseline", baseline_argument],
    );
    let suppressed_report: serde_json::Value =
        serde_json::from_slice(&suppressed.stdout).expect("baseline report must parse");
    assert_eq!(suppressed_report["actionableFindingCount"], 1);
    assert_eq!(
        suppressed_report["findings"][0]["code"],
        "structure-missing-required-dir"
    );

    root.write(
        "baseline.json",
        br#"{"entries":[{"code":"structure-top-level-file","path":"src","message":"source root has 2 top-level file(s), allowed 1","status":"accepted","expiry":"2000-01-01"}]}"#,
    );
    let expired = run_structure(
        &root.path,
        &["--format", "json", "--baseline", baseline_argument],
    );
    let expired_report: serde_json::Value =
        serde_json::from_slice(&expired.stdout).expect("expired baseline report must parse");
    assert_eq!(expired_report["actionableFindingCount"], 2);

    let failing = run_structure(&root.path, &["--fail-on-issues"]);
    assert_eq!(failing.status.code(), Some(2));
    assert!(failing.stderr.is_empty());
}

#[test]
fn structure_supports_legacy_config_and_empty_repository_exit_behavior() {
    let root = TempDirectory::new("cbr-structure-legacy");
    root.write(
        "code-buster.toml",
        br#"languages = ["rust"]
structure_source_roots = ["src"]
structure_max_top_level_files = 0
structure_required_dirs = ["domain"]
"#,
    );
    root.write("src/lib.rs", b"pub fn entry() {}\n");

    let output = run_structure(&root.path, &["--format", "ndjson"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let records = String::from_utf8(output.stdout)
        .expect("stdout must be UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["recordType"], "summary");
    assert_eq!(records[1]["code"], "structure-missing-required-dir");
    assert_eq!(records[2]["code"], "structure-top-level-file");

    let empty = TempDirectory::new("cbr-structure-empty");
    let rejected = run_structure(&empty.path, &[]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        String::from_utf8(rejected.stderr).expect("stderr must be UTF-8"),
        "no source files found (use --allow-empty to allow this)\n"
    );
    let allowed = run_structure(&empty.path, &["--allow-empty", "--format", "json"]);
    assert_eq!(allowed.status.code(), Some(0));
    assert!(allowed.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&allowed.stdout).expect("empty report must parse");
    assert_eq!(report["files"], 0);
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn duplication_reports_exact_blocks_with_advisory_policy() {
    let root = TempDirectory::new("cbr-duplication");
    root.write(
        "code-buster.toml",
        br#"languages = ["rust"]

[analysis]
duplication_min_lines = 3
"#,
    );
    let source =
        b"fn shared() {\n    let value = load();\n    save(value);\n    finish(value);\n}\n";
    root.write("src/a.rs", source);
    root.write("src/b.rs", source);

    let text = run_duplication(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✓ Code Buster duplication — no actionable findings\n"));
    assert!(stdout.contains("  Advisory    1"));
    assert!(stdout.contains("Advisory breakdown\n  maintainability   1"));
    assert!(stdout.contains(
        "Findings\n\n  WARN  duplicate-block\n        src/a.rs:1-4\n        duplicate block of 4 lines fingerprint=4FEBB33CC8BB"
    ));
    assert!(stdout.contains("→ Review advisory findings: cb review --advisory"));

    let json = run_duplication(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("duplication JSON must parse");
    assert_eq!(report["command"], "duplication");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["advisorySummary"]["groups"]["maintainability"], 1);
    assert_eq!(report["findings"][0]["code"], "duplicate-block");
    assert_eq!(report["findings"][0]["line"], 1);
    assert_eq!(report["findings"][0]["end_line"], 4);
    assert_eq!(
        report["findings"][0]["related_files"],
        serde_json::json!(["src/b.rs:1-4"])
    );

    let advisory_only = run_duplication(&root.path, &["--fail-on-issues"]);
    assert_eq!(advisory_only.status.code(), Some(0));
    root.write(
        "code-buster.toml",
        br#"languages = ["rust"]

[analysis]
duplication_min_lines = 3

[rules.severity]
duplicate-block = "warn"
"#,
    );
    let actionable = run_duplication(&root.path, &["--fail-on-issues"]);
    assert_eq!(actionable.status.code(), Some(2));
    assert!(actionable.stderr.is_empty());
}

#[test]
fn duplication_reports_repeated_conditions_and_rejects_invalid_modes() {
    let root = TempDirectory::new("cbr-repeated-condition");
    root.write("code-buster.toml", b"languages = [\"rust\"]\n");
    root.write(
        "src/policy.rs",
        br#"fn first(user: User) {
    if user.ready && user.enabled && user.allowed {
        allow();
    }
}
fn second(user: User) {
    if user.ready && user.enabled && user.allowed {
        allow_again();
    }
}
fn third(user: User) {
    if user.ready && user.enabled && user.allowed {
        allow_last();
    }
}
"#,
    );
    let output = run_duplication(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("repeated-condition JSON must parse");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["findings"][0]["code"], "repeated-condition");
    assert_eq!(report["findings"][0]["line"], 2);
    assert_eq!(
        report["findings"][0]["related_files"],
        serde_json::json!(["src/policy.rs:7", "src/policy.rs:12"])
    );

    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\nduplication_mode = \"fuzzy\"\n",
    );
    let unsupported = run_duplication(&root.path, &[]);
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(unsupported.stdout.is_empty());
    assert_eq!(
        String::from_utf8(unsupported.stderr).expect("stderr must be UTF-8"),
        "unsupported duplication mode: fuzzy\n"
    );

    let clean = TempDirectory::new("cbr-duplication-clean");
    clean.write("main.rs", b"fn unique() { println!(\"unique\"); }\n");
    let clean_output = run_duplication(&clean.path, &[]);
    assert_eq!(clean_output.status.code(), Some(0));
    assert!(clean_output.stderr.is_empty());
    let stdout = String::from_utf8(clean_output.stdout).expect("stdout must be UTF-8");
    assert_eq!(
        stdout,
        "✓ Code Buster duplication — no actionable findings\n\n  Files       1 analyzed\n"
    );
}

#[test]
fn duplication_normalized_mode_reports_bidirectional_near_duplicates() {
    let root = TempDirectory::new("cbr-normalized-duplication");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\nduplication_mode = \"normalized\"\nduplication_min_lines = 50\n",
    );
    root.write(
        "src/a.rs",
        br#"pub fn load_user(path: &str) -> i32 {
    if ready(path) && enabled(path) {
        let user = parse_json(read_file(path));
        save(user, 30);
        audit(user);
        return user;
    }
    fallback(path)
}
"#,
    );
    root.write(
        "src/b.rs",
        br#"pub fn load_product(file: &str) -> i32 {
    if ready(file) && enabled(file) {
        let product = parse_json(read_file(file));
        save(product, 60);
        notify(product);
        return product;
    }
    fallback(file)
}
"#,
    );

    let output = run_duplication(&root.path, &["--format", "json", "--fail-on-issues"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("normalized report must parse");
    assert_eq!(report["actionableFindingCount"], 2);
    assert_eq!(report["advisorySummary"]["total"], 0);
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0]["code"], "near-duplicate-function");
    assert_eq!(
        findings[0]["message"],
        "load_user is 96% structurally similar to load_product"
    );
    assert_eq!(
        findings[1]["message"],
        "load_product is 96% structurally similar to load_user"
    );
}

#[test]
fn duplication_semantic_mode_reports_contracts_and_overlapping_dart_models() {
    let root = TempDirectory::new("cbr-semantic-duplication");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\", \"dart\"]\n[analysis]\nduplication_mode = \"semantic\"\nduplication_min_lines = 50\n",
    );
    root.write(
        "src/a.rs",
        br#"pub fn fetch_user(client: Client) -> User {
    let response = client.get("/api/users/42");
    let body = response.body();
    decode_user(body)
}
"#,
    );
    root.write(
        "src/b.rs",
        br#"pub fn load_remote(api: Api) -> User {
    log_start();
    let result = api.get("/api/users/99");
    if result.ok() {
        return map_user(result);
    }
    fallback_user()
}
"#,
    );
    let common_fields = (0..8)
        .map(|index| format!("  final String field{index};\n"))
        .collect::<String>();
    root.write(
        "lib/customer.dart",
        format!("class CustomerRecord {{\n{common_fields}  final DateTime createdAt;\n}}\n")
            .as_bytes(),
    );
    root.write(
        "lib/user.dart",
        format!("class UserRecord {{\n{common_fields}  final bool active;\n}}\n").as_bytes(),
    );

    let output = run_duplication(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("semantic report must parse");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["advisorySummary"]["groups"]["maintainability"], 2);
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "parallel-contract-implementation",
            "dart-overlapping-data-model"
        ]
    );
    assert_eq!(
        findings[0]["message"],
        "2 functions independently implement HTTP GET /api/users/{number}; normalized bodies are 63% similar"
    );
    assert_eq!(
        findings[1]["message"],
        "CustomerRecord and UserRecord duplicate 8 data fields"
    );
    assert_eq!(
        findings[1]["suggestion"],
        "Confirm distinct contracts or share a common value object."
    );
}

#[test]
fn complexity_reports_metrics_lengths_and_goto_policy() {
    let root = TempDirectory::new("cbr-complexity");
    root.write(
        "code-buster.toml",
        br#"languages = ["rust", "cpp"]

[analysis]
complexity_threshold = 3
cognitive_complexity_threshold = 4
max_function_lines = 5
"#,
    );
    root.write(
        "src/logic.rs",
        br#"pub fn logic() {
    if first() && second() {
        for item in items() {
            if item.ready() {
                save(item);
            }
        }
    }
}
"#,
    );
    root.write(
        "src/jump.c",
        br#"int jump(int ready) {
  if (ready) {
    goto cleanup;
  }
cleanup:
  return 0;
}
"#,
    );

    let text = run_complexity(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✗ Code Buster complexity — 3 actionable findings\n"));
    assert!(stdout.contains("  Actionable  3"));
    assert!(stdout.contains("  Advisory    1"));
    assert!(stdout.contains("Languages\n  cpp              1 file     2 findings"));
    assert!(stdout.contains(
        "  WARN  complex-function\n        src/logic.rs:1\n        logic complexity=5 cognitive=7"
    ));
    assert!(stdout.contains(
        "  WARN  goto-statement\n        src/jump.c:3\n        use of goto makes control flow hard to review and analyze"
    ));

    let json = run_complexity(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("complexity JSON must parse");
    assert_eq!(report["command"], "complexity");
    assert_eq!(report["actionableFindingCount"], 3);
    assert_eq!(report["advisorySummary"]["groups"]["maintainability"], 1);
    assert_eq!(
        report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .map(|finding| finding["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "long-function",
            "complex-function",
            "long-function",
            "goto-statement"
        ]
    );
    assert_eq!(
        report["findings"][1]["why"],
        "The function exceeds configured complexity thresholds."
    );

    let sarif = run_complexity(&root.path, &["--format", "sarif"]);
    assert_eq!(sarif.status.code(), Some(0));
    let sarif_report: serde_json::Value =
        serde_json::from_slice(&sarif.stdout).expect("complexity SARIF must parse");
    assert_eq!(
        sarif_report["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("SARIF rules must be an array")
            .iter()
            .map(|rule| rule["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["long-function", "complex-function", "goto-statement"]
    );

    let failing = run_complexity(&root.path, &["--fail-on-issues"]);
    assert_eq!(failing.status.code(), Some(2));
    assert!(failing.stderr.is_empty());
}

#[test]
fn complexity_ignores_control_flow_and_gotos_inside_comments_and_strings() {
    let root = TempDirectory::new("cbr-complexity-lexical");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\", \"cpp\"]\n[analysis]\ncomplexity_threshold = 1\ncognitive_complexity_threshold = 0\n",
    );
    root.write(
        "src/clean.rs",
        br#"pub fn clean() {
    let example = "if ready && visible { goto cleanup; }";
    // if ignored && ignored {
    save(example);
}
"#,
    );
    root.write(
        "src/clean.c",
        br#"/*
 * goto ignored;
 */
int clean(void) {
  const char* marker = "goto hidden;";
  // goto ignored;
  return marker[0];
}
"#,
    );

    let output = run_complexity(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("clean complexity JSON must parse");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn clusters_reuses_duplication_findings_with_its_public_report_contract() {
    let root = TempDirectory::new("cbr-clusters");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\nduplication_min_lines = 3\n",
    );
    let source =
        b"fn shared() {\n    let value = load();\n    save(value);\n    finish(value);\n}\n";
    root.write("src/a.rs", source);
    root.write("src/b.rs", source);

    let text = run_clusters(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✓ Code Buster — no actionable findings\n"));
    assert!(stdout.contains("  Advisory    1"));
    assert!(stdout.contains(
        "Findings\n\n  WARN  duplicate-block\n        src/a.rs:1-4\n        duplicate block of 4 lines fingerprint=4FEBB33CC8BB"
    ));
    assert!(stdout.contains("→ Review advisory findings: cb review --advisory"));

    let json = run_clusters(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("clusters JSON must parse");
    assert_eq!(report["command"], "clusters");
    assert_eq!(report["manifest"]["command"], "clusters");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["findings"][0]["code"], "duplicate-block");

    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\nduplication_min_lines = 3\n[rules.severity]\nduplicate-block = \"warn\"\n",
    );
    let failing = run_clusters(&root.path, &["--fail-on-issues"]);
    assert_eq!(failing.status.code(), Some(2));
    assert!(failing.stderr.is_empty());
}

#[test]
fn flags_reports_unique_lifecycle_references_with_advisory_policy() {
    let root = TempDirectory::new("cbr-flags");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\", \"typescript\"]\n",
    );
    root.write(
        "src/a.rs",
        br#"fn check() {
    if Flags.featureNewCheckout { run(); }
    let duplicate = Flags.featureNewCheckout;
    let text = "Config.featureFake";
    let normal = Config.push;
    // Config.betaComment
}
"#,
    );
    root.write(
        "src/b.ts",
        br#"const enabled = Config.featureEnabled;
const beta = flags.beta;
const ordinary = flags.isChecked;
"#,
    );

    let text = run_flags(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✓ Code Buster flags — no actionable findings\n"));
    assert!(stdout.contains("  Advisory    4"));
    assert!(stdout.contains("Languages\n  rust             1 file     2 findings"));
    assert!(stdout.contains("  typescript       1 file     2 findings"));
    assert!(stdout.contains(
        "  WARN  feature-flag\n        src/a.rs:2\n        feature flag reference: featureNewCheckout"
    ));
    assert!(stdout.contains(
        "  WARN  feature-flag\n        src/b.ts:2\n        feature flag reference: beta"
    ));

    let json = run_flags(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("flags JSON must parse");
    assert_eq!(report["command"], "flags");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["advisorySummary"]["groups"]["maintainability"], 4);
    assert_eq!(
        report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .map(|finding| finding["line"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [2, 6, 1, 2]
    );
    assert_eq!(
        report["findings"][0]["why"],
        "A feature/config flag reference was found."
    );
    assert_eq!(
        report["findings"][0]["suggestion"],
        "Review ownership and lifecycle for this flag."
    );

    let advisory_only = run_flags(&root.path, &["--fail-on-issues"]);
    assert_eq!(advisory_only.status.code(), Some(0));
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\", \"typescript\"]\n[rules.mode]\nfeature-flag = \"report\"\n",
    );
    let actionable = run_flags(&root.path, &["--fail-on-issues"]);
    assert_eq!(actionable.status.code(), Some(2));
    assert!(actionable.stderr.is_empty());
}

#[test]
fn flags_excludes_strings_generic_members_and_duplicates() {
    let root = TempDirectory::new("cbr-flags-clean");
    root.write(
        "main.rs",
        br#"fn clean() {
    let text = "Flags.featureHidden";
    let normal = Config.push;
    let ordinary = flags.isChecked;
}
"#,
    );

    let output = run_flags(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("clean flags JSON must parse");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn graph_reports_display_edges_and_resolved_mermaid_nodes() {
    let root = TempDirectory::new("cbr-graph");
    root.write("code-buster.toml", b"languages = [\"dart\", \"rust\"]\n");
    root.write("lib/main.dart", b"import 'service.dart';\n");
    root.write("lib/service.dart", b"void service() {}\n");
    root.write("src/main.rs", b"mod util;\n");
    root.write("src/util.rs", b"pub fn run() {}\n");

    let text = run_graph(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    assert_eq!(
        String::from_utf8(text.stdout).expect("stdout must be UTF-8"),
        "Code Buster graph: 4 files\n\
         lib/main.dart -> ;\n\
         lib/main.dart -> service.dart\n\
         src/main.rs -> src/util.rs\n"
    );

    let json = run_graph(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("graph JSON must parse");
    assert_eq!(report["version"], 1);
    assert_eq!(report["command"], "graph");
    assert_eq!(report["files"], 4);
    assert_eq!(
        report["edges"],
        serde_json::json!([
            {"source": "lib/main.dart", "target": ";"},
            {"source": "lib/main.dart", "target": "service.dart"},
            {"source": "src/main.rs", "target": "src/util.rs"}
        ])
    );

    let mermaid = run_graph(&root.path, &["--format", "mermaid"]);
    assert_eq!(mermaid.status.code(), Some(0));
    assert!(mermaid.stderr.is_empty());
    assert_eq!(
        String::from_utf8(mermaid.stdout).expect("stdout must be UTF-8"),
        "flowchart LR\n\
         \x20 n0[\"lib/main.dart\"]\n\
         \x20 n1[\"lib/service.dart\"]\n\
         \x20 n2[\"src/main.rs\"]\n\
         \x20 n3[\"src/util.rs\"]\n\
         \x20 n0 --> null\n\
         \x20 n0 --> null\n\
         \x20 n2 --> n3\n"
    );
}
#[test]
fn graph_reads_javascript_edges_after_a_utf8_bom() {
    let root = TempDirectory::new("cbr-graph-javascript-bom");
    root.write("code-buster.toml", b"languages = [\"javascript\"]\n");
    root.write("index.mjs", b"\xef\xbb\xbfexport const msg = '[success]'\n");
    root.write(
        "main.js",
        b"\xef\xbb\xbfimport '@babel/runtime/helpers/esm/slicedToArray'\nexport const msg = '[success]'\n",
    );

    let output = run_graph(&root.path, &["--format", "json", "--no-cache"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("graph JSON must parse");

    assert_eq!(
        report["edges"],
        serde_json::json!([
            {"source": "index.mjs", "target": "[success]"},
            {"source": "main.js", "target": "@babel/runtime/helpers/esm/slicedToArray"},
            {"source": "main.js", "target": "[success]"}
        ])
    );
}

#[test]
fn summary_preserves_one_large_number_finding_per_literal() {
    let root = TempDirectory::new("cbr-large-number-per-literal");
    root.write("code-buster.toml", b"languages = [\"typescript\"]\n");
    root.write(
        "index.ts",
        b"let seed = (value * 1664525 + 1013904223) >>> 0;\n",
    );

    let output = run_summary(
        &root.path,
        &[
            "--format",
            "json",
            "--no-cache",
            "--advisory",
            "--all-findings",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary JSON must parse");
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|finding| finding["code"] == "large-number-ungrouped")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| finding["line"] == 1));
}

#[test]
fn graph_reads_rust_dependencies_after_lifetimes() {
    let root = TempDirectory::new("cbr-graph-rust-lifetime");
    root.write("code-buster.toml", b"languages = [\"rust\"]\n");
    root.write(
        "src/lib.rs",
        b"static TEXT: &'static str = \"value\";\npub(super) mod child;\nuse crate::helper;\n",
    );
    root.write("src/child.rs", b"pub fn child() {}\n");
    root.write("src/helper.rs", b"pub fn helper() {}\n");

    let output = run_graph(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("graph JSON must parse");

    assert_eq!(
        report["edges"],
        serde_json::json!([
            {"source": "src/lib.rs", "target": "src/child.rs"},
            {"source": "src/lib.rs", "target": "src/helper.rs"}
        ])
    );
}

#[test]
fn graph_renders_architecture_layers_and_preserves_empty_exit_behavior() {
    let root = TempDirectory::new("cbr-graph-architecture");
    root.write(
        "code-buster.toml",
        b"languages = [\"dart\"]\n[architecture]\nlayers = [\"ui\", \"domain\", \"data\"]\nallowed_dependencies = [\"ui -> domain\", \"domain -> data\"]\n",
    );
    root.write("lib/ui/view.dart", b"import '../domain/model.dart';\n");
    root.write("lib/domain/model.dart", b"import '../data/store.dart';\n");
    root.write("lib/data/store.dart", b"");

    let output = run_graph(&root.path, &["--format", "mermaid"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "graph TD\n  \"domain\" --> \"data\"\n  \"ui\" --> \"domain\"\n"
    );

    let empty = TempDirectory::new("cbr-graph-empty");
    let rejected = run_graph(&empty.path, &[]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        String::from_utf8(rejected.stderr).expect("stderr must be UTF-8"),
        "no source files found (use --allow-empty to allow this)\n"
    );
    let allowed = run_graph(&empty.path, &["--allow-empty", "--format", "mermaid"]);
    assert_eq!(allowed.status.code(), Some(0));
    assert!(allowed.stderr.is_empty());
    assert_eq!(allowed.stdout, b"flowchart LR\n");
}

#[test]
fn dead_reports_cycles_and_unreachable_files_with_actionable_policy() {
    let root = TempDirectory::new("cbr-dead");
    root.write(
        "code-buster.toml",
        b"languages = [\"dart\", \"javascript\"]\n",
    );
    root.write(
        "lib/main.dart",
        b"import 'src/live.dart';\nvoid main() {}\n",
    );
    root.write("lib/src/live.dart", b"void live() {}\n");
    root.write("lib/src/orphan.dart", b"void orphan() {}\n");
    root.write("web/a.js", b"import './b.js';\n");
    root.write("web/b.js", b"import './a.js';\n");

    let text = run_dead(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✗ Code Buster dead — 2 actionable findings\n"));
    assert!(stdout.contains("  Errors      1"));
    assert!(stdout.contains("  Warnings    1"));
    assert!(stdout.contains("Languages\n  dart             3 files     1 finding"));
    assert!(stdout.contains(
        "  WARN  cycle\n        web/a.js:1\n        circular dependency: a.js -> b.js -> a.js"
    ));
    assert!(stdout.contains(
        "  ERROR dead-file\n        lib/src/orphan.dart:1\n        file is not reachable from configured entry points"
    ));

    let json = run_dead(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("dead JSON must parse");
    assert_eq!(report["command"], "dead");
    assert_eq!(report["actionableFindingCount"], 2);
    assert_eq!(
        report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .map(|finding| finding["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["cycle", "dead-file"]
    );
    assert_eq!(report["findings"][0]["confidence"], "medium");
    assert_eq!(
        report["findings"][1]["suggestion"],
        "Remove the file, connect it from reachable code, or configure an entry point."
    );

    let failing = run_dead(&root.path, &["--fail-on-issues"]);
    assert_eq!(failing.status.code(), Some(2));
    assert!(failing.stderr.is_empty());
}

#[test]
fn dead_preserves_language_specific_roots() {
    let root = TempDirectory::new("cbr-dead-language-roots");
    root.write(
        "code-buster.toml",
        b"languages = [\"lua\", \"python\"]\nentry_points = [\"app/main.py\", \"src/init.lua\"]\n",
    );
    root.write("app/main.py", b"print('ready')\n");
    root.write("app/orphan.py", b"def orphan():\n    pass\n");
    root.write("src/init.lua", b"print('ready')\n");
    root.write("src/orphan.lua", b"local orphan = true\n");

    let output = run_dead(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("dead JSON must parse");
    let dead_paths = report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter(|finding| finding["code"] == "dead-file")
        .map(|finding| finding["path"].as_str().expect("finding path"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        dead_paths,
        std::collections::BTreeSet::from(["app/orphan.py", "src/orphan.lua"])
    );
}

#[test]
fn export_analysis_runs_only_for_the_dead_command() {
    let root = TempDirectory::new("cbr-dead-exports");
    root.write(
        "code-buster.toml",
        b"languages = [\"rust\", \"typescript\"]\n",
    );
    root.write(
        "Cargo.toml",
        b"[package]\nname = \"private-tool\"\nversion = \"0.1.0\"\npublish = false\n",
    );
    root.write("package.json", br#"{"private": true}"#);
    root.write(
        "src/lib.rs",
        b"pub use crate::api::Client;\npub fn orphaned() {}\npub fn used() {}\nfn caller() { used(); }\n",
    );
    root.write(
        "web/index.ts",
        b"export { Button } from './button';\nexport function lonely() {}\nexport function used() {}\nused();\n",
    );

    let summary = run_summary(&root.path, &["--format", "json", "--all-findings"]);
    assert_eq!(summary.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&summary.stdout).expect("summary JSON must parse");
    assert!(
        report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .all(|finding| !matches!(
                finding["code"].as_str(),
                Some("dead-export" | "re-export")
            ))
    );

    let dead = run_dead(&root.path, &["--format", "json", "--all-findings"]);
    assert_eq!(dead.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&dead.stdout).expect("dead JSON must parse");
    let mut counts = std::collections::BTreeMap::new();
    for code in report["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .filter(|code| matches!(*code, "dead-export" | "re-export"))
    {
        *counts.entry(code).or_insert(0) += 1;
    }
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([("dead-export", 2), ("re-export", 2)])
    );
}

#[test]
fn dead_handles_cycles_between_generated_dart_files() {
    let root = TempDirectory::new("cbr-dead-generated-dart-cycle");
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write("lib/main.dart", b"void main() {}\n");
    root.write(
        "lib/generated/a.g.dart",
        b"import 'b.g.dart';\nimport '../src/generated_dependency.dart';\n",
    );
    root.write(
        "lib/generated/b.g.dart",
        b"import 'a.g.dart';\nimport '../src/generated_dependency.dart';\n",
    );
    root.write(
        "lib/src/generated_dependency.dart",
        b"void generatedDependency() {}\n",
    );
    root.write("lib/src/orphan.dart", b"void orphan() {}\n");

    let output = run_dead(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("dead JSON must parse");
    assert_eq!(report["coverage"]["generated"], 2);
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["code"], "dead-file");
    assert_eq!(findings[0]["path"], "lib/src/orphan.dart");
}

#[test]
fn dead_reports_architecture_boundaries_and_clean_graphs() {
    let architecture = TempDirectory::new("cbr-dead-architecture");
    architecture.write(
        "code-buster.toml",
        b"languages = [\"dart\"]\n[architecture]\nlayers = [\"ui\", \"domain\"]\nallowed_dependencies = []\n",
    );
    architecture.write("lib/ui/view.dart", b"import '../domain/model.dart';\n");
    architecture.write("lib/domain/model.dart", b"");
    let violation = run_dead(&architecture.path, &[]);
    assert_eq!(violation.status.code(), Some(0));
    assert!(violation.stderr.is_empty());
    let stdout = String::from_utf8(violation.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✗ Code Buster dead — 1 actionable finding\n"));
    assert!(stdout.contains("  Errors      1"));
    assert!(stdout.contains(
        "Findings\n\n  ERROR architecture-forbidden-dependency\n        lib/ui/view.dart:1\n        forbidden architecture dependency ui -> domain"
    ));

    let mvvm = TempDirectory::new("cbr-dead-mvvm");
    mvvm.write(
        "code-buster.toml",
        b"languages = [\"dart\"]\n[architecture]\nprofile = \"dart-mvvm\"\n",
    );
    mvvm.write(
        "lib/x/views/page.dart",
        b"import '../repositories/store.dart';\n",
    );
    mvvm.write("lib/x/repositories/store.dart", b"");
    let advisory = run_dead(&mvvm.path, &["--fail-on-issues"]);
    assert_eq!(advisory.status.code(), Some(0));
    assert!(advisory.stderr.is_empty());
    let stdout = String::from_utf8(advisory.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✓ Code Buster dead — no actionable findings\n"));
    assert!(stdout.contains("  Advisory    1"));
    assert!(stdout.contains(
        "Findings\n\n  ERROR mvvm-forbidden-dependency\n        lib/x/views/page.dart:1\n        View must not depend on Repository"
    ));
    assert!(stdout.contains("→ Review advisory findings: cb review --advisory"));

    let clean = TempDirectory::new("cbr-dead-clean");
    clean.write("code-buster.toml", b"languages = [\"dart\"]\n");
    clean.write(
        "lib/main.dart",
        b"import 'src/live.dart';\nvoid main() {}\n",
    );
    clean.write("lib/src/live.dart", b"void live() {}\n");
    let output = run_dead(&clean.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("clean dead JSON must parse");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn hotspots_rank_discovered_files_from_git_history_and_honor_top() {
    let root = TempDirectory::new("cbr-hotspots");
    git(&root.path, &["init"]);
    git(&root.path, &["config", "user.email", "test@example.com"]);
    git(&root.path, &["config", "user.name", "Code Buster Test"]);
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write("lib/hot.dart", b"void hot() {}\nvoid more() {}\n");
    root.write("lib/cold.dart", b"void cold() {}\n");
    root.write("README.md", b"not a discovered source file\n");
    git(&root.path, &["add", "."]);
    git(&root.path, &["commit", "-m", "initial"]);
    root.write(
        "lib/hot.dart",
        b"void hot() {}\nvoid more() {}\nvoid added() {}\n",
    );
    git(&root.path, &["add", "."]);
    git(&root.path, &["commit", "-m", "hot"]);

    let expected = "Code Buster hotspots: 2\n\
                    lib/hot.dart — risk 6.3, churn 3, commits 2 (+3/-0)\n\
                    lib/cold.dart — risk 1.7, churn 1, commits 1 (+1/-0)\n";
    let text = run_hotspots(&root.path, &[]);
    assert_eq!(text.status.code(), Some(0));
    assert!(text.stderr.is_empty());
    assert_eq!(
        String::from_utf8(text.stdout).expect("stdout must be UTF-8"),
        expected
    );

    let ignored_target = run_hotspots(&root.path, &["ignored-target"]);
    assert_eq!(ignored_target.status.code(), Some(0));
    assert!(ignored_target.stderr.is_empty());
    assert_eq!(
        String::from_utf8(ignored_target.stdout).expect("stdout must be UTF-8"),
        expected
    );

    let limited = run_hotspots(&root.path, &["--top", "1"]);
    assert_eq!(limited.status.code(), Some(0));
    assert!(limited.stderr.is_empty());
    assert_eq!(
        String::from_utf8(limited.stdout).expect("stdout must be UTF-8"),
        "Code Buster hotspots: 1\n\
         lib/hot.dart — risk 6.3, churn 3, commits 2 (+3/-0)\n"
    );

    let json = run_hotspots(&root.path, &["--format", "json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("hotspots JSON must parse");
    assert_eq!(report["version"], 1);
    assert_eq!(report["command"], "hotspots");
    assert_eq!(report["root"], root.path.to_string_lossy().as_ref());
    assert_eq!(report["hotspots"][0]["path"], "lib/hot.dart");
    assert_eq!(report["hotspots"][0]["commits"], 2);
    assert_eq!(report["hotspots"][0]["added"], 3);
    assert_eq!(report["hotspots"][0]["deleted"], 0);
    assert_eq!(report["hotspots"][0]["churn"], 3);
    assert_eq!(report["hotspots"][0]["risk"], 6.29583686600433_f64);
    assert_eq!(report["hotspots"][1]["path"], "lib/cold.dart");
}

#[test]
fn hotspots_report_missing_history_and_preserve_empty_exit_behavior() {
    let root = TempDirectory::new("cbr-hotspots-no-git");
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write("lib/source.dart", b"void source() {}\n");
    let output = run_hotspots(&root.path, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "Code Buster hotspots: 0\nNo Git history available for discovered files.\n"
    );

    let empty = TempDirectory::new("cbr-hotspots-empty");
    empty.write("code-buster.toml", b"languages = [\"dart\"]\n");
    let output = run_hotspots(&empty.path, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr must be UTF-8"),
        "no source files found (use --allow-empty to allow this)\n"
    );
}

#[test]
fn repository_views_report_related_files_and_shortest_dependency_paths() {
    let root = TempDirectory::new("cbr-repository-views");
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write(
        "lib/main.dart",
        b"import 'a.dart';\nimport 'b.dart';\nvoid main() {}\n",
    );
    root.write("lib/a.dart", b"import 'target.dart';\n");
    root.write("lib/b.dart", b"import 'target.dart';\n");
    root.write("lib/target.dart", b"void target() {}\n");
    root.write("lib/orphan.dart", b"void orphan() {}\n");

    let related = run_repository_view("related", &root.path, &["lib/target.dart"]);
    assert_eq!(related.status.code(), Some(0));
    assert!(related.stderr.is_empty());
    assert_eq!(
        String::from_utf8(related.stdout).expect("stdout must be UTF-8"),
        "Code Buster related: lib/target.dart\nlib/a.dart\nlib/b.dart\n"
    );

    let related_json = run_repository_view(
        "related",
        &root.path,
        &["lib\\target.dart", "--format", "json"],
    );
    assert_eq!(related_json.status.code(), Some(0));
    assert!(related_json.stderr.is_empty());
    assert_eq!(
        String::from_utf8(related_json.stdout).expect("stdout must be UTF-8"),
        "{\"path\":\"lib/target.dart\",\"depends_on\":[],\"depended_on_by\":[\"lib/a.dart\",\"lib/b.dart\"]}\n"
    );

    let why = run_repository_view("why", &root.path, &["lib/target.dart"]);
    assert_eq!(why.status.code(), Some(0));
    assert!(why.stderr.is_empty());
    assert_eq!(
        String::from_utf8(why.stdout).expect("stdout must be UTF-8"),
        "lib/main.dart -> lib/a.dart -> lib/target.dart\n"
    );

    let path = run_repository_view(
        "path",
        &root.path,
        &["lib/main.dart", "lib/target.dart", "--format", "json"],
    );
    assert_eq!(path.status.code(), Some(0));
    assert!(path.stderr.is_empty());
    assert_eq!(
        String::from_utf8(path.stdout).expect("stdout must be UTF-8"),
        "{\"from\":\"lib/main.dart\",\"to\":\"lib/target.dart\",\"path\":[\"lib/main.dart\",\"lib/a.dart\",\"lib/target.dart\"]}\n"
    );
}

#[test]
fn repository_views_preserve_usage_and_unreachable_exits() {
    let root = TempDirectory::new("cbr-repository-view-errors");
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write("lib/main.dart", b"void main() {}\n");
    root.write("lib/orphan.dart", b"void orphan() {}\n");

    for (command, arguments, message) in [
        (
            "related",
            &[][..],
            "related requires a project-relative source path\n",
        ),
        (
            "why",
            &[][..],
            "why requires a project-relative source path\n",
        ),
        (
            "path",
            &["lib/main.dart"][..],
            "path requires FROM and TO project-relative source paths\n",
        ),
    ] {
        let output = run_repository_view(command, &root.path, arguments);
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).expect("stderr must be UTF-8"),
            message
        );
    }

    let unreachable = run_repository_view("why", &root.path, &["lib/orphan.dart"]);
    assert_eq!(unreachable.status.code(), Some(1));
    assert!(unreachable.stdout.is_empty());
    assert_eq!(
        String::from_utf8(unreachable.stderr).expect("stderr must be UTF-8"),
        "no dependency path reaches: lib/orphan.dart\n"
    );
}

