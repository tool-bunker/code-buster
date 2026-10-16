#[test]
fn version_identifies_the_rust_executable() {
    for arguments in [["version"].as_slice(), ["--version"].as_slice()] {
        let output = run(arguments);

        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
            format!("cb {}\nruntime: Rust\n", env!("CARGO_PKG_VERSION")),
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn help_lists_the_implemented_commands() {
    let output = run(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert_eq!(
        stdout.lines().nth(1),
        Some(
            "Commands: summary graph dead duplication structure clusters complexity flags hotspots inspect related why path score quality plan actions review pr doctor preview explain rules config baseline fix init test version update completions"
        )
    );
    assert!(stdout.contains("-r, --root"));
    assert!(stdout.contains("--include-tests"));
    assert!(stdout.contains("--all-findings"));
    assert!(stdout.contains("--profile"));
    assert!(stdout.contains("--dry-run"));
    assert!(output.stderr.is_empty());
}

#[test]
fn no_argument_invocation_shows_summary_for_current_directory() {
    let root = TempDirectory::new("cbr-no-argument-summary");
    root.write("code-buster.toml", b"languages = [\"dart\"]\n");
    root.write("lib/main.dart", b"void main() {}\n");

    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .current_dir(&root.path)
        .output()
        .expect("no-argument cb invocation must execute");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("✓ Code Buster — no actionable findings\n"));
    assert!(stdout.contains("  Files       1 analyzed"));
    assert!(!stdout.contains("Usage:"));
    assert!(!stdout.contains("\u{1b}["));
}
#[test]
fn verbose_summary_exposes_scope_and_analysis_stages() {
    let root = TempDirectory::new("cbr-verbose-summary");
    root.write("src/lib.rs", b"pub fn ready() -> bool { true }\n");

    let output = run_summary(&root.path, &["--verbose", "--no-cache"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.contains("\nScope\n  selected          1"));
    assert!(stdout.contains("\nPerformance\n"));
    assert!(stdout.contains("  graph             "));
    assert!(stdout.contains("  rules             "));
}

#[test]
fn profile_summary_reports_sorted_uncached_rule_pack_timings() {
    let root = TempDirectory::new("cbr-profile-summary");
    root.write(
        "src/lib.rs",
        b"pub fn ready(value: bool) -> bool { value }\n",
    );

    let output = run_summary(&root.path, &["--profile", "--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("profile must emit JSON");
    let manifest = &report["manifest"];
    assert_eq!(
        manifest["cache"],
        serde_json::json!({"graphHit": false, "findingsHit": false})
    );
    assert!(manifest.get("selectedFiles").is_none());
    let profile = &manifest["profile"];
    assert_eq!(profile["cacheBypassed"], true);
    assert_eq!(profile["measurementUnit"], "microseconds");
    let packs = profile["rulePacks"]
        .as_array()
        .expect("profile must contain rule packs");
    assert!(packs.iter().any(|pack| pack["id"] == "rust"));
    assert!(packs.windows(2).all(|pair| {
        pair[0]["durationMicroseconds"].as_u64().unwrap()
            >= pair[1]["durationMicroseconds"].as_u64().unwrap()
    }));
    assert!(
        profile["sharedAnalysis"]
            .as_array()
            .unwrap()
            .iter()
            .any(|timing| timing["name"] == "function-extraction")
    );
}

#[test]
fn profile_text_is_readable_and_rejects_cache_reuse() {
    let root = TempDirectory::new("cbr-profile-text");
    root.write("src/lib.rs", b"pub fn ready() -> bool { true }\n");

    let output = run_summary(&root.path, &["--profile"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.contains("\nPerformance\n"));
    assert!(stdout.contains("\nRule profile\n"));
    assert!(stdout.contains("  Pack execution"));
    assert!(stdout.contains("  rust"));
    assert!(stdout.contains('%'));

    let incompatible = run_summary(&root.path, &["--profile", "--cache"]);
    assert_eq!(incompatible.status.code(), Some(2));
    assert!(
        String::from_utf8(incompatible.stderr)
            .unwrap()
            .contains("--profile cannot be combined with --cache")
    );
}

#[test]
fn profile_reports_independent_oop_rule_checks_separately() {
    let root = TempDirectory::new("cbr-profile-oop-rules");
    root.write(
        "src/Example.cs",
        b"class Example { int value; int Read() { return value; } }\n",
    );

    let output = run_summary(&root.path, &["--profile", "--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("profile must emit JSON");
    let profile = &report["manifest"]["profile"];
    assert!(
        profile["individualRules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|timing| timing["name"] == "oop.data-clumps")
    );
    assert!(
        profile["sharedAnalysis"]
            .as_array()
            .unwrap()
            .iter()
            .any(|timing| timing["name"] == "oop.parse")
    );
}


#[test]
fn bare_invocation_reports_actionable_findings_and_summarizes_advisory_findings() {
    let root = TempDirectory::new("cbr-default-summary-policy");
    root.write(
        "lib/main.dart",
        b"void main() {\n\tprint(\"debug\");\n}\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cb"))
        .arg("--root")
        .arg(&root.path)
        .args(["--format", "json", "--no-cache"])
        .output()
        .expect("bare cb invocation must execute");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    assert_eq!(report["command"], "summary");
    assert_eq!(report["actionableFindingCount"], 0);
    assert_eq!(report["detailedFindingCount"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert!(report["advisorySummary"]["total"].as_u64().unwrap() > 0);
}

#[test]
fn summary_reports_actionable_security_findings_as_json() {
    let root = TempDirectory::new("cbr-summary-security");
    root.write(
        "agent.py",
        b"client = OpenAI()\nprompt = \"Ignore all previous instructions\"\n",
    );

    let output = run_summary(&root.path, &["--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    assert_eq!(report["command"], "summary");
    assert_eq!(report["files"], 1);
    assert_eq!(report["actionableFindingCount"], 1);
    assert_eq!(
        report["findings"][0]["code"],
        "ai-prompt-injection-instruction"
    );
    assert!(
        report["manifest"]
            .get("ruleFamilyDurationsMilliseconds")
            .is_none()
    );
}

#[test]
fn summary_reuses_and_invalidates_the_persistent_analysis_cache() {
    let root = TempDirectory::new("cbr-summary-cache-root");
    let cache = TempDirectory::new("cbr-summary-cache-directory");
    root.write("lib/main.dart", b"void main() { print('ready'); }\n");
    let cache_path = cache.path.to_str().expect("cache path must be UTF-8");
    let arguments = ["--format", "json", "--verbose", "--cache-dir", cache_path];

    let first = run_summary(&root.path, &arguments);
    assert_eq!(first.status.code(), Some(0));
    assert!(first.stderr.is_empty());
    let first_report: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("summary must emit JSON");
    assert_eq!(
        first_report["manifest"]["cache"],
        serde_json::json!({"graphHit": false, "findingsHit": false})
    );

    let second = run_summary(&root.path, &arguments);
    assert_eq!(second.status.code(), Some(0));
    assert!(second.stderr.is_empty());
    let second_report: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("summary must emit JSON");
    assert_eq!(
        second_report["manifest"]["cache"],
        serde_json::json!({"graphHit": true, "findingsHit": true})
    );
    let cache_files = fs::read_dir(&cache.path)
        .expect("cache directory must exist")
        .map(|entry| {
            entry
                .expect("cache entry must be readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(cache_files.len(), 2);
    assert!(cache_files.iter().any(|name| name.starts_with("graph-")));
    assert!(cache_files.iter().any(|name| name.starts_with("findings-")));

    root.write(
        "lib/main.dart",
        b"void main() { print('changed source invalidates the cache'); }\n",
    );
    let invalidated = run_summary(&root.path, &arguments);
    assert_eq!(invalidated.status.code(), Some(0));
    assert!(invalidated.stderr.is_empty());
    let invalidated_report: serde_json::Value =
        serde_json::from_slice(&invalidated.stdout).expect("summary must emit JSON");
    assert_eq!(
        invalidated_report["manifest"]["cache"],
        serde_json::json!({"graphHit": false, "findingsHit": false})
    );
}

#[test]
fn summary_cache_tracks_auxiliary_and_style_inputs() {
    let root = TempDirectory::new("cbr-summary-cache-inputs-root");
    let cache = TempDirectory::new("cbr-summary-cache-inputs-directory");
    root.write("src/main.js", b"export const ready = true;\n");
    root.write("package.json", br#"{"version":"1"}"#);
    let cache_path = cache.path.to_str().expect("cache path must be UTF-8");
    let arguments = ["--format", "json", "--verbose", "--cache-dir", cache_path];

    let run = || {
        let output = run_summary(&root.path, &arguments);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .expect("summary must emit JSON")
    };

    assert_eq!(
        run()["manifest"]["cache"],
        serde_json::json!({"graphHit": false, "findingsHit": false})
    );
    assert_eq!(
        run()["manifest"]["cache"],
        serde_json::json!({"graphHit": true, "findingsHit": true})
    );

    root.write("package.json", br#"{"version":"2"}"#);
    assert_eq!(
        run()["manifest"]["cache"],
        serde_json::json!({"graphHit": true, "findingsHit": false})
    );
    assert_eq!(
        run()["manifest"]["cache"],
        serde_json::json!({"graphHit": true, "findingsHit": true})
    );

    root.write(".editorconfig", b"root = true\n");
    assert_eq!(
        run()["manifest"]["cache"],
        serde_json::json!({"graphHit": false, "findingsHit": false})
    );
}

#[test]
fn summary_cache_reuses_findings_with_malformed_source_diagnostics() {
    let root = TempDirectory::new("cbr-summary-cache-malformed-root");
    let cache = TempDirectory::new("cbr-summary-cache-malformed-directory");
    root.write("src/main.js", b"export const value = '\xff';\n");
    let cache_path = cache.path.to_str().expect("cache path must be UTF-8");
    let arguments = ["--format", "json", "--verbose", "--cache-dir", cache_path];

    let run = || {
        let output = run_summary(&root.path, &arguments);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .expect("summary must emit JSON")
    };

    let first = run();
    assert_eq!(
        first["manifest"]["cache"],
        serde_json::json!({"graphHit": false, "findingsHit": false})
    );
    assert_eq!(
        first["processingDiagnostics"][0]["code"],
        "malformed-utf8"
    );

    let second = run();
    assert_eq!(
        second["manifest"]["cache"],
        serde_json::json!({"graphHit": true, "findingsHit": true})
    );
    assert_eq!(
        second["processingDiagnostics"][0]["code"],
        "malformed-utf8"
    );
}

#[test]
fn summary_keeps_filtered_findings_out_of_the_full_analysis_cache() {
    let root = TempDirectory::new("cbr-summary-only-cache-root");
    let cache = TempDirectory::new("cbr-summary-only-cache-directory");
    root.write(
        "src/main.rs",
        b"fn main() { let _ = Some(1).unwrap(); panic!(\"stop\"); }\n",
    );
    let cache_path = cache.path.to_str().expect("cache path must be UTF-8");

    let filtered = run_summary(
        &root.path,
        &[
            "--format",
            "json",
            "--verbose",
            "--cache-dir",
            cache_path,
            "--only",
            "rust-unwrap",
        ],
    );
    assert_eq!(filtered.status.code(), Some(0));
    let filtered_report: serde_json::Value =
        serde_json::from_slice(&filtered.stdout).expect("summary must emit JSON");
    assert_eq!(filtered_report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(filtered_report["findings"][0]["code"], "rust-unwrap");

    let full = run_summary(
        &root.path,
        &["--format", "json", "--verbose", "--cache-dir", cache_path],
    );
    assert_eq!(full.status.code(), Some(0));
    let full_report: serde_json::Value =
        serde_json::from_slice(&full.stdout).expect("summary must emit JSON");
    let codes = full_report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"rust-unwrap"));
    assert!(codes.contains(&"rust-panic-macro"));
    assert_eq!(
        full_report["manifest"]["cache"]["findingsHit"],
        serde_json::json!(false)
    );
}

#[test]
fn no_cache_neither_reads_nor_writes_the_analysis_cache() {
    let root = TempDirectory::new("cbr-no-cache-root");
    let home = TempDirectory::new("cbr-no-cache-home");
    root.write("lib/main.dart", b"void main() { print('ready'); }\n");

    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_cb"))
            .args(["summary", "--root"])
            .arg(&root.path)
            .args(["--format", "json", "--verbose", "--no-cache"])
            .env("HOME", &home.path)
            .env("USERPROFILE", &home.path)
            .env("XDG_CACHE_HOME", home.path.join("cache"))
            .env("LOCALAPPDATA", home.path.join("cache"))
            .env("APPDATA", home.path.join("cache"))
            .output()
            .expect("cb summary must execute");
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
        assert_eq!(
            report["manifest"]["cache"],
            serde_json::json!({"graphHit": false, "findingsHit": false})
        );
        let family_durations = report["manifest"]["ruleFamilyDurationsMilliseconds"]
            .as_object()
            .expect("verbose summary must report rule-family durations");
        assert!(family_durations.contains_key("complexity"));
        assert!(family_durations.contains_key("function-extraction"));
    }
    assert_eq!(
        fs::read_dir(&home.path)
            .expect("temporary home must be readable")
            .count(),
        0
    );

    let incompatible = run_summary(
        &root.path,
        &["--no-cache", "--cache-dir", home.path.to_str().unwrap()],
    );
    assert_eq!(incompatible.status.code(), Some(2));
    assert!(
        String::from_utf8(incompatible.stderr)
            .unwrap()
            .contains("--no-cache cannot be combined with --cache-dir")
    );
}

#[test]
fn summary_imports_safe_sarif_findings_and_reports_invalid_inputs() {
    let root = TempDirectory::new("cbr-sarif-ingestion");
    root.write("lib/main.dart", b"void main() {}\n");
    root.write(
        "external.sarif",
        br#"{
  "runs": [{
    "tool": {"driver": {"name": "Security Scanner"}},
    "results": [
      {
        "ruleId": "unsafe-call",
        "level": "warning",
        "message": {"text": "unsafe external call"},
        "locations": [{"physicalLocation": {
          "artifactLocation": {"uri": "lib/main.dart"},
          "region": {"startLine": 2, "endLine": 3}
        }}]
      },
      {
        "ruleId": "escaped",
        "locations": [{"physicalLocation": {
          "artifactLocation": {"uri": "../outside.dart"}
        }}]
      },
      {
        "ruleId": "remote",
        "locations": [{"physicalLocation": {
          "artifactLocation": {"uri": "file:///tmp/outside.dart"}
        }}]
      }
    ]
  }]
}"#,
    );
    root.write("invalid.sarif", b"{");
    let external = root.path.join("external.sarif");
    let invalid = root.path.join("invalid.sarif");

    let output = run_summary(
        &root.path,
        &[
            "--format",
            "json",
            "--all-findings",
            "--ingest-sarif",
            external.to_str().unwrap(),
            "--ingest-sarif",
            invalid.to_str().unwrap(),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let imported = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["code"] == "external:security-scanner:unsafe-call")
        .collect::<Vec<_>>();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0]["severity"], "warn");
    assert_eq!(imported[0]["path"], "lib/main.dart");
    assert_eq!(imported[0]["line"], 2);
    assert_eq!(imported[0]["end_line"], 3);
    assert_eq!(imported[0]["confidence"], "external");
    assert!(
        !report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |finding| finding["code"] == "external:security-scanner:escaped"
                    || finding["code"] == "external:security-scanner:remote"
            )
    );
    assert_eq!(
        report["processingDiagnostics"][0]["code"],
        "sarif-ingestion-failed"
    );
    assert_eq!(
        report["processingDiagnostics"][0]["path"],
        invalid.to_string_lossy().as_ref()
    );
}

#[test]
fn summary_uses_changed_base_for_diff_quality_findings() {
    let root = TempDirectory::new("cbr-summary-changed");
    root.write(
        "lib/upload.dart",
        b"void upload(bool ready) {\n  print('one');\n  print('two');\n  print('three');\n  print('four');\n  print('five');\n  print('six');\n}\n",
    );
    git(&root.path, &["init", "-q"]);
    git(&root.path, &["config", "user.name", "Code Buster Test"]);
    git(
        &root.path,
        &["config", "user.email", "code-buster@example.invalid"],
    );
    git(&root.path, &["add", "lib/upload.dart"]);
    git(&root.path, &["commit", "-qm", "baseline"]);
    root.write(
        "lib/upload.dart",
        b"void upload(bool ready) {\n  if (!ready) return;\n  print(\"one\");\n  print(\"two\");\n  print(\"three\");\n  print(\"four\");\n  print(\"five\");\n  print(\"six\");\n}\n",
    );

    let output = run_summary(
        &root.path,
        &[
            "--changed-base",
            "HEAD",
            "--all-findings",
            "--format",
            "json",
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("summary must emit JSON");
    let codes = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"broad-refactor-in-focused-change"));
    assert!(codes.contains(&"style-drift-in-diff"));
}

#[test]
fn preview_emits_deterministic_json_with_coverage_and_versions() {
    let output = run_preview(&preview_fixture(), &["--format", "json", "--verbose"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("preview must emit JSON");
    assert_eq!(report["schemaVersion"], 3);
    assert_eq!(report["command"], "preview");
    assert_eq!(
        report["files"],
        serde_json::json!([
            {"path": "lib/main.dart", "language": "dart"},
            {"path": "src/app.ts", "language": "typescript"},
            {"path": "src/main.rs", "language": "rust"}
        ])
    );
    assert_eq!(
        report["coverage"],
        serde_json::json!({
            "generated": 1,
            "selected": 3,
            "test": 1,
            "vendored": 1
        })
    );
    assert_eq!(report["languageVersions"]["rust"], "1.85");
    assert_eq!(report["languageVersions"]["node"], ">=22");
    assert_eq!(report["languageVersions"]["typescript"], "^5.0.0");
    assert_eq!(report["generatedProvenance"][0]["path"], "src/model.g.dart");
}

#[test]
fn preview_text_and_all_source_selection_match_the_public_contract() {
    let text = run_preview(&preview_fixture(), &["--format", "text"]);
    assert_eq!(text.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(text.stdout).expect("stdout must be UTF-8"),
        "Code Buster preview: 3 selected files\n\
         coverage: generated=1 selected=3 test=1 vendored=1\n\
         dart\tlib/main.dart\n\
         typescript\tsrc/app.ts\n\
         rust\tsrc/main.rs\n"
    );

    let all = run_preview(&preview_fixture(), &["--format=json", "--all"]);
    assert_eq!(all.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&all.stdout).expect("preview must emit JSON");
    assert_eq!(report["coverage"]["selected"], 5);
    assert_eq!(report["coverage"]["generated"], 1);
    assert!(report["coverage"].get("test").is_none());
    assert!(report["coverage"].get("vendored").is_none());
}
#[test]
fn preview_classifies_standalone_rust_test_modules() {
    let root = TempDirectory::new("cbr-rust-test-modules");
    root.write("code-buster.toml", b"languages = [\"rust\"]\n");
    root.write("src/lib.rs", b"pub fn production() {}\n");
    root.write("src/parser/tests.rs", b"fn parser_fixture() {}\n");

    let output = run_preview(&root.path, &["--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("preview must emit JSON");
    assert_eq!(
        report["files"],
        serde_json::json!([{"path": "src/lib.rs", "language": "rust"}])
    );
    assert_eq!(
        report["coverage"],
        serde_json::json!({"selected": 1, "test": 1})
    );

    let included = run_preview(&root.path, &["--format", "json", "--include-tests"]);
    assert_eq!(included.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&included.stdout).expect("preview must emit JSON");
    assert_eq!(
        report["files"],
        serde_json::json!([
            {"path": "src/lib.rs", "language": "rust"},
            {"path": "src/parser/tests.rs", "language": "rust"}
        ])
    );
}

#[test]
fn preview_keeps_case_sensitive_source_directories_named_build() {
    let root = TempDirectory::new("cbr-uppercase-build");
    root.write(
        "Mojo/tools/mojo/Build/mojo-build.cpp",
        b"int build_tool() { return 0; }\n",
    );
    root.write("Mojo/tools/mojo/Build/mojo-build.h", b"int build_tool();\n");

    let output = run_preview(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("preview must emit JSON");

    assert_eq!(
        report["files"],
        serde_json::json!([
            {
                "path": "Mojo/tools/mojo/Build/mojo-build.cpp",
                "language": "cpp"
            },
            {
                "path": "Mojo/tools/mojo/Build/mojo-build.h",
                "language": "cpp"
            }
        ])
    );
}
#[test]
fn preview_keeps_uppercase_example_source_directory() {
    let root = TempDirectory::new("cbr-uppercase-example");
    root.write("Example/client.m", b"void connect(void) {}\n");

    let output = run_preview(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("preview must emit JSON");

    assert_eq!(
        report["files"],
        serde_json::json!([
            {
                "path": "Example/client.m",
                "language": "objective-c"
            }
        ])
    );
}

#[test]
fn preview_honors_gitignore_negation_and_reports_malformed_utf8() {
    let root = TempDirectory::new("cbr-preview");
    root.write(".gitignore", b"*.g.dart\n!lib/keep.g.dart\n");
    root.write("lib/main.dart", b"void main() {}\n");
    root.write("lib/drop.g.dart", b"void drop() {}\n");
    root.write("lib/keep.g.dart", b"void keep() {}\n");
    root.write("lib/damaged.dart", &[0xff, b'v', b'o', b'i', b'd']);
    root.write(
        "lib/header.dart",
        b"// generated file - do not edit\nvoid generated() {}\n",
    );
    root.write(
        "lib/generated_test.dart",
        b"// generated file - do not edit\nvoid generatedTest() {}\n",
    );

    let output = run_preview(&root.path, &["--format=json", "--verbose"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("preview must emit JSON");
    assert_eq!(
        report["files"],
        serde_json::json!([
            {"path": "lib/damaged.dart", "language": "dart"},
            {"path": "lib/keep.g.dart", "language": "dart"},
            {"path": "lib/main.dart", "language": "dart"}
        ])
    );
    assert_eq!(report["coverage"]["generated"], 3);
    assert_eq!(report["coverage"]["malformed_encoding"], 1);
    assert_eq!(report["processingDiagnostics"][0]["code"], "malformed-utf8");
    assert_eq!(
        report["generatedProvenance"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["lib/drop.g.dart", "lib/generated_test.dart", "lib/header.dart"]
    );
}

#[test]
fn config_reports_effective_current_and_legacy_settings() {
    let root = TempDirectory::new("cbr-config");
    root.write(
        "code-buster.toml",
        br#"lang = "dart"
languages = ["dart"]
complexity_threshold = 11
max_file_lines = 600
rule_groups = ["core", "dart-style", "security"]
pattern_rules = ["no-debug|warn|debugCall|debug call"]

[structure]
source_roots = ["lib"]
max_top_level_files = 2

[severity]
dart-print = "off"
"#,
    );

    let output = run_config(&root.path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config must emit JSON");
    assert_eq!(report["languages"], serde_json::json!(["dart"]));
    assert_eq!(report["complexity_threshold"], 11);
    assert_eq!(report["max_file_lines"], 600);
    assert_eq!(report["pattern_rules"], 1);
    assert_eq!(report["severity_off"], serde_json::json!(["dart-print"]));
    assert_eq!(report["structure_source_roots"], serde_json::json!(["lib"]));
    assert_eq!(report["structure_max_top_level_files"], 2);
    assert_eq!(report["group_modes"]["correctness"], "report");
    assert_eq!(report["group_modes"]["style"], "report");
}

#[test]
fn config_validation_reports_schema_and_value_errors() {
    let root = TempDirectory::new("cbr-config-validate");
    root.write(
        "code-buster.toml",
        br#"[analysis]
duplication_mode = "fuzzy"
mystery = true
[quality]
gates = ["execute(user_code)"]
[unknown]
value = 1
"#,
    );

    let output = run_config(&root.path, &["validate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.contains("error: unknown configuration key: analysis.mystery"));
    assert!(stderr.contains("error: unknown configuration key: unknown"));
    assert!(stderr.contains("error: unsupported duplication mode: fuzzy"));
    assert!(stderr.contains("error: unsupported quality gate condition: execute(user_code)"));

    root.write(
        "code-buster.toml",
        b"languages = [\"rust\"]\n[analysis]\ncomplexity_threshold = 8\n",
    );
    let valid = run_config(&root.path, &["validate"]);
    assert_eq!(valid.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(valid.stdout).expect("stdout must be UTF-8"),
        "Code Buster configuration is valid\n"
    );
    assert!(valid.stderr.is_empty());
}

#[test]
fn config_migration_supports_review_and_backup_workflows() {
    let root = TempDirectory::new("cbr-config-migrate");
    let legacy = b"# project policy\nlang = \"dart\"\ncomplexity_threshold = 8\n\n[structure]\nmax_top_level_files = 4\n\n[severity]\ndead-file = \"off\"\n";
    root.write("code-buster.toml", legacy);

    let preview = run_config(&root.path, &["migrate", "--dry-run"]);
    assert_eq!(preview.status.code(), Some(0));
    assert!(preview.stderr.is_empty());
    let migrated = String::from_utf8(preview.stdout).expect("stdout must be UTF-8");
    assert!(migrated.contains("languages = [\"dart\"]"));
    assert!(migrated.contains("analysis.complexity_threshold = 8"));
    assert!(migrated.contains("max_root_files = 4"));
    assert!(migrated.contains("[rules.severity]"));
    assert_eq!(
        fs::read(root.path.join("code-buster.toml")).unwrap(),
        legacy
    );

    let applied = run_config(&root.path, &["migrate"]);
    assert_eq!(applied.status.code(), Some(0));
    assert!(applied.stderr.is_empty());
    assert_eq!(
        fs::read(root.path.join("code-buster.toml.bak")).unwrap(),
        legacy
    );
    let current = run_config(&root.path, &["migrate"]);
    assert_eq!(current.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(current.stdout).expect("stdout must be UTF-8"),
        "Code Buster configuration is already current\n"
    );
}

#[test]
fn config_explain_reports_detected_repository_policy_and_scope() {
    let root = TempDirectory::new("cbr-config-explain");
    root.write(
        "package.json",
        br#"{"engines":{"node":">=22"},"dependencies":{"react":"^19.0.0"}}"#,
    );
    root.write(".editorconfig", b"root = true\n");

    let output = run_config(&root.path, &["explain", "--format=json", "--include-tests"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("explain must emit JSON");
    assert_eq!(report["config_file"], "none");
    assert_eq!(report["scope"], "production+tests");
    assert_eq!(report["detected_profiles"], serde_json::json!(["react"]));
    assert_eq!(report["detected_frameworks"], serde_json::json!(["react"]));
    assert_eq!(report["language_versions"]["node"], ">=22");
    assert_eq!(
        report["formatter_files"],
        serde_json::json!([".editorconfig"])
    );
    assert_eq!(
        report["effective"]["frameworks"],
        serde_json::json!(["react"])
    );
}

#[test]
fn init_creates_valid_starter_config_and_requires_force_to_replace_it() {
    let root = TempDirectory::new("cbr-init");
    let root_argument = root.path.to_str().expect("temporary path must be UTF-8");

    let created = run(&["init", root_argument]);
    assert_eq!(created.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(created.stdout).expect("stdout must be UTF-8"),
        format!("created {}\n", root.path.join("code-buster.toml").display())
    );
    assert!(created.stderr.is_empty());
    let expected = "# Optional repository-specific overrides.\n\
                    # Code Buster already detects languages, frameworks, generated files, and\n\
                    # production source conventions when this file is absent.\n\
                    languages = [\"auto\"]\n";
    assert_eq!(
        fs::read_to_string(root.path.join("code-buster.toml")).unwrap(),
        expected
    );

    let exists = run(&["init", root_argument]);
    assert_eq!(exists.status.code(), Some(1));
    assert!(exists.stdout.is_empty());
    assert_eq!(
        String::from_utf8(exists.stderr).expect("stderr must be UTF-8"),
        "config exists (use --force)\n"
    );

    root.write("code-buster.toml", b"invalid = true\n");
    let forced = run(&["init", root_argument, "--force"]);
    assert_eq!(forced.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(root.path.join("code-buster.toml")).unwrap(),
        expected
    );
}

#[test]
fn doctor_reports_discovery_health_even_when_json_is_requested() {
    let output = run_doctor(&preview_fixture(), &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "Code Buster doctor\n\
         - Hidden directories are skipped by default; use explicit includes only if you want to analyze hidden tooling/vendor folders.\n\
         - Coverage: generated=1 selected=3 test=1 vendored=1\n"
    );

    let empty = TempDirectory::new("cbr-doctor-empty");
    let empty_output = run_doctor(&empty.path, &[]);
    assert_eq!(empty_output.status.code(), Some(0));
    let stdout = String::from_utf8(empty_output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.contains("- No source files were discovered"));
}

#[test]
fn doctor_advises_on_many_explicitly_requested_duplicate_groups() {
    let root = TempDirectory::new("cbr-doctor-duplicates");
    for group in 0..21 {
        let source = (0..15)
            .map(|line| format!("group_{group}_line_{line}();"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        root.write(&format!("a{group}.rs"), source.as_bytes());
        root.write(&format!("b{group}.rs"), source.as_bytes());
    }

    let output = run_doctor(&root.path, &["--only", "duplicate-block"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.contains("- Coverage: selected=42"));
    assert!(stdout.contains(
        "- There are many duplicate-block findings; consider raising min_duplication_lines above 15."
    ));
}

