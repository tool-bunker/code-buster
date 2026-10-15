use std::path::Path;
use std::sync::LazyLock;

use crate::analysis_cache::AnalysisCache;

use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::{ReportFormat, RepositoryViewOptions};
use crate::config::{Config, absolute_root};
use crate::discovery::{classify_target, prepare};
use crate::function_sources;
use crate::summary_command;

pub enum RepositoryViewOutcome {
    Success,
    Findings,
    NotFound,
    Usage,
}

#[derive(Serialize)]
struct RelatedReport<'a> {
    path: &'a str,
    depends_on: &'a [String],
    depended_on_by: &'a [String],
}

#[derive(Serialize)]
struct WhyReport<'a> {
    target: &'a str,
    reachable: bool,
    path: &'a [String],
}

#[derive(Serialize)]
struct PathReport<'a> {
    from: &'a str,
    to: &'a str,
    path: &'a [String],
}

fn included_by_scope(classification: &str, config: &Config) -> bool {
    classification != "generated"
        && (config.include_all
            || classification == "production"
            || (classification == "test" && config.include_tests)
            || (classification == "example" && config.include_examples)
            || (classification == "vendored" && config.include_vendored))
}

fn print_excluded_inspection(
    path: &str,
    classification: &str,
    classification_source: &str,
    matched: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    if json_output {
        let mut report = json!({
            "path": path,
            "classification": classification,
            "classification_source": classification_source,
            "included": false,
            "reason": "excluded by the default production scope",
            "override": scope_override(classification),
        });
        if let Some(matched) = matched {
            report["matched"] = json!(matched);
        }
        println!(
            "{}",
            serde_json::to_string(&report)
                .map_err(|error| format!("failed to encode inspect report: {error}"))?
        );
    } else {
        println!("path={path}");
        println!("classification={classification}");
        println!("classification_source={classification_source}");
        if let Some(pattern) = matched {
            println!("matched={pattern}");
        }
        println!("included=false");
        println!("reason=excluded by the default production scope");
    }
    Ok(())
}

fn scope_override(classification: &str) -> &'static str {
    match classification {
        "test" => "--include-tests",
        "example" => "--include-examples",
        "vendored" => "--include-vendored",
        _ => "--all",
    }
}

pub fn execute_inspect(options: &RepositoryViewOptions) -> Result<RepositoryViewOutcome, String> {
    let Some(target) = options.targets.first().filter(|target| !target.is_empty()) else {
        eprintln!("inspect requires a project-relative source path");
        return Ok(RepositoryViewOutcome::Usage);
    };
    let normalized = normalize(target);
    let root = absolute_root(&options.common.root)?;
    let config = Config::load(root.clone(), &options.common)?;
    let classification = classify_target(&root, &normalized, &config)?;
    let included = included_by_scope(classification.classification, &config);
    let target_path = root.join(normalized.replace('/', std::path::MAIN_SEPARATOR_STR));
    if target_path.is_file() && !included {
        print_excluded_inspection(
            &normalized,
            classification.classification,
            classification.source,
            classification.matched.as_deref(),
            matches!(options.common.format, ReportFormat::Json),
        )?;
        return Ok(RepositoryViewOutcome::Success);
    }

    let run = summary_command::analyze(&options.common)?;
    let Some(source) = run.prepared.sources.get(&normalized) else {
        eprintln!("target is not a discovered source file: {target}");
        return Ok(RepositoryViewOutcome::NotFound);
    };
    let mut findings = run
        .findings
        .iter()
        .filter(|finding| finding.path == normalized)
        .collect::<Vec<_>>();
    findings.sort_by_key(|finding| {
        !matches!(
            finding.code.as_str(),
            "tab-indent" | "trailing-whitespace" | "long-line"
        )
    });
    if matches!(options.common.format, ReportFormat::Json) {
        let Some(file) = run
            .prepared
            .files
            .iter()
            .find(|file| file.path == normalized)
        else {
            return Err(format!("missing discovered file metadata for {normalized}"));
        };
        let mut cache = AnalysisCache::new(&options.common, Path::new(&run.prepared.root));
        let graph = cache.graph(&run.prepared);
        let mut imported_by = graph
            .nodes()
            .filter(|node| {
                graph
                    .dependencies(node)
                    .any(|dependency| dependency == normalized)
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        imported_by.sort_unstable();
        let (imports, exports, functions) = if file.language == "dart" {
            dart_inspection(&normalized, source)
        } else {
            (
                graph.dependencies(&normalized).map(str::to_owned).collect(),
                Vec::new(),
                Vec::new(),
            )
        };
        let flags = findings
            .iter()
            .filter(|finding| finding.code == "feature-flag")
            .map(|finding| {
                finding
                    .message
                    .rsplit_once(": ")
                    .map_or(finding.message.as_str(), |(_, value)| value)
            })
            .collect::<Vec<_>>();
        let finding_lines = findings
            .iter()
            .map(|finding| format!("{}:{} {}", finding.code, finding.line, finding.message))
            .collect::<Vec<_>>();
        let mut report = json!({
            "path": normalized,
            "classification": classification.classification,
            "classification_source": classification.source,
            "included": true,
            "language": file.language,
            "lines": source.split('\n').count(),
            "imports": imports,
            "imported_by": imported_by,
            "exports": exports,
            "flags": flags,
            "functions": functions,
            "findings": finding_lines,
        });
        if let Some(matched) = &classification.matched {
            report["matched"] = json!(matched);
        }
        println!(
            "{}",
            serde_json::to_string(&report)
                .map_err(|error| format!("failed to encode inspect report: {error}"))?
        );
    } else {
        println!("classification={}", classification.classification);
        println!("classification_source={}", classification.source);
        if let Some(pattern) = classification.matched {
            println!("matched={pattern}");
        }
        println!("included=true");
        println!(
            "Code Buster inspect: 1 files, {} actionable findings",
            findings.len()
        );
        for finding in &findings {
            let location = if finding.end_line > finding.line {
                format!("{}:{}-{}", finding.path, finding.line, finding.end_line)
            } else {
                format!("{}:{}", finding.path, finding.line)
            };
            println!(
                "{} {} {location} {}",
                finding.severity.as_str(),
                finding.code,
                finding.message
            );
        }
    }
    Ok(inspect_outcome(
        options.common.fail_on_issues,
        findings.is_empty(),
    ))
}

fn inspect_outcome(fail_on_issues: bool, findings_empty: bool) -> RepositoryViewOutcome {
    if fail_on_issues && !findings_empty {
        RepositoryViewOutcome::Findings
    } else {
        RepositoryViewOutcome::Success
    }
}

fn dart_inspection(path: &str, source: &str) -> (Vec<String>, Vec<String>, Vec<Value>) {
    let imports = DART_DIRECTIVE
        .captures_iter(source)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str().to_owned()))
        .collect();
    let exports = DART_PUBLIC_DECLARATION
        .captures_iter(source)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str()))
        .filter(|name| !name.starts_with('_'))
        .map(str::to_owned)
        .collect();
    let functions = function_sources::extract(&std::collections::BTreeMap::from([(
        path.to_owned(),
        source.to_owned(),
    )]))
    .into_iter()
    .map(|function| json!({"name": function.name, "line": function.line}))
    .collect();
    (imports, exports, functions)
}

pub fn execute_related(options: &RepositoryViewOptions) -> Result<RepositoryViewOutcome, String> {
    let Some(target) = options.targets.first().filter(|target| !target.is_empty()) else {
        eprintln!("related requires a project-relative source path");
        return Ok(RepositoryViewOutcome::Usage);
    };
    let normalized = normalize(target);
    let prepared = prepare(&options.common)?;
    let mut cache = AnalysisCache::new(&options.common, Path::new(&prepared.root));
    let graph = cache.graph(&prepared);
    if !graph.contains(&normalized) {
        eprintln!("target is not a discovered source file: {target}");
        return Ok(RepositoryViewOutcome::NotFound);
    }

    let depends_on = graph
        .dependencies(&normalized)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let depended_on_by = graph
        .nodes()
        .filter(|node| {
            graph
                .dependencies(node)
                .any(|dependency| dependency == normalized)
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if matches!(options.common.format, ReportFormat::Json) {
        println!(
            "{}",
            serde_json::to_string(&RelatedReport {
                path: &normalized,
                depends_on: &depends_on,
                depended_on_by: &depended_on_by,
            })
            .map_err(|error| format!("failed to encode related report: {error}"))?
        );
    } else {
        println!("Code Buster related: {normalized}");
        let mut related = depends_on
            .iter()
            .chain(&depended_on_by)
            .map(String::as_str)
            .collect::<Vec<_>>();
        related.sort_unstable();
        related.dedup();
        for path in related {
            println!("{path}");
        }
    }
    Ok(RepositoryViewOutcome::Success)
}

pub fn execute_why(options: &RepositoryViewOptions) -> Result<RepositoryViewOutcome, String> {
    let Some(target) = options.targets.first().filter(|target| !target.is_empty()) else {
        eprintln!("why requires a project-relative source path");
        return Ok(RepositoryViewOutcome::Usage);
    };
    let normalized = normalize(target);
    let prepared = prepare(&options.common)?;
    let mut cache = AnalysisCache::new(&options.common, Path::new(&prepared.root));
    let graph = cache.graph(&prepared);
    let mut selected = Vec::new();
    for root in graph.default_roots(&prepared.config.entry_points) {
        let candidate = graph.shortest_path(root, &normalized);
        if !candidate.is_empty() && (selected.is_empty() || candidate.len() < selected.len()) {
            selected = candidate;
        }
    }
    if selected.is_empty() {
        eprintln!("no dependency path reaches: {target}");
        return Ok(RepositoryViewOutcome::NotFound);
    }

    if matches!(options.common.format, ReportFormat::Json) {
        println!(
            "{}",
            serde_json::to_string(&WhyReport {
                target: &normalized,
                reachable: true,
                path: &selected,
            })
            .map_err(|error| format!("failed to encode why report: {error}"))?
        );
    } else {
        println!("{}", selected.join(" -> "));
    }
    Ok(RepositoryViewOutcome::Success)
}

pub fn execute_path(options: &RepositoryViewOptions) -> Result<RepositoryViewOutcome, String> {
    if options.targets.len() != 2 {
        eprintln!("path requires FROM and TO project-relative source paths");
        return Ok(RepositoryViewOutcome::Usage);
    }
    let from = normalize(&options.targets[0]);
    let to = normalize(&options.targets[1]);
    let prepared = prepare(&options.common)?;
    let mut cache = AnalysisCache::new(&options.common, Path::new(&prepared.root));
    let graph = cache.graph(&prepared);
    let path = graph.shortest_path(&from, &to);
    if path.is_empty() {
        eprintln!("no dependency path from {from} to {to}");
        return Ok(RepositoryViewOutcome::NotFound);
    }

    if matches!(options.common.format, ReportFormat::Json) {
        println!(
            "{}",
            serde_json::to_string(&PathReport {
                from: &from,
                to: &to,
                path: &path,
            })
            .map_err(|error| format!("failed to encode path report: {error}"))?
        );
    } else {
        println!("{}", path.join(" -> "));
    }
    Ok(RepositoryViewOutcome::Success)
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

static DART_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*(?:import|export)\s+['"]([^'"]+)['"]"#)
        .expect("Dart directive regex must compile")
});
static DART_PUBLIC_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^(?:(?:abstract|base|final|interface|sealed)\s+)*(?:(?:class|enum|mixin|extension|typedef)\s+|(?:[A-Za-z]\w*(?:<[^>\r\n]+>)?\??|void)\s+)([A-Za-z]\w*)",
    )
    .expect("Dart public declaration regex must compile")
});
