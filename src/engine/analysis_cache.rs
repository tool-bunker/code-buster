use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::cli::PreviewOptions;
use crate::dependency_graph::DependencyGraph;
use crate::discovery::PreparedPreview;
use crate::findings::{CodeFlowStep, Finding, Severity};
use crate::report::cache_material;

const CACHE_SCHEMA_VERSION: u64 = 1;

pub(crate) struct AnalysisCache {
    enabled: bool,
    directory: PathBuf,
    pub graph_hit: bool,
    pub findings_hit: bool,
}

impl AnalysisCache {
    pub fn new(options: &PreviewOptions, project_root: &Path) -> Self {
        let directory = options
            .cache_directory
            .as_ref()
            .map(|path| absolute_path(path))
            .unwrap_or_else(|| default_directory(project_root));
        Self {
            enabled: options.cache_enabled,
            directory,
            graph_hit: false,
            findings_hit: false,
        }
    }

    pub fn graph(&mut self, prepared: &PreparedPreview) -> DependencyGraph {
        if !self.enabled {
            return DependencyGraph::build(prepared);
        }
        let key = cache_key(prepared, &prepared.sources, "graph");
        let path = self.directory.join(format!("graph-{key}.json"));
        if let Some(graph) = load_graph(&path) {
            self.graph_hit = true;
            return graph;
        }
        let _ = fs::remove_file(&path);
        let graph = DependencyGraph::build(prepared);
        store_graph(&path, &graph);
        graph
    }

    pub fn findings(
        &mut self,
        prepared: &PreparedPreview,
        sources: &BTreeMap<String, String>,
        family: &str,
    ) -> Option<Vec<Finding>> {
        if !self.enabled || !prepared.diagnostics.is_empty() {
            return None;
        }
        let key = cache_key(prepared, sources, &format!("findings-family:{family}"));
        let path = self.directory.join(format!("findings-{key}.json"));
        let findings = match load_findings(&path) {
            Some(findings) => findings,
            None => {
                let _ = fs::remove_file(&path);
                return None;
            }
        };
        self.findings_hit = true;
        Some(findings)
    }

    pub fn store_findings(
        &self,
        prepared: &PreparedPreview,
        sources: &BTreeMap<String, String>,
        family: &str,
        findings: &[Finding],
    ) {
        if !self.enabled || !prepared.diagnostics.is_empty() {
            return;
        }
        let key = cache_key(prepared, sources, &format!("findings-family:{family}"));
        let path = self.directory.join(format!("findings-{key}.json"));
        let entries = findings.iter().map(cache_finding).collect::<Vec<_>>();
        store_value(
            &path,
            &json!({
                "schemaVersion": CACHE_SCHEMA_VERSION,
                "kind": "findings",
                "entries": entries,
            }),
        );
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

pub(crate) fn default_directory(project_root: &Path) -> PathBuf {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let base = if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .or_else(|| env::var_os("APPDATA"))
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|path| path.join("AppData/Local")))
            .unwrap_or_else(env::temp_dir)
    } else if cfg!(target_os = "macos") {
        home.as_ref()
            .map(|path| path.join("Library/Caches"))
            .unwrap_or_else(env::temp_dir)
    } else {
        env::var_os("XDG_CACHE_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|path| path.join(".cache")))
            .unwrap_or_else(env::temp_dir)
    };
    let normalized = absolute_path(project_root);
    let project_name = normalized
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(normalized.to_string_lossy().as_bytes())
    );
    base.join("code-buster")
        .join("projects")
        .join(format!("{project_name}-{}", &fingerprint[..16]))
}

fn cache_key(prepared: &PreparedPreview, sources: &BTreeMap<String, String>, kind: &str) -> String {
    let mut material = cache_material(&prepared.config, kind);
    let root = Path::new(&prepared.root);
    let mut style_configs = BTreeSet::new();
    for (path, source) in sources {
        material.push_str(path);
        material.push('\n');
        material.push_str(&format!("{:x}", Sha256::digest(source.as_bytes())));
        material.push('\n');

        let mut directory = root.join(path).parent().map(Path::to_path_buf);
        while let Some(current) = directory {
            if !current.starts_with(root) {
                break;
            }
            for name in [
                ".prettierrc",
                ".prettierrc.json",
                ".prettierrc.js",
                "prettier.config.js",
                ".editorconfig",
                "biome.json",
            ] {
                let candidate = current.join(name);
                if candidate.is_file() {
                    style_configs.insert(candidate);
                }
            }
            if current == root {
                break;
            }
            directory = current.parent().map(Path::to_path_buf);
        }
    }
    for path in style_configs {
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        material.push_str(&path.to_string_lossy());
        material.push('\n');
        material.push_str(&source);
        material.push('\n');
    }
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

fn load_findings(path: &Path) -> Option<Vec<Finding>> {
    let value: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    if value.get("schemaVersion")?.as_u64()? != CACHE_SCHEMA_VERSION
        || value.get("kind")?.as_str()? != "findings"
    {
        return None;
    }
    value
        .get("entries")?
        .as_array()?
        .iter()
        .map(parse_finding)
        .collect()
}

fn parse_finding(value: &Value) -> Option<Finding> {
    let object = value.as_object()?;
    let code_flow = match object.get("code_flow") {
        Some(value) => value
            .as_array()?
            .iter()
            .map(parse_code_flow_step)
            .collect::<Option<Vec<_>>>()?,
        None => Vec::new(),
    };
    Some(Finding {
        code: string(object, "code")?,
        severity: Severity::parse(object.get("severity")?.as_str()?)?,
        path: string(object, "path")?,
        line: usize::try_from(object.get("line")?.as_u64()?).ok()?,
        end_line: usize::try_from(object.get("end_line")?.as_u64()?).ok()?,
        message: string(object, "message")?,
        confidence: string(object, "confidence")?,
        why: string(object, "why")?,
        suggestion: string(object, "suggestion")?,
        related_files: object
            .get("related_files")?
            .as_array()?
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
        snippet: string(object, "snippet")?,
        code_flow,
    })
}

fn parse_code_flow_step(value: &Value) -> Option<CodeFlowStep> {
    let object = value.as_object()?;
    Some(CodeFlowStep {
        path: string(object, "path")?,
        line: usize::try_from(object.get("line")?.as_u64()?).ok()?,
        message: string(object, "message")?,
    })
}

fn string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key)?.as_str().map(str::to_owned)
}

fn cache_finding(finding: &Finding) -> Value {
    json!({
        "code": finding.code,
        "severity": finding.severity.as_str(),
        "path": finding.path,
        "line": finding.line,
        "end_line": finding.end_line,
        "message": finding.message,
        "confidence": finding.confidence,
        "why": finding.why,
        "suggestion": finding.suggestion,
        "related_files": finding.related_files,
        "snippet": finding.snippet,
        "code_flow": finding.code_flow.iter().map(|step| json!({
            "path": step.path,
            "line": step.line,
            "message": step.message,
        })).collect::<Vec<_>>(),
    })
}

fn load_graph(path: &Path) -> Option<DependencyGraph> {
    let value: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    if value.get("schemaVersion")?.as_u64()? != CACHE_SCHEMA_VERSION
        || value.get("kind")?.as_str()? != "graph"
    {
        return None;
    }
    let edges = parse_edges(value.get("edges")?)?;
    let cycle_edges = value
        .get("cycleEdges")
        .and_then(parse_edges)
        .unwrap_or_else(|| edges.clone());
    Some(DependencyGraph::from_edges(edges, cycle_edges))
}

fn parse_edges(value: &Value) -> Option<BTreeMap<String, BTreeSet<String>>> {
    value
        .as_object()?
        .iter()
        .map(|(source, targets)| {
            let targets = targets
                .as_array()?
                .iter()
                .map(|target| target.as_str().map(str::to_owned))
                .collect::<Option<BTreeSet<_>>>()?;
            Some((source.clone(), targets))
        })
        .collect()
}

fn store_graph(path: &Path, graph: &DependencyGraph) {
    let mut edges = Map::new();
    let mut cycle_edges = Map::new();
    for node in graph.nodes() {
        edges.insert(
            node.to_owned(),
            json!(graph.dependencies(node).collect::<Vec<_>>()),
        );
        cycle_edges.insert(
            node.to_owned(),
            json!(graph.cycle_dependencies(node).collect::<Vec<_>>()),
        );
    }
    store_value(
        path,
        &json!({
            "schemaVersion": CACHE_SCHEMA_VERSION,
            "kind": "graph",
            "edges": edges,
            "cycleEdges": cycle_edges,
        }),
    );
}

fn store_value(path: &Path, value: &Value) {
    let Some(parent) = path.parent() else { return };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    if path.is_file() {
        return;
    }
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let Ok(encoded) = serde_json::to_vec(value) else {
        return;
    };
    if fs::write(&temporary, encoded).is_ok() {
        let _ = fs::rename(&temporary, path);
    }
    let _ = fs::remove_file(temporary);
}
