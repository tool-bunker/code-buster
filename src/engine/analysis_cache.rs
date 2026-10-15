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

const CACHE_SCHEMA_VERSION: u64 = 2;
const STYLE_CONFIG_NAMES: [&str; 6] = [
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.js",
    "prettier.config.js",
    ".editorconfig",
    "biome.json",
];

#[derive(Clone, Copy)]
pub(crate) struct FindingCacheInputs<'source> {
    base_sources: &'source BTreeMap<String, String>,
    changed_paths: &'source BTreeSet<String>,
    auxiliary: &'source BTreeMap<String, String>,
}

impl<'source> FindingCacheInputs<'source> {
    pub fn new(
        base_sources: &'source BTreeMap<String, String>,
        changed_paths: &'source BTreeSet<String>,
        auxiliary: &'source BTreeMap<String, String>,
    ) -> Self {
        Self {
            base_sources,
            changed_paths,
            auxiliary,
        }
    }

    fn hash_into(self, hasher: &mut Sha256) {
        for (path, source) in self.auxiliary {
            hash_entry(hasher, b"auxiliary", path.as_bytes(), source.as_bytes());
        }
        for (path, source) in self.base_sources {
            hash_entry(hasher, b"base", path.as_bytes(), source.as_bytes());
        }
        for path in self.changed_paths {
            hash_entry(hasher, b"changed", path.as_bytes(), b"");
        }
    }
}

pub(crate) struct AnalysisCache<'source> {
    enabled: bool,
    directory: PathBuf,
    finding_inputs: Option<FindingCacheInputs<'source>>,
    source_fingerprint: Option<[u8; 32]>,
    finding_paths: BTreeMap<String, PathBuf>,
    pub graph_hit: bool,
    pub findings_hit: bool,
}

impl<'source> AnalysisCache<'source> {
    pub fn new(options: &PreviewOptions, project_root: &Path) -> Self {
        let directory = options
            .cache_directory
            .as_ref()
            .map(|path| absolute_path(path))
            .unwrap_or_else(|| default_directory(project_root));
        Self {
            enabled: options.cache_enabled,
            directory,
            finding_inputs: None,
            source_fingerprint: None,
            finding_paths: BTreeMap::new(),
            graph_hit: false,
            findings_hit: false,
        }
    }

    pub fn with_finding_inputs(mut self, inputs: FindingCacheInputs<'source>) -> Self {
        self.finding_inputs = Some(inputs);
        self
    }

    pub fn graph(&mut self, prepared: &PreparedPreview) -> DependencyGraph {
        if !self.enabled {
            return DependencyGraph::build(prepared);
        }
        let key = self.cache_key(prepared, "graph", false);
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

    pub fn findings(&mut self, prepared: &PreparedPreview, family: &str) -> Option<Vec<Finding>> {
        if !self.enabled {
            return None;
        }
        let path = self.finding_path(prepared, family);
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
        &mut self,
        prepared: &PreparedPreview,
        family: &str,
        findings: &[Finding],
    ) {
        if !self.enabled {
            return;
        }
        let path = self.finding_path(prepared, family);
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

    fn finding_path(&mut self, prepared: &PreparedPreview, family: &str) -> PathBuf {
        if let Some(path) = self.finding_paths.get(family) {
            return path.clone();
        }
        let kind = format!("findings-family:{family}");
        let key = self.cache_key(prepared, &kind, true);
        let path = self.directory.join(format!("findings-{key}.json"));
        self.finding_paths.insert(family.to_owned(), path.clone());
        path
    }

    fn cache_key(
        &mut self,
        prepared: &PreparedPreview,
        kind: &str,
        include_finding_inputs: bool,
    ) -> String {
        let source_fingerprint = *self
            .source_fingerprint
            .get_or_insert_with(|| fingerprint_sources(prepared));
        let material = cache_material(&prepared.config, kind);
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, b"schema");
        hash_bytes(&mut hasher, &CACHE_SCHEMA_VERSION.to_le_bytes());
        hash_bytes(&mut hasher, b"configuration");
        hash_bytes(&mut hasher, material.as_bytes());
        hash_bytes(&mut hasher, b"sources");
        hash_bytes(&mut hasher, &source_fingerprint);
        if include_finding_inputs && let Some(inputs) = self.finding_inputs {
            inputs.hash_into(&mut hasher);
        }
        format!("{:x}", hasher.finalize())
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

fn fingerprint_sources(prepared: &PreparedPreview) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (path, source) in &prepared.sources {
        hash_entry(&mut hasher, b"source", path.as_bytes(), source.as_bytes());
    }

    let root = Path::new(&prepared.root);
    for path in style_config_paths(root, prepared.sources.keys().map(String::as_str)) {
        let Ok(source) = fs::read(&path) else {
            continue;
        };
        let relative = path.strip_prefix(root).unwrap_or(&path);
        hash_entry(
            &mut hasher,
            b"style",
            relative.to_string_lossy().as_bytes(),
            &source,
        );
    }
    hasher.finalize().into()
}

fn style_config_paths<'path>(
    root: &Path,
    source_paths: impl Iterator<Item = &'path str>,
) -> BTreeSet<PathBuf> {
    let mut visited_directories = BTreeSet::new();
    let mut style_configs = BTreeSet::new();
    visited_directories.insert(root.to_path_buf());
    for name in STYLE_CONFIG_NAMES {
        let candidate = root.join(name);
        if candidate.is_file() {
            style_configs.insert(candidate);
        }
    }
    for source_path in source_paths {
        let mut directory = root.join(source_path).parent().map(Path::to_path_buf);
        while let Some(current) = directory {
            if !current.starts_with(root) {
                break;
            }
            if visited_directories.insert(current.clone()) {
                for name in STYLE_CONFIG_NAMES {
                    let candidate = current.join(name);
                    if candidate.is_file() {
                        style_configs.insert(candidate);
                    }
                }
            }
            if current == root {
                break;
            }
            directory = current.parent().map(Path::to_path_buf);
        }
    }
    style_configs
}

fn hash_entry(hasher: &mut Sha256, kind: &[u8], path: &[u8], source: &[u8]) {
    hash_bytes(hasher, kind);
    hash_bytes(hasher, path);
    hash_bytes(hasher, source);
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes.len().to_le_bytes());
    hasher.update(bytes);
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
