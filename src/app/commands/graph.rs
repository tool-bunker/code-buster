use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::architecture_graph;
use regex::Regex;
use serde_json::json;

use crate::analysis_cache::AnalysisCache;
use crate::cli::{PreviewOptions, ReportFormat};
use crate::dependency_graph::DependencyGraph;
use crate::discovery::{PreparedPreview, prepare};

pub enum GraphOutcome {
    Success,
    Empty,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DisplayEdge {
    source: String,
    target: String,
}

pub fn execute(options: &PreviewOptions) -> Result<GraphOutcome, String> {
    let prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(GraphOutcome::Empty);
    }
    let mut cache = AnalysisCache::new(options, std::path::Path::new(&prepared.root));
    let graph = cache.graph(&prepared);
    let edges = display_edges(&prepared, &graph);
    match options.format {
        ReportFormat::Mermaid if !prepared.config.architecture_layers.is_empty() => {
            print!(
                "{}",
                architecture_mermaid(&graph, &prepared.config.architecture_layers)
            );
        }
        ReportFormat::Mermaid => print!("{}", dependency_mermaid(&graph, &edges)),
        ReportFormat::Json => {
            let edges = edges
                .iter()
                .map(|edge| json!({"source": edge.source, "target": edge.target}))
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "version": 1,
                    "command": "graph",
                    "root": prepared.root,
                    "files": prepared.files.len(),
                    "edges": edges,
                }))
                .map_err(|error| format!("failed to encode graph report: {error}"))?
            );
        }
        _ => {
            println!("Code Buster graph: {} files", prepared.files.len());
            for edge in edges {
                println!("{} -> {}", edge.source, edge.target);
            }
        }
    }
    Ok(GraphOutcome::Success)
}

fn display_edges(prepared: &PreparedPreview, graph: &DependencyGraph) -> Vec<DisplayEdge> {
    let mut edges = Vec::new();
    for file in &prepared.files {
        let Some(source) = prepared.sources.get(&file.path) else {
            continue;
        };
        render_file_display_edges(
            &file.path,
            file.language.as_str(),
            source,
            graph,
            &mut edges,
        );
    }
    edges.sort();
    edges
}

struct DisplayEdgeRenderer<'a> {
    source: &'a str,
    edges: &'a mut Vec<DisplayEdge>,
}

impl<'a> DisplayEdgeRenderer<'a> {
    fn new(source: &'a str, edges: &'a mut Vec<DisplayEdge>) -> Self {
        Self { source, edges }
    }

    fn render(&mut self, target: impl Into<String>) {
        self.edges.push(DisplayEdge {
            source: self.source.to_owned(),
            target: target.into(),
        });
    }
}

fn render_file_display_edges(
    path: &str,
    language: &str,
    source: &str,
    graph: &DependencyGraph,
    edges: &mut Vec<DisplayEdge>,
) {
    let mut renderer = DisplayEdgeRenderer::new(path, edges);
    match language {
        "dart" => for_each_regex_target(source, &DART_DISPLAY, |target| {
            renderer.render(";");
            renderer.render(target);
        }),
        "cpp" => {
            for_each_regex_target(source, &CPP_DISPLAY, |target| renderer.render(target));
        }
        "python" => python_display_edges(source, &mut renderer),
        "nim" => nim_display_edges(source, &mut renderer),
        "javascript" | "typescript" => quoted_display_edges(source, &mut renderer),
        _ => {
            for target in graph.dependencies(path) {
                renderer.render(target);
            }
        }
    }
}

fn for_each_regex_target(source: &str, pattern: &Regex, mut render: impl FnMut(&str)) {
    for capture in pattern.captures_iter(source) {
        let Some(target) = capture.get(1) else {
            continue;
        };
        render(target.as_str());
    }
}

fn quoted_display_edges(source: &str, renderer: &mut DisplayEdgeRenderer<'_>) {
    for raw in source.lines() {
        let line = raw.trim();
        if line.starts_with("import ") || line.starts_with("export ") {
            for_each_regex_target(line, &QUOTED, |target| renderer.render(target));
        }
    }
}

fn python_display_edges(source: &str, renderer: &mut DisplayEdgeRenderer<'_>) {
    for raw in source.split('\n') {
        let line = raw.trim();
        if let Some(body) = line.strip_prefix("import ") {
            for module in body.split(',') {
                if let Some(target) = module.split_whitespace().next() {
                    renderer.render(target);
                }
            }
        } else if let Some(target) = from_import_target(line) {
            renderer.render(target);
        }
    }
}

fn nim_display_edges(source: &str, renderer: &mut DisplayEdgeRenderer<'_>) {
    for raw in source.split('\n') {
        let line = raw.trim();
        if let Some(body) = line.strip_prefix("import ") {
            nim_import_display_edges(body, renderer);
        } else if let Some(target) = from_import_target(line) {
            renderer.render(target);
        }
    }
}

fn from_import_target(line: &str) -> Option<&str> {
    let body = line.strip_prefix("from ")?;
    let (module, _) = body.split_once(" import ")?;
    Some(module.trim())
}

fn nim_import_display_edges(body: &str, renderer: &mut DisplayEdgeRenderer<'_>) {
    if let Some((prefix, modules)) = nim_grouped_import(body) {
        for item in modules.split(',') {
            renderer.render(nim_grouped_target(prefix, item));
        }
        return;
    }
    for module in body.split(',') {
        renderer.render(normalize_nim_target(module.to_owned()));
    }
}

fn nim_grouped_import(body: &str) -> Option<(&str, &str)> {
    let open = body.find('[')?;
    let close = body.rfind(']')?;
    (close > open).then_some((&body[..open], &body[open + 1..close]))
}

fn nim_grouped_target(prefix: &str, item: &str) -> String {
    let item = item.trim();
    let mut target = String::with_capacity(prefix.len() + item.len());
    target.push_str(prefix);
    target.push_str(item);
    normalize_nim_target(target)
}

fn normalize_nim_target(mut target: String) -> String {
    let Some(start) = target
        .char_indices()
        .find_map(|(index, character)| (!character.is_whitespace()).then_some(index))
    else {
        target.clear();
        return target;
    };
    let end = if let Some(index) = target[start..]
        .char_indices()
        .find_map(|(index, character)| character.is_whitespace().then_some(index))
    {
        start + index
    } else {
        target.len()
    };
    target.truncate(end);
    if start > 0 {
        target.drain(..start);
    }
    if target.starts_with("../src/")
        && let Some(separator) = target.rfind('/')
    {
        target.drain(..=separator);
    }
    target
}

fn dependency_mermaid(graph: &DependencyGraph, edges: &[DisplayEdge]) -> String {
    let mut output = String::from("flowchart LR\n");
    let mut identifiers = BTreeMap::new();
    for (index, node) in graph.nodes().enumerate() {
        let id = format!("n{index}");
        identifiers.insert(node, id.clone());
        output.push_str(&format!("  {id}[\"{}\"]\n", node.replace('"', "&quot;")));
    }
    for edge in edges {
        let source = identifiers
            .get(edge.source.as_str())
            .map_or("null", String::as_str);
        let target = identifiers
            .get(edge.target.as_str())
            .map_or("null", String::as_str);
        output.push_str(&format!("  {source} --> {target}\n"));
    }
    output
}

fn architecture_mermaid(graph: &DependencyGraph, layers: &[String]) -> String {
    let mut output = String::from("graph TD\n");
    for (source, targets) in architecture_graph::layer_edges(graph, layers) {
        for target in targets {
            output.push_str(&format!("  \"{source}\" --> \"{target}\"\n"));
        }
    }
    output
}

static DART_DISPLAY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*(?:import|export)\s+["']([^"']+)["']\s*;"#).unwrap());
static CPP_DISPLAY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*#\s*include\s*[<"]([^>"]+)[>"]"#).unwrap());
static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["']([^"']+)["']"#).unwrap());
