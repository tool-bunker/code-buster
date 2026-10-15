use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::architecture_graph;
use crate::config::Config;
use crate::dependency_graph::DependencyGraph;
use crate::discovery::PreparedPreview;
use crate::findings::{Finding, Severity};

pub fn analyze(prepared: &PreparedPreview, graph: &DependencyGraph) -> Vec<Finding> {
    let mut findings = cycle_findings(graph);
    findings.extend(architecture_findings(graph, &prepared.config));
    findings.extend(mvvm_findings(graph, &prepared.config));

    let configured_roots = configured_roots(prepared, graph);
    let (general_roots, lua_findings) = lua_dead_file_findings(prepared, graph, &configured_roots);
    findings.extend(lua_findings);
    findings.extend(dart_dead_file_findings(prepared, graph, &configured_roots));
    findings.extend(python_dead_file_findings(
        prepared,
        graph,
        &configured_roots,
    ));
    findings.extend(csharp_dead_file_findings(prepared, graph, &general_roots));
    findings
}

fn configured_roots(prepared: &PreparedPreview, graph: &DependencyGraph) -> BTreeSet<String> {
    prepared
        .config
        .entry_points
        .iter()
        .filter(|path| graph.contains(path))
        .cloned()
        .collect()
}

fn lua_dead_file_findings(
    prepared: &PreparedPreview,
    graph: &DependencyGraph,
    configured_roots: &BTreeSet<String>,
) -> (BTreeSet<String>, Vec<Finding>) {
    let default_roots = default_roots(graph, &prepared.config.entry_points);
    let candidates = prepared
        .sources
        .keys()
        .filter(|path| is_lua_candidate(path))
        .cloned()
        .collect::<Vec<_>>();
    let has_inferred_main = default_roots
        .iter()
        .any(|root| candidates.contains(root) && stem(root) == "main");
    let conventional = LuaRootSets::collect(prepared, graph, &candidates);
    let has_conventional_root = conventional.has_any();
    let mut roots = BTreeSet::new();
    if include_default_lua_roots(configured_roots, has_inferred_main, has_conventional_root) {
        roots.extend(default_roots);
    }
    conventional.extend_into(&mut roots);
    let findings =
        if analyze_lua_dead_files(configured_roots, has_inferred_main, has_conventional_root) {
            dead_file_findings(graph, &roots, &candidates)
        } else {
            Vec::new()
        };
    (roots, findings)
}

fn is_lua_candidate(path: &str) -> bool {
    !runtime_test_source(path) && (path.ends_with(".lua") || path.ends_with(".luau"))
}

fn include_default_lua_roots(
    configured_roots: &BTreeSet<String>,
    has_inferred_main: bool,
    has_conventional_root: bool,
) -> bool {
    !configured_roots.is_empty() || has_inferred_main || !has_conventional_root
}

fn analyze_lua_dead_files(
    configured_roots: &BTreeSet<String>,
    has_inferred_main: bool,
    has_conventional_root: bool,
) -> bool {
    !configured_roots.is_empty() || has_inferred_main || has_conventional_root
}

struct LuaRootSets {
    public: BTreeSet<String>,
    conventional: BTreeSet<String>,
    neovim: BTreeSet<String>,
    shebang: BTreeSet<String>,
}

impl LuaRootSets {
    fn collect(prepared: &PreparedPreview, graph: &DependencyGraph, candidates: &[String]) -> Self {
        Self {
            public: lua_roots_matching(graph, candidates, public_lua_root),
            conventional: lua_roots_matching(graph, candidates, conventional_lua_root),
            neovim: lua_roots_matching(graph, candidates, neovim_runtime_root),
            shebang: prepared
                .files
                .iter()
                .filter(|file| file.language == "lua" && !basename(&file.path).contains('.'))
                .map(|file| file.path.clone())
                .filter(|path| graph.contains(path))
                .collect(),
        }
    }

    fn has_any(&self) -> bool {
        !self.public.is_empty()
            || !self.conventional.is_empty()
            || !self.neovim.is_empty()
            || !self.shebang.is_empty()
    }

    fn extend_into(self, roots: &mut BTreeSet<String>) {
        roots.extend(self.public);
        roots.extend(self.conventional);
        roots.extend(self.neovim);
        roots.extend(self.shebang);
    }
}

fn lua_roots_matching(
    graph: &DependencyGraph,
    candidates: &[String],
    predicate: fn(&str) -> bool,
) -> BTreeSet<String> {
    candidates
        .iter()
        .filter(|path| predicate(path))
        .filter(|path| graph.contains(path))
        .cloned()
        .collect()
}

fn dart_dead_file_findings(
    prepared: &PreparedPreview,
    graph: &DependencyGraph,
    configured_roots: &BTreeSet<String>,
) -> Vec<Finding> {
    let candidates = prepared
        .sources
        .keys()
        .filter(|path| path.ends_with(".dart") && dead_file_candidate(path))
        .cloned()
        .collect::<Vec<_>>();
    let package_roots = dart_package_roots(Path::new(&prepared.root), &candidates);
    let mut roots = configured_roots
        .iter()
        .filter(|path| path.ends_with(".dart"))
        .cloned()
        .collect::<BTreeSet<_>>();
    roots.extend(candidates.iter().filter_map(|path| {
        let source = prepared.sources.get(path)?;
        dart_root(path, source, &package_roots).then(|| path.clone())
    }));
    roots.extend(dart_builder_roots(Path::new(&prepared.root), &candidates));
    roots.extend(dart_generated_roots(prepared, &candidates));
    if roots.is_empty() {
        Vec::new()
    } else {
        dead_file_findings(graph, &roots, &candidates)
    }
}

fn python_dead_file_findings(
    prepared: &PreparedPreview,
    graph: &DependencyGraph,
    configured_roots: &BTreeSet<String>,
) -> Vec<Finding> {
    let candidates = prepared
        .sources
        .keys()
        .filter(|path| path.ends_with(".py") && dead_file_candidate(path))
        .cloned()
        .collect::<Vec<_>>();
    let configured = configured_roots
        .iter()
        .filter(|path| path.ends_with(".py"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let public_prefixes = candidates
        .iter()
        .filter_map(|path| python_public_package_prefix(path))
        .collect::<BTreeSet<_>>();
    let executable_roots = candidates
        .iter()
        .filter(|path| {
            prepared
                .sources
                .get(*path)
                .is_some_and(|source| python_executable_root(path, source))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let app_prefixes = python_app_prefixes(&executable_roots);
    let namespace_prefixes = python_namespace_prefixes(&candidates, &configured, &app_prefixes);
    let roots = python_roots(
        &candidates,
        &configured,
        &executable_roots,
        &public_prefixes,
        &namespace_prefixes,
    );
    let eligible = python_eligible_files(
        candidates,
        &configured,
        &public_prefixes,
        &namespace_prefixes,
        &app_prefixes,
    );
    dead_file_findings(graph, &roots, &eligible)
}

fn python_app_prefixes(executable_roots: &BTreeSet<String>) -> BTreeSet<String> {
    executable_roots
        .iter()
        .filter(|path| {
            path.as_str() == "main.py"
                || path.ends_with("/main.py")
                || path.ends_with("/__main__.py")
        })
        .map(|path| {
            path.rsplit_once('/')
                .map_or(String::new(), |(directory, _)| format!("{directory}/"))
        })
        .collect()
}

fn python_namespace_prefixes(
    candidates: &[String],
    configured: &BTreeSet<String>,
    app_prefixes: &BTreeSet<String>,
) -> BTreeSet<String> {
    if !configured.is_empty() {
        return BTreeSet::new();
    }
    let mut prefixes = candidates
        .iter()
        .filter_map(|path| path.split_once('/').map(|(first, _)| format!("{first}/")))
        .collect::<BTreeSet<_>>();
    prefixes.retain(|prefix| !app_prefixes.contains(prefix));
    prefixes
}

fn python_roots(
    candidates: &[String],
    configured: &BTreeSet<String>,
    executable: &BTreeSet<String>,
    public_prefixes: &BTreeSet<String>,
    namespace_prefixes: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut roots = configured.clone();
    roots.extend(executable.iter().cloned());
    roots.extend(paths_under_prefixes(candidates, public_prefixes));
    roots.extend(paths_under_prefixes(candidates, namespace_prefixes));
    roots
}

fn python_eligible_files(
    candidates: Vec<String>,
    configured: &BTreeSet<String>,
    public_prefixes: &BTreeSet<String>,
    namespace_prefixes: &BTreeSet<String>,
    app_prefixes: &BTreeSet<String>,
) -> Vec<String> {
    if !configured.is_empty() {
        return candidates;
    }
    candidates
        .into_iter()
        .filter(|path| {
            [public_prefixes, namespace_prefixes, app_prefixes]
                .iter()
                .any(|prefixes| prefixes.iter().any(|prefix| path.starts_with(prefix)))
        })
        .collect()
}

fn paths_under_prefixes<'a>(
    candidates: &'a [String],
    prefixes: &'a BTreeSet<String>,
) -> impl Iterator<Item = String> + 'a {
    candidates
        .iter()
        .filter(|path| prefixes.iter().any(|prefix| path.starts_with(prefix)))
        .cloned()
}

fn csharp_dead_file_findings(
    prepared: &PreparedPreview,
    graph: &DependencyGraph,
    roots: &BTreeSet<String>,
) -> Vec<Finding> {
    if !prepared.config.csharp_dead_code {
        return Vec::new();
    }
    let candidates = prepared
        .sources
        .keys()
        .filter(|path| !runtime_test_source(path) && path.ends_with(".cs"))
        .cloned()
        .collect::<Vec<_>>();
    dead_file_findings(graph, roots, &candidates)
}

fn cycle_findings(graph: &DependencyGraph) -> Vec<Finding> {
    cyclic_components(graph)
        .into_iter()
        .filter(|component| !component.iter().all(|path| path.ends_with(".cs")))
        .filter(|component| {
            !component
                .iter()
                .all(|path| path.ends_with(".java") || path.ends_with(".cs"))
        })
        .filter(|component| {
            !component
                .iter()
                .all(|path| path.ends_with(".dart") || path.ends_with(".rs"))
        })
        .filter_map(|component| {
            let cycle = representative_cycle(graph, &component)?;
            let path = cycle.first()?.clone();
            let module_cycle = component
                .iter()
                .all(|path| matches!(extension(path), "dart" | "js" | "jsx" | "ts" | "tsx"));
            let represented = cycle.iter().cloned().collect::<BTreeSet<_>>();
            let related_files = component
                .iter()
                .filter(|path| !represented.contains(*path))
                .take(20)
                .cloned()
                .collect::<Vec<_>>();
            let names = cycle.iter().map(|path| basename(path)).collect::<Vec<_>>();
            let unique_names = names.iter().copied().collect::<BTreeSet<_>>();
            let description = if unique_names.len() < cycle.len().saturating_sub(1) {
                cycle.join(" -> ")
            } else {
                names.join(" -> ")
            };
            let size_detail = if component.len() > represented.len() {
                format!(
                    " ({} modules in strongly connected component)",
                    component.len()
                )
            } else {
                String::new()
            };
            Some(Finding {
                code: "cycle".to_owned(),
                severity: if module_cycle {
                    Severity::Warn
                } else {
                    Severity::Error
                },
                path,
                line: 1,
                end_line: 1,
                message: format!("circular dependency: {description}{size_detail}"),
                confidence: if module_cycle { "medium" } else { "high" }.to_owned(),
                why: String::new(),
                suggestion: String::new(),
                related_files,
                snippet: String::new(),
                code_flow: Vec::new(),
            })
        })
        .collect()
}

struct Tarjan<'a> {
    graph: &'a DependencyGraph,
    next: usize,
    indices: BTreeMap<String, usize>,
    low_links: BTreeMap<String, usize>,
    stack: Vec<String>,
    on_stack: BTreeSet<String>,
    components: Vec<BTreeSet<String>>,
}

impl Tarjan<'_> {
    fn connect(&mut self, node: String) {
        self.indices.insert(node.clone(), self.next);
        self.low_links.insert(node.clone(), self.next);
        self.next += 1;
        self.stack.push(node.clone());
        self.on_stack.insert(node.clone());
        self.connect_targets(&node);

        let Some(component) = self.take_root_component(&node) else {
            return;
        };
        if self.is_cyclic_component(&node, &component) {
            self.components.push(component);
        }
    }

    fn connect_targets(&mut self, node: &str) {
        let targets = self
            .graph
            .cycle_dependencies(node)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for target in targets {
            self.connect_target(node, target);
        }
    }

    fn connect_target(&mut self, node: &str, target: String) {
        let target_link = if !self.indices.contains_key(&target) {
            self.connect(target.clone());
            self.low_links.get(&target).copied()
        } else if self.on_stack.contains(&target) {
            self.indices.get(&target).copied()
        } else {
            None
        };
        let (Some(node_link), Some(target_link)) = (self.low_links.get_mut(node), target_link)
        else {
            return;
        };
        *node_link = (*node_link).min(target_link);
    }

    fn take_root_component(&mut self, node: &str) -> Option<BTreeSet<String>> {
        if self.low_links.get(node)? != self.indices.get(node)? {
            return None;
        }
        let mut component = BTreeSet::new();
        while let Some(member) = self.stack.pop() {
            self.on_stack.remove(&member);
            let is_root = member == node;
            component.insert(member);
            if is_root {
                break;
            }
        }
        Some(component)
    }

    fn is_cyclic_component(&self, node: &str, component: &BTreeSet<String>) -> bool {
        component.len() > 1
            || (component.len() == 1
                && (self.graph.dependencies(node).any(|target| target == node)
                    || self
                        .graph
                        .cycle_dependencies(node)
                        .any(|target| target == node)))
    }
}

fn cyclic_components(graph: &DependencyGraph) -> Vec<BTreeSet<String>> {
    let mut tarjan = Tarjan {
        graph,
        next: 0,
        indices: BTreeMap::new(),
        low_links: BTreeMap::new(),
        stack: Vec::new(),
        on_stack: BTreeSet::new(),
        components: Vec::new(),
    };
    let nodes = graph.nodes().map(str::to_owned).collect::<Vec<_>>();
    for node in nodes {
        if !tarjan.indices.contains_key(&node) {
            tarjan.connect(node);
        }
    }
    tarjan
        .components
        .sort_by(|left, right| left.first().cmp(&right.first()));
    tarjan.components
}

fn representative_cycle(
    graph: &DependencyGraph,
    component: &BTreeSet<String>,
) -> Option<Vec<String>> {
    fn follow(
        graph: &DependencyGraph,
        component: &BTreeSet<String>,
        target: &str,
        stack: &mut Vec<String>,
        visiting: &mut BTreeSet<String>,
        cycle_only: bool,
    ) -> Option<Vec<String>> {
        if !component.contains(target) {
            return None;
        }
        if let Some(start) = stack.iter().position(|entry| entry == target) {
            let mut cycle = stack[start..].to_vec();
            cycle.push(target.to_owned());
            return Some(cycle);
        }
        if visiting.contains(target) {
            return None;
        }
        visit(graph, component, target, stack, visiting, cycle_only)
    }

    fn visit(
        graph: &DependencyGraph,
        component: &BTreeSet<String>,
        node: &str,
        stack: &mut Vec<String>,
        visiting: &mut BTreeSet<String>,
        cycle_only: bool,
    ) -> Option<Vec<String>> {
        stack.push(node.to_owned());
        visiting.insert(node.to_owned());
        let cycle = if cycle_only {
            graph
                .cycle_dependencies(node)
                .find_map(|target| follow(graph, component, target, stack, visiting, cycle_only))
        } else {
            graph
                .dependencies(node)
                .find_map(|target| follow(graph, component, target, stack, visiting, cycle_only))
        };
        if cycle.is_some() {
            return cycle;
        }
        stack.pop();
        visiting.remove(node);
        None
    }

    for cycle_only in [false, true] {
        for node in component {
            if let Some(cycle) = visit(
                graph,
                component,
                node,
                &mut Vec::new(),
                &mut BTreeSet::new(),
                cycle_only,
            ) {
                return Some(cycle);
            }
        }
    }
    None
}

fn architecture_findings(graph: &DependencyGraph, config: &Config) -> Vec<Finding> {
    if config.architecture_layers.is_empty() {
        return Vec::new();
    }
    let allowed = config
        .architecture_allowed_dependencies
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let denied = config
        .architecture_denied_dependencies
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    for source in graph.nodes() {
        let Some(source_layer) = architecture_graph::layer_for(source, &config.architecture_layers)
        else {
            continue;
        };
        for target in graph.dependencies(source) {
            let Some(target_layer) =
                architecture_graph::layer_for(target, &config.architecture_layers)
            else {
                continue;
            };
            if target_layer == source_layer {
                continue;
            }
            let edge = format!("{source_layer} -> {target_layer}");
            if denied.contains(edge.as_str()) || !allowed.contains(edge.as_str()) {
                findings.push(Finding {
                    code: "architecture-forbidden-dependency".to_owned(),
                    severity: Severity::Error,
                    path: source.to_owned(),
                    line: 1,
                    end_line: 1,
                    message: format!("forbidden architecture dependency {edge}"),
                    confidence: "high".to_owned(),
                    why: if denied.contains(edge.as_str()) {
                        "The module graph crosses an explicitly denied layer boundary."
                    } else {
                        "The module graph crosses a layer boundary that is not explicitly allowed."
                    }
                    .to_owned(),
                    suggestion: "Move or invert the dependency, or update intentional policy."
                        .to_owned(),
                    related_files: vec![target.to_owned()],
                    snippet: String::new(),
                    code_flow: Vec::new(),
                });
            }
        }
    }
    findings.extend(architecture_cycle_findings(
        graph,
        &config.architecture_layers,
    ));
    findings
}

fn architecture_cycle_findings(graph: &DependencyGraph, layers: &[String]) -> Vec<Finding> {
    fn visit(
        layer: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        visited: &mut BTreeSet<String>,
        visiting: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
        emitted: &mut BTreeSet<String>,
        findings: &mut Vec<Finding>,
    ) {
        if visiting.contains(layer) {
            if let Some(start) = stack.iter().position(|entry| entry == layer) {
                let mut cycle = stack[start..].to_vec();
                cycle.push(layer.to_owned());
                let mut key_parts = cycle[..cycle.len() - 1].to_vec();
                key_parts.sort();
                let key = key_parts.join("|");
                if emitted.insert(key) {
                    findings.push(Finding {
                        code: "architecture-layer-cycle".to_owned(),
                        severity: Severity::Error,
                        path: "code-buster.toml".to_owned(),
                        line: 1,
                        end_line: 1,
                        message: format!("architecture layer cycle: {}", cycle.join(" -> ")),
                        confidence: "high".to_owned(),
                        why: "Layer cycles make dependency direction and ownership ambiguous."
                            .to_owned(),
                        suggestion:
                            "Invert or extract one dependency so the layer graph is acyclic."
                                .to_owned(),
                        related_files: Vec::new(),
                        snippet: String::new(),
                        code_flow: Vec::new(),
                    });
                }
            }
            return;
        }
        if !visited.insert(layer.to_owned()) {
            return;
        }
        visiting.insert(layer.to_owned());
        stack.push(layer.to_owned());
        if let Some(targets) = edges.get(layer) {
            for target in targets {
                visit(target, edges, visited, visiting, stack, emitted, findings);
            }
        }
        stack.pop();
        visiting.remove(layer);
    }

    let edges = architecture_graph::layer_edges(graph, layers);
    let mut findings = Vec::new();
    let mut visited = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    let mut stack = Vec::new();
    let mut emitted = BTreeSet::new();
    for layer in layers {
        visit(
            layer,
            &edges,
            &mut visited,
            &mut visiting,
            &mut stack,
            &mut emitted,
            &mut findings,
        );
    }
    findings
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MvvmLayer {
    View,
    ViewModel,
    Model,
    Repository,
}

#[derive(Clone, Copy)]
struct MvvmComponent<'a> {
    path: &'a str,
    layer: MvvmLayer,
}

struct MvvmViolation<'a> {
    source: MvvmComponent<'a>,
    target: MvvmComponent<'a>,
    reason: &'static str,
}

fn mvvm_findings(graph: &DependencyGraph, config: &Config) -> Vec<Finding> {
    if config.architecture_profile != "dart-mvvm" {
        return Vec::new();
    }
    emit_mvvm_findings(graph, config)
}

fn classify_mvvm_component<'a>(path: &'a str, config: &Config) -> Option<MvvmComponent<'a>> {
    classify_mvvm(path, config).map(|layer| MvvmComponent { path, layer })
}

fn collect_mvvm_violations<'a>(
    graph: &'a DependencyGraph,
    config: &Config,
    mut collect: impl FnMut(MvvmViolation<'a>),
) {
    for source_path in graph.nodes() {
        let Some(source) = classify_mvvm_component(source_path, config) else {
            continue;
        };
        for target_path in graph.dependencies(source_path) {
            let Some(target) = classify_mvvm_component(target_path, config) else {
                continue;
            };
            if let Some(reason) = mvvm_violation_reason(
                source.layer,
                target.layer,
                config.mvvm_strict_view_model_boundary,
            ) {
                collect(MvvmViolation {
                    source,
                    target,
                    reason,
                });
            }
        }
    }
}

fn mvvm_violation_reason(
    source: MvvmLayer,
    target: MvvmLayer,
    strict_view_model_boundary: bool,
) -> Option<&'static str> {
    if source == target {
        return None;
    }
    match source {
        MvvmLayer::View if strict_view_model_boundary && target == MvvmLayer::Repository => {
            Some("Views should delegate data access and orchestration to a ViewModel.")
        }
        MvvmLayer::ViewModel if target == MvvmLayer::View => {
            Some("ViewModels should remain independent of presentation classes.")
        }
        MvvmLayer::Model
            if matches!(
                target,
                MvvmLayer::View | MvvmLayer::ViewModel | MvvmLayer::Repository
            ) =>
        {
            Some("Models should not depend on presentation or data-access layers.")
        }
        MvvmLayer::Repository if matches!(target, MvvmLayer::View | MvvmLayer::ViewModel) => Some(
            "Repositories should expose data through model abstractions without presentation dependencies.",
        ),
        _ => None,
    }
}

fn emit_mvvm_findings(graph: &DependencyGraph, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    collect_mvvm_violations(graph, config, |violation| {
        findings.push(Finding {
            code: "mvvm-forbidden-dependency".to_owned(),
            severity: Severity::Error,
            path: violation.source.path.to_owned(),
            line: 1,
            end_line: 1,
            message: format!(
                "{} must not depend on {}",
                mvvm_label(violation.source.layer),
                mvvm_label(violation.target.layer)
            ),
            confidence: "high".to_owned(),
            why: violation.reason.to_owned(),
            suggestion: "Move the dependency behind the ViewModel or invert it through a model/repository abstraction.".to_owned(),
            related_files: vec![violation.target.path.to_owned()],
            snippet: String::new(),
            code_flow: Vec::new(),
        });
    });
    findings
}

pub(crate) fn classify_mvvm(path: &str, config: &Config) -> Option<MvvmLayer> {
    const VIEWS: &[&str] = &[
        "lib/**/views/**",
        "lib/**/pages/**",
        "lib/**/screens/**",
        "lib/**/*_view.dart",
        "lib/**/*_page.dart",
        "lib/**/*_screen.dart",
    ];
    const VIEW_MODELS: &[&str] = &[
        "lib/**/view_models/**",
        "lib/**/viewmodels/**",
        "lib/**/*_view_model.dart",
        "lib/**/*_viewmodel.dart",
    ];
    const MODELS: &[&str] = &[
        "lib/**/models/**",
        "lib/**/domain/**",
        "lib/**/*_model.dart",
    ];
    const REPOSITORIES: &[&str] = &[
        "lib/**/repositories/**",
        "lib/**/data/**",
        "lib/**/*_repository.dart",
    ];
    let matches = |configured: &[String], defaults: &[&str]| {
        if configured.is_empty() {
            defaults.iter().any(|pattern| glob_matches(path, pattern))
        } else {
            configured.iter().any(|pattern| glob_matches(path, pattern))
        }
    };
    if matches(&config.mvvm_view_models, VIEW_MODELS) {
        Some(MvvmLayer::ViewModel)
    } else if matches(&config.mvvm_views, VIEWS) {
        Some(MvvmLayer::View)
    } else if matches(&config.mvvm_repositories, REPOSITORIES) {
        Some(MvvmLayer::Repository)
    } else if matches(&config.mvvm_models, MODELS) {
        Some(MvvmLayer::Model)
    } else {
        None
    }
}

fn glob_matches(path: &str, pattern: &str) -> bool {
    let normalized = pattern.replace('\\', "/");
    let mut expression = String::from("^");
    let bytes = normalized.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'*' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            if index + 2 < bytes.len() && bytes[index + 2] == b'/' {
                expression.push_str("(?:.*/)?");
                index += 3;
            } else {
                expression.push_str(".*");
                index += 2;
            }
        } else if bytes[index] == b'*' {
            expression.push_str("[^/]*");
            index += 1;
        } else if bytes[index] == b'?' {
            expression.push_str("[^/]");
            index += 1;
        } else {
            expression.push_str(&regex::escape(&(bytes[index] as char).to_string()));
            index += 1;
        }
    }
    expression.push('$');
    let Ok(regex) = Regex::new(&expression) else {
        return false;
    };
    regex.is_match(&path.replace('\\', "/"))
}

fn mvvm_label(layer: MvvmLayer) -> &'static str {
    match layer {
        MvvmLayer::View => "View",
        MvvmLayer::ViewModel => "ViewModel",
        MvvmLayer::Model => "Model",
        MvvmLayer::Repository => "Repository",
    }
}

fn dead_file_findings(
    graph: &DependencyGraph,
    roots: &BTreeSet<String>,
    eligible_nodes: &[String],
) -> Vec<Finding> {
    let eligible = eligible_nodes
        .iter()
        .filter(|node| graph.contains(node))
        .cloned()
        .collect::<BTreeSet<_>>();
    if eligible.len() <= 1 {
        return Vec::new();
    }
    let reachable = reachable_from(graph, roots);
    if !eligible.iter().any(|node| reachable.contains(node)) {
        return Vec::new();
    }
    eligible
        .into_iter()
        .filter(|node| !reachable.contains(node))
        .map(|node| Finding {
            code: "dead-file".to_owned(),
            severity: Severity::Error,
            path: node,
            line: 1,
            end_line: 1,
            message: "file is not reachable from configured entry points".to_owned(),
            confidence: "high".to_owned(),
            why: "The file is not reachable from the static dependency graph and configured entry points.".to_owned(),
            suggestion:
                "Remove the file, connect it from reachable code, or configure an entry point."
                    .to_owned(),
            related_files: Vec::new(),
            snippet: String::new(),
            code_flow: Vec::new(),
        })
        .collect()
}

fn reachable_from(graph: &DependencyGraph, roots: &BTreeSet<String>) -> BTreeSet<String> {
    let mut reachable = BTreeSet::new();
    let mut pending = roots
        .iter()
        .filter(|root| graph.contains(root))
        .cloned()
        .collect::<VecDeque<_>>();
    while let Some(node) = pending.pop_front() {
        if !reachable.insert(node.clone()) {
            continue;
        }
        pending.extend(graph.dependencies(&node).map(str::to_owned));
    }
    reachable
}

fn default_roots(graph: &DependencyGraph, configured: &[String]) -> BTreeSet<String> {
    let selected = configured
        .iter()
        .filter(|path| graph.contains(path))
        .cloned()
        .collect::<BTreeSet<_>>();
    if !selected.is_empty() {
        return selected;
    }
    let mains = graph
        .nodes()
        .filter(|node| stem(node) == "main")
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if !mains.is_empty() {
        return mains;
    }
    graph
        .nodes()
        .next()
        .map(str::to_owned)
        .into_iter()
        .collect()
}

fn runtime_test_source(path: &str) -> bool {
    path.split('/')
        .any(|segment| matches!(segment, "__tests__" | "test" | "tests" | "spec" | "specs"))
}

fn dead_file_candidate(path: &str) -> bool {
    !runtime_test_source(path)
        && !path.split('/').any(|segment| {
            matches!(
                segment,
                "example"
                    | "examples"
                    | "fixture"
                    | "fixtures"
                    | "bench"
                    | "benchmark"
                    | "benchmarks"
            )
        })
}

fn dart_package_roots(root: &Path, paths: &[String]) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for path in paths {
        let segments = path.split('/').collect::<Vec<_>>();
        if let Some(index) = segments
            .iter()
            .position(|segment| *segment == "lib" || *segment == "bin")
        {
            candidates.insert(segments[..index].join("/"));
        }
    }
    candidates
        .into_iter()
        .filter(|package| {
            PUBSPEC_NAME.is_match(
                &fs::read_to_string(root.join(package).join("pubspec.yaml")).unwrap_or_default(),
            )
        })
        .collect()
}

fn dart_root(path: &str, source: &str, package_roots: &BTreeSet<String>) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    let workspace_root = package_roots.iter().any(|package| {
        let prefix = if package.is_empty() {
            String::new()
        } else {
            format!("{package}/")
        };
        let Some(relative) = path.strip_prefix(&prefix) else {
            return false;
        };
        let relative = relative.split('/').collect::<Vec<_>>();
        (relative.len() >= 2
            && relative[0] == "lib"
            && (relative.len() == 2 || relative[1] != "src"))
            || (relative.len() == 2 && relative[0] == "bin")
    });
    workspace_root
        || (segments.len() == 2 && matches!(segments[0], "lib" | "bin"))
        || DART_MAIN.is_match(source)
}

fn dart_builder_roots(root: &Path, sources: &[String]) -> BTreeSet<String> {
    let source_set = sources.iter().cloned().collect::<BTreeSet<_>>();
    let package_roots = sources
        .iter()
        .filter_map(|path| {
            let segments = path.split('/').collect::<Vec<_>>();
            segments
                .iter()
                .position(|segment| *segment == "lib")
                .map(|index| segments[..index].join("/"))
        })
        .collect::<BTreeSet<_>>();
    let mut roots = BTreeSet::new();
    for package in package_roots {
        let Ok(source) = fs::read_to_string(root.join(&package).join("build.yaml")) else {
            continue;
        };
        for capture in BUILD_IMPORT.captures_iter(&source) {
            let candidate = normalize_join(
                &package,
                &format!("lib/{}", capture.get(2).unwrap().as_str()),
            );
            if source_set.contains(&candidate) {
                roots.insert(candidate);
            }
        }
    }
    roots
}

fn dart_generated_roots(prepared: &PreparedPreview, selected: &[String]) -> BTreeSet<String> {
    let selected = selected.iter().cloned().collect::<BTreeSet<_>>();
    let mut generated = BTreeMap::new();
    for provenance in &prepared.generated_provenance {
        if provenance.path.ends_with(".dart")
            && let Ok(source) = fs::read_to_string(Path::new(&prepared.root).join(&provenance.path))
        {
            generated.insert(provenance.path.clone(), source);
        }
    }
    if generated.is_empty() {
        return BTreeSet::new();
    }
    let mut reachable = BTreeSet::new();
    for (path, source) in &generated {
        for capture in DART_DIRECTIVE.captures_iter(source) {
            let uri = capture.get(1).unwrap().as_str();
            if uri.starts_with("dart:") || uri.starts_with("package:") {
                continue;
            }
            let target = normalize_join(dirname(path), uri);
            if selected.contains(&target) {
                reachable.insert(target);
            }
        }
    }
    reachable
}

fn python_public_package_prefix(path: &str) -> Option<String> {
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.last()? != &"__init__.py" {
        return None;
    }
    if segments.len() == 2 {
        return Some(format!("{}/", segments[0]));
    }
    let src = segments.iter().rposition(|segment| *segment == "src")?;
    (src == segments.len() - 3).then(|| format!("{}/", segments[..src + 2].join("/")))
}

fn python_executable_root(path: &str, source: &str) -> bool {
    matches!(basename(path), "__main__.py" | "main.py") || PYTHON_MAIN.is_match(source)
}

fn public_lua_root(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    (segments.len() == 3 && segments[0] == "lua" && matches!(extension(path), "lua" | "luau"))
        || (segments.len() == 4
            && segments[0] == "lua"
            && segments[2] == "plugins"
            && matches!(extension(path), "lua" | "luau"))
}

fn conventional_lua_root(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    matches!(segments.last(), Some(&"init.lua" | &"init.luau"))
        && (segments.len() == 1 || (segments.len() == 2 && segments[0] == "src"))
}

fn neovim_runtime_root(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    segments.len() == 2
        && matches!(segments[0], "plugin" | "ftplugin")
        && segments[1].ends_with(".lua")
}

fn normalize_join(base: &str, child: &str) -> String {
    let joined = if base.is_empty() || base == "." {
        child.to_owned()
    } else {
        format!("{base}/{child}")
    };
    let mut parts = Vec::new();
    for part in joined.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_owned()),
        }
    }
    parts.join("/")
}

fn dirname(path: &str) -> &str {
    path.rsplit_once('/')
        .map_or(".", |(directory, _)| directory)
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn stem(path: &str) -> &str {
    basename(path)
        .rsplit_once('.')
        .map_or(basename(path), |(stem, _)| stem)
}

fn extension(path: &str) -> &str {
    basename(path)
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension)
}

static PUBSPEC_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^name:[ \t]*([^\s#]+)").unwrap());
static DART_MAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:FutureOr<\s*void\s*>|Future<\s*void\s*>|void)\s+main\s*\(").unwrap()
});
static BUILD_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*import:[ \t]*["']package:([^/]+)/([^"']+)["'][ \t]*$"#).unwrap()
});
static DART_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*(?:import|export|part)[ \t]+["']([^"']+)["']"#).unwrap()
});
static PYTHON_MAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*if\s+__name__\s*==\s*["']__main__["']\s*:"#).unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_edges_missing_from_dependencies_remain_reportable() {
        let path = "src/orphan.js".to_owned();
        let graph = DependencyGraph::from_edges(
            BTreeMap::from([(path.clone(), BTreeSet::new())]),
            BTreeMap::from([(path.clone(), BTreeSet::from([path.clone()]))]),
        );

        let findings = cycle_findings(&graph);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.message.as_str()))
                .collect::<Vec<_>>(),
            vec![(path.as_str(), "circular dependency: orphan.js -> orphan.js")]
        );
    }
}
