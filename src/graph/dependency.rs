use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::discovery::PreparedPreview;
use crate::rust_rules::function_lexical_facts;

#[derive(Debug, Default)]
pub struct DependencyGraph {
    edges: BTreeMap<String, BTreeSet<String>>,
    cycle_edges: BTreeMap<String, BTreeSet<String>>,
    classified_edges: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    pub fn build(prepared: &PreparedPreview) -> Self {
        let selected = prepared
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>();
        let mut by_language: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        for file in &prepared.files {
            if let Some(source) = prepared.sources.get(&file.path) {
                by_language
                    .entry(file.language.as_str())
                    .or_default()
                    .insert(file.path.clone(), source.clone());
            }
        }
        for file in &prepared.excluded_source_files {
            by_language
                .entry(file.language.as_str())
                .or_default()
                .entry(file.path.clone())
                .or_default();
        }

        let mut resolved = Self::default();
        let mut cpp = by_language.remove("cpp").unwrap_or_default();
        cpp.append(&mut by_language.remove("objective-c").unwrap_or_default());
        resolved.merge(cpp_graph(&cpp));
        resolved.merge(owner_graph(by_language.get("csharp"), &CSHARP_TYPE));
        resolved.merge(dart_graph(
            by_language.get("dart"),
            Path::new(&prepared.root),
        ));
        resolved.merge(rust_graph(by_language.get("rust")));
        resolved.merge(mojo_graph(by_language.get("mojo")));
        resolved.merge(odin_graph(by_language.get("odin")));
        resolved.merge(nim_graph(by_language.get("nim")));
        resolved.merge(python_graph(by_language.get("python")));

        let mut javascript = by_language.remove("javascript").unwrap_or_default();
        javascript.append(&mut by_language.remove("typescript").unwrap_or_default());
        resolved.merge(javascript_graph(&javascript));
        resolved.merge(go_graph(by_language.get("go")));
        resolved.merge(owner_graph(by_language.get("java"), &JAVA_TYPE));
        resolved.merge(wren_graph(by_language.get("wren")));
        let (lua_edges, lua_cycle_edges) = lua_graph(by_language.get("lua"));
        resolved.merge_with_cycle_edges(lua_edges, lua_cycle_edges);

        let classified_edges = resolved
            .edges
            .iter()
            .filter(|(source, _)| selected.contains(source.as_str()))
            .map(|(source, targets)| (source.clone(), targets.clone()))
            .collect();
        let edges = selected_edges(&resolved.edges, &selected);
        let cycle_edges = selected_edges(&resolved.cycle_edges, &selected);
        Self {
            edges,
            cycle_edges,
            classified_edges,
        }
    }

    pub(crate) fn from_edges(
        edges: BTreeMap<String, BTreeSet<String>>,
        cycle_edges: BTreeMap<String, BTreeSet<String>>,
        classified_edges: BTreeMap<String, BTreeSet<String>>,
    ) -> Self {
        Self {
            edges,
            cycle_edges,
            classified_edges,
        }
    }

    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.edges.keys().map(String::as_str)
    }

    pub fn dependencies(&self, source: &str) -> impl Iterator<Item = &str> {
        self.edges
            .get(source)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }

    pub fn classified_dependencies(&self, source: &str) -> impl Iterator<Item = &str> {
        self.classified_edges
            .get(source)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }
    pub fn cycle_dependencies(&self, source: &str) -> impl Iterator<Item = &str> {
        self.cycle_edges
            .get(source)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }

    pub fn contains(&self, node: &str) -> bool {
        self.edges.contains_key(node)
    }
    pub fn default_roots(&self, configured: &[String]) -> Vec<&str> {
        let configured = configured
            .iter()
            .filter_map(|path| {
                self.edges
                    .get_key_value(path)
                    .map(|(path, _)| path.as_str())
            })
            .collect::<BTreeSet<_>>();
        if !configured.is_empty() {
            return configured.into_iter().collect();
        }
        let mains = self
            .nodes()
            .filter(|node| {
                let base = node.rsplit('/').next().unwrap_or(node);
                base.rsplit_once('.').map_or(base, |(stem, _)| stem) == "main"
            })
            .collect::<Vec<_>>();
        if mains.is_empty() {
            self.nodes().next().into_iter().collect()
        } else {
            mains
        }
    }

    pub fn shortest_path(&self, start: &str, goal: &str) -> Vec<String> {
        let (Some((start, _)), Some((goal, _))) = (
            self.edges.get_key_value(start),
            self.edges.get_key_value(goal),
        ) else {
            return Vec::new();
        };
        let start = start.as_str();
        let goal = goal.as_str();
        let mut pending = VecDeque::from([start]);
        let mut predecessor = BTreeMap::<&str, Option<&str>>::from([(start, None)]);
        while let Some(node) = pending.pop_front() {
            if node == goal {
                let mut path = Vec::new();
                let mut current = Some(goal);
                while let Some(value) = current {
                    path.push(value.to_owned());
                    current = predecessor[value];
                }
                path.reverse();
                return path;
            }
            for dependency in self.dependencies(node) {
                if let Entry::Vacant(entry) = predecessor.entry(dependency) {
                    entry.insert(Some(node));
                    pending.push_back(dependency);
                }
            }
        }
        Vec::new()
    }

    fn merge(&mut self, other: BTreeMap<String, BTreeSet<String>>) {
        self.cycle_edges.extend(other.clone());
        self.edges.extend(other);
    }

    fn merge_with_cycle_edges(
        &mut self,
        edges: BTreeMap<String, BTreeSet<String>>,
        cycle_edges: BTreeMap<String, BTreeSet<String>>,
    ) {
        self.edges.extend(edges);
        self.cycle_edges.extend(cycle_edges);
    }
}

fn selected_edges(
    edges: &BTreeMap<String, BTreeSet<String>>,
    selected: &BTreeSet<&str>,
) -> BTreeMap<String, BTreeSet<String>> {
    edges
        .iter()
        .filter(|(source, _)| selected.contains(source.as_str()))
        .map(|(source, targets)| {
            (
                source.clone(),
                targets
                    .iter()
                    .filter(|target| selected.contains(target.as_str()))
                    .cloned()
                    .collect(),
            )
        })
        .collect()
}

fn cpp_graph(sources: &BTreeMap<String, String>) -> BTreeMap<String, BTreeSet<String>> {
    const EXTENSIONS: &[&str] = &[
        ".h", ".hh", ".hpp", ".c", ".cc", ".cpp", ".cxx", ".m", ".mm",
    ];
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    sources
        .iter()
        .map(|(path, source)| {
            let mut dependencies = BTreeSet::new();
            for capture in CPP_LOCAL_INCLUDE.captures_iter(source) {
                let include = capture.get(1).unwrap().as_str();
                let relative = normalize_join(dirname(path), include);
                let mut candidates = vec![relative.clone(), include.to_owned()];
                if extension(&relative).is_empty() {
                    candidates.extend(
                        EXTENSIONS
                            .iter()
                            .map(|suffix| format!("{relative}{suffix}")),
                    );
                }
                if extension(include).is_empty() {
                    candidates.extend(EXTENSIONS.iter().map(|suffix| format!("{include}{suffix}")));
                }
                if let Some(candidate) = candidates.into_iter().find(|value| known.contains(value))
                    && candidate != *path
                {
                    dependencies.insert(candidate);
                }
            }
            (path.clone(), dependencies)
        })
        .collect()
}

fn owner_graph(
    sources: Option<&BTreeMap<String, String>>,
    declarations: &Regex,
) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let mut owners = BTreeMap::new();
    for (path, source) in sources {
        for declaration in declarations
            .captures_iter(source)
            .filter_map(|capture| capture.get(1))
        {
            owners
                .entry(declaration.as_str().to_owned())
                .or_insert_with(|| path.clone());
        }
    }
    sources
        .iter()
        .map(|(path, source)| {
            let dependencies = IDENTIFIER
                .find_iter(source)
                .filter_map(|token| owners.get(token.as_str()))
                .filter(|owner| *owner != path)
                .cloned()
                .collect();
            (path.clone(), dependencies)
        })
        .collect()
}

fn dart_graph(
    sources: Option<&BTreeMap<String, String>>,
    root: &Path,
) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    let packages = dart_packages(root, sources.keys());
    sources
        .iter()
        .map(|(path, source)| {
            let dependencies = dart_directive_uris(source)
                .into_iter()
                .filter_map(|uri| {
                    if uri.starts_with("dart:") {
                        return None;
                    }
                    let candidate = if let Some(package_uri) = uri.strip_prefix("package:") {
                        let (package, relative) = package_uri.split_once('/')?;
                        normalize_join(packages.get(package)?, relative)
                    } else {
                        normalize_join(dirname(path), uri)
                    };
                    known.contains(&candidate).then_some(candidate)
                })
                .filter(|target| target != path)
                .collect();
            (path.clone(), dependencies)
        })
        .collect()
}

fn dart_directive_uris(source: &str) -> Vec<&str> {
    DART_DIRECTIVE
        .find_iter(source)
        .flat_map(|directive| {
            DART_URI
                .captures_iter(directive.as_str())
                .filter_map(|capture| capture.get(1).map(|uri| uri.as_str()))
        })
        .collect()
}

fn dart_packages<'a>(
    root: &Path,
    paths: impl Iterator<Item = &'a String>,
) -> BTreeMap<String, String> {
    let mut roots = BTreeSet::new();
    for path in paths {
        let segments = path.split('/').collect::<Vec<_>>();
        if let Some(index) = segments
            .iter()
            .position(|segment| *segment == "lib" || *segment == "bin")
        {
            roots.insert(segments[..index].join("/"));
        }
    }
    let mut packages = BTreeMap::new();
    for package_root in roots {
        let pubspec = root.join(&package_root).join("pubspec.yaml");
        let Ok(source) = fs::read_to_string(pubspec) else {
            continue;
        };
        if let Some(capture) = PUBSPEC_NAME.captures(&source) {
            packages.insert(
                capture.get(1).unwrap().as_str().to_owned(),
                normalize_join(&package_root, "lib"),
            );
        }
    }
    packages
}

fn rust_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    let production_sources = sources
        .iter()
        .map(|(path, source)| (path.clone(), rust_production_code(source)))
        .collect::<BTreeMap<_, _>>();
    let declared = production_sources
        .values()
        .flat_map(|source| rust_module_candidates(source))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut by_stem: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in sources.keys() {
        let name = stem(path);
        let module = if name == "mod" {
            basename(dirname(path)).to_owned()
        } else {
            name.to_owned()
        };
        by_stem.entry(module).or_default().push(path.clone());
    }
    production_sources
        .iter()
        .map(|(path, source)| {
            let declared_modules = rust_module_candidates(source).flat_map(|module| {
                resolve_rust_module(path, module, &known)
                    .into_iter()
                    .flatten()
            });
            let imported_modules = rust_use_candidates(source).filter_map(|(module, explicit)| {
                resolve_rust_use(path, module, explicit, &declared, &by_stem)
            });
            let dependencies = declared_modules.chain(imported_modules).collect();
            (path.clone(), dependencies)
        })
        .collect()
}

fn rust_production_code(source: &str) -> String {
    let (code, test_lines) = function_lexical_facts(source);
    if test_lines.is_empty() {
        return code;
    }
    let mut bytes = code.into_bytes();
    for (index, line) in bytes.split_mut(|byte| *byte == b'\n').enumerate() {
        if test_lines.contains(&index) {
            line.fill(b' ');
        }
    }
    String::from_utf8(bytes).expect("masked Rust source must remain UTF-8")
}

fn rust_module_candidates(code: &str) -> impl Iterator<Item = &str> {
    RUST_MODULE
        .captures_iter(code)
        .filter_map(|capture| capture.get(1).map(|module| module.as_str()))
}

fn rust_use_candidates(code: &str) -> impl Iterator<Item = (&str, bool)> {
    RUST_USE.captures_iter(code).filter_map(|capture| {
        let prefix = capture.get(1)?.as_str();
        let module = capture.get(2)?.as_str();
        Some((module, !prefix.is_empty()))
    })
}

fn resolve_rust_module(path: &str, module: &str, known: &BTreeSet<String>) -> [Option<String>; 2] {
    [
        normalize_join(dirname(path), &format!("{module}.rs")),
        normalize_join(dirname(path), &format!("{module}/mod.rs")),
    ]
    .map(|candidate| (candidate != path && known.contains(&candidate)).then_some(candidate))
}

fn resolve_rust_use(
    path: &str,
    module: &str,
    explicit: bool,
    declared: &BTreeSet<String>,
    by_stem: &BTreeMap<String, Vec<String>>,
) -> Option<String> {
    if !explicit && !declared.contains(module) {
        return None;
    }
    let crate_root = rust_crate_root(path);
    let mut owners = by_stem
        .get(module)?
        .iter()
        .filter(|owner| owner.as_str() != path && rust_crate_root(owner) == crate_root);
    let owner = owners.next()?;
    owners.next().is_none().then(|| owner.clone())
}

fn rust_crate_root(path: &str) -> &str {
    if path.starts_with("src/") {
        return "";
    }
    path.split_once("/src/")
        .map_or_else(|| dirname(path), |(root, _)| root)
}

fn mojo_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in sources.keys() {
        owners
            .entry(stem(path).to_owned())
            .or_default()
            .push(path.clone());
    }
    sources
        .iter()
        .map(|(path, source)| {
            let dependencies = MOJO_IMPORT
                .captures_iter(source)
                .filter_map(|capture| capture.get(1).or_else(|| capture.get(2)))
                .filter_map(|module| owners.get(module.as_str().rsplit('.').next().unwrap()))
                .filter(|candidates| candidates.len() == 1 && candidates[0] != *path)
                .map(|candidates| candidates[0].clone())
                .collect();
            (path.clone(), dependencies)
        })
        .collect()
}

fn odin_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let mut by_directory: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in sources.keys() {
        by_directory
            .entry(dirname(path).to_owned())
            .or_default()
            .push(path.clone());
    }
    sources
        .iter()
        .map(|(path, source)| {
            let positions = code_positions(source);
            let dependencies = ODIN_IMPORT
                .captures_iter(source)
                .filter_map(|capture| {
                    let offset = capture.get(0)?.start();
                    if !positions.get(offset).copied().unwrap_or(false) {
                        return None;
                    }
                    let imported = capture.get(1)?.as_str();
                    (!imported.contains(':')).then_some(imported)
                })
                .flat_map(|imported| {
                    by_directory
                        .get(&normalize_join(dirname(path), imported))
                        .into_iter()
                        .flatten()
                })
                .filter(|target| *target != path)
                .cloned()
                .collect();
            (path.clone(), dependencies)
        })
        .collect()
}

fn nim_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    sources
        .iter()
        .map(|(path, source)| {
            let candidates = nim_import_candidates(source);
            let dependencies = candidates
                .filter_map(|module| resolve_nim_module(path, &module, &known))
                .collect::<BTreeSet<_>>();
            (path.clone(), dependencies)
        })
        .collect()
}

fn nim_import_candidates(source: &str) -> impl Iterator<Item = String> + '_ {
    source
        .lines()
        .flat_map(|raw| nim_modules(without_hash_comment(raw).trim()))
        .filter(|module| !module.starts_with("std/") && !module.starts_with("pkg/"))
        .map(|module| module.replace(['\'', '"'], ""))
}

fn resolve_nim_module(path: &str, module: &str, known: &BTreeSet<String>) -> Option<String> {
    let relative = normalize_join(dirname(path), module);
    [
        relative.clone(),
        format!("{relative}.nim"),
        format!("{relative}.nims"),
        module.to_owned(),
        format!("{module}.nim"),
        format!("{module}.nims"),
    ]
    .into_iter()
    .find(|candidate| candidate.as_str() != path && known.contains(candidate))
}

fn nim_modules(line: &str) -> Vec<String> {
    let body = if let Some(body) = line
        .strip_prefix("import ")
        .or_else(|| line.strip_prefix("include "))
    {
        body
    } else if let Some(body) = line.strip_prefix("from ") {
        let Some((module, _)) = body.split_once(" import ") else {
            return Vec::new();
        };
        module
    } else {
        return Vec::new();
    };
    if let Some(open) = body.find('[')
        && let Some(close) = body.rfind(']')
        && close > open
    {
        let prefix = body[..open].trim();
        return body[open + 1..close]
            .split(',')
            .map(|item| format!("{prefix}{}", item.trim()).replace('.', "/"))
            .collect();
    }
    body.split(',')
        .filter_map(|item| {
            let module = item.split(" as ").next().unwrap().trim();
            (!module.is_empty()).then(|| {
                if module.starts_with('.') || module.contains('/') {
                    module.to_owned()
                } else {
                    module.replace('.', "/")
                }
            })
        })
        .collect()
}

fn python_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    sources
        .iter()
        .map(|(path, source)| {
            let runtime = python_runtime_import_source(source);
            let candidates = python_import_candidates(&runtime);
            let resolved =
                candidates.filter_map(|candidate| resolve_python_import(path, candidate, &known));
            let dependencies = resolved
                .filter(|target| target != path)
                .collect::<BTreeSet<_>>();
            (path.clone(), dependencies)
        })
        .collect()
}

enum PythonImportCandidate<'a> {
    From { module: &'a str, imported: &'a str },
    Direct(&'a str),
}

fn python_import_candidates(source: &str) -> impl Iterator<Item = PythonImportCandidate<'_>> {
    PYTHON_IMPORT.captures_iter(source).filter_map(|capture| {
        if let (Some(module), Some(imported)) = (capture.get(1), capture.get(2)) {
            return Some(PythonImportCandidate::From {
                module: module.as_str(),
                imported: imported.as_str(),
            });
        }
        capture
            .get(3)
            .map(|imported| PythonImportCandidate::Direct(imported.as_str()))
    })
}

fn resolve_python_import(
    path: &str,
    candidate: PythonImportCandidate<'_>,
    known: &BTreeSet<String>,
) -> Option<String> {
    match candidate {
        PythonImportCandidate::Direct(module) => resolve_python(path, module, known),
        PythonImportCandidate::From {
            module: ".",
            imported,
        } => resolve_python(path, &format!(".{imported}"), known),
        PythonImportCandidate::From { module, imported } => {
            if imported != "*" {
                let specific = format!("{module}.{imported}");
                if let Some(target) = resolve_python(path, &specific, known) {
                    return Some(target);
                }
            }
            resolve_python(path, module, known)
        }
    }
}

fn python_runtime_import_source(source: &str) -> String {
    let masked = mask_python_strings_and_comments(source);
    let mut result = String::with_capacity(masked.len());
    let mut excluded_indent = None;
    for raw in masked.split_inclusive('\n') {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if excluded_indent.is_some_and(|value| !trimmed.is_empty() && indent <= value) {
            excluded_indent = None;
        }
        let excluded_start =
            PYTHON_BLOCK.is_match(trimmed) || PYTHON_TYPE_CHECKING.is_match(trimmed);
        if excluded_start {
            excluded_indent = Some(indent);
            result.extend(std::iter::repeat_n(' ', line.len()));
        } else if excluded_indent.is_some_and(|value| indent > value) {
            result.extend(std::iter::repeat_n(' ', line.len()));
        } else {
            result.push_str(line);
        }
        if raw.ends_with('\n') {
            result.push('\n');
        }
    }
    result
}

fn resolve_python(path: &str, module: &str, known: &BTreeSet<String>) -> Option<String> {
    let relative = if module.starts_with('.') {
        let dots = module.bytes().take_while(|byte| *byte == b'.').count();
        let mut base = dirname(path)
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let keep = base.len().saturating_sub(dots.saturating_sub(1));
        base.truncate(keep);
        let suffix = module[dots..].replace('.', "/");
        if !suffix.is_empty() {
            base.push(&suffix);
        }
        base.join("/")
    } else {
        module.replace('.', "/")
    };
    [format!("{relative}.py"), format!("{relative}/__init__.py")]
        .into_iter()
        .find(|candidate| known.contains(candidate))
}

fn javascript_graph(sources: &BTreeMap<String, String>) -> BTreeMap<String, BTreeSet<String>> {
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    sources
        .iter()
        .map(|(path, source)| {
            let mut dependencies = BTreeSet::new();
            for specifier in javascript_specifiers(source) {
                if !specifier.starts_with('.') {
                    continue;
                }
                let base = normalize_join(dirname(path), &specifier);
                let mut candidates = vec![base.clone()];
                for suffix in JS_EXTENSIONS {
                    candidates.push(format!("{base}{suffix}"));
                }
                for suffix in JS_EXTENSIONS {
                    candidates.push(format!("{base}/index{suffix}"));
                }
                if let Some(target) = candidates
                    .into_iter()
                    .find(|candidate| known.contains(candidate))
                    && target != *path
                {
                    dependencies.insert(target);
                }
            }
            (path.clone(), dependencies)
        })
        .collect()
}

fn javascript_specifiers(source: &str) -> Vec<String> {
    let positions = code_positions(source);
    JS_SPECIFIER
        .captures_iter(source)
        .filter_map(|capture| {
            let matched = capture.get(0)?;
            if !positions.get(matched.start()).copied().unwrap_or(false) {
                return None;
            }
            let directive = matched.as_str().trim_start();
            if directive.starts_with("import type ") || directive.starts_with("export type ") {
                return None;
            }
            capture
                .get(1)
                .map(|specifier| specifier.as_str().to_owned())
        })
        .collect()
}

fn go_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let module = sources
        .get("go.mod")
        .and_then(|source| GO_MODULE.captures(source))
        .and_then(|capture| capture.get(1))
        .map(|module| module.as_str())
        .unwrap_or("");
    let mut by_directory: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in sources
        .keys()
        .filter(|path| path.ends_with(".go") && !path.ends_with("_test.go"))
    {
        by_directory
            .entry(dirname(path).to_owned())
            .or_default()
            .push(path.clone());
    }
    sources
        .iter()
        .filter(|(path, _)| path.ends_with(".go"))
        .map(|(path, source)| {
            let mut dependencies = BTreeSet::new();
            for capture in QUOTED.captures_iter(source) {
                let imported = capture.get(1).unwrap().as_str();
                if module.is_empty()
                    || (imported != module && !imported.starts_with(&format!("{module}/")))
                {
                    continue;
                }
                let directory = if imported == module {
                    "."
                } else {
                    &imported[module.len() + 1..]
                };
                if let Some(targets) = by_directory.get(directory) {
                    dependencies.extend(targets.iter().filter(|target| *target != path).cloned());
                }
            }
            (path.clone(), dependencies)
        })
        .collect()
}

fn wren_graph(sources: Option<&BTreeMap<String, String>>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(sources) = sources else {
        return BTreeMap::new();
    };
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    sources
        .iter()
        .map(|(path, source)| {
            let dependencies = WREN_IMPORT
                .captures_iter(source)
                .filter_map(|capture| {
                    let module = capture.get(1)?.as_str();
                    let base = normalize_join(dirname(path), module);
                    [
                        base.clone(),
                        format!("{base}.wren"),
                        module.to_owned(),
                        format!("{module}.wren"),
                    ]
                    .into_iter()
                    .find(|candidate| known.contains(candidate) && candidate != path)
                })
                .collect();
            (path.clone(), dependencies)
        })
        .collect()
}

fn lua_graph(
    sources: Option<&BTreeMap<String, String>>,
) -> (
    BTreeMap<String, BTreeSet<String>>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let Some(sources) = sources else {
        return (BTreeMap::new(), BTreeMap::new());
    };
    let known = sources.keys().cloned().collect::<BTreeSet<_>>();
    let mut edges = BTreeMap::new();
    let mut cycle_edges = BTreeMap::new();
    for (path, source) in sources {
        let dependencies = parse_lua_dependencies(path, source, &known);
        edges.insert(path.clone(), dependencies.all);
        cycle_edges.insert(path.clone(), dependencies.load_time);
    }
    (edges, cycle_edges)
}

struct LuaDependencies<'a> {
    path: &'a str,
    code: String,
    all: BTreeSet<String>,
    load_time: BTreeSet<String>,
}

impl<'a> LuaDependencies<'a> {
    fn new(path: &'a str, source: &str) -> Self {
        Self {
            path,
            code: mask_comments_and_strings(source),
            all: BTreeSet::new(),
            load_time: BTreeSet::new(),
        }
    }

    fn insert(&mut self, target: Option<String>, offset: usize) {
        let Some(target) = target else {
            return;
        };
        if target == self.path {
            return;
        }
        if lua_load_time(&self.code, offset) {
            self.load_time.insert(target.clone());
        }
        self.all.insert(target);
    }
}

fn parse_lua_dependencies<'a>(
    path: &'a str,
    source: &str,
    known: &BTreeSet<String>,
) -> LuaDependencies<'a> {
    let positions = code_positions(source);
    let aliases = discover_lua_aliases(path, source, &positions);
    let mut dependencies = LuaDependencies::new(path, source);
    parse_lua_requires(source, &positions, known, &mut dependencies);
    parse_lua_roblox_requires(source, &positions, known, &aliases, &mut dependencies);
    parse_lua_dofiles(source, &positions, known, &mut dependencies);
    dependencies
}

fn discover_lua_aliases(path: &str, source: &str, positions: &[bool]) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for capture in LUA_ROBLOX_ALIAS.captures_iter(source) {
        if !positions[capture.get(0).unwrap().start()] {
            continue;
        }
        if let Some(base) =
            roblox_expression_base(path, capture.get(2).unwrap().as_str(), &BTreeMap::new())
        {
            aliases.insert(capture.get(1).unwrap().as_str().to_owned(), base);
        }
    }
    aliases
}

fn parse_lua_requires(
    source: &str,
    positions: &[bool],
    known: &BTreeSet<String>,
    dependencies: &mut LuaDependencies<'_>,
) {
    for capture in LUA_REQUIRE.captures_iter(source) {
        let offset = capture.get(0).unwrap().start();
        if positions[offset] {
            let target = resolve_lua(dependencies.path, capture.get(1).unwrap().as_str(), known);
            dependencies.insert(target, offset);
        }
    }
}

fn parse_lua_roblox_requires(
    source: &str,
    positions: &[bool],
    known: &BTreeSet<String>,
    aliases: &BTreeMap<String, String>,
    dependencies: &mut LuaDependencies<'_>,
) {
    for capture in LUA_ROBLOX_REQUIRE.captures_iter(source) {
        let offset = capture.get(0).unwrap().start();
        if positions[offset] {
            let target = roblox_expression_base(
                dependencies.path,
                capture.get(1).unwrap().as_str(),
                aliases,
            )
            .and_then(|base| lua_candidates(&base).find(|value| known.contains(value)));
            dependencies.insert(target, offset);
        }
    }
}

fn parse_lua_dofiles(
    source: &str,
    positions: &[bool],
    known: &BTreeSet<String>,
    dependencies: &mut LuaDependencies<'_>,
) {
    for capture in LUA_DOFILE.captures_iter(source) {
        let offset = capture.get(0).unwrap().start();
        if positions[offset] {
            let target =
                normalize_join(dirname(dependencies.path), capture.get(1).unwrap().as_str());
            dependencies.insert(known.contains(&target).then_some(target), offset);
        }
    }
}

fn lua_load_time(code: &str, call_offset: usize) -> bool {
    let mut blocks = Vec::new();
    let mut function_depth = 0usize;
    let mut pending_loop_do = 0usize;
    for capture in LUA_BLOCK_KEYWORD.captures_iter(&code[..call_offset]) {
        match capture.get(1).unwrap().as_str() {
            "function" => {
                blocks.push(true);
                function_depth += 1;
            }
            "if" | "repeat" => blocks.push(false),
            "for" | "while" => {
                blocks.push(false);
                pending_loop_do += 1;
            }
            "do" => {
                if pending_loop_do > 0 {
                    pending_loop_do -= 1;
                } else {
                    blocks.push(false);
                }
            }
            "end" | "until" => {
                if blocks.pop().unwrap_or(false) {
                    function_depth -= 1;
                }
            }
            _ => unreachable!(),
        }
    }
    function_depth == 0
}

fn resolve_lua(path: &str, module: &str, known: &BTreeSet<String>) -> Option<String> {
    let bases = if module.starts_with('.') {
        vec![normalize_join(dirname(path), module)]
    } else {
        let module = module.replace('.', "/");
        vec![module.clone(), format!("lua/{module}")]
    };
    for base in bases {
        if let Some(candidate) = lua_candidates(&base).find(|value| known.contains(value)) {
            return Some(candidate);
        }
    }
    None
}

fn lua_candidates(base: &str) -> impl Iterator<Item = String> {
    [
        base.to_owned(),
        format!("{base}.lua"),
        format!("{base}.luau"),
        format!("{base}/init.lua"),
        format!("{base}/init.luau"),
    ]
    .into_iter()
}

fn roblox_expression_base(
    source_path: &str,
    expression: &str,
    aliases: &BTreeMap<String, String>,
) -> Option<String> {
    let mut segments = expression.split('.').map(str::trim);
    let first = segments.next()?;
    let mut base = if first == "script" {
        roblox_script_base(source_path)
    } else {
        aliases.get(first)?.clone()
    };
    for segment in segments {
        base = if segment == "Parent" {
            dirname(&base).to_owned()
        } else {
            normalize_join(&base, segment)
        };
    }
    Some(normalize(base))
}

fn roblox_script_base(source_path: &str) -> String {
    let directory = dirname(source_path);
    let file = basename(source_path);
    let mut script = file
        .strip_suffix(".luau")
        .or_else(|| file.strip_suffix(".lua"))
        .unwrap_or(file);
    script = script
        .strip_suffix(".server")
        .or_else(|| script.strip_suffix(".client"))
        .unwrap_or(script);
    if script == "init" {
        directory.to_owned()
    } else {
        normalize_join(directory, script)
    }
}

fn mask_comments_and_strings(source: &str) -> String {
    let positions = code_positions(source);
    source
        .char_indices()
        .map(|(index, character)| {
            if positions[index] || character == '\n' {
                character
            } else {
                ' '
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
enum PythonMaskState {
    Code,
    Comment,
    Quoted { delimiter: u8, escaped: bool },
    TripleQuoted { delimiter: u8 },
}

struct PythonSourceMasker<'a> {
    bytes: &'a [u8],
    masked: Vec<u8>,
    state: PythonMaskState,
    index: usize,
}

impl<'a> PythonSourceMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            masked: source.as_bytes().to_vec(),
            state: PythonMaskState::Code,
            index: 0,
        }
    }

    fn mask(mut self) -> String {
        while self.index < self.bytes.len() {
            match self.state {
                PythonMaskState::Code => self.advance_code(),
                PythonMaskState::Comment => self.advance_comment(),
                PythonMaskState::Quoted { delimiter, escaped } => {
                    self.advance_quoted(delimiter, escaped);
                }
                PythonMaskState::TripleQuoted { delimiter } => {
                    self.advance_triple_quoted(delimiter);
                }
            }
        }
        String::from_utf8(self.masked).unwrap_or_else(|_| String::new())
    }

    fn advance_code(&mut self) {
        match self.bytes[self.index] {
            b'#' => {
                self.masked[self.index] = b' ';
                self.state = PythonMaskState::Comment;
                self.index += 1;
            }
            delimiter @ (b'\'' | b'"') => self.begin_quoted(delimiter),
            _ => self.index += 1,
        }
    }

    fn begin_quoted(&mut self, delimiter: u8) {
        let triple_quoted = self.bytes[self.index..].starts_with(&[delimiter; 3]);
        let width = if triple_quoted { 3 } else { 1 };
        self.masked[self.index..self.index + width].fill(b' ');
        self.state = if triple_quoted {
            PythonMaskState::TripleQuoted { delimiter }
        } else {
            PythonMaskState::Quoted {
                delimiter,
                escaped: false,
            }
        };
        self.index += width;
    }

    fn advance_comment(&mut self) {
        if self.bytes[self.index] == b'\n' {
            self.state = PythonMaskState::Code;
        } else {
            self.masked[self.index] = b' ';
        }
        self.index += 1;
    }

    fn advance_quoted(&mut self, delimiter: u8, escaped: bool) {
        let current = self.bytes[self.index];
        self.mask_current_unless_line_break();
        if !escaped && current == delimiter {
            self.state = PythonMaskState::Code;
        } else {
            self.state = PythonMaskState::Quoted {
                delimiter,
                escaped: current == b'\\' && !escaped,
            };
        }
        self.index += 1;
    }

    fn advance_triple_quoted(&mut self, delimiter: u8) {
        if self.bytes[self.index..].starts_with(&[delimiter; 3]) {
            self.masked[self.index..self.index + 3].fill(b' ');
            self.state = PythonMaskState::Code;
            self.index += 3;
            return;
        }
        self.mask_current_unless_line_break();
        self.index += 1;
    }

    fn mask_current_unless_line_break(&mut self) {
        if !matches!(self.bytes[self.index], b'\n' | b'\r') {
            self.masked[self.index] = b' ';
        }
    }
}

fn mask_python_strings_and_comments(source: &str) -> String {
    PythonSourceMasker::new(source).mask()
}

fn code_positions(source: &str) -> Vec<bool> {
    CodePositionMasker::new(source).mask()
}

struct CodePositionMasker<'a> {
    bytes: &'a [u8],
    code: Vec<bool>,
    index: usize,
}

impl<'a> CodePositionMasker<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            code: vec![true; source.len() + 1],
            index: 0,
        }
    }

    fn mask(mut self) -> Vec<bool> {
        while self.index < self.bytes.len() {
            if self.bytes[self.index..].starts_with(b"//") {
                self.mask_line_comment(2);
            } else if self.bytes[self.index..].starts_with(b"/*") {
                self.mask_block_comment();
            } else if self.bytes[self.index] == b'#' {
                self.mask_line_comment(1);
            } else if self.bytes[self.index..].starts_with(b"--") {
                self.mask_line_comment(2);
            } else if matches!(self.bytes[self.index], b'\'' | b'"') {
                self.mask_quoted_string();
            } else {
                self.index += 1;
            }
        }
        self.code
    }

    fn mask_line_comment(&mut self, delimiter_width: usize) {
        let start = self.index;
        self.index += delimiter_width;
        while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
            self.index += 1;
        }
        self.code[start..self.index].fill(false);
    }

    fn mask_block_comment(&mut self) {
        let start = self.index;
        self.index += 2;
        while self.index + 1 < self.bytes.len() && !self.bytes[self.index..].starts_with(b"*/") {
            self.index += 1;
        }
        self.index = (self.index + 2).min(self.bytes.len());
        self.code[start..self.index].fill(false);
    }

    fn mask_quoted_string(&mut self) {
        let quote = self.bytes[self.index];
        let start = self.index;
        self.index += 1;
        while self.index < self.bytes.len() {
            if self.bytes[self.index] == b'\\' {
                self.index = (self.index + 2).min(self.bytes.len());
                continue;
            }
            self.index += 1;
            if self.bytes[self.index - 1] == quote {
                break;
            }
        }
        self.code[start..self.index].fill(false);
    }
}

#[derive(Default)]
struct HashCommentBoundary {
    quote: Option<u8>,
    previous_was_escape: bool,
}

impl HashCommentBoundary {
    fn is_comment_start(&mut self, byte: u8) -> bool {
        if matches!(byte, b'\'' | b'"') && !self.previous_was_escape {
            self.update_quote(byte);
        }
        self.previous_was_escape = byte == b'\\';
        byte == b'#' && self.quote.is_none()
    }

    fn update_quote(&mut self, quote: u8) {
        if self.quote == Some(quote) {
            self.quote = None;
        } else if self.quote.is_none() {
            self.quote = Some(quote);
        }
    }
}

fn without_hash_comment(line: &str) -> &str {
    let mut boundary = HashCommentBoundary::default();
    for (index, byte) in line.bytes().enumerate() {
        if boundary.is_comment_start(byte) {
            return &line[..index];
        }
    }
    line
}

fn normalize_join(base: &str, child: &str) -> String {
    normalize(if base.is_empty() || base == "." {
        child.to_owned()
    } else {
        format!("{base}/{child}")
    })
}

fn normalize(path: String) -> String {
    let mut parts = Vec::new();
    for part in path.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_owned()),
        }
    }
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
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

const JS_EXTENSIONS: &[&str] = &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"];

static CPP_LOCAL_INCLUDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*#\s*(?:include|import)\s*"([^"]+)""#).unwrap());
static CSHARP_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:public|internal|private|protected)\s+)?(?:(?:static|sealed|abstract|partial)\s+)*(?:class|interface|struct|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap()
});
static JAVA_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap()
});
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\b").unwrap());
static DART_DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?ms)^\s*(?:import|export|part)\s+.*?;").unwrap());
static DART_URI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["']([^"']+)["']"#).unwrap());
static PUBSPEC_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^name:\s*([^\s#]+)").unwrap());
static RUST_MODULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;").unwrap()
});
static RUST_USE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+((?:(?:crate|self|super)::)*)([A-Za-z_][A-Za-z0-9_]*)",
    )
    .unwrap()
});
static MOJO_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:import\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)|from\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s+import\s+)").unwrap()
});
static ODIN_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*import[ \t]+(?:[A-Za-z_][A-Za-z0-9_]*|_|\.)?[ \t]*"([^"]+)""#).unwrap()
});
static PYTHON_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:from\s+([.A-Za-z0-9_]+)\s+import\s+([A-Za-z_][A-Za-z0-9_]*|\*)|import\s+([A-Za-z0-9_.]+))").unwrap()
});
static PYTHON_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:async\s+def|def|class)\s+").unwrap());
static PYTHON_TYPE_CHECKING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^if\s+(?:typing\.)?TYPE_CHECKING\s*:").unwrap());
static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["']([^"']+)["']"#).unwrap());
static JS_SPECIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:import\s+(?:[^;'"\n]*?\s+from\s+)?|export\s+[^;'"\n]*?\s+from\s+|require\s*\()\s*["']([^"']+)["']"#).unwrap()
});
static GO_MODULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*module\s+(\S+)").unwrap());
static WREN_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*import\s+["']([^"']+)["']"#).unwrap());
static LUA_REQUIRE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\brequire\s*(?:\(\s*)?["']([^"']+)["']\s*\)?"#).unwrap());
static LUA_ROBLOX_REQUIRE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\brequire\s*(?:\(\s*)?((?:script|[A-Za-z_][A-Za-z0-9_]*)(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*\)?").unwrap()
});
static LUA_ROBLOX_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\blocal\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(script(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)",
    )
    .unwrap()
});
static LUA_BLOCK_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(function|if|for|while|repeat|do|end|until)\b").unwrap());
static LUA_DOFILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"paths\.dofile\s*\(\s*["']([^"']+)["']\s*\)"#).unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        CSHARP_TYPE, code_positions, dart_directive_uris, go_graph, javascript_specifiers,
        nim_modules, odin_graph, owner_graph, python_graph, rust_graph, wren_graph,
    };

    #[test]
    fn extracts_all_conditional_dart_directive_uris() {
        assert_eq!(
            dart_directive_uris(
                "import 'stub.dart'\n  if (dart.library.io) 'io.dart'\n  if (dart.library.html) 'html.dart';"
            ),
            ["stub.dart", "io.dart", "html.dart"]
        );
    }

    #[test]
    fn python_graph_ignores_imports_in_triple_quoted_documentation() {
        let sources = BTreeMap::from([
            (
                "package/__init__.py".to_owned(),
                "from .application import Application\n".to_owned(),
            ),
            (
                "package/application.py".to_owned(),
                "from package import routing\n\
                 class Application:\n\
                 \x20   def configure(\n\
                 \x20       self,\n\
                 \x20       docs: str = \"\"\"\n\
                 \x20       Example:\n\
                 \x20           from package import Application\n\
                 \x20       \"\"\",\n\
                 \x20   ) -> None:\n\
                 \x20       pass\n"
                    .to_owned(),
            ),
            ("package/routing.py".to_owned(), String::new()),
        ]);

        assert_eq!(
            python_graph(Some(&sources))["package/application.py"],
            ["package/routing.py".to_owned()].into_iter().collect()
        );
    }

    #[test]
    fn rust_graph_ignores_test_only_module_declarations() {
        let sources = BTreeMap::from([
            (
                "src/lib.rs".to_owned(),
                "#[cfg(test)]\nmod tests;\nmod runtime;\nuse console::Term;\n".to_owned(),
            ),
            ("src/runtime.rs".to_owned(), String::new()),
            ("src/tests.rs".to_owned(), String::new()),
            ("tests/console.rs".to_owned(), String::new()),
            (
                "workspace/app/src/lib.rs".to_owned(),
                "use crate::process::Command;\n".to_owned(),
            ),
            ("workspace/tools/src/process.rs".to_owned(), String::new()),
        ]);

        let graph = rust_graph(Some(&sources));
        assert_eq!(
            graph["src/lib.rs"],
            ["src/runtime.rs".to_owned()].into_iter().collect()
        );
        assert!(
            graph["workspace/app/src/lib.rs"].is_empty(),
            "crate-relative imports must not resolve into another workspace crate"
        );
    }

    #[test]
    fn malformed_dependency_directives_are_ignored() {
        let csharp = BTreeMap::from([("main.cs".to_owned(), "public class".to_owned())]);
        assert!(owner_graph(Some(&csharp), &CSHARP_TYPE)["main.cs"].is_empty());

        assert!(dart_directive_uris("import 'unterminated;").is_empty());

        let odin = BTreeMap::from([
            (
                "src/main.odin".to_owned(),
                r#"import "unterminated"#.to_owned(),
            ),
            ("src/dependency.odin".to_owned(), String::new()),
        ]);
        assert!(odin_graph(Some(&odin))["src/main.odin"].is_empty());

        assert!(nim_modules("import ").is_empty());
        assert!(nim_modules("from dependency").is_empty());

        let python = BTreeMap::from([
            (
                "package/main.py".to_owned(),
                "from package import".to_owned(),
            ),
            ("package/dependency.py".to_owned(), String::new()),
        ]);
        assert!(python_graph(Some(&python))["package/main.py"].is_empty());

        assert!(
            javascript_specifiers("import 'unterminated\nexport { value } from\nrequire(")
                .is_empty()
        );

        let go = BTreeMap::from([
            ("go.mod".to_owned(), "module \n".to_owned()),
            ("main.go".to_owned(), "import (\n".to_owned()),
        ]);
        assert!(go_graph(Some(&go))["main.go"].is_empty());

        let wren = BTreeMap::from([
            ("main.wren".to_owned(), "import \"unterminated".to_owned()),
            ("dependency.wren".to_owned(), String::new()),
        ]);
        assert!(wren_graph(Some(&wren))["main.wren"].is_empty());
    }

    #[test]
    fn code_positions_exclude_supported_comments_and_quoted_strings() {
        let source = "live // slash\n\"quoted\" /* block */\n# hash\n-- dash\nstill_live";
        let positions = code_positions(source);

        for code in ["live", "still_live"] {
            assert!(positions[source.find(code).expect("code marker")]);
        }
        for masked in ["slash", "quoted", "block", "hash", "dash"] {
            assert!(!positions[source.find(masked).expect("masked marker")]);
        }
    }
}
