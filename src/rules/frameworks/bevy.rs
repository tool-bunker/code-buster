use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use toml::Value;

use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;
use crate::trivial_wrappers::{mask_comments_and_strings, matching_delimiter, split_top_level};

pub fn analyze(context: &SourceAnalysisContext<'_>, functions: &[FunctionSource]) -> Vec<Finding> {
    let projects = BevyProjects::new(context.auxiliary_files());
    if projects.manifests.is_empty() {
        return Vec::new();
    }

    let frame_systems = frame_systems(context, functions, &projects);
    let dynamic_fonts_allowed = context.sources().iter().any(|(path, source)| {
        projects.capabilities_for(path).text
            && mask_comments_and_strings(source).contains("allow_dynamic_font_size: true")
    });
    let mut findings = Vec::new();
    for function in functions
        .iter()
        .filter(|function| function_is_active(context, function))
    {
        analyze_function(
            function,
            projects.capabilities_for(&function.path),
            frame_systems.contains(&(function.path.clone(), function.line)),
            dynamic_fonts_allowed,
            &mut findings,
        );
    }
    findings
}

fn analyze_function(
    function: &FunctionSource,
    capabilities: BevyCapabilities,
    frame_system: bool,
    dynamic_fonts_allowed: bool,
    findings: &mut Vec<Finding>,
) {
    if capabilities.is_empty() {
        return;
    }
    let signature = FunctionSignature::new(function);
    if capabilities.ecs {
        conflicting_queries(function, &signature, findings);
        conflicting_resources(function, &signature, findings);
        command_after_despawn(function, &signature, findings);
    }
    if capabilities.asset {
        dropped_asset_handles(function, &signature, findings);
        if frame_system {
            frame_asset_allocations(function, &signature, findings);
        }
    }
    if capabilities.text && frame_system && !dynamic_fonts_allowed {
        dynamic_font_atlas_growth(function, &signature, findings);
    }
}

pub(crate) fn manifest_uses_bevy(source: &str) -> bool {
    let Ok(manifest) = toml::from_str::<Value>(source) else {
        return false;
    };
    package_capabilities(&manifest).is_some_and(|capabilities| !capabilities.is_empty())
        || dependency_tables(&manifest).any(|table| {
            table.iter().any(|(alias, dependency)| {
                is_bevy_package(dependency_package(alias, dependency, None))
            })
        })
        || manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("dependencies"))
            .and_then(Value::as_table)
            .is_some_and(|table| {
                table.iter().any(|(alias, dependency)| {
                    is_bevy_package(dependency_package(alias, dependency, None))
                })
            })
}

#[derive(Clone, Copy, Default)]
struct BevyCapabilities {
    ecs: bool,
    app: bool,
    asset: bool,
    text: bool,
}

impl BevyCapabilities {
    fn for_package(package: &str) -> Self {
        match package {
            "bevy" => Self {
                ecs: true,
                app: true,
                asset: true,
                text: true,
            },
            "bevy_ecs" => Self {
                ecs: true,
                ..Self::default()
            },
            "bevy_app" => Self {
                app: true,
                ..Self::default()
            },
            "bevy_asset" => Self {
                asset: true,
                ..Self::default()
            },
            "bevy_text" => Self {
                text: true,
                ..Self::default()
            },
            _ => Self::default(),
        }
    }

    fn merge(&mut self, other: Self) {
        self.ecs |= other.ecs;
        self.app |= other.app;
        self.asset |= other.asset;
        self.text |= other.text;
    }

    fn is_empty(self) -> bool {
        !(self.ecs || self.app || self.asset || self.text)
    }
}

struct BevyManifest {
    directory: String,
    capabilities: BevyCapabilities,
}

struct WorkspaceDependencies {
    directory: String,
    packages: BTreeMap<String, String>,
}

struct BevyProjects {
    manifests: Vec<BevyManifest>,
}

impl BevyProjects {
    fn new(auxiliary_files: &BTreeMap<String, String>) -> Self {
        let parsed = auxiliary_files
            .iter()
            .filter(|(path, _)| cargo_manifest_path(path))
            .filter_map(|(path, source)| {
                toml::from_str::<Value>(source)
                    .ok()
                    .map(|manifest| (normalize_path(path), manifest))
            })
            .collect::<Vec<_>>();
        let workspaces = parsed
            .iter()
            .filter_map(|(path, manifest)| {
                let dependencies = manifest.get("workspace")?.get("dependencies")?.as_table()?;
                let packages = dependencies
                    .iter()
                    .map(|(alias, dependency)| {
                        (
                            alias.to_owned(),
                            dependency_package(alias, dependency, None).to_owned(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                Some(WorkspaceDependencies {
                    directory: manifest_directory(path),
                    packages,
                })
            })
            .collect::<Vec<_>>();
        let mut manifests = parsed
            .iter()
            .map(|(path, manifest)| {
                let directory = manifest_directory(path);
                let workspace = nearest_workspace(&directory, &workspaces);
                let mut capabilities = package_capabilities(manifest).unwrap_or_default();
                for table in dependency_tables(manifest) {
                    for (alias, dependency) in table {
                        let package = dependency_package(alias, dependency, workspace);
                        capabilities.merge(BevyCapabilities::for_package(package));
                    }
                }
                BevyManifest {
                    directory,
                    capabilities,
                }
            })
            .collect::<Vec<_>>();
        manifests.sort_by_key(|manifest| std::cmp::Reverse(manifest.directory.len()));
        Self { manifests }
    }

    fn capabilities_for(&self, path: &str) -> BevyCapabilities {
        let path = normalize_path(path);
        self.manifests
            .iter()
            .find(|manifest| path_belongs_to(&path, &manifest.directory))
            .map_or_else(BevyCapabilities::default, |manifest| manifest.capabilities)
    }
}

fn package_capabilities(manifest: &Value) -> Option<BevyCapabilities> {
    let package = manifest.get("package")?.get("name")?.as_str()?;
    Some(BevyCapabilities::for_package(package))
}

fn dependency_tables(manifest: &Value) -> impl Iterator<Item = &toml::map::Map<String, Value>> {
    let direct = manifest.get("dependencies").and_then(Value::as_table);
    let targeted = manifest
        .get("target")
        .and_then(Value::as_table)
        .into_iter()
        .flat_map(|targets| targets.values())
        .filter_map(|target| target.get("dependencies"))
        .filter_map(Value::as_table);
    direct.into_iter().chain(targeted)
}

fn dependency_package<'a>(
    alias: &'a str,
    dependency: &'a Value,
    workspace: Option<&'a WorkspaceDependencies>,
) -> &'a str {
    if let Some(package) = dependency.get("package").and_then(Value::as_str) {
        return package;
    }
    if dependency
        .get("workspace")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return workspace
            .and_then(|workspace| workspace.packages.get(alias))
            .map_or(alias, String::as_str);
    }
    alias
}

fn nearest_workspace<'a>(
    directory: &str,
    workspaces: &'a [WorkspaceDependencies],
) -> Option<&'a WorkspaceDependencies> {
    workspaces
        .iter()
        .filter(|workspace| path_belongs_to(directory, &workspace.directory))
        .max_by_key(|workspace| workspace.directory.len())
}

fn is_bevy_package(package: &str) -> bool {
    matches!(
        package,
        "bevy" | "bevy_ecs" | "bevy_app" | "bevy_asset" | "bevy_text"
    )
}

fn cargo_manifest_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .and_then(|name| name.rsplit('\\').next())
        .is_some_and(|name| name.eq_ignore_ascii_case("Cargo.toml"))
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn manifest_directory(path: &str) -> String {
    path.strip_suffix("/Cargo.toml")
        .or_else(|| path.strip_suffix("/cargo.toml"))
        .unwrap_or(if path.eq_ignore_ascii_case("Cargo.toml") {
            ""
        } else {
            path
        })
        .to_owned()
}

fn path_belongs_to(path: &str, directory: &str) -> bool {
    directory.is_empty()
        || path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn function_is_active(context: &SourceAnalysisContext<'_>, function: &FunctionSource) -> bool {
    context
        .sources()
        .get(&function.path)
        .and_then(|source| source.lines().nth(function.line.saturating_sub(1)))
        .is_some_and(|line| !line.trim().is_empty())
}

fn frame_systems(
    context: &SourceAnalysisContext<'_>,
    functions: &[FunctionSource],
    projects: &BevyProjects,
) -> BTreeSet<(String, usize)> {
    let mut by_name = BTreeMap::<&str, Vec<&FunctionSource>>::new();
    for function in functions {
        by_name.entry(&function.name).or_default().push(function);
    }
    let mut result = BTreeSet::new();
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| projects.capabilities_for(path).app)
    {
        let masked = mask_comments_and_strings(source);
        for name in frame_system_names(&masked) {
            let Some(candidates) = by_name.get(name) else {
                continue;
            };
            for function in frame_function_candidates(candidates, path) {
                result.insert((function.path.clone(), function.line));
            }
        }
    }
    result
}

fn frame_system_names(source: &str) -> BTreeSet<&str> {
    let mut result = BTreeSet::new();
    for call in ADD_SYSTEMS.find_iter(source) {
        let open = call.end() - 1;
        let Some(close) = matching_delimiter(source, open, b'(', b')') else {
            continue;
        };
        let arguments = split_top_level(&source[open + 1..close]);
        if arguments.len() < 2 || !frame_schedule(arguments[0]) {
            continue;
        }
        result.extend(
            IDENTIFIER
                .find_iter(arguments[1])
                .map(|matched| matched.as_str()),
        );
    }
    result
}

fn frame_function_candidates<'a>(
    candidates: &'a [&FunctionSource],
    path: &str,
) -> Vec<&'a FunctionSource> {
    let local = candidates
        .iter()
        .copied()
        .filter(|function| function.path == path)
        .collect::<Vec<_>>();
    if local.is_empty() && candidates.len() == 1 {
        candidates.to_vec()
    } else {
        local
    }
}

fn frame_schedule(source: &str) -> bool {
    matches!(
        source.trim().rsplit("::").next(),
        Some("Update" | "FixedUpdate")
    )
}

struct FunctionSignature {
    masked: String,
    parameters: Vec<Parameter>,
}

struct Parameter {
    name: String,
    ty: String,
}

impl FunctionSignature {
    fn new(function: &FunctionSource) -> Self {
        let masked = mask_comments_and_strings(&function.source);
        let parameters = function_parameters(&masked, &function.name);
        Self { masked, parameters }
    }
}

fn function_parameters(source: &str, name: &str) -> Vec<Parameter> {
    let marker = format!("fn {name}");
    let Some(function) = source.find(&marker) else {
        return Vec::new();
    };
    let Some(open) = source[function + marker.len()..]
        .find('(')
        .map(|offset| function + marker.len() + offset)
    else {
        return Vec::new();
    };
    let Some(close) = matching_delimiter(source, open, b'(', b')') else {
        return Vec::new();
    };
    split_top_level(&source[open + 1..close])
        .into_iter()
        .filter_map(parse_parameter)
        .collect()
}

fn parse_parameter(source: &str) -> Option<Parameter> {
    let colon = top_level_colon(source)?;
    let name = IDENTIFIER
        .find_iter(&source[..colon])
        .last()?
        .as_str()
        .to_owned();
    Some(Parameter {
        name,
        ty: source[colon + 1..].trim().to_owned(),
    })
}

fn top_level_colon(source: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in source.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b')' | b']' | b'}' | b'>' => depth = depth.saturating_sub(1),
            b':' if depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

#[derive(Clone)]
struct QueryAccess {
    component: String,
    mutable: bool,
    query: usize,
    extracted: bool,
    with: BTreeSet<String>,
    without: BTreeSet<String>,
}

fn conflicting_queries(
    function: &FunctionSource,
    signature: &FunctionSignature,
    findings: &mut Vec<Finding>,
) {
    let accesses = query_accesses(signature);
    let mut reported = BTreeSet::new();
    for (index, left) in accesses.iter().enumerate() {
        for right in &accesses[index + 1..] {
            if left.component != right.component
                || left.extracted != right.extracted
                || !(left.mutable || right.mutable)
                || queries_are_disjoint(left, right)
                || !reported.insert(left.component.clone())
            {
                continue;
            }
            let scope = if left.query == right.query {
                "one query"
            } else {
                "separate queries"
            };
            findings.push(finding(
                "bevy-conflicting-query-access",
                function,
                0,
                &format!(
                    "{scope} access `{}` mutably and through another reference",
                    left.component
                ),
                "high",
            ));
        }
    }
}

fn query_accesses(signature: &FunctionSignature) -> Vec<QueryAccess> {
    let mut accesses = Vec::new();
    let mut query_index = 0usize;
    for parameter in signature
        .parameters
        .iter()
        .filter(|parameter| generic_contents(&parameter.ty, "ParamSet").is_empty())
    {
        let extracted = !generic_contents(&parameter.ty, "Extract").is_empty();
        for query in generic_contents(&parameter.ty, "Query") {
            let arguments = split_top_level(query);
            let Some(data) = arguments.first() else {
                continue;
            };
            let filters = arguments.get(1).copied().unwrap_or_default();
            let mut with = generic_types(filters, "With");
            with.extend(
                required_query_types(data)
                    .into_iter()
                    .map(|(component, _)| component),
            );
            let without = generic_types(filters, "Without");
            accesses.extend(query_component_accesses(data).into_iter().map(
                |(component, mutable)| QueryAccess {
                    component,
                    mutable,
                    query: query_index,
                    extracted,
                    with: with.clone(),
                    without: without.clone(),
                },
            ));
            query_index += 1;
        }
    }
    accesses
}

fn queries_are_disjoint(left: &QueryAccess, right: &QueryAccess) -> bool {
    left.query != right.query
        && (left
            .with
            .iter()
            .any(|marker| right.without.contains(marker))
            || right
                .with
                .iter()
                .any(|marker| left.without.contains(marker)))
}

fn generic_types(source: &str, name: &str) -> BTreeSet<String> {
    generic_contents(source, name)
        .into_iter()
        .map(normalize_type)
        .filter(|ty| !ty.is_empty())
        .collect()
}

fn required_query_types(source: &str) -> Vec<(String, bool)> {
    tuple_items(source)
        .into_iter()
        .filter(|item| {
            item.trim_start().starts_with('&') || direct_generic_content(item, "Ref").is_some()
        })
        .flat_map(query_component_accesses)
        .collect()
}

fn query_component_accesses(source: &str) -> Vec<(String, bool)> {
    let mut accesses = reference_types(source);
    for component in generic_contents(source, "Ref") {
        accesses.push((normalize_type(component), false));
    }
    accesses
}

fn direct_generic_content<'a>(source: &'a str, expected: &str) -> Option<&'a str> {
    let source = source.trim();
    let open = source.find('<')?;
    if source[..open].trim().rsplit("::").next()? != expected {
        return None;
    }
    let close = matching_delimiter(source, open, b'<', b'>')?;
    Some(&source[open + 1..close])
}

fn reference_types(source: &str) -> Vec<(String, bool)> {
    REFERENCE_TYPE
        .captures_iter(source)
        .filter_map(|capture| {
            Some((
                normalize_type(capture.get(2)?.as_str()),
                capture.get(1).is_some(),
            ))
        })
        .collect()
}

fn normalize_type(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn generic_contents<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut search = 0usize;
    while let Some(relative) = source[search..].find(name) {
        let start = search + relative;
        let before = source.as_bytes().get(start.wrapping_sub(1));
        let after_name = start + name.len();
        if before.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_') {
            search = after_name;
            continue;
        }
        let mut open = after_name;
        while source
            .as_bytes()
            .get(open)
            .is_some_and(u8::is_ascii_whitespace)
        {
            open += 1;
        }
        if source.as_bytes().get(open) != Some(&b'<') {
            search = after_name;
            continue;
        }
        let Some(close) = matching_delimiter(source, open, b'<', b'>') else {
            break;
        };
        result.push(&source[open + 1..close]);
        search = close + 1;
    }
    result
}

#[derive(Clone)]
struct ResourceAccess {
    ty: String,
    mutable: bool,
    non_send: bool,
    extracted: bool,
}

fn conflicting_resources(
    function: &FunctionSource,
    signature: &FunctionSignature,
    findings: &mut Vec<Finding>,
) {
    let accesses = resource_accesses(signature);
    let mut reported = BTreeSet::new();
    for (index, left) in accesses.iter().enumerate() {
        for right in &accesses[index + 1..] {
            if left.ty != right.ty
                || left.non_send != right.non_send
                || left.extracted != right.extracted
                || !(left.mutable || right.mutable)
                || !reported.insert((left.ty.clone(), left.non_send))
            {
                continue;
            }
            findings.push(finding(
                "bevy-conflicting-resource-access",
                function,
                0,
                &format!(
                    "resource `{}` is requested with conflicting access",
                    left.ty
                ),
                "high",
            ));
        }
    }
}

fn resource_accesses(signature: &FunctionSignature) -> Vec<ResourceAccess> {
    let mut accesses = Vec::new();
    for parameter in signature
        .parameters
        .iter()
        .filter(|parameter| generic_contents(&parameter.ty, "ParamSet").is_empty())
    {
        let extracted = !generic_contents(&parameter.ty, "Extract").is_empty();
        for (name, mutable, non_send) in [
            ("ResMut", true, false),
            ("Res", false, false),
            ("NonSendMut", true, true),
            ("NonSend", false, true),
        ] {
            accesses.extend(generic_contents(&parameter.ty, name).into_iter().map(|ty| {
                ResourceAccess {
                    ty: normalize_type(ty),
                    mutable,
                    non_send,
                    extracted,
                }
            }));
        }
    }
    accesses
}

fn command_after_despawn(
    function: &FunctionSource,
    signature: &FunctionSignature,
    findings: &mut Vec<Finding>,
) {
    let command_bindings = signature
        .parameters
        .iter()
        .filter(|parameter| type_ends_with(&parameter.ty, "Commands"))
        .map(|parameter| parameter.name.as_str())
        .collect::<BTreeSet<_>>();
    if command_bindings.is_empty() {
        return;
    }
    let mut despawned = BTreeSet::new();
    for capture in ENTITY_COMMAND.captures_iter(&signature.masked) {
        let commands = &capture[1];
        if !command_bindings.contains(commands) {
            continue;
        }
        let entity = capture[2]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let method = &capture[3];
        let key = (commands.to_owned(), entity.clone());
        let matched = capture.get(0).expect("entity command must have a match");
        if method == "despawn" {
            despawned.insert(key);
            continue;
        }
        if despawned.contains(&key) {
            findings.push(finding(
                "bevy-command-after-despawn",
                function,
                matched.start(),
                &format!("`{entity}` receives `{method}` after a queued despawn"),
                "high",
            ));
        }
    }
}

fn dropped_asset_handles(
    function: &FunctionSource,
    signature: &FunctionSignature,
    findings: &mut Vec<Finding>,
) {
    let asset_servers = signature
        .parameters
        .iter()
        .filter(|parameter| {
            generic_contents(&parameter.ty, "Res")
                .into_iter()
                .any(|ty| type_ends_with(ty, "AssetServer"))
        })
        .map(|parameter| parameter.name.as_str())
        .collect::<BTreeSet<_>>();
    if asset_servers.is_empty() {
        return;
    }
    for capture in DROPPED_ASSET_LOAD.captures_iter(&signature.masked) {
        if !asset_servers.contains(&capture[1]) {
            continue;
        }
        let matched = capture.get(0).expect("asset load must have a match");
        let Some(open) = signature.masked[matched.start()..]
            .find('(')
            .map(|offset| matched.start() + offset)
        else {
            continue;
        };
        let Some(close) = matching_delimiter(&signature.masked, open, b'(', b')') else {
            continue;
        };
        if !signature.masked[close + 1..].trim_start().starts_with(';') {
            continue;
        }
        findings.push(finding(
            "bevy-dropped-asset-handle",
            function,
            matched.start(),
            "AssetServer load result is discarded immediately",
            "high",
        ));
    }
}

fn frame_asset_allocations(
    function: &FunctionSource,
    signature: &FunctionSignature,
    findings: &mut Vec<Finding>,
) {
    if frame_system_is_gated(signature) {
        return;
    }
    let assets = signature
        .parameters
        .iter()
        .filter(|parameter| {
            generic_contents(&parameter.ty, "ResMut")
                .into_iter()
                .any(|ty| !generic_contents(ty, "Assets").is_empty())
        })
        .map(|parameter| parameter.name.as_str())
        .collect::<BTreeSet<_>>();
    for capture in ADD_ASSET.captures_iter(&signature.masked) {
        if !assets.contains(&capture[1]) {
            continue;
        }
        let matched = capture.get(0).expect("asset add must have a match");
        findings.push(finding(
            "bevy-frame-asset-allocation",
            function,
            matched.start(),
            &format!("`{}` creates an asset from a per-frame system", &capture[1]),
            "high",
        ));
    }
}

fn frame_system_is_gated(signature: &FunctionSignature) -> bool {
    signature.parameters.iter().any(|parameter| {
        [
            "Added",
            "Changed",
            "Without",
            "RemovedComponents",
            "MessageReader",
            "EventReader",
        ]
        .iter()
        .any(|name| !generic_contents(&parameter.ty, name).is_empty())
    })
}

fn dynamic_font_atlas_growth(
    function: &FunctionSource,
    signature: &FunctionSignature,
    findings: &mut Vec<Finding>,
) {
    let font_bindings = mutable_query_item_bindings(signature, "TextFont");
    let scale_bindings = signature
        .parameters
        .iter()
        .filter(|parameter| {
            generic_contents(&parameter.ty, "ResMut")
                .into_iter()
                .any(|ty| type_ends_with(ty, "UiScale"))
        })
        .map(|parameter| parameter.name.as_str())
        .collect::<BTreeSet<_>>();

    for capture in DYNAMIC_FONT_FIELD.captures_iter(&signature.masked) {
        let receiver = &capture[1];
        let field = &capture[2];
        if field == "font_size" && !font_bindings.contains(receiver)
            || field == "scale" && !scale_bindings.contains(receiver)
        {
            continue;
        }
        let operation = &capture[3];
        let value = capture.get(4).map_or("", |matched| matched.as_str());
        if operation == "=" && !dynamic_value(value) {
            continue;
        }
        let matched = capture.get(0).expect("font mutation must have a match");
        findings.push(finding(
            "bevy-dynamic-font-atlas-growth",
            function,
            matched.start(),
            &format!("`{receiver}.{field}` changes dynamically in a per-frame system"),
            "high",
        ));
    }
}

fn mutable_query_item_bindings<'a>(
    signature: &'a FunctionSignature,
    target: &str,
) -> BTreeSet<&'a str> {
    let mut result = BTreeSet::new();
    let loops = QUERY_LOOP
        .captures_iter(&signature.masked)
        .filter_map(|capture| Some((capture.get(1)?.as_str(), capture.get(2)?.as_str())))
        .collect::<Vec<_>>();
    for parameter in &signature.parameters {
        let patterns = loops
            .iter()
            .filter(|(_, query_binding)| *query_binding == parameter.name)
            .map(|(pattern, _)| *pattern)
            .collect::<Vec<_>>();
        for query in generic_contents(&parameter.ty, "Query") {
            let positions = query_target_positions(query, target);
            for pattern in &patterns {
                result.extend(
                    positions
                        .iter()
                        .filter_map(|position| binding_at_position(pattern, *position)),
                );
            }
        }
    }
    result
}

fn query_target_positions(query: &str, target: &str) -> Vec<usize> {
    split_top_level(query)
        .first()
        .into_iter()
        .flat_map(|data| tuple_items(data))
        .enumerate()
        .filter(|(_, item)| {
            reference_types(item)
                .into_iter()
                .any(|(ty, mutable)| mutable && type_ends_with(&ty, target))
        })
        .map(|(index, _)| index)
        .collect()
}

fn binding_at_position(pattern: &str, position: usize) -> Option<&str> {
    tuple_items(pattern)
        .get(position)
        .and_then(|binding| IDENTIFIER.find_iter(binding).last())
        .map(|matched| matched.as_str())
}

fn tuple_items(source: &str) -> Vec<&str> {
    let source = source.trim();
    if source.starts_with('(') && source.ends_with(')') {
        split_top_level(&source[1..source.len() - 1])
    } else {
        vec![source]
    }
}

fn dynamic_value(value: &str) -> bool {
    ["time.", "delta", "elapsed", ".sin(", ".cos(", "lerp("]
        .iter()
        .any(|marker| value.contains(marker))
}

fn type_ends_with(source: &str, expected: &str) -> bool {
    normalize_type(source)
        .rsplit("::")
        .next()
        .is_some_and(|name| name == expected)
}

fn finding(
    code: &str,
    function: &FunctionSource,
    offset: usize,
    message: &str,
    confidence: &str,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Bevy rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: function.path.clone(),
        line: function.line
            + function.source.as_bytes()[..offset]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
        end_line: 0,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static ADD_SYSTEMS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\s*add_systems\s*\(").unwrap());
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\b").unwrap());
static REFERENCE_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&\s*(?:'[A-Za-z_]\w*\s+)?(?:(mut)\s+)?([A-Za-z_]\w*(?:::\w+)*(?:\s*<[^&()]+>)?)")
        .unwrap()
});
static ENTITY_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)\b([A-Za-z_]\w*)\s*\.\s*entity\s*\(\s*([A-Za-z_]\w*(?:\s*\.\s*(?:[A-Za-z_]\w*|\d+))*)\s*\)\s*\.\s*(despawn|insert_if_new|insert|remove_with_requires|remove|retain|clear|observe|trigger)\s*\(",
    )
    .unwrap()
});
static DROPPED_ASSET_LOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*(?:let[ \t]+_[ \t]*=[ \t]*)?([A-Za-z_]\w*)\s*\.\s*(?:load|load_untyped|load_folder)(?:\s*::\s*<[^>]+>)?\s*\(",
    )
    .unwrap()
});
static ADD_ASSET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*\.\s*add\s*\(").unwrap());
static DYNAMIC_FONT_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\b([A-Za-z_]\w*)\s*\.\s*(font_size|scale)\s*(\+=|-=|\*=|/=|=)\s*([^;\n]+)")
        .unwrap()
});
static QUERY_LOOP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)\bfor\s+(.+?)\s+in\s+(?:&\s*mut\s+)?([A-Za-z_]\w*)(?:\s*\.\s*iter_mut\s*\(\s*\))?\s*\{",
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_sources;

    fn findings(
        sources: BTreeMap<String, String>,
        auxiliary: BTreeMap<String, String>,
    ) -> Vec<Finding> {
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);
        let functions = function_sources::extract(&sources);
        analyze(&context, &functions)
    }

    #[test]
    fn reports_conservative_bevy_runtime_and_performance_problems() {
        let sources = BTreeMap::from([(
            "src/main.rs".to_owned(),
            r#"use bevy::prelude::*;

fn conflicting_queries(
    mut enemies: Query<&mut Transform, With<Enemy>>,
    players: Query<&Transform, With<Player>>,
) {}

fn conflicting_change_ref(
    changed: Query<Option<Ref<Transform>>>,
    mut writers: Query<&mut Transform>,
) {}

fn conflicting_resources(
    mut materials: ResMut<Assets<StandardMaterial>>,
    current: Res<Assets<StandardMaterial>>,
) {}

fn invalid_commands(mut commands: Commands, target: Res<Target>) {
    commands.entity(target.0).despawn();
    commands.entity(target.0).insert(Disabled);
}

fn dropped_load(asset_server: Res<AssetServer>) {
    asset_server.load("ship.png");
}

fn animate_text(time: Res<Time>, mut fonts: Query<&mut TextFont>) {
    for mut font in &mut fonts {
        font.font_size += time.delta_secs();
    }
}

fn allocate_mesh(mut meshes: ResMut<Assets<Mesh>>) {
    let handle = meshes.add(Cuboid::default());
    consume(handle);
}

fn main() {
    App::new().add_systems(Update, (animate_text, allocate_mesh));
}
"#
            .to_owned(),
        )]);
        let auxiliary = BTreeMap::from([(
            "Cargo.toml".to_owned(),
            "[package]\nname = \"game\"\n[dependencies]\nbevy = \"0.20\"\n".to_owned(),
        )]);

        let selected = findings(sources, auxiliary)
            .into_iter()
            .map(|finding| (finding.code, finding.line))
            .collect::<BTreeSet<_>>();

        assert_eq!(
            selected,
            BTreeSet::from([
                ("bevy-command-after-despawn".to_owned(), 20),
                ("bevy-conflicting-query-access".to_owned(), 3),
                ("bevy-conflicting-query-access".to_owned(), 8),
                ("bevy-conflicting-resource-access".to_owned(), 13),
                ("bevy-dropped-asset-handle".to_owned(), 24),
                ("bevy-dynamic-font-atlas-growth".to_owned(), 29),
                ("bevy-frame-asset-allocation".to_owned(), 34),
            ])
        );
    }

    #[test]
    fn accepts_disjoint_owned_and_one_shot_bevy_patterns() {
        let sources = BTreeMap::from([(
            "src/main.rs".to_owned(),
            r#"use bevy::prelude::*;

fn disjoint(
    mut enemies: Query<&mut Transform, With<Enemy>>,
    players: Query<&Transform, (With<Player>, Without<Enemy>)>,
) {}

fn parameter_set(
    mut transforms: ParamSet<(
        Query<&mut Transform, With<Enemy>>,
        Query<&Transform, With<Player>>,
    )>,
) {}

fn implicitly_disjoint(
    source: Query<(&SourceMarker, &mut Node)>,
    target: Query<&Node, Without<SourceMarker>>,
) {}

fn ref_disjoint(
    source: Query<(Ref<VoxelPos>, &mut Transform)>,
    target: Query<&mut Transform, Without<VoxelPos>>,
) {}

fn separate_worlds(
    main: Extract<Query<&Widget>>,
    mut render: Query<&mut Widget>,
) {}

fn separate_world_resources(
    main: Extract<Res<Settings>>,
    mut render: ResMut<Settings>,
) {}

fn valid_commands(mut commands: Commands, target: Res<Target>) {
    commands.entity(target.0).insert(Disabled);
    commands.entity(target.0).despawn();
}

fn cleanup_groups(
    mut commands: Commands,
    first: Query<Entity, With<First>>,
    second: Query<Entity, With<Second>>,
) {
    for entity in &first {
        commands.entity(entity).despawn();
    }
    for entity in &second {
        commands.entity(entity).despawn();
    }
}

fn stored_load(asset_server: Res<AssetServer>, mut cache: ResMut<Cache>) {
    cache.ship = asset_server.load("ship.png");
}

fn fixed_font(mut fonts: Query<&mut TextFont>) {
    for mut font in &mut fonts {
        font.font_size = 24.0;
    }
}

fn setup(mut meshes: ResMut<Assets<Mesh>>) {
    let handle = meshes.add(Cuboid::default());
    consume(handle);
}

fn gated_asset_creation(
    mut meshes: ResMut<Assets<Mesh>>,
    changed: Query<&Shape, Changed<Shape>>,
) {
    let handle = meshes.add(Cuboid::default());
    consume(handle);
}

fn main() {
    App::new()
        .add_systems(Update, (fixed_font, gated_asset_creation))
        .add_systems(Startup, setup);
}
"#
            .to_owned(),
        )]);
        let auxiliary = BTreeMap::from([(
            "Cargo.toml".to_owned(),
            "[package]\nname = \"game\"\n[dependencies]\nbevy = \"0.20\"\n".to_owned(),
        )]);

        assert!(findings(sources, auxiliary).is_empty());
    }

    #[test]
    fn scopes_bevy_rules_to_renamed_workspace_dependencies() {
        let sources = BTreeMap::from([
            (
                "game/src/lib.rs".to_owned(),
                "fn broken(mut first: Query<&mut Transform>, second: Query<&Transform>) {}\n"
                    .to_owned(),
            ),
            (
                "utility/src/lib.rs".to_owned(),
                "fn unrelated(mut first: Query<&mut Transform>, second: Query<&Transform>) {}\n"
                    .to_owned(),
            ),
        ]);
        let auxiliary = BTreeMap::from([
            (
                "Cargo.toml".to_owned(),
                "[workspace]\nmembers = [\"game\", \"utility\"]\n[workspace.dependencies]\nengine = { package = \"bevy\", version = \"0.20\" }\n"
                    .to_owned(),
            ),
            (
                "game/Cargo.toml".to_owned(),
                "[package]\nname = \"game\"\n[dependencies]\nengine = { workspace = true }\n"
                    .to_owned(),
            ),
            (
                "utility/Cargo.toml".to_owned(),
                "[package]\nname = \"utility\"\n[dependencies]\nserde = \"1\"\n"
                    .to_owned(),
            ),
        ]);

        let selected = findings(sources, auxiliary)
            .into_iter()
            .filter(|finding| finding.code == "bevy-conflicting-query-access")
            .collect::<Vec<_>>();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].path, "game/src/lib.rs");
    }

    #[test]
    fn does_not_apply_bevy_rules_without_a_bevy_manifest() {
        let sources = BTreeMap::from([(
            "src/lib.rs".to_owned(),
            "fn unrelated(mut first: Query<&mut Transform>, second: Query<&Transform>) {}\n"
                .to_owned(),
        )]);
        let auxiliary = BTreeMap::from([(
            "Cargo.toml".to_owned(),
            "[package]\nname = \"utility\"\n[dependencies]\nserde = \"1\"\n".to_owned(),
        )]);

        assert!(findings(sources, auxiliary).is_empty());
    }
}
