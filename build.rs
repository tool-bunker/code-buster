use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleDefinition {
    id: String,
    language: String,
    group: String,
    listing_title: String,
    title: String,
    mvvm: bool,
    default_severity: String,
    legacy_group: String,
    why: String,
    suggestion: String,
    version: u32,
    semantic_maturity: String,
    security_kind: String,
    taxonomy: Vec<String>,
    requirements: Vec<String>,
    packs: Vec<String>,
    implementation: String,
    languages: Vec<String>,
    frameworks: Vec<String>,
    language_versions: Vec<[String; 2]>,
    limitations: Vec<String>,
}

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=rules/catalog");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| "CARGO_MANIFEST_DIR is not set".to_owned())?,
    );
    let catalog_dir = manifest_dir.join("rules/catalog");
    let definitions = load_definitions(&catalog_dir, &manifest_dir)?;
    for implementation in definitions
        .values()
        .map(|definition| definition.implementation.as_str())
        .collect::<BTreeSet<_>>()
    {
        println!("cargo:rerun-if-changed={implementation}");
    }
    let generated = generate_catalog(&definitions);
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR is not set".to_owned())?);
    let catalog_output = out_dir.join("rule_catalog.rs");
    fs::write(&catalog_output, generated).map_err(|error| {
        format!(
            "write generated catalog {}: {error}",
            catalog_output.display()
        )
    })?;
    generate_rule_pack_registry(&manifest_dir, &out_dir)?;
    Ok(())
}

fn load_definitions(
    catalog_dir: &Path,
    manifest_dir: &Path,
) -> Result<BTreeMap<String, RuleDefinition>, String> {
    let mut paths = Vec::new();
    collect_json_files(catalog_dir, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err(format!(
            "no rule definitions found under {}",
            catalog_dir.display()
        ));
    }

    let mut definitions = BTreeMap::new();
    for path in paths {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let definition: RuleDefinition = serde_json::from_str(&source)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        validate_definition(&path, &definition, catalog_dir, manifest_dir)?;
        let id = definition.id.clone();
        if let Some(previous) = definitions.insert(id.clone(), definition) {
            return Err(format!(
                "duplicate rule id {id:?}; first definition used language {:?}",
                previous.language
            ));
        }
    }
    Ok(definitions)
}

fn collect_json_files(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read catalog directory {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read catalog entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_json_files(&path, paths)?;
        } else if file_type.is_file() && path.extension().is_some_and(|value| value == "json") {
            paths.push(path);
        }
    }
    Ok(())
}

fn validate_definition(
    path: &Path,
    definition: &RuleDefinition,
    catalog_dir: &Path,
    manifest_dir: &Path,
) -> Result<(), String> {
    validate_definition_location(path, definition, catalog_dir)?;
    validate_required_fields(path, definition)?;
    validate_field_values(path, definition)?;
    validate_implementation(path, definition, manifest_dir)
}

fn validate_definition_location(
    path: &Path,
    definition: &RuleDefinition,
    catalog_dir: &Path,
) -> Result<(), String> {
    let relative = path
        .strip_prefix(catalog_dir)
        .map_err(|_| format!("{} is outside the catalog directory", path.display()))?;
    let expected_id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("{} has no UTF-8 file stem", path.display()))?;
    let expected_language = relative
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("{} has no language directory", path.display()))?;
    if definition.id != expected_id {
        return Err(format!(
            "{} declares id {:?}; the filename requires {:?}",
            path.display(),
            definition.id,
            expected_id
        ));
    }
    if definition.language != expected_language {
        return Err(format!(
            "{} declares language {:?}; the directory requires {:?}",
            path.display(),
            definition.language,
            expected_language
        ));
    }
    Ok(())
}

fn validate_required_fields(path: &Path, definition: &RuleDefinition) -> Result<(), String> {
    for (field, value) in [
        ("id", definition.id.as_str()),
        ("language", definition.language.as_str()),
        ("group", definition.group.as_str()),
        ("listingTitle", definition.listing_title.as_str()),
        ("title", definition.title.as_str()),
        ("defaultSeverity", definition.default_severity.as_str()),
        ("legacyGroup", definition.legacy_group.as_str()),
        ("why", definition.why.as_str()),
        ("suggestion", definition.suggestion.as_str()),
        ("semanticMaturity", definition.semantic_maturity.as_str()),
        ("securityKind", definition.security_kind.as_str()),
        ("implementation", definition.implementation.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{} has an empty {field}", path.display()));
        }
    }
    Ok(())
}

fn validate_field_values(path: &Path, definition: &RuleDefinition) -> Result<(), String> {
    if !matches!(
        definition.default_severity.as_str(),
        "info" | "warn" | "error"
    ) {
        return Err(format!(
            "{} has invalid defaultSeverity {:?}",
            path.display(),
            definition.default_severity
        ));
    }
    if !matches!(
        definition.security_kind.as_str(),
        "none" | "hotspot" | "vulnerability"
    ) {
        return Err(format!(
            "{} has invalid securityKind {:?}",
            path.display(),
            definition.security_kind
        ));
    }
    if definition.version == 0 {
        return Err(format!("{} has rule version 0", path.display()));
    }
    if definition.taxonomy.is_empty() {
        return Err(format!("{} has no taxonomy", path.display()));
    }
    if definition.packs.is_empty() {
        return Err(format!("{} has no execution packs", path.display()));
    }
    for (index, pack) in definition.packs.iter().enumerate() {
        if pack.trim().is_empty() {
            return Err(format!("{} has an empty execution pack", path.display()));
        }
        if definition.packs[..index].contains(pack) {
            return Err(format!(
                "{} repeats execution pack {pack:?}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_implementation(
    definition_path: &Path,
    definition: &RuleDefinition,
    manifest_dir: &Path,
) -> Result<(), String> {
    let relative = Path::new(&definition.implementation);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || !relative.starts_with("src")
        || relative
            .extension()
            .is_none_or(|extension| extension != "rs")
        || relative.file_name().is_some_and(|name| name == "tests.rs")
    {
        return Err(format!(
            "{} has invalid implementation path {:?}",
            definition_path.display(),
            definition.implementation
        ));
    }
    let implementation_path = manifest_dir.join(relative);
    let source = fs::read_to_string(&implementation_path).map_err(|error| {
        format!(
            "{} implementation {} cannot be read: {error}",
            definition_path.display(),
            implementation_path.display()
        )
    })?;
    let id_literal = format!("{:?}", definition.id);
    if !source.contains(&id_literal) {
        return Err(format!(
            "{} implementation {} does not declare rule ID {:?}",
            definition_path.display(),
            implementation_path.display(),
            definition.id
        ));
    }
    Ok(())
}

fn generate_catalog(definitions: &BTreeMap<String, RuleDefinition>) -> String {
    let mut output = String::from(
        "// Generated by build.rs from rules/catalog/**/*.json.\n\
         // Do not edit this build artifact; edit the owning rule definition instead.\n\
         #[rustfmt::skip]\n\
         pub static RULE_DESCRIPTORS: &[RuleDescriptor] = &[\n",
    );
    for definition in definitions.values() {
        let _ = writeln!(
            output,
            "RuleDescriptor{{id:{},language:{},group:{},title:{},mvvm:{}}},",
            string(&definition.id),
            string(&definition.language),
            string(&definition.group),
            string(&definition.listing_title),
            definition.mvvm,
        );
    }
    output.push_str(
        "];
#[rustfmt::skip]\npub static RULE_METADATA: &[RuleMetadata] = &[\n",
    );
    for definition in definitions.values() {
        let _ = writeln!(
            output,
            "RuleMetadata{{id:{},default_severity:{},legacy_group:{},title:{},why:{},suggestion:{},version:{},semantic_maturity:{},security_kind:{},taxonomy:{},requirements:{},packs:{},languages:{},frameworks:{},language_versions:{},limitations:{}}},",
            string(&definition.id),
            string(&definition.default_severity),
            string(&definition.legacy_group),
            string(&definition.title),
            string(&definition.why),
            string(&definition.suggestion),
            definition.version,
            string(&definition.semantic_maturity),
            string(&definition.security_kind),
            string_slice(&definition.taxonomy),
            string_slice(&definition.requirements),
            string_slice(&definition.packs),
            string_slice(&definition.languages),
            string_slice(&definition.frameworks),
            version_slice(&definition.language_versions),
            string_slice(&definition.limitations),
        );
    }
    output.push_str("];\n");
    output
}

fn string(value: &str) -> String {
    format!("{value:?}")
}

fn string_slice(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| string(value))
        .collect::<Vec<_>>()
        .join(",");
    format!("&[{values}]")
}

fn version_slice(values: &[[String; 2]]) -> String {
    let values = values
        .iter()
        .map(|[language, requirement]| format!("({},{})", string(language), string(requirement)))
        .collect::<Vec<_>>()
        .join(",");
    format!("&[{values}]")
}

fn generate_rule_pack_registry(manifest_dir: &Path, out_dir: &Path) -> Result<(), String> {
    let pack_dir = manifest_dir.join("src/rule_packs");
    println!("cargo:rerun-if-changed={}", pack_dir.display());
    let mut paths = Vec::new();
    collect_rust_files(&pack_dir, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err(format!("no rule packs found under {}", pack_dir.display()));
    }

    let mut generated = String::from(
        "// Generated by build.rs from src/rule_packs/**/*.rs.\n\
         // Adding a rule-pack file requires no central module registration.\n",
    );
    let mut modules = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let relative = path
            .strip_prefix(manifest_dir)
            .map_err(|_| format!("{} is outside the crate", path.display()))?;
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("{} has no UTF-8 file stem", path.display()))?;
        validate_pack_filename(path, stem)?;
        let module = format!("discovered_pack_{index:03}");
        modules.push((module.clone(), stem.to_owned()));
        let include_path = format!("/{}", relative.to_string_lossy());
        let _ = writeln!(
            generated,
            "mod {module} {{ include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), {include_path:?})); }}"
        );
    }
    generated.push_str("pub static RULE_PACKS: &[RulePack] = &[\n");
    for (module, _) in &modules {
        let _ = writeln!(generated, "{module}::PACK,");
    }
    generated.push_str("];\n#[cfg(test)]\npub static RULE_PACK_SOURCES: &[&str] = &[\n");
    for (_, stem) in &modules {
        let _ = writeln!(generated, "{},", string(stem));
    }
    generated.push_str("];\n");

    let output = out_dir.join("rule_packs.rs");
    fs::write(&output, generated).map_err(|error| {
        format!(
            "write generated pack registry {}: {error}",
            output.display()
        )
    })
}

fn collect_rust_files(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read rule-pack directory {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read rule-pack entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_rust_files(&path, paths)?;
        } else if file_type.is_file() && path.extension().is_some_and(|value| value == "rs") {
            paths.push(path);
        }
    }
    Ok(())
}

fn validate_pack_filename(path: &Path, stem: &str) -> Result<(), String> {
    let bytes = stem.as_bytes();
    let valid_order =
        bytes.len() > 4 && bytes[..3].iter().all(u8::is_ascii_digit) && bytes[3] == b'-';
    let valid_name = bytes[4..]
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if valid_order && valid_name {
        Ok(())
    } else {
        Err(format!(
            "{} must use NNN-kebab-case.rs ordering",
            path.display()
        ))
    }
}
