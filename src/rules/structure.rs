use crate::config::Config;
use crate::discovery::SourceFile;
use crate::findings::Finding;

pub fn analyze(files: &[SourceFile], config: &Config) -> Vec<Finding> {
    if !structure_analysis_enabled(config) {
        return Vec::new();
    }

    let default_roots = ["src".to_owned()];
    let roots = if config.structure_source_roots.is_empty() {
        default_roots.as_slice()
    } else {
        &config.structure_source_roots
    };
    let mut findings = Vec::new();
    for root in roots {
        analyze_source_root(files, config, root, &mut findings);
    }
    findings
}

fn structure_analysis_enabled(config: &Config) -> bool {
    config.structure_max_top_level_files >= 0
        || !config.structure_allowed_top_level.is_empty()
        || !config.structure_required_directories.is_empty()
}

fn analyze_source_root(
    files: &[SourceFile],
    config: &Config,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    let normalized_root = root.replace('\\', "/").trim_matches('/').to_owned();
    if !config.root.join(&normalized_root).is_dir() {
        emit_missing_source_root(config, &normalized_root, findings);
        return;
    }

    emit_missing_required_directories(config, &normalized_root, findings);
    let candidates = aggregate_top_level_candidates(files, &normalized_root);
    let qualified = qualify_top_level_candidates(candidates, config, &normalized_root);
    emit_top_level_finding(config, &normalized_root, qualified, findings);
}

fn emit_missing_source_root(config: &Config, normalized_root: &str, findings: &mut Vec<Finding>) {
    if config.structure_required_directories.is_empty() {
        return;
    }
    findings.push(Finding::structure(
        "structure-missing-source-root",
        normalized_root.to_owned(),
        format!("configured source root is missing: {normalized_root}"),
        "Create the source root or remove it from [structure].source_roots.",
        Vec::new(),
    ));
}

fn emit_missing_required_directories(
    config: &Config,
    normalized_root: &str,
    findings: &mut Vec<Finding>,
) {
    for required in &config.structure_required_directories {
        let required_path = format!("{normalized_root}/{required}").replace("//", "/");
        if !config.root.join(&required_path).is_dir() {
            findings.push(Finding::structure(
                "structure-missing-required-dir",
                required_path.clone(),
                format!("required source subdirectory is missing: {required_path}"),
                "Create the subsystem folder or update [structure].required_dirs.",
                Vec::new(),
            ));
        }
    }
}

fn aggregate_top_level_candidates<'a>(
    files: &'a [SourceFile],
    normalized_root: &str,
) -> Vec<&'a str> {
    let prefix = format!("{normalized_root}/");
    files
        .iter()
        .map(|file| file.path.as_str())
        .filter(|relative| relative.starts_with(&prefix))
        .filter(|relative| !relative[prefix.len()..].contains('/'))
        .collect()
}

fn qualify_top_level_candidates<'a>(
    mut candidates: Vec<&'a str>,
    config: &Config,
    normalized_root: &str,
) -> Vec<&'a str> {
    let prefix_len = normalized_root.len() + 1;
    candidates.retain(|relative| {
        let name = &relative[prefix_len..];
        !config
            .structure_allowed_top_level
            .iter()
            .any(|allowed| allowed == name || allowed == *relative)
    });
    candidates.sort();
    candidates
}

fn emit_top_level_finding(
    config: &Config,
    normalized_root: &str,
    qualified: Vec<&str>,
    findings: &mut Vec<Finding>,
) {
    if config.structure_max_top_level_files < 0
        || qualified.len() as i64 <= config.structure_max_top_level_files
    {
        return;
    }

    findings.push(Finding::structure(
        "structure-top-level-file",
        normalized_root.to_owned(),
        format!(
            "source root has {} top-level file(s), allowed {}",
            qualified.len(),
            config.structure_max_top_level_files
        ),
        "Move implementation files into subsystem folders or add intentional entry/facade files to [structure].allowed_top_level.",
        qualified.into_iter().map(str::to_owned).collect(),
    ));
}

#[cfg(test)]
mod tests {
    use super::analyze;
    use crate::config::Config;
    use crate::discovery::SourceFile;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reports_missing_directories_and_excess_top_level_files() {
        let root = tempdir().expect("temporary repository must be created");
        fs::create_dir_all(root.path().join("lib")).unwrap();
        let mut config = Config::defaults(root.path().to_path_buf());
        config.structure_source_roots = vec!["lib".to_owned()];
        config.structure_required_directories = vec!["features".to_owned()];
        config.structure_max_top_level_files = 1;
        let files = vec![source("lib/a.dart"), source("lib/b.dart")];

        let findings = analyze(&files, &config);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            ["structure-missing-required-dir", "structure-top-level-file"]
        );
    }

    fn source(path: &str) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            language: "dart".to_owned(),
        }
    }
}
