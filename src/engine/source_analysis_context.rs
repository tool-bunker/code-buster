use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::sync::LazyLock;

use crate::generic_rules::{mask_generic_rule_strings, mask_rust_test_regions};

pub struct SourceAnalysisContext<'a> {
    sources: BTreeMap<String, String>,
    masked_source_lines: BTreeMap<String, Vec<String>>,
    base_sources: BTreeMap<String, String>,
    changed_paths: &'a BTreeSet<String>,
    auxiliary_files: &'a BTreeMap<String, String>,
    changed_base: bool,
}

impl<'a> SourceAnalysisContext<'a> {
    #[cfg(test)]
    pub fn new(
        sources: &'a BTreeMap<String, String>,
        base_sources: &'a BTreeMap<String, String>,
        changed_paths: &'a BTreeSet<String>,
        changed_base: bool,
    ) -> Self {
        static EMPTY_AUXILIARY: LazyLock<BTreeMap<String, String>> = LazyLock::new(BTreeMap::new);
        Self::with_auxiliary(
            sources,
            base_sources,
            changed_paths,
            changed_base,
            &EMPTY_AUXILIARY,
        )
    }

    #[cfg(test)]
    pub fn unchanged(sources: &'a BTreeMap<String, String>) -> Self {
        static EMPTY_SOURCES: LazyLock<BTreeMap<String, String>> = LazyLock::new(BTreeMap::new);
        static EMPTY_PATHS: LazyLock<BTreeSet<String>> = LazyLock::new(BTreeSet::new);
        Self::new(sources, &EMPTY_SOURCES, &EMPTY_PATHS, false)
    }

    pub fn with_auxiliary(
        sources: &'a BTreeMap<String, String>,
        base_sources: &'a BTreeMap<String, String>,
        changed_paths: &'a BTreeSet<String>,
        changed_base: bool,
        auxiliary_files: &'a BTreeMap<String, String>,
    ) -> Self {
        let sources = sources
            .iter()
            .map(|(path, source)| (path.clone(), mask_rust_test_regions(path, source)))
            .collect::<BTreeMap<_, _>>();
        let base_sources = base_sources
            .iter()
            .map(|(path, source)| (path.clone(), mask_rust_test_regions(path, source)))
            .collect::<BTreeMap<_, _>>();
        let masked_source_lines = sources
            .iter()
            .map(|(path, source)| {
                let lines = source.split('\n').map(str::to_owned).collect::<Vec<_>>();
                (path.clone(), mask_generic_rule_strings(&lines, path))
            })
            .collect();
        Self {
            sources,
            masked_source_lines,
            base_sources,
            changed_paths,
            auxiliary_files,
            changed_base,
        }
    }

    pub fn sources(&self) -> &BTreeMap<String, String> {
        &self.sources
    }

    pub fn masked_lines(&self, path: &str) -> &[String] {
        self.masked_source_lines
            .get(path)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn base_sources(&self) -> &BTreeMap<String, String> {
        &self.base_sources
    }

    pub fn changed_paths(&self) -> &BTreeSet<String> {
        self.changed_paths
    }

    pub fn auxiliary_files(&self) -> &BTreeMap<String, String> {
        self.auxiliary_files
    }

    pub fn has_changed_base(&self) -> bool {
        self.changed_base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_rust_test_regions_from_rule_sources() {
        let source = "fn production() {}\n\
#[cfg(test)]\n\
mod tests {\n\
    #[test]\n\
    fn fixture() { let sample = \"TODO: fixture\"; }\n\
}\n\
fn after() {}\n";
        let sources = BTreeMap::from([("src/lib.rs".to_owned(), source.to_owned())]);
        let empty_sources = BTreeMap::new();
        let empty_paths = BTreeSet::new();
        let context = SourceAnalysisContext::with_auxiliary(
            &sources,
            &empty_sources,
            &empty_paths,
            false,
            &empty_sources,
        );
        let analyzed = &context.sources()["src/lib.rs"];

        assert!(analyzed.contains("fn production() {}"));
        assert!(analyzed.contains("fn after() {}"));
        assert!(!analyzed.contains("TODO: fixture"));
        assert_eq!(analyzed.lines().count(), source.lines().count());
    }
}
