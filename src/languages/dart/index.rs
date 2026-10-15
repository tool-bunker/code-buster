use std::collections::BTreeMap;

use crate::dart_core_rules::mask_comments_preserving_strings;
use crate::source_analysis_context::SourceAnalysisContext;

pub struct DartSourceIndex<'a> {
    context: &'a SourceAnalysisContext<'a>,
    paths: Vec<&'a str>,
    comments_masked: BTreeMap<&'a str, String>,
}

impl<'a> DartSourceIndex<'a> {
    pub fn new(context: &'a SourceAnalysisContext<'a>) -> Self {
        let paths = context
            .sources()
            .keys()
            .filter(|path| path.ends_with(".dart"))
            .map(String::as_str)
            .collect::<Vec<_>>();
        let comments_masked = paths
            .iter()
            .map(|path| {
                (
                    *path,
                    mask_comments_preserving_strings(&context.sources()[*path]),
                )
            })
            .collect();
        Self {
            context,
            paths,
            comments_masked,
        }
    }

    pub fn paths(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.paths.iter().copied()
    }

    pub fn source(&self, path: &str) -> &'a str {
        self.context.sources()[path].as_str()
    }

    pub fn masked_lines(&self, path: &str) -> &[String] {
        self.context.masked_lines(path)
    }

    pub fn comments_masked(&self, path: &str) -> &str {
        &self.comments_masked[path]
    }

    pub fn context(&self) -> &SourceAnalysisContext<'a> {
        self.context
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn indexes_only_dart_sources_in_stable_path_order() {
        let sources = BTreeMap::from([
            ("lib/z.dart".to_owned(), "void z() {}".to_owned()),
            ("src/a.rs".to_owned(), "fn a() {}".to_owned()),
            ("lib/a.dart".to_owned(), "void a() {}".to_owned()),
        ]);
        let empty_sources = BTreeMap::new();
        let empty_paths = BTreeSet::new();
        let context = SourceAnalysisContext::with_auxiliary(
            &sources,
            &empty_sources,
            &empty_paths,
            false,
            &empty_sources,
        );
        let index = DartSourceIndex::new(&context);

        assert_eq!(
            index.paths().collect::<Vec<_>>(),
            ["lib/a.dart", "lib/z.dart"]
        );
        assert_eq!(index.source("lib/a.dart"), "void a() {}");
    }
}
