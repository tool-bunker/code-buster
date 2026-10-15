use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

use super::index::DartSourceIndex;

#[cfg(test)]
pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    analyze_index(&DartSourceIndex::new(context))
}

pub fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    let context = index.context();
    let package_roots = index
        .paths()
        .filter(|path| !is_embedded_fixture(path))
        .filter_map(|path| package_root(path, context))
        .collect::<BTreeSet<_>>();

    package_roots
        .into_iter()
        .filter_map(|root| package_finding(&root, context))
        .collect()
}

fn is_embedded_fixture(path: &str) -> bool {
    EMBEDDED_FIXTURE.is_match(&path.replace('\\', "/"))
}

fn package_root(path: &str, context: &SourceAnalysisContext<'_>) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let mut directory = normalized
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    loop {
        let manifest = if directory.is_empty() {
            "pubspec.yaml".to_owned()
        } else {
            format!("{directory}/pubspec.yaml")
        };
        if context.auxiliary_files().contains_key(&manifest) {
            return Some(directory.to_owned());
        }
        if directory.is_empty() {
            return None;
        }
        directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

fn package_finding(root: &str, context: &SourceAnalysisContext<'_>) -> Option<Finding> {
    let options_path = if root.is_empty() {
        "analysis_options.yaml".to_owned()
    } else {
        format!("{root}/analysis_options.yaml")
    };
    let Some(options) = context.auxiliary_files().get(&options_path) else {
        return Some(finding(&options_path, "analysis_options.yaml is missing"));
    };

    let configured = configured_rules(options);
    let mut missing = RECOMMENDED_RULES
        .into_iter()
        .filter(|rule| !configured.contains(*rule))
        .collect::<BTreeSet<_>>();
    if options.contains("package:lints/recommended.yaml") {
        missing.remove("implementation_imports");
        missing.remove("use_rethrow_when_possible");
    }
    if options.contains("package:flutter_lints/flutter.yaml") {
        missing.remove("implementation_imports");
        missing.remove("use_build_context_synchronously");
        missing.remove("use_rethrow_when_possible");
    }
    if missing.is_empty() {
        return None;
    }
    Some(finding(
        &options_path,
        &format!(
            "important analyzer coverage is missing: [{}]",
            missing.into_iter().collect::<Vec<_>>().join(", ")
        ),
    ))
}

fn configured_rules(source: &str) -> BTreeSet<&str> {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let candidate = trimmed
                .strip_prefix('-')
                .map_or(trimmed, |value| value.trim_start());
            let name = candidate
                .split_once(':')
                .map_or(candidate, |(name, _)| name)
                .trim();
            RECOMMENDED_RULES.contains(&name).then_some(name)
        })
        .collect()
}

fn finding(path: &str, message: &str) -> Finding {
    let metadata = rule_catalog::metadata("dart-recommended-lints-missing")
        .expect("Dart analyzer configuration metadata must exist");
    Finding {
        code: "dart-recommended-lints-missing".to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Dart analyzer configuration severity must be valid"),
        path: path.to_owned(),
        line: 1,
        end_line: 1,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const RECOMMENDED_RULES: [&str; 7] = [
    "cancel_subscriptions",
    "close_sinks",
    "discarded_futures",
    "implementation_imports",
    "unawaited_futures",
    "use_build_context_synchronously",
    "use_rethrow_when_possible",
];

static EMBEDDED_FIXTURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|/)(?:__tests__|test|tests)/fixtures(?:/|$)").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn ignores_loose_sources_and_embedded_fixtures() {
        let loose = Fixture::new([("main.dart", "void main() {}")]);
        assert!(analyze(&loose.context()).is_empty());

        let mut embedded = Fixture::new([(
            "__tests__/fixtures/kernel-parity/torture.dart",
            "void run() {}",
        )]);
        embedded.add_auxiliary("pubspec.yaml", "name: app\n");
        assert!(analyze(&embedded.context()).is_empty());
    }

    #[test]
    fn requires_options_for_each_recognized_package() {
        let mut fixture = Fixture::new([
            ("lib/main.dart", "void main() {}"),
            ("tools/lib/tool.dart", "void run() {}"),
        ]);
        fixture.add_auxiliary("pubspec.yaml", "name: app\n");
        fixture.add_auxiliary("tools/pubspec.yaml", "name: tools\n");

        assert_eq!(
            analyze(&fixture.context())
                .into_iter()
                .map(|finding| (finding.path, finding.message))
                .collect::<Vec<_>>(),
            vec![
                (
                    "analysis_options.yaml".to_owned(),
                    "analysis_options.yaml is missing".to_owned(),
                ),
                (
                    "tools/analysis_options.yaml".to_owned(),
                    "analysis_options.yaml is missing".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn applies_recommended_and_flutter_lint_sets() {
        let mut recommended = Fixture::new([("lib/main.dart", "void main() {}")]);
        recommended.add_auxiliary("pubspec.yaml", "name: app\n");
        recommended.add_auxiliary(
            "analysis_options.yaml",
            "include: package:lints/recommended.yaml\n",
        );
        let message = analyze(&recommended.context()).remove(0).message;
        assert_eq!(
            message,
            "important analyzer coverage is missing: [cancel_subscriptions, close_sinks, discarded_futures, unawaited_futures, use_build_context_synchronously]"
        );

        let mut flutter = Fixture::new([("app/lib/main.dart", "void main() {}")]);
        flutter.add_auxiliary("app/pubspec.yaml", "name: app\nflutter:\n");
        flutter.add_auxiliary(
            "app/analysis_options.yaml",
            "include: package:flutter_lints/flutter.yaml\n",
        );
        let finding = analyze(&flutter.context()).remove(0);
        assert_eq!(finding.path, "app/analysis_options.yaml");
        assert_eq!(
            finding.message,
            "important analyzer coverage is missing: [cancel_subscriptions, close_sinks, discarded_futures, unawaited_futures]"
        );
    }

    #[test]
    fn accepts_explicit_complete_rule_coverage() {
        let mut fixture = Fixture::new([("lib/main.dart", "void main() {}")]);
        fixture.add_auxiliary("pubspec.yaml", "name: app\n");
        fixture.add_auxiliary(
            "analysis_options.yaml",
            "linter:\n  rules:\n    - cancel_subscriptions\n    close_sinks: true\n    discarded_futures:\n    implementation_imports: false\n    - unawaited_futures\n    use_build_context_synchronously: true\n    use_rethrow_when_possible:\n",
        );

        assert!(analyze(&fixture.context()).is_empty());
    }

    struct Fixture {
        sources: BTreeMap<String, String>,
        auxiliary: BTreeMap<String, String>,
    }

    impl Fixture {
        fn new<const N: usize>(sources: [(&str, &str); N]) -> Self {
            Self {
                sources: sources
                    .into_iter()
                    .map(|(path, source)| (path.to_owned(), source.to_owned()))
                    .collect(),
                auxiliary: BTreeMap::new(),
            }
        }

        fn add_auxiliary(&mut self, path: &str, source: &str) {
            self.auxiliary.insert(path.to_owned(), source.to_owned());
        }

        fn context(&self) -> SourceAnalysisContext<'_> {
            static EMPTY_SOURCES: LazyLock<BTreeMap<String, String>> = LazyLock::new(BTreeMap::new);
            static EMPTY_PATHS: LazyLock<BTreeSet<String>> = LazyLock::new(BTreeSet::new);
            SourceAnalysisContext::with_auxiliary(
                &self.sources,
                &EMPTY_SOURCES,
                &EMPTY_PATHS,
                false,
                &self.auxiliary,
            )
        }
    }
}
