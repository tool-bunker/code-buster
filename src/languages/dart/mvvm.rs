#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use super::index::DartSourceIndex;
use crate::config::Config;
use crate::dead_analysis::{MvvmLayer, classify_mvvm};
use crate::findings::{Finding, Severity};

#[cfg(test)]
pub fn analyze(sources: &BTreeMap<String, String>, config: &Config) -> Vec<Finding> {
    analyze_sources(
        sources
            .iter()
            .filter(|(path, _)| path.ends_with(".dart"))
            .map(|(path, source)| (path.as_str(), source.as_str())),
        config,
    )
}

pub fn analyze_index(index: &DartSourceIndex<'_>, config: &Config) -> Vec<Finding> {
    analyze_sources(index.paths().map(|path| (path, index.source(path))), config)
}

fn analyze_sources<'a>(
    sources: impl Iterator<Item = (&'a str, &'a str)>,
    config: &Config,
) -> Vec<Finding> {
    if !config.dart_mvvm_enabled() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (path, source) in sources {
        match classify_mvvm(path, config) {
            Some(MvvmLayer::Model) => check_model(path, source, &mut findings),
            Some(MvvmLayer::ViewModel) => check_view_model(path, source, &mut findings),
            Some(MvvmLayer::View | MvvmLayer::Repository) | None => {}
        }
    }
    findings
}

fn check_model(path: &str, source: &str, findings: &mut Vec<Finding>) {
    let Some(matched) = FLUTTER_UI_IMPORT.find(source) else {
        return;
    };
    findings.push(finding(
        "mvvm-model-imports-ui",
        Severity::Error,
        path,
        source,
        matched.start(),
        "Model imports a Flutter presentation library",
    ));
}

fn check_view_model(path: &str, source: &str, findings: &mut Vec<Finding>) {
    for check in VIEW_MODEL_CHECKS {
        let Some(matched) = check.pattern.find(source) else {
            continue;
        };
        findings.push(finding(
            check.code,
            Severity::Warn,
            path,
            source,
            matched.start(),
            check.message,
        ));
    }
}

fn finding(
    code: &str,
    severity: Severity,
    path: &str,
    source: &str,
    offset: usize,
    message: &str,
) -> Finding {
    let metadata = crate::rule_catalog::metadata(code).expect("MVVM rule metadata must exist");
    let line = source.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1;
    Finding {
        code: code.to_owned(),
        severity,
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

struct ViewModelCheck {
    pattern: &'static LazyLock<Regex>,
    code: &'static str,
    message: &'static str,
}

static FLUTTER_UI_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"import\s+['"]package:flutter/(?:material|widgets|cupertino)\.dart['"]"#).unwrap()
});
static BUILD_CONTEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bBuildContext\b").unwrap());
static WIDGET_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Widget|PreferredSizeWidget)\s+(?:get\s+)?[A-Za-z_]\w*").unwrap()
});
static PRESENTATION_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:Navigator\s*\.|showDialog\s*\(|showModalBottomSheet\s*\(|ScaffoldMessenger\s*\.)",
    )
    .unwrap()
});

static VIEW_MODEL_CHECKS: &[ViewModelCheck] = &[
    ViewModelCheck {
        pattern: &BUILD_CONTEXT,
        code: "mvvm-viewmodel-ui-context",
        message: "ViewModel depends on BuildContext",
    },
    ViewModelCheck {
        pattern: &WIDGET_RETURN,
        code: "mvvm-viewmodel-returns-widget",
        message: "ViewModel exposes a Widget",
    },
    ViewModelCheck {
        pattern: &PRESENTATION_ACTION,
        code: "mvvm-viewmodel-performs-navigation",
        message: "ViewModel performs context-dependent presentation behavior",
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn mvvm_config() -> Config {
        let mut config = Config::defaults(".".into());
        config.architecture_profile = "dart-mvvm".to_owned();
        config
    }

    #[test]
    fn reports_complete_mvvm_semantic_rule_family() {
        let findings = analyze(
            &BTreeMap::from([
                (
                    "lib/models/user_model.dart".to_owned(),
                    "import 'package:flutter/widgets.dart';\nclass UserModel {}".to_owned(),
                ),
                (
                    "lib/view_models/login_view_model.dart".to_owned(),
                    r#"class LoginViewModel {
  Widget build(BuildContext context) {
    Navigator.of(context);
    return const SizedBox();
  }
}"#
                    .to_owned(),
                ),
            ]),
            &mvvm_config(),
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "mvvm-model-imports-ui",
                "mvvm-viewmodel-performs-navigation",
                "mvvm-viewmodel-returns-widget",
                "mvvm-viewmodel-ui-context",
            ])
        );
        assert_eq!(findings.len(), 4);
        for finding in findings {
            let metadata = crate::rule_catalog::metadata(&finding.code)
                .expect("MVVM rule metadata must exist");
            assert_eq!(finding.why, metadata.why);
            assert_eq!(finding.suggestion, metadata.suggestion);
        }
    }

    #[test]
    fn requires_mvvm_profile_and_classified_paths() {
        let sources = BTreeMap::from([(
            "lib/other.dart".to_owned(),
            "class Other { Widget build(BuildContext context) => throw 0; }".to_owned(),
        )]);
        assert!(analyze(&sources, &mvvm_config()).is_empty());
        assert!(analyze(&sources, &Config::defaults(".".into())).is_empty());
    }
}
