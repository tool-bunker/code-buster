use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};

static FLAG_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|[^A-Za-z0-9_.])(flags|Flags|Config)(?:\.|::)([A-Za-z_][A-Za-z0-9_]*)")
        .expect("feature flag regex must compile")
});
static STRING_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#).expect("string literal regex must compile")
});
static FEATURE_SEMANTICS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)feature|experiment|rollout|beta|treatment|variant")
        .expect("feature semantics regex must compile")
});

const IGNORED_MEMBERS: &[&str] = &[
    "trygetvalue",
    "getvalue",
    "getvalueordefault",
    "contains",
    "containskey",
    "add",
    "remove",
    "clear",
    "count",
    "push",
    "pop",
    "join",
    "map",
    "filter",
    "length",
    "get",
    "set",
    "hasflag",
    "setflag",
    "html",
    "foo",
    "bar",
    "baz",
    "test",
    "mock",
    "put",
];

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        let mut seen = BTreeSet::new();
        for (index, line) in source.split('\n').enumerate() {
            let stripped = STRING_LITERAL.replace_all(line, " ");
            for capture in FLAG_REFERENCE.captures_iter(&stripped) {
                let flag = capture
                    .get(3)
                    .expect("feature flag regex must capture the member")
                    .as_str();
                if !FEATURE_SEMANTICS.is_match(flag)
                    || IGNORED_MEMBERS.contains(&flag.to_ascii_lowercase().as_str())
                    || !seen.insert(flag.to_owned())
                {
                    continue;
                }
                findings.push(Finding {
                    code: "feature-flag".to_owned(),
                    severity: Severity::Warn,
                    path: path.clone(),
                    line: index + 1,
                    end_line: index + 1,
                    message: format!("feature flag reference: {flag}"),
                    confidence: String::new(),
                    why: String::new(),
                    suggestion: String::new(),
                    related_files: Vec::new(),
                    snippet: String::new(),
                    code_flow: Vec::new(),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::analyze;
    use std::collections::BTreeMap;

    #[test]
    fn finds_unique_flags_but_excludes_literals_and_collection_members() {
        let sources = BTreeMap::from([(
            "lib/flags.dart".to_owned(),
            "final first = Flags.featureNewCheckout;\n\
             final duplicate = Flags.featureNewCheckout;\n\
             final text = \"Flags.notAFlag\";\n\
             final contains = Config.Contains;\n\
             final collection = Config.push;\n\
             final enabled = Config.featureEnabled;\n\
             final other = flags.beta;\n\
             final semantics = flags.isChecked;\n\
             final geometry = flags.appliesStyle;\n"
                .to_owned(),
        )]);

        let findings = analyze(&sources);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            [
                "feature flag reference: featureNewCheckout",
                "feature flag reference: featureEnabled",
                "feature flag reference: beta",
            ]
        );
    }
}
