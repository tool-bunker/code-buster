#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn reports_style_drift_and_broad_refactoring_beside_behavior() {
        let fixture = Fixture::new(
            "void upload(bool ready) {\n  if (!ready) return;\n  print(\"one\");\n  print(\"two\");\n  print(\"three\");\n  print(\"four\");\n  print(\"five\");\n  print(\"six\");\n}",
            "void upload(bool ready) {\n  print('one');\n  print('two');\n  print('three');\n  print('four');\n  print('five');\n  print('six');\n}",
        );
        let context = fixture.context();
        let findings = analyze(&context);

        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "broad-refactor-in-focused-change" | "style-drift-in-diff"
                    )
                })
                .map(|finding| (
                    finding.code.as_str(),
                    finding.line,
                    finding.confidence.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("broad-refactor-in-focused-change", 2, "high"),
                ("style-drift-in-diff", 2, "high"),
            ]
        );
    }

    #[test]
    fn changed_behavior_requires_a_concept_related_test() {
        let after = "bool upload(String value) {\n  if (value.isEmpty) return false;\n  return value.startsWith('https:');\n}";
        let mut uncovered = Fixture::new(after, "bool upload(String value) => true;");
        let context = uncovered.context();
        assert_eq!(
            changed_behavior_without_test(&context, &focused_diff(&context).unwrap()).len(),
            1
        );

        uncovered.add_changed("test/upload_test.dart", "void main() { testUpload(); }", "");
        let context = uncovered.context();
        assert!(
            changed_behavior_without_test(&context, &focused_diff(&context).unwrap()).is_empty()
        );
    }

    #[test]
    fn reports_stale_public_contract_references_but_ignores_masked_text() {
        let mut fixture = Fixture::new(
            "String uploadAsset(String value) => value;",
            "String upload(String value) => value;",
        );
        fixture.add_unchanged(
            "lib/caller.dart",
            "import 'upload.dart';\nvoid run() => upload('x');",
        );
        let context = fixture.context();
        let findings = stale_contract_references(&context, &focused_diff(&context).unwrap());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "lib/caller.dart");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].related_files, vec!["lib/upload.dart"]);

        fixture.sources.insert(
            "lib/caller.dart".to_owned(),
            "// upload(value);\nconst example = 'upload(value)';".to_owned(),
        );
        let context = fixture.context();
        assert!(stale_contract_references(&context, &focused_diff(&context).unwrap()).is_empty());
    }

    #[test]
    fn classifies_untested_high_risk_changes() {
        let fixture = Fixture::new(
            "double refund(double amount, double fee) => amount - fee;",
            "double refund(double amount, double fee) => amount;",
        );
        let context = fixture.context();
        let findings = risky_changes_without_test(&context, &focused_diff(&context).unwrap());

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "changed money behavior has no concept-related changed test"
        );
    }

    #[test]
    fn detects_new_behavior_duplicated_from_unchanged_code() {
        let mut fixture = Fixture::new(
            "String upload(String input) => input.trim().toLowerCase().replaceAll(' ', '-');",
            "",
        );
        fixture.add_unchanged(
            "lib/slug.dart",
            "String slugify(String value) => value.trim().toLowerCase().replaceAll(' ', '-');",
        );
        let context = fixture.context();
        let findings =
            changed_duplicate_implementations(&context, &focused_diff(&context).unwrap());

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "new `upload` repeats unchanged `slugify` behavior"
        );
        assert_eq!(findings[0].related_files, vec!["lib/slug.dart"]);
    }

    #[test]
    fn reports_optional_feature_bundles_and_boolean_option_explosions() {
        let fixture = Fixture::new(
            "void save(bool merge, bool validate, bool notify) {\n  bool cache = true;\n  bool retry = false;\n  bool hook = false;\n  validator.check();\n}",
            "",
        );
        let context = fixture.context();
        let change = focused_diff(&context).unwrap();

        assert_eq!(optional_feature_bundles(&context, &change).len(), 1);
        assert_eq!(boolean_option_explosions(&context, &change).len(), 1);
    }

    #[test]
    fn reports_declaration_heavy_changes() {
        let fixture = Fixture::new(
            "interface class DiscountStrategy {}\nclass PercentageDiscount implements DiscountStrategy {}\nclass DiscountConfig {}",
            "",
        );
        let context = fixture.context();
        let findings = abstraction_cost_exceeds_use(&context, &focused_diff(&context).unwrap());

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "change adds 3 declarations for 0 behavioral lines"
        );
    }

    #[test]
    fn distinguishes_unused_declarations_from_single_caller_wrappers() {
        let unused = Fixture::new("int _prepare(int value) => compute(value);", "");
        let context = unused.context();
        let findings = new_unused_declarations(&context, &focused_diff(&context).unwrap());
        assert_eq!(findings.len(), 1);

        let wrapper = Fixture::new(
            "int _prepare(int value) => compute(value);\nint save(int value) => _prepare(value);",
            "",
        );
        let context = wrapper.context();
        let change = focused_diff(&context).unwrap();
        assert!(new_unused_declarations(&context, &change).is_empty());
        assert_eq!(single_caller_wrappers(&context, &change).len(), 1);
    }

    #[test]
    fn reports_disconnected_changed_symbols() {
        let fixture = Fixture::new(
            "int load(int value) => parse(value);\nint parse(int value) => value + 1;\nint rename(int value) => value + 2;\nint archive(int value) => value + 3;",
            "",
        );
        let context = fixture.context();
        let findings = unrelated_symbol_churn(&context, &focused_diff(&context).unwrap());

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec![
                "changed symbol `rename` is disconnected from 3 other changed functions",
                "changed symbol `archive` is disconnected from 3 other changed functions",
            ]
        );
    }

    #[test]
    fn reports_equivalent_guards_around_a_project_function() {
        let mut fixture = Fixture::new(
            "void upload(String? value) { if (value != null) parse(value); }",
            "",
        );
        fixture.add_changed(
            "lib/preview.dart",
            "void preview(String? input) { if (input != null) parse(input); }",
            "",
        );
        fixture.add_unchanged(
            "lib/parser.ts",
            "export function parse(value: string): void {}",
        );
        let context = fixture.context();
        let findings = caller_side_guard_duplication(&context, &focused_diff(&context).unwrap());

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "2 callers add the same guard around `parse`"
        );
    }

    #[test]
    fn reports_new_dependencies_that_duplicate_native_capabilities() {
        let mut fixture = Fixture::new(
            "import leftPad from 'left-pad';\nexport const code = leftPad('7', 3, '0');",
            "",
        );
        fixture.changed_paths.insert("package.json".to_owned());
        fixture.auxiliary.insert(
            "package.json".to_owned(),
            r#"{"dependencies":{"left-pad":"^1.3.0"}}"#.to_owned(),
        );
        fixture.auxiliary.insert(
            "@base/package.json".to_owned(),
            r#"{"dependencies":{}}"#.to_owned(),
        );
        let context = fixture.context();
        let findings = thin_dependencies(&context, &focused_diff(&context).unwrap());

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("String.padStart"));
    }

    #[test]
    fn requires_runtime_evidence_for_node_globals() {
        let mut supported = Fixture::new("import fetch from 'node-fetch';\nfetch(url);", "");
        supported.changed_paths.insert("package.json".to_owned());
        supported.auxiliary.insert(
            "package.json".to_owned(),
            r#"{"engines":{"node":">=18"},"dependencies":{"node-fetch":"^3.3.2"}}"#.to_owned(),
        );
        supported.auxiliary.insert(
            "@base/package.json".to_owned(),
            r#"{"dependencies":{}}"#.to_owned(),
        );
        let context = supported.context();
        assert_eq!(
            thin_dependencies(&context, &focused_diff(&context).unwrap()).len(),
            1
        );

        supported.auxiliary.insert(
            "package.json".to_owned(),
            r#"{"engines":{"node":">=16"},"dependencies":{"node-fetch":"^3.3.2"}}"#.to_owned(),
        );
        let context = supported.context();
        assert!(thin_dependencies(&context, &focused_diff(&context).unwrap()).is_empty());
    }

    #[test]
    fn skips_intent_rules_for_broad_migrations() {
        let mut fixture = Fixture::new("", "");
        fixture.sources.clear();
        fixture.base_sources.clear();
        fixture.changed_paths.clear();
        for index in 0..6 {
            fixture.add_changed(
                &format!("lib/change_{index}.dart"),
                "if (changed) return;",
                "",
            );
        }
        let context = fixture.context();
        assert!(focused_diff(&context).is_none());
        assert!(analyze(&context).is_empty());
    }

    struct Fixture {
        sources: BTreeMap<String, String>,
        base_sources: BTreeMap<String, String>,
        changed_paths: BTreeSet<String>,
        auxiliary: BTreeMap<String, String>,
    }

    impl Fixture {
        fn new(after: &str, before: &str) -> Self {
            Self {
                sources: BTreeMap::from([("lib/upload.dart".to_owned(), after.to_owned())]),
                base_sources: BTreeMap::from([("lib/upload.dart".to_owned(), before.to_owned())]),
                changed_paths: BTreeSet::from(["lib/upload.dart".to_owned()]),
                auxiliary: BTreeMap::new(),
            }
        }

        fn add_changed(&mut self, path: &str, after: &str, before: &str) {
            self.sources.insert(path.to_owned(), after.to_owned());
            self.base_sources.insert(path.to_owned(), before.to_owned());
            self.changed_paths.insert(path.to_owned());
        }

        fn add_unchanged(&mut self, path: &str, source: &str) {
            self.sources.insert(path.to_owned(), source.to_owned());
            self.base_sources.insert(path.to_owned(), source.to_owned());
        }

        fn context(&self) -> SourceAnalysisContext<'_> {
            SourceAnalysisContext::with_auxiliary(
                &self.sources,
                &self.base_sources,
                &self.changed_paths,
                true,
                &self.auxiliary,
            )
        }
    }
}
