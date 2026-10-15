#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_all_generic_lexical_rules_in_repository_order() {
        let findings = analyze(
            &sources(&[(
                "source.dart",
                r#"// TODO: clean up
// FIXME: incorrect
if (value == value) {}
Process.run('unsafe command', []);
final timeout = 10000000;
final values = [1,2,3,4,5,6,7,8,9,10,11,12,13,14];
if (ready) return true;
return false;
"#,
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.severity.as_str(),
                    finding.line,
                    finding.end_line,
                    finding.message.as_str(),
                    finding.confidence.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "todo-comment",
                    "info",
                    1,
                    1,
                    "TODO marker left in source",
                    "high",
                ),
                (
                    "fixme-comment",
                    "warn",
                    2,
                    2,
                    "FIXME marker left in source",
                    "high",
                ),
                (
                    "operation-on-same-value",
                    "warn",
                    3,
                    3,
                    "operation compares value with itself",
                    "high",
                ),
                (
                    "suspicious-command-arg-space",
                    "warn",
                    4,
                    4,
                    "command argument appears to contain embedded spaces",
                    "medium",
                ),
                (
                    "large-number-ungrouped",
                    "info",
                    5,
                    5,
                    "large numeric literal is not digit-grouped",
                    "high",
                ),
                (
                    "large-inline-list",
                    "info",
                    6,
                    6,
                    "large inline collection literal",
                    "medium",
                ),
                (
                    "needless-bool-branch",
                    "info",
                    7,
                    7,
                    "boolean branch can return its condition directly",
                    "medium",
                ),
            ]
        );
    }

    #[test]
    fn recognizes_markers_only_at_the_start_of_real_comments() {
        let findings = analyze(
            &sources(&[
                (
                    "source.go",
                    r#"fixmeHandler()
const marker = "FIXME // FIXME"
// Finds TODO and FIXME comments
// FIXME: replace workaround
value := 1 /* todo: remove compatibility */
"#,
                ),
                (
                    "script.py",
                    r##"label = "TODO # TODO"
# todo track follow-up
text = """# FIXME inside text"""
"##,
                ),
            ]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| matches!(finding.code.as_str(), "todo-comment" | "fixme-comment"))
                .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("todo-comment", "script.py", 2),
                ("todo-comment", "source.go", 5),
                ("fixme-comment", "source.go", 4),
            ]
        );
    }

    #[test]
    fn excludes_intentional_same_value_comparisons() {
        let findings = analyze(
            &sources(&[(
                "comparison.cpp",
                r#"double value = read();
if (value != value) return NAN;
assert(count == count);
if ((size_t)size != size) return false;
if (item. property == property) return false;
// eslint-disable-next-line no-self-compare
if (other != other) return false;
if (count == count) return true;
"#,
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "operation-on-same-value")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![8]
        );
    }

    #[test]
    fn preserves_large_number_language_and_context_exclusions() {
        let findings = analyze(
            &sources(&[
                ("Cargo.toml", "version_code = 10000000"),
                ("clock.c", "const long timeout = 10000000;"),
                ("citation.html", "<p>Published as paper 3319535.</p>"),
                (
                    "benchmark.cpp",
                    "#if 0\nconst long disabled = 10000000;\n#else\nconst long active = 20000000;\n#endif",
                ),
                (
                    "Server.java",
                    "private static final long serialVersionUID = 2459603L;\nlong timeout = 10000000L;",
                ),
                (
                    "stats.py",
                    "\"\"\"\nExample 10474959\n\"\"\"\ntimeout = 20474959",
                ),
                (
                    "permissions.cpp",
                    "auto owner = 0000700;\nauto decimal = 10000000;",
                ),
            ]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("Server.java", 2),
                ("benchmark.cpp", 4),
                ("permissions.cpp", 2),
                ("stats.py", 4),
            ]
        );
    }

    #[test]
    fn excludes_generated_commented_and_rust_test_collections() {
        let findings = analyze(
            &sources(&[
                (
                    "generated.go",
                    "// Code generated by go generate. DO NOT EDIT.\nvar values = []int{0,1,2,3,4,5,6,7,8,9,10,11,12}",
                ),
                (
                    "kernel.cpp",
                    "// values = [0,1,2,3,4,5,6,7,8,9,10,11,12]\nconst values = [0,1,2,3,4,5,6,7,8,9,10,11,12];",
                ),
                (
                    "src/lib.rs",
                    "#[cfg(test)]\nmod tests {\n let values = [0,1,2,3,4,5,6,7,8,9,10,11,12];\n}",
                ),
            ]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-inline-list")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("kernel.cpp", 2)]
        );
    }

    #[test]
    fn distinguishes_command_literals_from_split_argument_lists() {
        let findings = analyze(
            &sources(&[
                (
                    "setup.py",
                    r#"subprocess.run(["cmake", "--version"])
subprocess.run("sysctl -n value".split())
subprocess.run(["cmake --version"])
"#,
                ),
                (
                    "tool.dart",
                    r#"// Process.run('commented unsafe command', []);
final cmd = 'flutter build macos';
Process.start(cmd.split(' ')[0], cmd.split(' ').sublist(1));
Process.start('unsafe command', []);
"#,
                ),
            ]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "suspicious-command-arg-space")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("setup.py", 3), ("tool.dart", 4)]
        );
    }

    #[test]
    fn keeps_boolean_returns_in_one_control_flow_sequence() {
        let findings = analyze(
            &sources(&[(
                "predicate.cpp",
                r#"bool direct(bool ready) {
  if (ready) return true;
  return false;
}
bool sideEffect(bool ready) {
  if (ready) return true;
  restore();
  return false;
}
bool nested(bool ready) {
  for (;;) {
    if (ready) return true;
  }
  return false;
}
"#,
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "needless-bool-branch")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn handles_unicode_while_masking_multiline_strings() {
        let findings = analyze(
            &sources(&[(
                "unicode.py",
                "\"\"\"\nnaïve 10000000\n\"\"\"\nvalue = 20000000",
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![4]
        );
    }

    fn config() -> Config {
        Config::defaults(".".into())
    }

    fn sources(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
            .collect()
    }
}
