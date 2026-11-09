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
if (mask == mask & bits) return false;
if (count == count) return true;
if (alpha == alpha || beta != beta) return false;
bool isnan(float sample) { return sample != sample; }
bool __tg_isfinite(float sample) { return sample == sample && fabs(sample) != INFINITY; }
if (unknown != unknown) return false;
int order = (_a == _a) ? -1 : (_b == _b) ? 1 : 0;
"#,
            ), (
                "comparison.rs",
                "if num == num as i64 as f64 { return true; }",
            ), (
                "comments.py",
                "# Note: infinity <= infinity is true",
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "operation-on-same-value")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![9, 10]
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
                (
                    "seeds.ts",
                    "const seed = 1664525 + 1013904223;",
                ),
                (
                    "lookup.java",
                    "int hex = 0x00000000;\nint binary = 0b00000000;\nlong decimal = 10000000L;",
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
                ("lookup.java", 3),
                ("permissions.cpp", 2),
                ("seeds.ts", 1),
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
                    "kernel.ts",
                    "// values = [0,1,2,3,4,5,6,7,8,9,10,11,12]\nconst values = [0,1,2,3,4,5,6,7,8,9,10,11,12];",
                ),
                (
                    "src/lib.rs",
                    "#[cfg(test)]\nmod tests {\n let values = [0,1,2,3,4,5,6,7,8,9,10,11,12];\n}",
                ),
                (
                    "table.cpp",
                    "static const int values[] = {0,1,2,3,4,5,6,7,8,9,10,11,12};\n\
static const int rows[][13] = {\n\
 {0,1,2,3,4,5,6,7,8,9,10,11,12},\n\
};",
                ),
                (
                    "matrix.c",
                    "const unsigned char matrix[2][13] = {\n{0,1,2,3,4,5,6,7,8,9,10,11,12},\n};",
                ),
                (
                    "Labels.java",
                    "private static final byte[] LABEL = new byte[]\n    {'s','h','a','r','e','d','_','s','e','c','r','e','t'};\nprivate static final short TABLE[][] =\n{\n{0,1,2,3,4,5,6,7,8,9,10,11,12},\n};",
                ),
                (
                    "capture.cpp",
                    "auto work = [a,b,c,d,e,f,g,h,i,j,k,l,m](int value) { return value; };",
                ),
                (
                    "effects.css",
                    ".particles { background: radial-gradient(circle, red, blue), radial-gradient(circle, red, blue), radial-gradient(circle, red, blue), radial-gradient(circle, red, blue), radial-gradient(circle, red, blue), radial-gradient(circle, red, blue), radial-gradient(circle, red, blue); }",
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
            vec![("kernel.ts", 2)]
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
subprocess.run("black module.py", shell=True)
subprocess.run(["cmake --version"])
subprocess.run(["git", "merge-file", "-L", "before the split"])
subprocess.run([sys.executable, "-c", "import module; print(module.value)"])
subprocess.run(["tool", "file with spaces.txt"])
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
            vec![("setup.py", 4), ("tool.dart", 4)]
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

    #[test]
    fn excludes_python_strings_and_comments_from_large_number_advice() {
        let findings = analyze(
            &sources(&[(
                "patterns.py",
                "pattern = r\"release-20080830\"\nvalue = 12345678  # example 87654321",
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn excludes_shell_where_digit_separators_are_not_portable_syntax() {
        let findings = analyze(
            &sources(&[
                ("install.sh", "timeout=10000000"),
                ("bin/install", "#!/usr/bin/env bash\ntimeout=10000000"),
                ("timeout.rs", "const TIMEOUT: u64 = 10000000;"),
            ]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| finding.path.as_str())
                .collect::<Vec<_>>(),
            vec!["timeout.rs"]
        );
    }


    #[test]
    fn accepts_cpp_apostrophe_grouped_decimals() {
        let findings = analyze(
            &sources(&[(
                "amount.cpp",
                "auto tera = 1'000'000'000'000;\n\
auto rounded = Money(500'000'000'000) / Money(1'000'000'000);\n\
auto raw = 10000000;",
            )]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn excludes_dense_protocol_enum_value_catalogs() {
        let protocol = (0..20)
            .map(|index| format!("VALUE_4x4_{index} = {},", 10_000_000 + index))
            .collect::<Vec<_>>()
            .join("\n");
        let sources = BTreeMap::from([
            ("Protocol.cs".to_owned(), protocol),
            (
                "Timeout.cs".to_owned(),
                "const int timeout = 10000000;".to_owned(),
            ),
        ]);

        assert_eq!(
            analyze(&sources, &config())
                .into_iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| (finding.path, finding.line))
                .collect::<Vec<_>>(),
            vec![("Timeout.cs".to_owned(), 1)]
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
