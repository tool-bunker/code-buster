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
    fn distinguishes_byte_literal_prefixes_from_compared_identifiers() {
        let findings = analyze(
            &sources(&[
                (
                    "bytes.rs",
                    r#"fn newline(b: u8) -> bool { b == b'\n' }
fn matching_bytes(b: &[u8]) -> bool { b == b"ok" }
fn same_byte(b: u8) -> bool { b == b }
// b == b
fn example() { let text = "b == b"; }
"#,
                ),
                (
                    "bytes.py",
                    "def matches_bytes(b): return b == b'ok'\n\
                     def matches_uppercase(B): return B == B'ok'\n\
                     def same_value(b): return b == b\n",
                ),
            ]),
            &config(),
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "operation-on-same-value")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("bytes.py", 3), ("bytes.rs", 3)]
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
    fn excludes_rust_use_trees_and_typescript_declarations_from_runtime_collections() {
        let findings = analyze(
            &sources(&[
                (
                    "src/imports.rs",
                    "use crate::{A,B,C,D,E,F,G,H,I,J,K,L,M};\n\
                     struct Fields { a: u8,b: u8,c: u8,d: u8,e: u8,f: u8,g: u8,h: u8,i: u8,j: u8,k: u8,l: u8,m: u8 }\n\
                     const VALUES: [u8; 13] = [0,1,2,3,4,5,6,7,8,9,10,11,12];",
                ),
                (
                    "src/runtime.ts",
                    "const values = [0,1,2,3,4,5,6,7,8,9,10,11,12];",
                ),
                (
                    "types/api.d.ts",
                    "import {A,B,C,D,E,F,G,H,I,J,K,L,M} from 'api';\n\
                     type Tuple = [A,B,C,D,E,F,G,H,I,J,K,L,M];",
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
            vec![("src/imports.rs", 3), ("src/runtime.ts", 1)]
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
    fn reports_numeric_tokens_without_rewriting_digit_bearing_identifiers() {
        let findings = analyze(
            &sources(&[
                ("src/format.rs", "let format = ZetaFormat::V0114180EditableRegion;\nmod v0114180_editable_region {}\nlet 模型12345678 = value;\nlet timeout = 12345678u64;\nlet grouped = 12_345_678;\n"),
                ("src/format.ts", "const model12345678 = input;\nconst $12345678 = input;\nconst timeout = 12345678n;\n"),
            ]),
            &config(),
        );
        assert_eq!(
            findings.iter().filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| (finding.path.as_str(), finding.line)).collect::<Vec<_>>(),
            [("src/format.rs", 4), ("src/format.ts", 3)]
        );
    }

    #[test]
    fn excludes_multiline_rust_text_but_keeps_following_numeric_code() {
        let source = r####"fn query<'a>(name: &'a str) {
    let sql = "PRAGMA journal_mode=WAL;\
               PRAGMA mmap_size=6000000;\
               CREATE TABLE messages (value TEXT);";
    let sample = r###"inner "quote"
12345678 // still text
"###;
    let bytes = b"multi
23456789";
    let character = '字';
    let size = 34567890u64;
}
"####;
        let findings = analyze(&sources(&[("src/query.rs", source)]), &config());
        assert_eq!(
            findings.iter().filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| finding.line).collect::<Vec<_>>(),
            [11]
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
    #[test]
    fn preserves_comment_scanner_quotes_unicode_and_continuations() {
        let syntax = CommentSyntax::for_path("source.dart");
        let mut state = CommentState::default();
        assert_eq!(
            extract_comments("π = \"// TODO\"; /* first */ // second\r", syntax, &mut state),
            " first \n second\r"
        );
        assert_eq!(extract_comments("/* café", syntax, &mut state), " café");
        assert_eq!(
            extract_comments(" encore */ \"// hidden\" // visible\r", syntax, &mut state),
            " encore \n visible\r"
        );
        assert_eq!(extract_comments("π = \"\"\"// hidden", syntax, &mut state), "");
        assert_eq!(
            extract_comments("é \"\"\" // visible", syntax, &mut state),
            " visible"
        );
        assert_eq!(extract_comments("'unterminated // hidden", syntax, &mut state), "");
        assert_eq!(extract_comments("// visible", syntax, &mut state), " visible");
    }

    #[test]
    fn preserves_language_specific_line_comment_boundaries() {
        for (path, source) in [
            ("script.py", "π = '# hidden'; # visible\r"),
            ("query.sql", "SELECT '-- hidden'; -- visible\r"),
            ("source.lisp", "\"; hidden\" ; visible\r"),
            ("source.tex", "\"% hidden\" % visible\r"),
        ] {
            assert_eq!(
                extract_comments(
                    source,
                    CommentSyntax::for_path(path),
                    &mut CommentState::default(),
                ),
                " visible\r",
                "{path}"
            );
        }
    }

    #[test]
    fn preserves_command_quotes_and_block_comment_spacing() {
        let mut in_block = false;
        assert_eq!(
            strip_command_comments(r#"run("é // # /* \"")/**/next # ignored"#, &mut in_block),
            r#"run("é // # /* \"")  next "#
        );
        assert_eq!(strip_command_comments("/*é\r", &mut in_block), "    ");
        assert!(in_block);
        assert_eq!(strip_command_comments("*/next\r", &mut in_block), " next\r");
        assert!(!in_block);
        assert_eq!(
            strip_command_comments("'unterminated # //", &mut in_block),
            "'unterminated # //"
        );
    }

    #[test]
    fn preserves_rule_major_order_and_selective_configuration_across_files() {
        let source = r#"// TODO: clean up
// FIXME: incorrect
if (value == value) {}
Process.run('unsafe command', []);
final timeout = 10000000;
final values = [1,2,3,4,5,6,7,8,9,10,11,12,13,14];
if (ready) return true;
return false;
"#;
        let sources = sources(&[("z.dart", source), ("a.dart", source)]);
        let all = analyze(&sources, &config());
        let expected_order = RULE_ORDER
            .iter()
            .enumerate()
            .flat_map(|(index, code)| {
                ["a.dart", "z.dart"]
                    .into_iter()
                    .map(move |path| (*code, path, index + 1))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            all.iter()
                .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            expected_order
        );

        for selection in 0usize..(1 << RULE_ORDER.len()) {
            let mut selected_config = config();
            selected_config.rule_groups.clear();
            selected_config.rule_groups.insert("core".into());
            for (index, code) in RULE_ORDER.iter().enumerate() {
                if selection & (1 << index) != 0 {
                    selected_config
                        .severity_overrides
                        .insert((*code).into(), "warn".into());
                }
            }
            let expected = all
                .iter()
                .filter(|finding| selected_config.severity_overrides.contains_key(&finding.code))
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(analyze(&sources, &selected_config), expected, "{selection}");
        }
    }

    #[test]
    fn preserves_consumer_specific_rust_test_comment_state_and_file_isolation() {
        let findings = analyze(
            &sources(&[
                (
                    "a.rs",
                    r##"#[test]
fn skipped() {
    let text = r#"
/*
"#;
}
fn production() {
    let values = [0,1,2,3,4,5,6,7,8,9,10,11,12];
    if (value == value) {}
}
"##,
                ),
                (
                    "b.rs",
                    r##"const TEXT: &str = r#"
/*
"#;
#[test]
fn skipped() {
    let text = r#"
*/
"#;
}
fn production() {
    let values = [0,1,2,3,4,5,6,7,8,9,10,11,12];
    if (value == value) {}
}
"##,
                ),
                (
                    "c.ts",
                    "const text = '/*'; if (value == value) {}\nconst values = [0,1,2,3,4,5,6,7,8,9,10,11,12];",
                ),
            ]),
            &config(),
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("operation-on-same-value", "b.rs", 12),
                ("operation-on-same-value", "c.ts", 1),
                ("large-inline-list", "a.rs", 8),
                ("large-inline-list", "c.ts", 2),
            ]
        );
    }

    #[test]
    fn preserves_boolean_return_whitespace_exposed_by_string_removal() {
        let findings = analyze(
            &sources(&[(
                "source.dart",
                r#"if (ready) return true;
  "" return false;
if (ready) return true;
  return "false";
if (ready) return true;
  return false;
if (ready) return true;
  "prefix"return false;
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
            vec![5, 7]
        );
    }

    #[test]
    fn preserves_command_comment_state_and_collection_thresholds() {
        let findings = analyze(
            &sources(&[
                (
                    "branches.cpp",
                    "\u{2003}#if 0\r\nconst hidden = 10000000;\r\n#if 1\r\nconst nested = 20000000;\r\n#endif\r\n#else\r\nconst active = 30000000;\r\n#endif\r\n",
                ),
                (
                    "collections.ts",
                    r#"const below = [0,1,2,3,4,5,6,7,8,9,10,11];
const edge = [0,1,2,3,4,5,6,7,8,9,10,11,12];
const first = [0,1,2,3,4,5,6]; const second = [7,8,9,10,11,12,13];
const quoted = ["é,,,,,,,,,,,,"];
/*
const hidden = [0,1,2,3,4,5,6,7,8,9,10,11,12];
*/const later = [0,1,2,3,4,5,6,7,8,9,10,11,12];
"#,
                ),
                (
                    "commands.py",
                    r#"subprocess.run("outside task")
/*
subprocess.run("inside task")
*/
message = "é /* quoted marker */ # slash //"
subprocess.run("after task")
subprocess.run/* intervening comment */("separated task")
subprocess.run(["ok", "separate arg"])
# subprocess.run("comment task")
subprocess.run("tool task".split())
"#,
                ),
            ]),
            &config(),
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "suspicious-command-arg-space"
                            | "large-number-ungrouped"
                            | "large-inline-list"
                    )
                })
                .map(|finding| (finding.code.as_str(), finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("suspicious-command-arg-space", "commands.py", 1),
                ("suspicious-command-arg-space", "commands.py", 6),
                ("suspicious-command-arg-space", "commands.py", 7),
                ("large-number-ungrouped", "branches.cpp", 7),
                ("large-inline-list", "collections.ts", 2),
                ("large-inline-list", "collections.ts", 7),
            ]
        );
    }

    #[test]
    fn preserves_numeric_masks_across_utf8_spans_and_multiline_state() {
        let source = [
            "var plain = 10000000;",
            r#"var 模型 = 20000000 / 2; var text = r"hidden 30000000";"#,
            r#"var block = r""""#,
            "hidden = 40000000;",
            r#""""; var after = 50000000;"#,
            r#"var literal = "escaped \" 60000000"; var tail = 70000000;"#,
            "/* comment",
            "still inside the comment",
            "hidden = 80000000;",
            "*/ var resumed = 90000000;",
            "var finalValue = 11000000; // 12000000",
            "",
        ]
        .join("\r\n");
        let findings = analyze(&sources(&[("numeric.dart", &source)]), &config());
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("numeric.dart", 1),
                ("numeric.dart", 2),
                ("numeric.dart", 5),
                ("numeric.dart", 6),
                ("numeric.dart", 10),
                ("numeric.dart", 11),
            ]
        );
    }

    #[test]
    fn excludes_nested_dart_numeric_comments_without_hiding_following_code() {
        let nested = [
            "var before = 10000000;",
            "/* outer é",
            "/* inner",
            "hidden = 20000000;",
            "*/",
            "hidden = 30000000;",
            "/* sibling */",
            "hidden = 40000000;",
            "*/ var after = 50000000;",
            r#"var raw = r"/* 60000000 */";"#,
            r#"var quoted = "/* 70000000 */";"#,
            r#"var multiline = r""""#,
            "/* literal 80000000 */",
            r#"""";"#,
            "// /* ignored opener",
            "var next = 90000000;",
            "",
        ]
        .join("\r\n");
        let findings = analyze(
            &sources(&[
                ("nested.dart", &nested),
                (
                    "inline.dart",
                    "/* outer /* inner */ hidden = 12345678; */ var small = 1;\n",
                ),
                (
                    "unterminated.dart",
                    "/* outer /* inner */\nhidden = 12345678;\n",
                ),
                (
                    "unchanged.js",
                    "/* outer\n/* inner */\nconst live = 12345678;\n",
                ),
                ("z_after.dart", "var live = 12345678;\n"),
            ]),
            &config(),
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "large-number-ungrouped")
                .map(|finding| {
                    (finding.path.as_str(), finding.line, finding.confidence.as_str())
                })
                .collect::<Vec<_>>(),
            vec![
                ("nested.dart", 1, "high"),
                ("nested.dart", 9, "high"),
                ("nested.dart", 16, "high"),
                ("unchanged.js", 3, "high"),
                ("z_after.dart", 1, "high"),
            ]
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
