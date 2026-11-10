use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use tokei::{CodeStats, Config, LanguageType};

use crate::discovery::{PreparedPreview, SourceFile};
use crate::source_analysis_context::mask_test_regions;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SourceMetrics<'a> {
    schema_version: u32,
    code_lines: usize,
    file_code_lines: BTreeMap<&'a str, usize>,
}

pub(super) fn measure(prepared: &PreparedPreview) -> Result<SourceMetrics<'_>, String> {
    let config = Config::default();
    let mut file_code_lines = BTreeMap::new();
    for file in &prepared.files {
        let source = prepared
            .sources
            .get(&file.path)
            .ok_or_else(|| format!("cannot measure selected source file: {}", file.path))?;
        file_code_lines.insert(file.path.as_str(), measure_file(file, source, &config)?);
    }
    Ok(SourceMetrics {
        schema_version: 1,
        code_lines: file_code_lines.values().sum(),
        file_code_lines,
    })
}

fn measure_file(file: &SourceFile, source: &str, config: &Config) -> Result<usize, String> {
    let source = mask_test_regions(&file.path, source);
    match crate::languages::canonical_name(&file.language) {
        Some("wren") => return Ok(crate::languages::wren::code_lines(source.as_ref())),
        Some("nim") => return Ok(crate::languages::nim::code_lines(source.as_ref())),
        _ => {}
    }
    let language = counting_language(file)
        .ok_or_else(|| format!("cannot measure source language: {}", file.language))?;
    let stats = language.parse_from_str(source.as_ref(), config);
    // Rust's embedded blobs are documentation examples, not production code.
    // String literals remain code; in Python that includes runtime docstrings.
    Ok(if language == LanguageType::Rust {
        stats.code
    } else {
        code_lines_with_embedded(&stats)
    })
}

fn code_lines_with_embedded(stats: &CodeStats) -> usize {
    stats.code
        + stats
            .blobs
            .values()
            .map(code_lines_with_embedded)
            .sum::<usize>()
}

fn counting_language(file: &SourceFile) -> Option<LanguageType> {
    if let Some(extension) = Path::new(&file.path)
        .extension()
        .and_then(|ext| ext.to_str())
    {
        if let Some(language) = LanguageType::from_file_extension(extension) {
            return Some(language);
        }
        if let Some((language, _)) = LanguageType::list().iter().find(|(_, extensions)| {
            extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        }) {
            return Some(*language);
        }
    }
    // Keep discovery's selected language for extensionless shell and extensions
    // Tokei does not know (for example .nims and CB's existing Go .mod selection).
    let canonical = crate::languages::canonical_name(&file.language)?;
    let name = match canonical {
        "cpp" => "C++",
        "csharp" => "C#",
        language => language,
    };
    LanguageType::list()
        .iter()
        .map(|(language, _)| *language)
        .find(|language| language.name().eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::prepare;
    use crate::options::PreviewOptions;
    use serde_json::json;
    use std::fs;

    fn metrics_for(files: &[(&str, &str)]) -> serde_json::Value {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("code-buster.toml"),
            "languages = [\"auto\"]\n",
        )
        .unwrap();
        for (path, source) in files {
            let path = root.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        let options = PreviewOptions {
            root: root.path().to_path_buf(),
            ..PreviewOptions::default()
        };
        let prepared = prepare(&options).unwrap();
        serde_json::to_value(measure(&prepared).unwrap()).unwrap()
    }

    #[test]
    fn measures_selected_sources_including_empty_and_comment_only_files() {
        let metrics = metrics_for(&[
            ("src/main.rs", "// comment\nfn main() {}\n\n"),
            ("src/empty.py", ""),
            (
                "src/comments.js",
                "/* explanatory comment\n * no code */\n// comment\n",
            ),
            ("README.md", "This is not a selected source file.\n"),
            ("tests/fixture.rs", "fn excluded_fixture() {}\n"),
        ]);
        assert_eq!(
            metrics,
            json!({
                "schemaVersion": 1,
                "codeLines": 1,
                "fileCodeLines": {
                    "src/main.rs": 1,
                    "src/empty.py": 0,
                    "src/comments.js": 0,
                },
            })
        );
    }

    #[test]
    fn excludes_canonical_inline_tests_and_rust_doc_examples() {
        let metrics = metrics_for(&[(
            "src/lib.rs",
            "/// Example:\n/// ```rust\n/// let example = 1;\n/// ```\npub fn production() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn fixture() { let sample = 1; }\n}\n",
        )]);
        assert_eq!(metrics["fileCodeLines"]["src/lib.rs"], 1);
        assert_eq!(metrics["codeLines"], 1);
    }

    #[test]
    fn preserves_python_string_literals_and_excludes_embedded_test_data() {
        let metrics = metrics_for(&[(
            "src/main.py",
            "\"\"\"Module documentation.\nStill a runtime string.\n\"\"\"\nQUERY = \"\"\"\nSELECT 1\n\"\"\"\nclass Extractor:\n    _TESTS = [{\n        'value': 123,\n    }]\n    def production(self):\n        \"\"\"Method documentation.\"\"\"\n        return QUERY\n",
        )]);
        assert_eq!(metrics["fileCodeLines"]["src/main.py"], 10);
        assert_eq!(metrics["codeLines"], 10);
    }

    #[test]
    fn assigned_multiline_python_strings_are_measured_source() {
        let metrics = metrics_for(&[("query.py", "QUERY = \"\"\"\nSELECT 1\n\"\"\"\n")]);
        assert_eq!(metrics["fileCodeLines"]["query.py"], 3);
        assert_eq!(metrics["codeLines"], 3);
    }

    #[test]
    fn includes_embedded_html_and_svelte_script_and_style_code() {
        let source = "<script>\n// comment\nconst value = 1;\n</script>\n<style>\n/* comment */\nh1 { color: red; }\n</style>\n<h1>Hello</h1>\n";
        for language in [LanguageType::Html, LanguageType::Svelte] {
            let config = Config::default();
            let stats = language.parse_from_str(source, &config);
            assert!(code_lines_with_embedded(&stats) > stats.code);
            assert_eq!(code_lines_with_embedded(&stats), 7);
        }
        let metrics = metrics_for(&[("src/view.html", source), ("src/view.svelte", source)]);
        assert_eq!(metrics["fileCodeLines"]["src/view.html"], 7);
        assert_eq!(metrics["fileCodeLines"]["src/view.svelte"], 7);
        assert_eq!(metrics["codeLines"], 14);
    }

    #[test]
    fn measures_discovery_languages_without_a_direct_counter_extension() {
        let metrics = metrics_for(&[
            ("src/script.nims", "# comment\nlet value = 1\n"),
            ("go.mod", "// comment\nmodule example.org/example\n"),
            ("scripts/run", "#!/bin/sh\n# comment\necho ready\n"),
            (
                "src/main.wren",
                "// comment\nvar value = \"not // a comment\"\n",
            ),
        ]);
        assert_eq!(metrics["fileCodeLines"]["src/script.nims"], 1);
        assert_eq!(metrics["fileCodeLines"]["go.mod"], 1);
        assert_eq!(metrics["fileCodeLines"]["scripts/run"], 1);
        assert_eq!(metrics["fileCodeLines"]["src/main.wren"], 1);
        assert_eq!(metrics["codeLines"], 4);
    }

    #[test]
    fn excludes_nested_nim_comment_blocks_without_erasing_literals() {
        let metrics = metrics_for(&[(
            "src/main.nim",
            "##[\ndocumentation\n#[ nested comment ]#\n]##\necho \"#[ literal ]#\"\n",
        )]);
        assert_eq!(metrics["fileCodeLines"]["src/main.nim"], 1);
        assert_eq!(metrics["codeLines"], 1);
    }
}
