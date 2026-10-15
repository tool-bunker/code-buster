use std::fs;
use std::path::Path;

use crate::cli::PreviewOptions;
use crate::summary_command;

pub enum FixOutcome {
    Success,
    Empty,
}

pub fn execute(options: &PreviewOptions) -> Result<FixOutcome, String> {
    let run = summary_command::analyze(options)?;
    if run.prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(FixOutcome::Empty);
    }
    let root = Path::new(&run.prepared.root);
    let mut changed = Vec::new();
    for source_file in &run.prepared.files {
        let path = root.join(source_file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let before = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let after = fixed_content(&before, &source_file.path);
        if before == after {
            continue;
        }
        if !options.dry_run {
            fs::write(&path, after)
                .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
        }
        changed.push(source_file.path.as_str());
    }
    for path in &changed {
        println!(
            "{} {path}",
            if options.dry_run {
                "would fix"
            } else {
                "fixed"
            }
        );
    }
    if changed.is_empty() {
        println!("no safe fixes needed");
    } else {
        println!(
            "{} file(s) {}",
            changed.len(),
            if options.dry_run {
                "would change"
            } else {
                "changed"
            }
        );
    }
    Ok(FixOutcome::Success)
}

pub(crate) fn fixed_content(source: &str, path: &str) -> String {
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let has_final_newline = source.ends_with(newline);
    let mut lines = source.split(newline).collect::<Vec<_>>();
    if has_final_newline {
        lines.pop();
    }
    let fix_nim_imports = path.ends_with(".nim") || path.ends_with(".nims");
    let mut multiline_delimiter = None;
    let mut output = Vec::with_capacity(lines.len());
    for raw_line in lines {
        let plan = line_fix_policy(raw_line, multiline_delimiter, fix_nim_imports);
        let (line, next_delimiter) =
            apply_line_fixes(raw_line.to_owned(), plan, multiline_delimiter);
        output.push(line);
        multiline_delimiter = next_delimiter;
    }
    let mut result = output.join(newline);
    if has_final_newline {
        result.push_str(newline);
    }
    result
}

#[derive(Clone, Copy, Default)]
struct FixCandidates {
    indentation_end: Option<usize>,
    trim_trailing_whitespace: bool,
    fix_nim_import: bool,
}

#[derive(Clone, Copy)]
enum DelimiterPolicy {
    Preserve,
    Detect,
    Clear,
}

#[derive(Clone, Copy)]
struct LineFixPlan {
    candidates: FixCandidates,
    delimiter_policy: DelimiterPolicy,
}

fn select_fix_candidates(line: &str, fix_nim_import: bool) -> FixCandidates {
    let indentation = indentation_end(line);
    FixCandidates {
        indentation_end: line.as_bytes()[..indentation]
            .contains(&b'\t')
            .then_some(indentation),
        trim_trailing_whitespace: true,
        fix_nim_import,
    }
}

fn line_fix_policy(
    line: &str,
    multiline_delimiter: Option<&'static str>,
    fix_nim_import: bool,
) -> LineFixPlan {
    match multiline_delimiter {
        None => LineFixPlan {
            candidates: select_fix_candidates(line, fix_nim_import),
            delimiter_policy: DelimiterPolicy::Detect,
        },
        Some(delimiter) if line.contains(delimiter) => LineFixPlan {
            candidates: FixCandidates {
                trim_trailing_whitespace: true,
                ..FixCandidates::default()
            },
            delimiter_policy: DelimiterPolicy::Clear,
        },
        Some(_) => LineFixPlan {
            candidates: FixCandidates::default(),
            delimiter_policy: DelimiterPolicy::Preserve,
        },
    }
}

fn apply_line_fixes(
    mut line: String,
    plan: LineFixPlan,
    multiline_delimiter: Option<&'static str>,
) -> (String, Option<&'static str>) {
    if let Some(indentation) = plan.candidates.indentation_end {
        let prefix = line[..indentation].replace('\t', "  ");
        line.replace_range(..indentation, &prefix);
    }
    if plan.candidates.trim_trailing_whitespace {
        trim_trailing_whitespace(&mut line);
    }
    if plan.candidates.fix_nim_import {
        line = fix_nim_std_import(line);
    }
    let next_delimiter = match plan.delimiter_policy {
        DelimiterPolicy::Preserve => multiline_delimiter,
        DelimiterPolicy::Detect => opening_delimiter(&line),
        DelimiterPolicy::Clear => None,
    };
    (line, next_delimiter)
}

fn indentation_end(line: &str) -> usize {
    line.bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()
}

fn trim_trailing_whitespace(line: &mut String) {
    let trimmed = line.trim_end_matches([' ', '\t']).len();
    line.truncate(trimmed);
}

fn fix_nim_std_import(line: String) -> String {
    let indentation = indentation_end(&line);
    let prefix = &line[..indentation];
    let trimmed = line.trim();
    if trimmed == "import os" {
        format!("{prefix}import std/os")
    } else if let Some(rest) = trimmed.strip_prefix("from os import") {
        format!("{prefix}from std/os import{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("import os,") {
        format!("{prefix}import std/os,{rest}")
    } else {
        line
    }
}

fn opening_delimiter(line: &str) -> Option<&'static str> {
    let double_index = line.find("\"\"\"");
    let single_index = line.find("'''");
    let delimiter = match (double_index, single_index) {
        (None, None) => return None,
        (Some(_), None) => "\"\"\"",
        (None, Some(_)) => "'''",
        (Some(double), Some(single)) if double < single => "\"\"\"",
        (Some(_), Some(_)) => "'''",
    };
    (line.matches(delimiter).count() % 2 == 1).then_some(delimiter)
}

#[cfg(test)]
mod tests {
    use super::fixed_content;

    #[test]
    fn fixes_only_safe_whitespace_outside_dart_multiline_strings() {
        let source =
            "\tvoid main() { print(\"left\\tmiddle\"); }  \nfinal text = '''\n\tkeep  \n''';  \n";
        assert_eq!(
            fixed_content(source, "lib/main.dart"),
            "  void main() { print(\"left\\tmiddle\"); }\nfinal text = '''\n\tkeep  \n''';\n"
        );
    }

    #[test]
    fn preserves_crlf_and_updates_nim_os_imports() {
        assert_eq!(
            fixed_content("\timport os  \r\n", "main.nim"),
            "  import std/os\r\n"
        );
    }
}
