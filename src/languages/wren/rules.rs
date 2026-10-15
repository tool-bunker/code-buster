use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".wren"))
    {
        analyze_file(path, source, &mut findings);
    }
    findings
}

fn analyze_file(path: &str, source: &str, findings: &mut Vec<Finding>) {
    let mut loop_depth = 0usize;
    for (index, raw) in source.split('\n').enumerate() {
        let code = DOUBLE_QUOTED.replace_all(raw, "");
        let line = code.trim();
        update_loop_depth(line, &mut loop_depth);
        analyze_line(path, raw, line, index + 1, loop_depth, findings);
    }
}

fn update_loop_depth(line: &str, loop_depth: &mut usize) {
    if line.starts_with("for (") || line.starts_with("while (") {
        *loop_depth += 1;
    }
    if line == "}" && *loop_depth > 0 {
        *loop_depth -= 1;
    }
}

fn analyze_line(
    path: &str,
    raw: &str,
    line: &str,
    line_number: usize,
    loop_depth: usize,
    findings: &mut Vec<Finding>,
) {
    report_system_print(path, line, line_number, findings);
    report_loop_output(path, line, line_number, loop_depth, findings);
    report_fiber_abort(path, line, line_number, findings);
    report_foreign_boundary(path, line, line_number, findings);
    report_fiber_call(path, line, line_number, findings);
    report_broad_import(path, line, line_number, findings);
    report_inheritance(path, line, line_number, findings);
    report_unchecked_number_parse(path, raw, line, line_number, findings);
}

fn report_system_print(path: &str, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if line.contains("System.print(") {
        findings.push(finding(
            "wren-system-print",
            path,
            line_number,
            "System.print call left in code",
        ));
    }
}

fn report_loop_output(
    path: &str,
    line: &str,
    line_number: usize,
    loop_depth: usize,
    findings: &mut Vec<Finding>,
) {
    if loop_depth > 0 && (line.contains("System.print(") || line.contains("System.write(")) {
        findings.push(finding(
            "wren-print-in-loop",
            path,
            line_number,
            "console output inside loop",
        ));
    }
}

fn report_fiber_abort(path: &str, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if line.contains("Fiber.abort(") {
        findings.push(finding(
            "wren-fiber-abort",
            path,
            line_number,
            "Fiber.abort terminates the current fiber",
        ));
    }
}

fn report_foreign_boundary(
    path: &str,
    line: &str,
    line_number: usize,
    findings: &mut Vec<Finding>,
) {
    if line.starts_with("foreign ") {
        findings.push(finding(
            "wren-foreign-boundary",
            path,
            line_number,
            "foreign API boundary declared",
        ));
    }
}

fn report_fiber_call(path: &str, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if line.contains(".call(") && (line.contains("Fiber") || line.contains("fiber")) {
        findings.push(finding(
            "wren-fiber-call",
            path,
            line_number,
            "fiber resumed directly with call",
        ));
    }
}

fn report_broad_import(path: &str, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if line.starts_with("import ") && line.contains(" for ") && line.matches(',').count() >= 8 {
        findings.push(finding(
            "wren-broad-import",
            path,
            line_number,
            "broad Wren import list",
        ));
    }
}

fn report_inheritance(path: &str, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
    if line.starts_with("class ") && line.contains(" is ") {
        findings.push(finding(
            "wren-inheritance",
            path,
            line_number,
            "class inheritance used",
        ));
    }
}

fn report_unchecked_number_parse(
    path: &str,
    raw: &str,
    line: &str,
    line_number: usize,
    findings: &mut Vec<Finding>,
) {
    if line.contains("Num.fromString(") && !raw.to_ascii_lowercase().contains("null") {
        findings.push(finding(
            "wren-number-parse-unchecked",
            path,
            line_number,
            "Num.fromString result may be unchecked",
        ));
    }
}

fn finding(code: &str, path: &str, line: usize, message: &str) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Wren rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static DOUBLE_QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:\\.|[^"\\])*""#).unwrap());

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::analyze;
    use crate::source_analysis_context::SourceAnalysisContext;

    #[test]
    fn reports_every_wren_rule_with_original_contracts() {
        let sources = BTreeMap::from([(
            "main.wren".to_owned(),
            "import \"module\" for A, B, C, D, E, F, G, H, I\n\
class Main is Base {\n\
  foreign static nativeCall()\n\
  run(fiber) {\n\
    while (true) {\n\
      System.print(\"tick\")\n\
      System.write(\".\")\n\
    }\n\
    fiber.call()\n\
    var value = Num.fromString(input)\n\
    Fiber.abort(\"stop\")\n\
  }\n\
}"
            .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context);
        let codes = findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            codes,
            BTreeSet::from([
                "wren-broad-import",
                "wren-fiber-abort",
                "wren-fiber-call",
                "wren-foreign-boundary",
                "wren-inheritance",
                "wren-number-parse-unchecked",
                "wren-print-in-loop",
                "wren-system-print",
            ])
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "wren-print-in-loop")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![6, 7]
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.end_line == finding.line)
        );
    }

    #[test]
    fn ignores_patterns_inside_strings_and_accepts_same_line_null_checks() {
        let sources = BTreeMap::from([(
            "safe.wren".to_owned(),
            "var text = \"System.print( Fiber.abort( Num.fromString(\"\n\
var parsed = Num.fromString(input) // null is handled by the caller\n\
System.print(\"outside loop\")"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "wren-system-print");
        assert_eq!(findings[0].line, 3);
    }
}
