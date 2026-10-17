use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context.sources() {
        if path.ends_with(".sql") || !SUPPORTED_PATH.is_match(path) {
            continue;
        }
        let lines = sql_source_lines(path, source);
        for index in 0..lines.len() {
            if reportable_dynamic_sql(&lines, index, source) {
                findings.push(finding(path, index + 1));
            }
        }
    }
    findings
}

fn sql_source_lines(path: &str, source: &str) -> Vec<String> {
    let masked = mask_embedded_source_fixtures(path, source);
    let mut lines = Vec::new();
    let mut in_block_comment = false;
    for original in masked.split('\n') {
        let (line, next_state) = strip_block_comments(original, in_block_comment);
        in_block_comment = next_state;
        lines.push(line);
    }
    lines
}

fn reportable_dynamic_sql(lines: &[String], index: usize, source: &str) -> bool {
    let line = &lines[index];
    if ignored_sql_line(line) {
        return false;
    }
    let Some(statement) = SQL_STATEMENT.find(line) else {
        return false;
    };
    if statement_uses_bound_from(line, &statement) || is_management_object_query(lines, index) {
        return false;
    }
    has_unsafe_dynamic_sql(line, lines, index, source) && is_sql_construction_context(lines, index)
}

fn ignored_sql_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*')
}

fn statement_uses_bound_from(line: &str, statement: &regex::Match<'_>) -> bool {
    statement.as_str().to_ascii_lowercase().ends_with("from")
        && line[statement.end()..].trim_start().starts_with(':')
}

fn has_unsafe_dynamic_sql(line: &str, lines: &[String], index: usize, source: &str) -> bool {
    let concatenated = line.contains('+') && is_concatenated_sql(line);
    let interpolated = JS_INTERPOLATION.is_match(line) || is_csharp_interpolated(line);
    concatenated
        || (interpolated
            && !has_safe_sql_interpolation(line, lines, index, source)
            && !is_ef_core_parameterized_interpolation(lines, index))
}

fn has_safe_sql_interpolation(line: &str, lines: &[String], index: usize, source: &str) -> bool {
    (line.contains("sql") && SQL_TAG.is_match(line))
        || only_safe_sql_interpolation(line, source)
        || only_safe_csharp_numeric_interpolation(line, lines, index)
}

fn strip_block_comments(line: &str, mut in_block: bool) -> (String, bool) {
    let mut result = String::new();
    let mut index = 0usize;
    while index < line.len() {
        if in_block {
            if let Some(relative) = line[index..].find("*/") {
                index += relative + 2;
                in_block = false;
            } else {
                return (result, true);
            }
        } else if let Some(relative) = line[index..].find("/*") {
            let start = index + relative;
            result.push_str(&line[index..start]);
            index = start + 2;
            in_block = true;
            result.push(' ');
        } else {
            result.push_str(&line[index..]);
            break;
        }
    }
    (result, in_block)
}

fn mask_embedded_source_fixtures(path: &str, source: &str) -> String {
    if !path.to_ascii_lowercase().ends_with(".dart") {
        return source.to_owned();
    }
    let mut masked = source.as_bytes().to_vec();
    for opening in EMBEDDED_FIXTURE.captures_iter(source) {
        let quote = opening.name("quote").unwrap();
        let content_start = quote.end();
        let Some(relative_end) = source[content_start..].find(quote.as_str()) else {
            continue;
        };
        let content_end = content_start + relative_end;
        for byte in &mut masked[content_start..content_end] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(masked).expect("masking ASCII fixture bytes preserves UTF-8")
}

fn is_concatenated_sql(line: &str) -> bool {
    STRING_THEN_VALUE.is_match(line) || VALUE_THEN_STRING.is_match(line)
}

fn is_sql_construction_context(lines: &[String], index: usize) -> bool {
    let line = &lines[index];
    if EXECUTION.is_match(line) {
        return true;
    }
    if let Some(assignment) = ASSIGNMENT.captures(line) {
        let variable = assignment.get(1).unwrap().as_str().to_ascii_lowercase();
        let sql_storage = variable.contains("query") || variable.contains("sql");
        let diagnostic = variable.contains("error")
            || variable.contains("message")
            || variable.contains("label");
        if sql_storage && !diagnostic {
            return true;
        }
    }
    index > 0 && CONTINUATION.is_match(line) && EXECUTION.is_match(&lines[index - 1])
}

// code-buster-ignore complex-function: forward data-flow stops at first use or reassignment and must retain scan order.
fn is_management_object_query(lines: &[String], index: usize) -> bool {
    let line = &lines[index];
    if SEARCHER_CALL.is_match(line) || (index > 0 && SEARCHER_CALL.is_match(&lines[index - 1])) {
        return true;
    }
    let Some(assignment) = SIMPLE_ASSIGNMENT.captures(line) else {
        return false;
    };
    let variable = assignment.get(1).unwrap().as_str();
    let lower = variable.to_ascii_lowercase();
    if (lower.contains("wmi") || lower.contains("cim")) && lower.contains("query") {
        return true;
    }
    let reference = Regex::new(&format!(r"\b{}\b", regex::escape(variable))).unwrap();
    let reassignment = Regex::new(&format!(r"\b{}\s*=", regex::escape(variable))).unwrap();
    for candidate in lines.iter().skip(index + 1) {
        if !candidate.trim_start().starts_with("//")
            && SEARCHER_CALL.is_match(candidate)
            && reference.is_match(candidate)
        {
            return true;
        }
        if reassignment.is_match(candidate) {
            return false;
        }
    }
    false
}

fn only_safe_sql_interpolation(line: &str, source: &str) -> bool {
    let mut found_expression = false;
    for capture in JS_INTERPOLATION.captures_iter(line) {
        let Some(expression) = capture.get(1) else {
            continue;
        };
        found_expression = true;
        let expression = expression.as_str().trim();
        if PARAMETER_PLACEHOLDER_FACTORY.is_match(expression) {
            continue;
        }
        if !IDENTIFIER.is_match(expression) {
            return false;
        }
        if is_static_numeric_constant(expression, source)
            || is_allowlisted_sql_identifier(expression, source)
        {
            continue;
        }
        let Ok(declaration) = Regex::new(&format!(
            r"\b(?:const|let|var)\s+{}\s*=\s*([^;\n]+)",
            regex::escape(expression)
        )) else {
            return false;
        };
        if declaration
            .captures(source)
            .and_then(|capture| capture.get(1))
            .is_none_or(|value| !PARAMETER_PLACEHOLDER_FACTORY.is_match(value.as_str().trim()))
        {
            return false;
        }
    }
    found_expression
}

fn is_static_numeric_constant(expression: &str, source: &str) -> bool {
    Regex::new(&format!(
        r"\bconst\s+{}\s*=\s*[0-9][0-9_]*(?:\.[0-9_]+)?\s*;",
        regex::escape(expression)
    ))
    .unwrap()
    .is_match(source)
}

fn is_allowlisted_sql_identifier(expression: &str, source: &str) -> bool {
    let loop_pattern = Regex::new(&format!(
        r"\bfor\s*\(\s*const\s+{}\s+of\s+([A-Za-z_$][\w$]*)\s*\)",
        regex::escape(expression)
    ))
    .unwrap();
    let Some(list_name) = loop_pattern
        .captures(source)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str())
    else {
        return false;
    };
    let declaration = Regex::new(&format!(
        r"(?s)\bconst\s+{}\s*=\s*\[(.*?)\]\s+as\s+const",
        regex::escape(list_name)
    ))
    .unwrap();
    let Some(values) = declaration
        .captures(source)
        .and_then(|capture| capture.get(1))
    else {
        return false;
    };
    let values = values
        .as_str()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    !values.is_empty() && values.into_iter().all(is_quoted_literal)
}

fn is_quoted_literal(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2
        && matches!(bytes[0], b'\'' | b'"')
        && bytes[bytes.len() - 1] == bytes[0]
        && !value[1..value.len() - 1].contains(['\'', '"'])
}

fn is_csharp_interpolated(line: &str) -> bool {
    CSHARP_INTERPOLATED.is_match(line) && csharp_expressions(line).next().is_some()
}

fn csharp_expressions(line: &str) -> impl Iterator<Item = &str> {
    CSHARP_EXPRESSION
        .captures_iter(line)
        .filter_map(move |capture| {
            let whole = capture.get(0)?;
            let bytes = line.as_bytes();
            if (whole.start() > 0 && bytes[whole.start() - 1] == b'{')
                || (whole.end() < bytes.len() && bytes[whole.end()] == b'}')
            {
                None
            } else {
                capture.get(1).map(|value| value.as_str())
            }
        })
}

fn only_safe_csharp_numeric_interpolation(line: &str, lines: &[String], index: usize) -> bool {
    if !CSHARP_INTERPOLATED.is_match(line) {
        return false;
    }
    let expressions = csharp_expressions(line).collect::<Vec<_>>();
    if expressions.is_empty() {
        return false;
    }
    expressions.into_iter().all(|expression| {
        let expression = expression.trim();
        if NUMERIC_CAST.is_match(expression) {
            return true;
        }
        if !SIMPLE_IDENTIFIER.is_match(expression) {
            return false;
        }
        let name = regex::escape(expression);
        let Ok(typed) = Regex::new(&format!(
            r"\b(?:const\s+)?(?:s?byte|u?short|u?int|u?long|float|double|decimal)\s+{name}\b"
        )) else {
            return false;
        };
        let Ok(inferred) = Regex::new(&format!(r"\bvar\s+{name}\s*=\s*([^;]+)")) else {
            return false;
        };
        let first = index.saturating_sub(80);
        for declaration in lines[first..index].iter().rev() {
            if typed.is_match(declaration) {
                return true;
            }
            if let Some(value) = inferred
                .captures(declaration)
                .and_then(|capture| capture.get(1))
            {
                let value = value.as_str().trim();
                return NUMERIC_LITERAL.is_match(value) || value.contains(".Ticks");
            }
        }
        false
    })
}

fn is_ef_core_parameterized_interpolation(lines: &[String], index: usize) -> bool {
    let start = index.saturating_sub(1);
    EF_INTERPOLATED.is_match(&lines[start..=index].join(" "))
}

fn finding(path: &str, line: usize) -> Finding {
    let metadata = rule_catalog::metadata("sql-inline-string-concat")
        .expect("SQL inline construction metadata must exist");
    Finding {
        code: metadata.id.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("SQL inline construction severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: "inline SQL appears dynamically concatenated or interpolated".to_owned(),
        confidence: "medium".to_owned(),
        why: "String-built SQL can introduce injection and quoting bugs.".to_owned(),
        suggestion: "Use parameter placeholders and pass values separately.".to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static SUPPORTED_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(?:dart|java|kt|kts|cs|js|jsx|mjs|cjs|ts|tsx|py|rb|php|go)$").unwrap()
});
static SQL_STATEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:select\s+.+\s+from\b|insert\s+into|update\s+.+\s+set|delete\s+from)\b")
        .unwrap()
});
static SQL_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bsql\s*`").unwrap());
static STRING_THEN_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\"'][^\"']*(?:select|insert|update|delete)[^\"']*[\"']\s*\+\s*[A-Za-z_]\w*"#)
        .unwrap()
});
static VALUE_THEN_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b\w[\w.()]*\s*\+\s*[\"'][^\"']*(?:select|insert|update|delete)"#).unwrap()
});
static EXECUTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:execute|exec|query|prepare|raw)\w*\s*\(").unwrap());
static ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=").unwrap());
static SIMPLE_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*)\s*=").unwrap());
static CONTINUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*(?:[\"'`]|\$\")"#).unwrap());
static SEARCHER_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:ManagementObjectSearcher|QueryInstances)\s*\(").unwrap());
static JS_INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{([^}]*)\}").unwrap());
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*$").unwrap());
static SIMPLE_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());
static PARAMETER_PLACEHOLDER_FACTORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:[A-Za-z_$][\w$]*\.map\(\s*\(\s*\)\s*=>\s*[\"']\?[\"']\s*\)|new\s+Array\([^)]*\)\.fill\(\s*[\"']\?[\"']\s*\))\.join\(\s*[\"'],[\"']\s*\)$"#).unwrap()
});
static CSHARP_INTERPOLATED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:\$@?\"|@\$\")"#).unwrap());
static CSHARP_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{([^{}]+)\}").unwrap());
static NUMERIC_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\((?:s?byte|u?short|u?int|u?long|float|double|decimal)\)\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$").unwrap()
});
static NUMERIC_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[+-]?\d[\d_]*(?:\.\d[\d_]*)?[fFdDmMuUlL]*$").unwrap());
static EF_INTERPOLATED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bExecuteSqlInterpolated(?:Async)?\s*\(").unwrap());
static EMBEDDED_FIXTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\"'][^\"'\r\n]+\.(?:cs|java|kt|kts|js|jsx|mjs|cjs|ts|tsx|py|rb|php|go)[\"']\s*:\s*r?(?P<quote>'''|\"\"\")"#).unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn reports_interpolated_sql_assignments() {
        let fixture = Fixture::new([(
            "query.dart",
            "final query = \"SELECT name FROM users WHERE id = ${id}\";",
        )]);
        let findings = analyze(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "sql-inline-string-concat");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn ignores_static_comments_non_source_and_management_queries() {
        let fixture = Fixture::new([
            (
                "parser.dart",
                "final sql = 'UPDATE x SET value = value + 1 RETURNING *';",
            ),
            (
                "prototype.html",
                "<span>`SELECT * FROM users WHERE id = ${userId}`</span>",
            ),
            (
                "disabled.dart",
                "/* final sql = \"SELECT * FROM users WHERE id = ${id}\"; */",
            ),
            (
                "commented.ts",
                "// const sql = `DELETE FROM users WHERE id = ${id}`;",
            ),
            (
                "wmi.cs",
                "new ManagementObjectSearcher(\n\"SELECT CommandLine FROM Win32_Process WHERE ProcessId = \" + process.Id);\nvar searchString = $\"Select * From Win32_Process Where ParentProcessID={process.Id}\";\nusing (var searcher = new ManagementObjectSearcher(searchString)) {}\nconst string wmiServiceQuery = \"Select * from \" + WMI_Class_Service + \" Where name = 'Winmgmt'\";\nstring queryString = \"Select * From Win32_Service Where ProcessId=\" + process.Id;\ncimSession.QueryInstances(\"root/cimv2\", \"WQL\", queryString);",
            ),
            (
                "prompt.cs",
                "var question = $\"Which team member responds next? (Select only from: {{${names}}}).\";",
            ),
        ]);

        assert!(analyze(&fixture.context()).is_empty());
    }

    #[test]
    fn requires_sql_construction_or_execution_context() {
        let fixture = Fixture::new([(
            "db.go",
            "tx.ExecContext(ctx, \"DELETE FROM \"+table)\nreturn wrap(err, \"delete from \"+table)\nfmt.Errorf(\"failed to insert into dataset: \"+err.Error())",
        )]);

        assert_eq!(
            analyze(&fixture.context())
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn accepts_tagged_and_generated_parameter_placeholders() {
        let fixture = Fixture::new([
            (
                "rpc.ts",
                "const rows = sql`select * from users where id = ${userId}`;",
            ),
            (
                "queries.ts",
                "const placeholders = ids.map(() => '?').join(',');\ndb.prepare(`SELECT * FROM users WHERE id IN (${placeholders})`).all(...ids);\ndb.prepare(`SELECT * FROM users WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids);\ndb.prepare(`SELECT * FROM users WHERE id = ${userId}`);",
            ),
        ]);
        let findings = analyze(&fixture.context());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "queries.ts");
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn accepts_compile_time_constants_and_identifier_allowlists() {
        let fixture = Fixture::new([(
            "rollup.ts",
            "const LIMIT = 5_000;\nconst TABLES = ['daily_counts', 'daily_events'] as const;\nfor (const table of TABLES) {\n  db.prepare(`DELETE FROM ${table} WHERE day = ?`).run(day);\n}\ndb.prepare(`DELETE FROM events WHERE id IN (SELECT id FROM events LIMIT ${LIMIT})`);",
        )]);

        assert!(analyze(&fixture.context()).is_empty());
    }

    #[test]
    fn accepts_only_ef_core_parameterized_interpolation() {
        let fixture = Fixture::new([(
            "Queries.cs",
            "await db.Database.ExecuteSqlInterpolatedAsync(\n    $\"INSERT INTO Users (Id) VALUES ({userId})\");\ndb.Database.ExecuteSqlInterpolated($\"DELETE FROM Users WHERE Id = {userId}\");\nawait db.Database.ExecuteSqlRawAsync(\n    $\"UPDATE Users SET Name = {userName} WHERE Id = {userId}\");\nvar query = $\"SELECT * FROM Users WHERE Id = {userId}\";",
        )]);

        assert_eq!(
            analyze(&fixture.context())
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![5, 6]
        );
    }

    #[test]
    fn accepts_only_provably_numeric_csharp_interpolation() {
        let fixture = Fixture::new([(
            "Queries.cs",
            "const int pageSize = 100;\nvar offset = 0;\nvar ticks = DateTime.Now.Date.Ticks;\nvar page = $\"SELECT * FROM Items LIMIT {pageSize} OFFSET {offset}\";\nvar kind = $\"DELETE FROM Items WHERE Kind = {(int)ItemKind.Archived}\";\nvar cleanup = $\"UPDATE Items SET Seen = 0 WHERE SeenAt < {ticks}\";\nvar unsafeQuery = $\"SELECT * FROM Items WHERE Owner = '{owner}'\";",
        )]);

        assert_eq!(
            analyze(&fixture.context())
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![7]
        );
    }

    #[test]
    fn skips_incomplete_interpolations_without_moving_valid_findings() {
        let fixture = Fixture::new([
            (
                "csharp.cs",
                "var query = $\"SELECT * FROM Users WHERE Id = {\";\nvar query = $\"SELECT * FROM Users WHERE Id = {userId}\";",
            ),
            (
                "javascript.ts",
                "const query = `SELECT * FROM users WHERE id = ${`;\nconst query = `SELECT * FROM users WHERE id = ${userId}`;",
            ),
        ]);

        assert_eq!(
            analyze(&fixture.context())
                .iter()
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("csharp.cs", 2), ("javascript.ts", 2)]
        );
    }

    #[test]
    fn ignores_foreign_source_fixtures_embedded_in_dart_tests() {
        let fixture = Fixture::new([(
            "adapter_test.dart",
            "const sources = <String, String>{\n  'Queries.cs': r'''\nvar query = $\"SELECT * FROM Users WHERE Id = {id}\";\n''',\n  'queries.py':\n      '''query = \"SELECT * FROM \" + table_name\n''',\n};",
        )]);

        assert!(analyze(&fixture.context()).is_empty());
    }

    struct Fixture {
        sources: BTreeMap<String, String>,
    }

    impl Fixture {
        fn new<const N: usize>(sources: [(&str, &str); N]) -> Self {
            Self {
                sources: sources
                    .into_iter()
                    .map(|(path, source)| (path.to_owned(), source.to_owned()))
                    .collect(),
            }
        }

        fn context(&self) -> SourceAnalysisContext<'_> {
            SourceAnalysisContext::unchanged(&self.sources)
        }
    }
}
