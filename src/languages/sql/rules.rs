use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>, config: &Config) -> Vec<Finding> {
    let sql_sources = context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".sql"))
        .collect::<Vec<_>>();
    let mut mysql_evidence_by_directory = BTreeMap::<String, usize>::new();
    for (path, source) in &sql_sources {
        if MYSQL_SYNTAX.is_match(source) {
            *mysql_evidence_by_directory
                .entry(source_directory(path))
                .or_default() += 1;
        }
    }
    let configured_mysql = config.language.eq_ignore_ascii_case("mysql")
        || config
            .languages
            .iter()
            .any(|language| language.eq_ignore_ascii_case("mysql"));
    let mut findings = Vec::new();
    for (path, source) in sql_sources {
        let directory = source_directory(path);
        let postgres = !configured_mysql
            && (POSTGRES_PATH.is_match(path)
                || (!is_clearly_non_postgres(path, source)
                    && mysql_evidence_by_directory
                        .get(&directory)
                        .copied()
                        .unwrap_or_default()
                        < 2));
        scan_source(path, source, postgres, &mut findings);
    }
    findings
}

fn scan_source(path: &str, source: &str, postgres: bool, findings: &mut Vec<Finding>) {
    let mut statement = String::new();
    let mut statement_lines = Vec::new();
    let mut in_block_comment = false;
    for (index, raw_line) in source.split('\n').enumerate() {
        let code = strip_sql_comments(raw_line, &mut in_block_comment);
        let code = code.trim();
        if code.is_empty() {
            continue;
        }
        if !statement.is_empty() {
            statement.push('\n');
        }
        statement.push_str(code);
        statement_lines.push((index + 1, code.to_owned()));
        if code.contains(';') {
            check_statement(path, &statement, &statement_lines, postgres, findings);
            statement.clear();
            statement_lines.clear();
        }
    }
    if !statement.is_empty() {
        check_statement(path, &statement, &statement_lines, postgres, findings);
    }
}

struct StatementCheck {
    applies: fn(&str, bool) -> bool,
    code: &'static str,
    message: &'static str,
    location: &'static LazyLock<Regex>,
    confidence: &'static str,
}

fn check_statement(
    path: &str,
    statement: &str,
    lines: &[(usize, String)],
    postgres: bool,
    findings: &mut Vec<Finding>,
) {
    let sql = WHITESPACE.replace_all(statement, " ").to_ascii_lowercase();
    for check in STATEMENT_CHECKS {
        if (check.applies)(&sql, postgres) {
            push(
                findings,
                path,
                lines,
                check.code,
                check.message,
                check.location,
                check.confidence,
            );
        }
    }
}

fn uses_select_star(sql: &str, _postgres: bool) -> bool {
    sql.contains("select *")
}

fn deletes_without_where(sql: &str, _postgres: bool) -> bool {
    sql.contains("delete from ") && !sql.contains(" where ")
}

fn updates_without_where(sql: &str, _postgres: bool) -> bool {
    UPDATE_START.is_match(sql) && sql.contains(" set ") && !sql.contains(" where ")
}

fn drops_table_without_if_exists(sql: &str, _postgres: bool) -> bool {
    sql.contains("drop table") && !sql.contains("if exists")
}

fn uses_not_in_subquery(sql: &str, _postgres: bool) -> bool {
    sql.contains("not in") && sql.contains("select")
}

fn uses_case_sensitive_like(sql: &str, _postgres: bool) -> bool {
    sql.contains(" like '")
        && sql.contains('%')
        && !sql.contains("lower(")
        && !sql.contains("ilike")
}

fn uses_leading_wildcard(sql: &str, _postgres: bool) -> bool {
    sql.contains(" like '%")
}

fn creates_nonconcurrent_postgres_index(sql: &str, postgres: bool) -> bool {
    postgres && sql.contains("create index ") && !sql.contains(" concurrently")
}

fn adds_not_null_column_with_default(sql: &str, _postgres: bool) -> bool {
    sql.contains("alter table ")
        && sql.contains(" add column ")
        && sql.contains(" not null")
        && sql.contains(" default ")
}

static STATEMENT_CHECKS: &[StatementCheck] = &[
    StatementCheck {
        applies: uses_select_star,
        code: "sql-select-star",
        message: "SQL uses SELECT *",
        location: &SELECT_STAR,
        confidence: "low",
    },
    StatementCheck {
        applies: deletes_without_where,
        code: "sql-delete-without-where",
        message: "DELETE has no WHERE clause",
        location: &DELETE_FROM,
        confidence: "medium",
    },
    StatementCheck {
        applies: updates_without_where,
        code: "sql-update-without-where",
        message: "UPDATE has no WHERE clause",
        location: &UPDATE_START,
        confidence: "medium",
    },
    StatementCheck {
        applies: drops_table_without_if_exists,
        code: "sql-drop-table-without-if-exists",
        message: "DROP TABLE lacks IF EXISTS",
        location: &DROP_TABLE,
        confidence: "low",
    },
    StatementCheck {
        applies: uses_not_in_subquery,
        code: "sql-not-in-subquery-null-risk",
        message: "NOT IN subquery can behave unexpectedly with NULLs",
        location: &NOT_IN,
        confidence: "low",
    },
    StatementCheck {
        applies: uses_case_sensitive_like,
        code: "sql-case-sensitive-like",
        message: "LIKE search appears case-sensitive",
        location: &LIKE,
        confidence: "low",
    },
    StatementCheck {
        applies: uses_leading_wildcard,
        code: "sql-leading-wildcard-like",
        message: "LIKE pattern starts with wildcard",
        location: &LEADING_WILDCARD,
        confidence: "low",
    },
    StatementCheck {
        applies: creates_nonconcurrent_postgres_index,
        code: "sql-create-index-nonconcurrent",
        message: "CREATE INDEX is not CONCURRENTLY",
        location: &CREATE_INDEX,
        confidence: "low",
    },
    StatementCheck {
        applies: adds_not_null_column_with_default,
        code: "sql-add-not-null-default",
        message: "ADD COLUMN NOT NULL DEFAULT may rewrite or lock table",
        location: &ALTER_ADD_COLUMN,
        confidence: "medium",
    },
];

fn push(
    findings: &mut Vec<Finding>,
    path: &str,
    lines: &[(usize, String)],
    code: &str,
    message: &str,
    location: &Regex,
    confidence: &str,
) {
    let start_line = lines.first().map_or(1, |(line, _)| *line);
    let line = lines
        .iter()
        .position(|(_, line)| location.is_match(line))
        .map_or(start_line, |offset| start_line + offset);
    let metadata = rule_catalog::metadata(code).expect("SQL rule metadata must exist");
    findings.push(Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    });
}

#[derive(Clone, Copy)]
enum SqlCommentState {
    Code,
    Quote(char),
    BlockComment,
}

enum SqlCommentAction {
    Copy(usize),
    Skip(usize),
    Stop,
}

fn strip_sql_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut code = String::new();
    let mut state = if *in_block_comment {
        SqlCommentState::BlockComment
    } else {
        SqlCommentState::Code
    };
    let mut index = 0;

    while index < line.len() {
        let Some(character) = line[index..].chars().next() else {
            break;
        };
        match sql_comment_transition(&line[index..], &mut state, character) {
            SqlCommentAction::Copy(length) => {
                code.push_str(&line[index..index + length]);
                index += length;
            }
            SqlCommentAction::Skip(length) => index += length,
            SqlCommentAction::Stop => break,
        }
    }

    *in_block_comment = matches!(state, SqlCommentState::BlockComment);
    code
}

fn sql_comment_transition(
    input: &str,
    state: &mut SqlCommentState,
    character: char,
) -> SqlCommentAction {
    match *state {
        SqlCommentState::Code => code_transition(input, state, character),
        SqlCommentState::Quote(delimiter) => quote_transition(input, state, character, delimiter),
        SqlCommentState::BlockComment => block_comment_transition(input, state, character),
    }
}

fn code_transition(input: &str, state: &mut SqlCommentState, character: char) -> SqlCommentAction {
    if matches!(character, '\'' | '"') {
        *state = SqlCommentState::Quote(character);
        SqlCommentAction::Copy(character.len_utf8())
    } else if input.starts_with("--") {
        SqlCommentAction::Stop
    } else if input.starts_with("/*") {
        *state = SqlCommentState::BlockComment;
        SqlCommentAction::Skip(2)
    } else {
        SqlCommentAction::Copy(character.len_utf8())
    }
}

fn quote_transition(
    input: &str,
    state: &mut SqlCommentState,
    character: char,
    delimiter: char,
) -> SqlCommentAction {
    let character_length = character.len_utf8();
    if character != delimiter {
        return SqlCommentAction::Copy(character_length);
    }
    if input[character_length..].starts_with(delimiter) {
        return SqlCommentAction::Copy(character_length + delimiter.len_utf8());
    }
    *state = SqlCommentState::Code;
    SqlCommentAction::Copy(character_length)
}

fn block_comment_transition(
    input: &str,
    state: &mut SqlCommentState,
    character: char,
) -> SqlCommentAction {
    if input.starts_with("*/") {
        *state = SqlCommentState::Code;
        SqlCommentAction::Skip(2)
    } else {
        SqlCommentAction::Skip(character.len_utf8())
    }
}

fn is_clearly_non_postgres(path: &str, source: &str) -> bool {
    if NON_POSTGRES_PATH.is_match(path) {
        return true;
    }
    let header = source.lines().take(5).collect::<Vec<_>>().join("\n");
    SQLITE_HEADER.is_match(&header)
        || SQLITE_SYNTAX.is_match(source)
        || MYSQL_SYNTAX.is_match(source)
        || SQL_SERVER_SYNTAX.is_match(source)
}

fn source_directory(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    normalized
        .rsplit_once('/')
        .map_or_else(String::new, |(directory, _)| directory.to_owned())
}

static POSTGRES_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\\/])postgres(?:ql)?(?:[\\/]|$)|postgres(?:ql)?\.sql$").unwrap()
});
static NON_POSTGRES_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\\/])(?:mysql|sqlite|sqlserver|mssql)(?:[\\/]|$)").unwrap()
});
static SQLITE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*--[^\n]*\bsqlite\b").unwrap());
static SQLITE_SYNTAX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bAUTOINCREMENT\b").unwrap());
static MYSQL_SYNTAX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bENGINE\s*=\s*[A-Za-z]|\bCHARACTER\s+SET\s*=?\s*utf8mb4\b|`[^`\r\n]+`")
        .unwrap()
});
static SQL_SERVER_SYNTAX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)\bOBJECT_ID\s*\(|\bsys\.indexes\b|^\s*GO\s*$").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static SELECT_STAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bselect\s+\*").unwrap());
static DELETE_FROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bdelete\s+from\b").unwrap());
static UPDATE_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^update\b").unwrap());
static DROP_TABLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bdrop\s+table\b").unwrap());
static NOT_IN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bnot\s+in\s*\(").unwrap());
static LIKE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\blike\s+['"]"#).unwrap());
static LEADING_WILDCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\blike\s+['"]%"#).unwrap());
static CREATE_INDEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bcreate\s+index\b").unwrap());
static ALTER_ADD_COLUMN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\balter\s+table\b.*\badd\s+column\b").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::analyze;
    use crate::config::Config;
    use crate::source_analysis_context::SourceAnalysisContext;

    #[test]
    fn reports_every_standalone_sql_rule_with_original_locations() {
        let sources = BTreeMap::from([(
            "migration.sql".to_owned(),
            "SELECT * FROM users WHERE name LIKE '%bob';\n\
DELETE FROM sessions;\n\
UPDATE accounts SET active = false;\n\
DROP TABLE audit;\n\
CREATE INDEX idx_users_name ON users(name);\n\
ALTER TABLE users ADD COLUMN enabled boolean NOT NULL DEFAULT true;\n\
SELECT id FROM users WHERE id NOT IN (SELECT user_id FROM bans);"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context, &Config::defaults(PathBuf::from(".")));

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.line,
                    finding.confidence.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("sql-select-star", 1, "low"),
                ("sql-case-sensitive-like", 1, "low"),
                ("sql-leading-wildcard-like", 1, "low"),
                ("sql-delete-without-where", 2, "medium"),
                ("sql-update-without-where", 3, "medium"),
                ("sql-drop-table-without-if-exists", 4, "low"),
                ("sql-create-index-nonconcurrent", 5, "low"),
                ("sql-add-not-null-default", 6, "medium"),
                ("sql-not-in-subquery-null-risk", 7, "low"),
            ]
        );
    }

    #[test]
    fn reports_compound_statement_hazard_on_the_expression_line() {
        let sources = BTreeMap::from([(
            "migration.sql".to_owned(),
            "DO $$\nBEGIN\n  IF true THEN\n    ALTER TABLE users ADD COLUMN enabled boolean NOT NULL DEFAULT true;\n  END IF;\nEND $$;"
                .to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context, &Config::defaults(PathBuf::from(".")));

        let finding = findings
            .iter()
            .find(|finding| finding.code == "sql-add-not-null-default")
            .unwrap();
        assert_eq!(finding.line, 4);
    }

    #[test]
    fn respects_safe_statements_comments_and_non_postgres_dialects() {
        let sources = BTreeMap::from([
            (
                "safe.sql".to_owned(),
                "INSERT INTO versions (name, value) VALUES ('schema', 1) ON CONFLICT (name) DO UPDATE SET value = 1;\n\
DELETE FROM sessions WHERE expired = true;\n\
UPDATE accounts SET active = false WHERE id = 1;\n\
DROP TABLE IF EXISTS audit;\n\
SELECT id FROM users WHERE lower(name) LIKE 'bob%';\n\
CREATE INDEX CONCURRENTLY idx_users ON users(name);\n\
/* ALTER TABLE users ADD COLUMN bad TEXT NOT NULL DEFAULT 'x'; */"
                    .to_owned(),
            ),
            (
                "sqlite/schema.sql".to_owned(),
                "-- Application SQLite Schema\nCREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT);\nCREATE INDEX idx_messages ON messages(id);"
                    .to_owned(),
            ),
            (
                "sql-server.sql".to_owned(),
                "IF OBJECT_ID('[dbo].[users]') IS NULL\nBEGIN\nCREATE TABLE [dbo].[users] ([name] NVARCHAR(100));\nEND\nGO\nCREATE INDEX [idx] ON [dbo].[users] ([name]);"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(analyze(&context, &Config::defaults(PathBuf::from("."))).is_empty());
    }

    #[test]
    fn uses_configured_and_inferred_mysql_dialects() {
        let configured_sources = BTreeMap::from([(
            "index.sql".to_owned(),
            "CREATE INDEX idx ON users(name);".to_owned(),
        )]);
        let configured_context = SourceAnalysisContext::unchanged(&configured_sources);
        let mut mysql = Config::defaults(PathBuf::from("."));
        mysql.languages = vec!["mysql".to_owned()];
        assert!(analyze(&configured_context, &mysql).is_empty());

        let inferred_sources = BTreeMap::from([
            (
                "db/tables.sql".to_owned(),
                "CREATE TABLE `users` (`name` varchar(100));".to_owned(),
            ),
            (
                "db/options.sql".to_owned(),
                "CREATE TABLE logs (id int) ENGINE=InnoDB;".to_owned(),
            ),
            (
                "db/indexes.sql".to_owned(),
                "CREATE INDEX idx_users ON users(name);".to_owned(),
            ),
            (
                "db/postgresql.sql".to_owned(),
                "CREATE INDEX idx_events ON events(name);".to_owned(),
            ),
        ]);
        let inferred_context = SourceAnalysisContext::unchanged(&inferred_sources);
        assert_eq!(
            analyze(&inferred_context, &Config::defaults(PathBuf::from(".")),)
                .into_iter()
                .filter(|finding| finding.code == "sql-create-index-nonconcurrent")
                .map(|finding| finding.path)
                .collect::<Vec<_>>(),
            vec!["db/postgresql.sql"]
        );
    }
    #[test]
    fn handles_unterminated_sql_constructs_with_multibyte_text() {
        let sources = BTreeMap::from([
            (
                "malformed-comment.sql".to_owned(),
                "SELECT * FROM users;\n/* unterminated 🦀\nDROP TABLE audit;".to_owned(),
            ),
            (
                "malformed-string.sql".to_owned(),
                "SELECT 'unterminated 🦀".to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let findings = analyze(&context, &Config::defaults(PathBuf::from(".")));

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.code, "sql-select-star");
        assert_eq!(finding.path, "malformed-comment.sql");
        assert_eq!((finding.line, finding.end_line), (1, 1));
        assert_eq!(finding.confidence, "low");
        assert_eq!(finding.message, "SQL uses SELECT *");
        assert!(!finding.why.is_empty());
        assert!(!finding.suggestion.is_empty());
    }

    #[test]
    fn preserves_legacy_locations_across_blank_and_comment_lines() {
        let sources = BTreeMap::from([(
            "model.sql".to_owned(),
            "with source as (\n\n    /* template note */\n    select * from users\n)".to_owned(),
        )]);
        let context = SourceAnalysisContext::unchanged(&sources);

        let finding = analyze(&context, &Config::defaults(PathBuf::from(".")))
            .into_iter()
            .find(|finding| finding.code == "sql-select-star")
            .unwrap();

        assert_eq!(finding.line, 2);
    }
}
