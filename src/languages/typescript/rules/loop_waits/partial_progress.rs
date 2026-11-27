use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::languages::functions::JavascriptFunctionRegion;

static FOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfor\s*\(").expect("progress loop regex"));
static COUNTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([A-Za-z_$][\w$]*)\s*=\s*0\s*;\s*$")
        .expect("progress counter declaration regex")
});
static TRY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*try\s*\{").expect("progress try regex"));
static CATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*catch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{")
        .expect("progress catch binding regex")
});
static INCREMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*([A-Za-z_$][\w$]*)\s*(?:\+\+\s*;|\+=\s*(?:[A-Za-z_$][\w$]*|[1-9][0-9]*)\s*;)",
    )
    .expect("successful progress increment regex")
});
static PUBLICATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*([A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*\s*=\s*([A-Za-z_$][\w$]*)\s*;")
        .expect("partial progress error field regex")
});
static THROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bthrow\s+([A-Za-z_$][\w$]*)\s*;\s*$").expect("progress error propagation regex")
});
static RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*return\s+([A-Za-z_$][\w$]*)\s*;\s*$")
        .expect("successful progress return regex")
});

pub(super) fn awaited_lines(syntax: &str, functions: &[JavascriptFunctionRegion]) -> Vec<usize> {
    if !syntax.contains("throw") || !(syntax.contains("+=") || syntax.contains("++")) {
        return Vec::new();
    }
    let regions = FOR
        .find_iter(syntax)
        .filter_map(|candidate| progress_region(syntax, candidate, functions))
        .collect::<Vec<_>>();
    if regions.is_empty() {
        return Vec::new();
    }
    let mut offset = 0;
    let mut lines = Vec::new();
    for (line, text) in syntax.split_inclusive('\n').enumerate() {
        let start = offset + text.len() - text.trim_start().len();
        if text.trim_start().starts_with("await ")
            && regions.iter().any(|region| region.contains(&start))
        {
            lines.push(line);
        }
        offset += text.len();
    }
    lines
}

fn progress_region(
    syntax: &str,
    candidate: regex::Match<'_>,
    functions: &[JavascriptFunctionRegion],
) -> Option<Range<usize>> {
    let owner = functions
        .iter()
        .filter(|function| function.body.contains(&candidate.start()))
        .min_by_key(|function| function.body.len())?;
    let prefix = &syntax[owner.body.start..candidate.start()];
    let declaration = COUNTER.captures(prefix)?;
    let counter = declaration.get(1)?.as_str();
    let header_end = super::super::matching_delimiter(syntax, candidate.end() - 1, b'(', b')')?;
    let open = header_end + 1 + syntax[header_end + 1..].len()
        - syntax[header_end + 1..].trim_start().len();
    let close = super::super::matching_delimiter(syntax, open, b'{', b'}')?;
    if close >= owner.body.end {
        return None;
    }
    let result = RETURN.captures(&syntax[close + 1..owner.body.end])?;
    if result.get(1)?.as_str() != counter
        || uses(prefix, counter) != 1
        || uses(&syntax[candidate.start()..=close], counter) != 2
        || functions
            .iter()
            .any(|function| (open..close).contains(&function.start))
    {
        return None;
    }
    let body = &syntax[open + 1..close];
    if body.contains("=>")
        || forbidden_tokens(
            body,
            &[
                "for", "while", "do", "function", "class", "finally", "return", "break", "continue",
            ],
        )
    {
        return None;
    }
    let (attempt, handler, error) = attempt_and_handler(body)?;
    let attempt_source = &body[attempt.clone()];
    let increment = INCREMENT.captures_iter(attempt_source).find(|increment| {
        increment
            .get(1)
            .is_some_and(|name| name.as_str() == counter)
    })?;
    let increment_start = increment.get(0)?.start();
    if !top_level_statement(&attempt_source[..increment_start])
        || !publishes_progress(&body[handler], counter, error)
    {
        return None;
    }
    Some(open + 1 + attempt.start..open + 1 + attempt.start + increment_start)
}

fn attempt_and_handler(body: &str) -> Option<(Range<usize>, Range<usize>, &str)> {
    let attempt = TRY.find(body)?;
    let attempt_close = super::super::matching_delimiter(body, attempt.end() - 1, b'{', b'}')?;
    let handler = CATCH.captures(&body[attempt_close + 1..])?;
    let handler_open = attempt_close + handler.get(0)?.end();
    let handler_close = super::super::matching_delimiter(body, handler_open, b'{', b'}')?;
    if !body[handler_close + 1..].trim().is_empty() {
        return None;
    }
    Some((
        attempt.end()..attempt_close,
        handler_open + 1..handler_close,
        handler.get(1)?.as_str(),
    ))
}

static PUBLICATION_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\bif\s*\([^{};]*\)\s*$").expect("partial progress guard regex")
});

fn publishes_progress(handler: &str, counter: &str, error: &str) -> bool {
    if forbidden_tokens(
        handler,
        &[
            "let", "const", "var", "catch", "return", "continue", "break",
        ],
    ) {
        return false;
    }
    let Some(thrown) = THROW.captures(handler) else {
        return false;
    };
    if thrown.get(1).is_none_or(|name| name.as_str() != error) {
        return false;
    }
    PUBLICATION.captures_iter(handler).any(|publication| {
        publication
            .get(1)
            .is_some_and(|name| name.as_str() == error)
            && publication
                .get(2)
                .is_some_and(|name| name.as_str() == counter)
            && publication.get(0).is_some_and(|statement| {
                direct_publication(&handler[..statement.start()])
                    && uses(&handler[statement.end()..], error) == 1
            })
    })
}

fn direct_publication(before: &str) -> bool {
    let mut depth = 0_i32;
    let mut guard_start = 0;
    for (offset, byte) in before.bytes().enumerate() {
        match byte {
            b'{' => {
                if depth == 0 {
                    guard_start = offset;
                }
                depth += 1;
            }
            b'}' => depth -= 1,
            _ => {}
        }
    }
    depth == 0 || depth == 1 && PUBLICATION_GUARD.is_match(&before[..guard_start])
}

fn top_level_statement(before: &str) -> bool {
    let depth = before.bytes().fold(0_i32, |depth, byte| match byte {
        b'{' => depth + 1,
        b'}' => depth - 1,
        _ => depth,
    });
    depth == 0 && before.trim_end().ends_with([';', '}'])
}

fn uses(source: &str, name: &str) -> usize {
    super::super::JAVASCRIPT_IDENTIFIERS
        .find_iter(source)
        .filter(|token| token.as_str() == name)
        .count()
}

fn forbidden_tokens(source: &str, forbidden: &[&str]) -> bool {
    super::super::JAVASCRIPT_IDENTIFIERS
        .find_iter(source)
        .any(|token| forbidden.contains(&token.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::source_analysis_context::SourceAnalysisContext;
    use std::collections::BTreeMap;

    fn findings(source: &str) -> Vec<crate::findings::Finding> {
        let sources = BTreeMap::from([("src/send.ts".to_owned(), source.to_owned())]);
        super::super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "ts-await-in-loop")
            .collect()
    }

    const PREFIX: &str = "async function run(items) {\nlet completed = 0;\nfor (const { body, amount } of items) {\ntry {\ntry {\nawait submit(body);\n} catch (error) {\nrefresh();\nawait submit(body);\n}\ncompleted += amount;\nobserveSuccess();\n} catch (error) {\nif (error instanceof DeliveryFailure) {\nerror.accepted = completed;\n}\nobserveFailure();\nthrow error;\n}\n}\nreturn completed;\n}";

    #[test]
    fn recognizes_propagated_success_prefix_without_domain_names() {
        for source in [
            PREFIX.to_owned(),
            PREFIX
                .replace("completed", "count")
                .replace("accepted", "processed"),
            PREFIX.replace("completed += amount;", "completed++;"),
            PREFIX.replace('\n', "\r\n"),
            PREFIX.replace(
                "observeSuccess();",
                "// café: success accounted above\nobserveSuccess();",
            ),
        ] {
            assert!(findings(&source).is_empty(), "{source}");
        }
    }

    #[test]
    fn retains_unproven_or_unrelated_progress_accounting() {
        for source in [
            PREFIX.replace("error.accepted = completed;", "error.accepted = 0;"),
            PREFIX.replace("throw error;", "throw other;"),
            PREFIX.replace("throw error;", "observe(error);"),
            PREFIX.replace("completed += amount;", "completed += 0;"),
            PREFIX.replace("completed += amount;", "if (ok) { completed += amount; }"),
            PREFIX.replace("completed += amount;", "continue;\ncompleted += amount;"),
            PREFIX.replace("refresh();", "try { check(); } finally { continue; }"),
            PREFIX.replace(
                "completed += amount;",
                "const update = () => completed += amount;",
            ),
            PREFIX.replace("observeFailure();", "reset(error);"),
            PREFIX.replace("observeFailure();", "error.accepted = 0;"),
            PREFIX.replace("observeFailure();", "if (ignored) continue;"),
            PREFIX.replace("observeSuccess();", "const escaped = completed;"),
            PREFIX.replace(
                "error.accepted = completed;",
                "const completed = 0;\nerror.accepted = completed;",
            ),
            PREFIX.replace(
                "error.accepted = completed;",
                "const error = other;\nerror.accepted = completed;",
            ),
            PREFIX.replace(
                "error.accepted = completed;",
                "// error.accepted = completed;\nconst text = 'error.accepted = completed';",
            ),
        ] {
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 6, "{source}");
            assert_eq!(found[0].related_files, ["src/send.ts:9"], "{source}");
            assert_eq!(found[0].path, "src/send.ts");
            assert_eq!(found[0].confidence, "medium");
        }
    }

    #[test]
    fn does_not_borrow_other_function_loop_or_catch_contracts() {
        for source in [
            PREFIX.replace("error.accepted = completed;", "notify({ report(error) {\nerror.accepted = completed;\n} });"),
            PREFIX.replace("observeSuccess();", "for (const other of others) { await store(other); }"),
            PREFIX.replace("} catch (error) {\nif", "} catch (error) {\ntry { check(); } catch (error) { error.accepted = completed; }\nif"),
            PREFIX.replace("completed += amount;", "update();").replace("refresh();", "completed += amount;"),
        ] {
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 6, "{source}");
            assert!(found[0].related_files.iter().any(|location| location == "src/send.ts:9"), "{source}");
        }
    }

    #[test]
    fn preserves_independent_neighboring_work() {
        let source = format!(
            "{PREFIX}\nasync function all(items) {{\nfor (const item of items) {{\nawait store(item);\n}}\n}}"
        );
        let found = findings(&source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 25);
        assert!(found[0].related_files.is_empty());
    }
}
