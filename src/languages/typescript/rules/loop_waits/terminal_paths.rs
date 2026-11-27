use std::sync::LazyLock;

use regex::Regex;

use crate::languages::functions::JavascriptFunctionRegion;

static AWAIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*await[ \t]+").expect("terminal awaited statement regex")
});
static CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\(")
        .expect("terminal path call statement regex")
});
static FINALLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfinally\s*\{").expect("finally block regex"));

#[derive(Clone, Copy)]
enum Exit {
    Return,
    Break,
}

pub(super) fn awaited_lines(syntax: &str, functions: &[JavascriptFunctionRegion]) -> Vec<usize> {
    let mut lines = Vec::new();
    let mut previous = 0;
    let mut line = 0;
    for candidate in AWAIT.find_iter(syntax) {
        line += syntax[previous..candidate.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        previous = candidate.start();
        let Some((exit, end)) = terminal_exit(&syntax[candidate.end()..]) else {
            continue;
        };
        let Some(owner) = functions
            .iter()
            .filter(|function| function.body.contains(&candidate.start()))
            .min_by_key(|function| function.body.len())
        else {
            continue;
        };
        let body = &syntax[owner.body.clone()];
        if candidate.end() + end >= owner.body.end || FINALLY.is_match(body) {
            continue;
        }
        if matches!(exit, Exit::Return) || single_loop_without_switch(body) {
            lines.push(line);
        }
    }
    lines
}

fn terminal_exit(mut tail: &str) -> Option<(Exit, usize)> {
    let length = tail.len();
    loop {
        let call = CALL.find(tail)?;
        let close = super::super::matching_delimiter(tail, call.end() - 1, b'(', b')')?;
        tail = tail[close + 1..]
            .trim_start()
            .strip_prefix(';')?
            .trim_start();
        let next = super::super::JAVASCRIPT_IDENTIFIER_PREFIX.find(tail)?;
        match next.as_str() {
            "return" => return Some((Exit::Return, length - tail.len())),
            "break" if tail[next.end()..].trim_start().starts_with(';') => {
                return Some((Exit::Break, length - tail.len()));
            }
            "await" => tail = tail[next.end()..].trim_start(),
            _ => {}
        }
    }
}

fn single_loop_without_switch(body: &str) -> bool {
    let mut loops = 0;
    for token in super::super::JAVASCRIPT_IDENTIFIERS.find_iter(body) {
        match token.as_str() {
            "for" | "while" | "do" => loops += 1,
            "switch" => return false,
            _ => {}
        }
    }
    loops == 1
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::source_analysis_context::SourceAnalysisContext;

    fn findings(source: &str) -> Vec<crate::findings::Finding> {
        let sources = BTreeMap::from([("src/attempts.ts".to_owned(), source.to_owned())]);
        super::super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "ts-await-in-loop")
            .collect()
    }

    #[test]
    fn accepts_terminal_success_paths_without_retry_names() {
        for statements in [
            "await store.put(key, value);\nreturn value;",
            "await store.put(\nkey,\nencode({ value }),\n);\nreturn;",
            "await store.put(key, value);\nlogger.info(message, { key });\nreturn key;",
            "await store.put(key, value);\nawait recordSuccess();\nreturn value;",
            "await store.put(key, value);\nresults.push({ error: null });\nbreak;",
            "await store.put(key, value);\n// café: return only after persisting\nreturn value;",
        ] {
            let source = format!(
                "async function run() {{\nfor (const item of items) {{\ntry {{\n{statements}\n}} catch (error) {{ observe(error); }}\n}}\n}}"
            );
            assert!(findings(&source).is_empty(), "{source}");
            assert!(
                findings(&source.replace('\n', "\r\n")).is_empty(),
                "{source}"
            );
        }
    }

    #[test]
    fn retains_independent_work_and_unproven_exits() {
        for statements in [
            "await store.put(key, value);",
            "await store.put(key, value);\nif (done) return;",
            "await store.put(key, value);\ncontinue;",
            "await store.put(key, value);\nconst finish = () => { return value; };",
            "await store.put(key, value);\nconst note = 'return';\n// return value;",
            "await store.put(key, value);\nreturning();",
            "await store.put(key, value).then(recordSuccess);\nreturn;",
        ] {
            let source = format!(
                "async function run() {{\nfor (const item of items) {{\n{statements}\n}}\nreturn;\n}}"
            );
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 3, "{source}");
            assert_eq!(found[0].confidence, "medium");
            assert_eq!(found[0].path, "src/attempts.ts");
            assert!(found[0].related_files.is_empty());
        }
    }

    #[test]
    fn does_not_borrow_inner_loop_or_switch_breaks() {
        for source in [
            "async function run() {\nfor (const group of groups) {\nfor (const item of group) {\nawait store.put(item);\nbreak;\n}\n}\n}",
            "async function run() {\nfor (const item of items) {\nswitch (item.kind) {\ncase 1:\nawait store.put(item);\nbreak;\n}\n}\n}",
            "async function run() {\nfor (const item of items) {\nblock: {\nawait store.put(item);\nbreak block;\n}\n}\n}",
        ] {
            let found = findings(source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].confidence, "medium");
        }
    }

    #[test]
    fn retains_exits_that_finally_can_override() {
        for exit in ["return value;", "break;"] {
            let source = format!(
                "async function run() {{\nfor (const item of items) {{\ntry {{\nawait store.put(item);\n{exit}\n}} finally {{ if (again) continue; }}\n}}\n}}"
            );
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 4);
        }
    }

    #[test]
    fn preserves_grouped_independent_work_beside_terminal_paths() {
        let source = "async function first() {\nfor (const item of items) {\nawait store.put(item);\nreturn;\n}\n}\nasync function all() {\nfor (const item of items) {\nawait store.put(item);\nawait audit.record(item);\n}\n}";
        let found = findings(source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 9);
        assert_eq!(found[0].related_files, ["src/attempts.ts:10"]);
    }
}
