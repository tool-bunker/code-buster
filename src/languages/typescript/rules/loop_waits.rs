use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::languages::functions::javascript_function_regions;

mod partial_progress;
mod stabilization;
mod terminal_paths;
mod wait_helpers;
mod worker_pools;

static AWAITED_PROMISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*await\s+new\s+Promise(?:\s*<[^<>\n]+>)?\s*\(")
        .expect("awaited timer promise regex")
});
static RESOLVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*))\s*=>\s*")
        .expect("timer promise resolver regex")
});
static SCHEDULER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(setTimeout|setImmediate)\s*\(").expect("timer scheduler regex")
});

pub(super) fn sequential_await_lines(source: &str, syntax: &str) -> BTreeSet<usize> {
    let mut lines = direct_promise_wait_lines(syntax);
    if syntax.contains("await")
        && (syntax.contains("Promise")
            || syntax.contains("Array")
            || syntax.contains("return")
            || syntax.contains("break")
            || syntax.contains("do") && syntax.contains("!=="))
    {
        let functions = javascript_function_regions(syntax);
        lines.extend(wait_helpers::awaited_lines(source, syntax, &functions));
        lines.extend(worker_pools::awaited_lines(syntax, &functions));
        lines.extend(terminal_paths::awaited_lines(syntax, &functions));
        lines.extend(partial_progress::awaited_lines(syntax, &functions));
        lines.extend(stabilization::awaited_lines(syntax, &functions));
    }
    lines
}

fn direct_promise_wait_lines(syntax: &str) -> BTreeSet<usize> {
    let mut candidates = AWAITED_PROMISE.find_iter(syntax).peekable();
    if candidates.peek().is_none() || !unshadowed_global(syntax, "Promise") {
        return BTreeSet::new();
    }
    let timeout = unshadowed_global(syntax, "setTimeout");
    let immediate = unshadowed_global(syntax, "setImmediate");
    let mut lines = BTreeSet::new();
    let mut previous = 0;
    let mut line = 0;
    for candidate in candidates {
        line += syntax[previous..candidate.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        previous = candidate.start();
        let open = candidate.end() - 1;
        let Some(close) = super::matching_delimiter(syntax, open, b'(', b')') else {
            continue;
        };
        let tail = syntax[close + 1..].trim_start();
        if !tail.is_empty() && !tail.starts_with([';', '}']) {
            continue;
        }
        let timer = promise_scheduler(&syntax[open + 1..close]);
        if matches!(timer, Some("setTimeout")) && timeout
            || matches!(timer, Some("setImmediate")) && immediate
        {
            lines.insert(line);
        }
    }
    lines
}

fn promise_scheduler(executor: &str) -> Option<&str> {
    let executor = executor.trim().strip_suffix(',').unwrap_or(executor).trim();
    let resolver = RESOLVER.captures(executor)?;
    let name = resolver.get(1).or_else(|| resolver.get(2))?.as_str();
    let mut body = executor[resolver.get(0)?.end()..].trim();
    if body.starts_with('{') {
        let end = super::matching_delimiter(body, 0, b'{', b'}')?;
        if end != body.len() - 1 {
            return None;
        }
        body = body[1..end].trim();
        body = body.strip_prefix("return ").unwrap_or(body).trim();
        body = body.strip_suffix(';').unwrap_or(body).trim();
    }
    let scheduler = SCHEDULER.captures(body)?;
    let open = scheduler.get(0)?.end() - 1;
    let close = super::matching_delimiter(body, open, b'(', b')')?;
    if close != body.len() - 1 {
        return None;
    }
    let arguments = &body[open + 1..close];
    let callback = arguments
        .split_once(',')
        .map_or(arguments, |(first, _)| first);
    if callback.trim() != name {
        return None;
    }
    scheduler.get(1).map(|timer| timer.as_str())
}

fn unshadowed_global(syntax: &str, name: &str) -> bool {
    super::JAVASCRIPT_IDENTIFIERS
        .find_iter(syntax)
        .filter(|token| token.as_str() == name)
        .all(|token| {
            let before = syntax[..token.start()].trim_end();
            let after = syntax[token.end()..].trim_start();
            if let Some(owner) = before.strip_suffix('.') {
                let owner = trailing_identifier(owner.trim_end());
                return !matches!(owner, "globalThis" | "window") || after.starts_with('(');
            }
            let previous = before.split_whitespace().next_back();
            let type_query = trailing_identifier(before) == "typeof";
            type_query
                || !matches!(
                    previous,
                    Some(
                        "const"
                            | "let"
                            | "var"
                            | "function"
                            | "function*"
                            | "*"
                            | "class"
                            | "import"
                    )
                ) && (after.starts_with('(')
                    || matches!(name, "Promise" | "Array" | "Math")
                        && after.starts_with(['<', '.']))
        })
}

fn trailing_identifier(source: &str) -> &str {
    source
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != '$')
        .next()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::source_analysis_context::SourceAnalysisContext;

    fn loop_findings(source: &str) -> Vec<super::super::Finding> {
        let sources = BTreeMap::from([("src/worker.ts".to_owned(), source.to_owned())]);
        super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "ts-await-in-loop")
            .collect()
    }

    #[test]
    fn accepts_multiline_timer_waits_and_cooperative_yields() {
        for wait in [
            "await new Promise(resolve => setImmediate(resolve));",
            "await new Promise(resolve =>\n setTimeout(resolve, options.delay * 1000),\n);",
            "await new Promise<void>((done) => { setTimeout(done, delays[attempt]); });",
            "await new Promise((done) => { return setImmediate(done); });",
            "await new Promise(\n resolve =>\n setTimeout(resolve, delay),\n);",
            "await new Promise(done => setTimeout(done, 100 * (attempt + 1)));",
            "await new Promise(done => setTimeout(done, Math.max(1000, interval * 1000)));",
            "socket.setTimeout(1000, onReady);\nawait new Promise(done => setTimeout(done, 500));",
            "let timer: ReturnType<typeof setTimeout>;\nawait new Promise(done => setTimeout(done, delay));",
            "const color = '\\x1b[0m';\nawait new Promise(done => setTimeout(done, 500));",
        ] {
            let source = format!(
                "async function run(): Promise<void> {{\nfor (const attempt of attempts) {{\n{wait}\n}}\n}}"
            );
            assert!(loop_findings(&source).is_empty(), "{source}");
        }
    }

    #[test]
    fn retains_real_work_and_unproven_executors() {
        for work in [
            "await send(item);",
            "await send('setTimeout(');",
            "await send(() => setTimeout(done, delay));",
            "await send(`setTimeout(${startJob()})`);",
            "await new Promise(done => startJob(done));",
            "await new Promise(done => setTimeout(otherCallback, delay));",
            "await new Promise(done => { startJob(); setTimeout(done, delay); });",
            "await new Promise(done => setImmediate(done)).then(startJob);",
            "await new Promise(done => timers.setTimeout(done, delay));",
            "await new Promise(done => setTimeout(done, delay)).catch(handleFailure);",
        ] {
            let source =
                format!("async function run() {{\nfor (const item of items) {{\n{work}\n}}\n}}");
            let findings = loop_findings(&source);
            assert_eq!(findings.len(), 1, "{source}");
            assert_eq!(findings[0].line, 3, "{source}");
            assert_eq!(findings[0].path, "src/worker.ts");
            assert_eq!(findings[0].confidence, "medium");
            assert!(findings[0].related_files.is_empty(), "{source}");
        }
    }

    #[test]
    fn does_not_certify_replaced_or_shadowed_runtime_names() {
        for source in [
            "async function run(setTimeout) {\nfor (const item of items) {\nawait new Promise(done => setTimeout(done, delay));\n}\n}",
            "function setImmediate(callback) { startJob(callback); }\nasync function run() {\nfor (const item of items) {\nawait new Promise(done => setImmediate(done));\n}\n}",
            "function* setImmediate(callback) { yield startJob(callback); }\nasync function run() {\nfor (const item of items) {\nawait new Promise(done => setImmediate(done));\n}\n}",
            "const Promise = CustomPromise;\nasync function run() {\nfor (const item of items) {\nawait new Promise(done => setTimeout(done, delay));\n}\n}",
            "globalThis.setTimeout = startJob;\nasync function run() {\nfor (const item of items) {\nawait new Promise(done => setTimeout(done, delay));\n}\n}",
        ] {
            assert_eq!(loop_findings(source).len(), 1, "{source}");
        }
    }

    #[test]
    fn preserves_grouped_work_locations_around_timer_waits() {
        let source = "async function run() {\nfor (const item of items) {\n// await new Promise(done => setTimeout(done, delay));\nconst sample = 'await new Promise(done => setImmediate(done));';\nawait first(item);\nawait new Promise(resolve =>\nsetTimeout(resolve, delay),\n);\nawait second(item);\n}\n}";
        let findings = loop_findings(source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 5);
        assert_eq!(findings[0].related_files, ["src/worker.ts:9"]);
    }

    #[test]
    fn accepts_equivalent_infinite_service_loops() {
        for header in [
            "while (true)",
            "for (;;)",
            "for ( ; ; )",
            "for (/* polling */; /* backpressure */;)",
            "for (;;)\n",
        ] {
            let source = format!(
                "async function run() {{\n{header} {{\nawait receive();\nawait dispatch();\n}}\n}}"
            );
            assert!(loop_findings(&source).is_empty(), "{source}");
            assert!(
                loop_findings(&source.replace('\n', "\r\n")).is_empty(),
                "{source}"
            );
        }
    }

    #[test]
    fn retains_finite_for_and_while_loop_work() {
        for header in [
            "for (const item of items)",
            "for (let index = 0; index < items.length; index++)",
            "for (; ready;)",
            "for (; index < items.length; index++)",
            "while (ready)",
            "while (true && ready)",
        ] {
            let source = format!(
                "async function run() {{\n{header} {{\nawait persist(item);\nawait notify(item);\n}}\n}}"
            );
            let found = loop_findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 3, "{source}");
            assert_eq!(found[0].related_files, ["src/worker.ts:4"], "{source}");
            assert_eq!(found[0].confidence, "medium");
            assert_eq!(found[0].path, "src/worker.ts");
        }
    }

    #[test]
    fn keeps_nested_finite_loops_independent_of_service_loops() {
        for header in ["while (true)", "for (;;)"] {
            let source = format!(
                "async function run() {{\n{header} {{\nawait receive();\nfor (const item of items) {{\nawait persist(item);\nawait notify(item);\n}}\nawait checkpoint();\n}}\n}}"
            );
            let found = loop_findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 5, "{source}");
            assert_eq!(found[0].related_files, ["src/worker.ts:6"], "{source}");
        }
        let source = "async function run() {\nfor (const item of items) {\nawait persist(item);\nfor (;;) {\nawait receive();\n}\nawait notify(item);\n}\n}";
        let found = loop_findings(source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 3);
        assert_eq!(found[0].related_files, ["src/worker.ts:7"]);
    }

    #[test]
    fn ignores_infinite_loop_text_in_comments_and_strings() {
        let source = "async function run() {\n// for (;;) {\nconst example = 'for (;;) { await receive(); }';\nfor (const item of items) {\nawait persist(item);\n}\n}";
        let found = loop_findings(source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 5);
        assert!(found[0].related_files.is_empty());
    }
}
