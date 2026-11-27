use regex::Regex;
use std::sync::LazyLock;

use crate::languages::functions::JavascriptFunctionRegion;

static WORKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*async\s*\(\s*\)\s*(?::\s*Promise\s*<\s*void\s*>)?\s*=>\s*\{")
        .expect("async pool worker regex")
});
static CURSOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([A-Za-z_$][\w$]*)\s*=\s*0\s*;\s*$").expect("shared pool cursor regex")
});
static CLAIM_LOOP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?x)
        ^\s*while\s*\(\s*(?P<cursor>[A-Za-z_$][\w$]*)\s*<\s*(?P<items>[A-Za-z_$][\w$]*)\.length\s*\)\s*\{
        \s*const\s+(?P<claim>[A-Za-z_$][\w$]*)\s*=\s*(?P<increment>[A-Za-z_$][\w$]*)\s*\+\+\s*;
        \s*(?P<await>await)\s+[A-Za-z_$][\w$]*\s*\(\s*(?P<input>[A-Za-z_$][\w$]*)\s*\[\s*(?P<index>[A-Za-z_$][\w$]*)\s*\]\s*\)\s*;
        \s*\}\s*$")
        .expect("shared cursor claim loop regex")
});
static POOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?x)
        ^\s*;\s*const\s+(?P<pool>[A-Za-z_$][\w$]*)\s*=\s*Array\s*\.\s*from\s*\(\s*\{\s*length\s*:
        \s*Math\s*\.\s*min\s*\(\s*(?:[A-Za-z_$][\w$]*|[0-9]+)\s*,\s*(?P<items>[A-Za-z_$][\w$]*)\s*\.\s*length\s*,?\s*\)\s*,?\s*\}
        \s*,\s*(?P<worker>[A-Za-z_$][\w$]*)\s*,?\s*\)\s*;
        \s*await\s+Promise\s*\.\s*all\s*\(\s*(?P<join>[A-Za-z_$][\w$]*)\s*,?\s*\)\s*;")
        .expect("bounded pool launch and join regex")
});
static RUNTIME_MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Array\s*\.\s*from|Promise\s*\.\s*all|Math\s*\.\s*min)\b")
        .expect("pool runtime member regex")
});

pub(super) fn awaited_lines(syntax: &str, functions: &[JavascriptFunctionRegion]) -> Vec<usize> {
    let mut workers = WORKER.captures_iter(syntax).peekable();
    if !syntax.contains("Array") || workers.peek().is_none() || !runtime_is_unmodified(syntax) {
        return Vec::new();
    }
    workers
        .filter_map(|worker| {
            let offset = claimed_await(syntax, &worker, functions)?;
            Some(
                syntax[..offset]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
            )
        })
        .collect()
}

fn claimed_await(
    syntax: &str,
    worker: &regex::Captures<'_>,
    functions: &[JavascriptFunctionRegion],
) -> Option<usize> {
    let declaration = worker.get(0)?;
    let region = functions
        .iter()
        .find(|region| region.body.start == declaration.end())?;
    let owner = enclosing_scope(syntax, declaration.start())?;
    let claimed = CLAIM_LOOP.captures(&syntax[region.body.clone()])?;
    let cursor = CURSOR.captures(&syntax[owner.start..declaration.start()])?;
    let launched = POOL.captures(&syntax[region.body.end + 1..owner.end])?;
    if cursor[1] != claimed["cursor"]
        || claimed["cursor"] != claimed["increment"]
        || claimed["items"] != claimed["input"]
        || claimed["claim"] != claimed["index"]
        || worker["name"] != launched["worker"]
        || claimed["items"] != launched["items"]
        || launched["pool"] != launched["join"]
    {
        return None;
    }
    if !expected_binding_uses(
        &syntax[owner],
        [&worker["name"], &launched["pool"], &claimed["cursor"]],
    ) {
        return None;
    }
    Some(region.body.start + claimed.name("await")?.start())
}

fn enclosing_scope(syntax: &str, offset: usize) -> Option<std::ops::Range<usize>> {
    let mut closed = 0usize;
    for (index, byte) in syntax.as_bytes()[..offset].iter().enumerate().rev() {
        match byte {
            b'}' => closed += 1,
            b'{' if closed == 0 => {
                return Some(
                    index + 1..super::super::matching_delimiter(syntax, index, b'{', b'}')?,
                );
            }
            b'{' => closed -= 1,
            _ => {}
        }
    }
    None
}

fn expected_binding_uses(source: &str, names: [&str; 3]) -> bool {
    let mut uses = [0; 3];
    for token in super::super::JAVASCRIPT_IDENTIFIERS.find_iter(source) {
        for (name, count) in names.iter().zip(&mut uses) {
            *count += usize::from(token.as_str() == *name);
        }
    }
    uses == [2, 2, 3]
}

fn runtime_is_unmodified(syntax: &str) -> bool {
    ["Array", "Promise", "Math"]
        .iter()
        .all(|name| super::unshadowed_global(syntax, name))
        && RUNTIME_MEMBER.find_iter(syntax).all(|member| {
            syntax[..member.start()].trim_end().ends_with('.')
                || syntax[member.end()..].trim_start().starts_with('(')
        })
}

#[cfg(test)]
mod tests {
    use crate::source_analysis_context::SourceAnalysisContext;
    use std::collections::BTreeMap;

    fn findings(source: &str) -> Vec<crate::findings::Finding> {
        let sources = BTreeMap::from([("src/pool.ts".to_owned(), source.to_owned())]);
        super::super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "ts-await-in-loop")
            .collect()
    }

    const POOL_SOURCE: &str = "async function map<T>(input: T[], cap: number, job: (item: T) => Promise<void>): Promise<void> {\nlet cursor = 0;\nconst consume = async (): Promise<void> => {\nwhile (cursor < input.length) {\nconst claimed = cursor++;\nawait job(input[claimed]);\n}\n};\nconst pending = Array.from({ length: Math.min(cap, input.length) }, consume);\nawait Promise.all(pending);\n}";

    #[test]
    fn accepts_claim_before_await_in_a_joined_bounded_worker_pool() {
        assert!(findings(POOL_SOURCE).is_empty());
        assert!(findings(&POOL_SOURCE.replace('\n', "\r\n")).is_empty());
    }

    #[test]
    fn retains_unproven_serial_workers_and_conflicting_pool_bindings() {
        for source in [
            POOL_SOURCE.replace("await Promise.all(pending);", "void pending;"),
            POOL_SOURCE.replace("Math.min(cap, input.length)", "input.length"),
            POOL_SOURCE.replace("}, consume)", "}, () => consume)"),
            POOL_SOURCE.replace("const claimed = cursor++;", "const claimed = cursor;"),
            POOL_SOURCE.replace("await job(input[claimed]);", "await job(input[cursor]);"),
            POOL_SOURCE.replace(
                "await Promise.all(pending);",
                "await Promise.all(pending);\nawait consume();",
            ),
            POOL_SOURCE.replace("const pending =", "cursor = 0;\nconst pending ="),
            format!("const Array = customArray;\n{POOL_SOURCE}"),
            format!("Promise.all = customJoin;\n{POOL_SOURCE}"),
        ] {
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].confidence, "medium");
            assert_eq!(found[0].path, "src/pool.ts");
        }
    }

    #[test]
    fn preserves_other_awaits_beside_a_recognized_pool() {
        let source = format!(
            "{POOL_SOURCE}\nasync function serial() {{\nfor (const item of items) {{\nawait save(item);\n}}\n}}"
        );
        let found = findings(&source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 14);
        assert!(found[0].related_files.is_empty());
    }
}
