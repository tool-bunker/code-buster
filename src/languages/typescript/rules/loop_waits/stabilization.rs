use std::sync::LazyLock;

use regex::Regex;

use crate::languages::functions::JavascriptFunctionRegion;

static BARRIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        \bdo\s*\{
        \s*(?P<assigned>[A-Za-z_$][\w$]*)\s*=\s*
        (?P<source>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(\s*\))?)\s*;
        \s*(?P<await>await)\s+(?P<waited>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;
        \s*\}\s*while\s*\(
        \s*(?P<compared>[A-Za-z_$][\w$]*)\s*!==\s*
        (?P<rechecked>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(\s*\))?)\s*
        \)\s*;",
    )
    .expect("promise stabilization loop regex")
});
static LOCAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^;=\n]+)?\s*;\s*$")
        .expect("local barrier snapshot declaration regex")
});

pub(super) fn awaited_lines(syntax: &str, functions: &[JavascriptFunctionRegion]) -> Vec<usize> {
    if !syntax.contains("!==") || !syntax.contains("do") {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut previous = 0;
    let mut line = 0;
    for candidate in BARRIER.captures_iter(syntax) {
        let Some(statement) = candidate.get(0) else {
            continue;
        };
        line += syntax[previous..statement.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        previous = statement.start();
        if !same_snapshot(&candidate) {
            continue;
        }
        let Some(owner) = functions
            .iter()
            .filter(|function| {
                function.body.contains(&statement.start()) && statement.end() <= function.body.end
            })
            .min_by_key(|function| function.body.len())
        else {
            continue;
        };
        let Some(declaration) = LOCAL.captures(&syntax[owner.body.start..statement.start()]) else {
            continue;
        };
        let snapshot = &candidate["assigned"];
        if &declaration[1] != snapshot
            || super::super::JAVASCRIPT_IDENTIFIERS
                .find_iter(&syntax[owner.body.clone()])
                .filter(|token| token.as_str() == snapshot)
                .count()
                != 4
        {
            continue;
        }
        if let Some(wait) = candidate.name("await") {
            lines.push(
                line + syntax[statement.start()..wait.start()]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
            );
        }
    }
    lines
}

fn same_snapshot(candidate: &regex::Captures<'_>) -> bool {
    candidate["assigned"] == candidate["compared"]
        && candidate["waited"].split('.').next() == Some(&candidate["assigned"])
        && candidate["source"]
            .chars()
            .filter(|character| !character.is_whitespace())
            .eq(candidate["rechecked"]
                .chars()
                .filter(|character| !character.is_whitespace()))
}

#[cfg(test)]
mod tests {
    use crate::source_analysis_context::SourceAnalysisContext;
    use std::collections::BTreeMap;

    fn findings(source: &str) -> Vec<crate::findings::Finding> {
        let sources = BTreeMap::from([("src/barrier.ts".to_owned(), source.to_owned())]);
        super::super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "ts-await-in-loop")
            .collect()
    }

    const GETTER: &str = "async function run(context) {\nlet snapshot: Promise<void>;\ndo {\nsnapshot = context.current();\nawait snapshot;\n} while (snapshot !== context.current());\nreturn read();\n}";
    const OBJECT: &str = "async function run() {\nlet snapshot: typeof current;\ndo {\nsnapshot = current;\nawait snapshot.done;\n} while (snapshot !== current);\nreturn read();\n}";

    #[test]
    fn accepts_local_snapshot_and_getter_stabilization() {
        for source in [
            GETTER.to_owned(),
            OBJECT.to_owned(),
            GETTER.replace("snapshot", "settled"),
            OBJECT.replace(".done", ".ready"),
            GETTER.replace(": Promise<void>", ""),
            GETTER
                .replace(": Promise<void>", "")
                .replace("return read();", "read();"),
            GETTER.replace(
                "snapshot = context.current();",
                "snapshot = context.current( );",
            ),
            GETTER.replace('\n', "\r\n"),
            OBJECT.replace("snapshot =", "// café: current barrier\nsnapshot ="),
        ] {
            assert!(findings(&source).is_empty(), "{source}");
        }
    }

    #[test]
    fn retains_mismatched_waits_getters_and_extra_work() {
        for source in [
            GETTER.replace("await snapshot;", "await other;"),
            GETTER.replace("while (snapshot !==", "while (other !=="),
            GETTER.replace(
                "while (snapshot !== context.current()",
                "while (snapshot !== context.other()",
            ),
            GETTER.replace("await snapshot;", "await snapshot;\nlaunchWork();"),
            GETTER.replace("await snapshot;", "await snapshot.then(launchWork);"),
            GETTER.replace(
                "snapshot = context.current();",
                "snapshot = context.current(item);",
            ),
            GETTER.replace("while (snapshot !==", "while (snapshot ==="),
            OBJECT.replace("await snapshot.done;", "await current.done;"),
        ] {
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].line, 5, "{source}");
            assert_eq!(found[0].path, "src/barrier.ts");
            assert_eq!(found[0].confidence, "medium");
            assert!(found[0].related_files.is_empty());
        }
    }

    #[test]
    fn does_not_borrow_other_bindings_or_quoted_barrier_examples() {
        for source in [
            GETTER.replace("let snapshot: Promise<void>;", "let different: Promise<void>;"),
            GETTER.replace("return read();", "observe(snapshot);\nreturn read();"),
            GETTER.replace("let snapshot:", "const readSnapshot = () => snapshot;\nlet snapshot:"),
            "async function run(items) {\nconst example = 'do { snapshot = context.current(); await snapshot; } while (snapshot !== context.current());';\nfor (const item of items) {\nawait launch(item);\n}\n}".to_owned(),
        ] {
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].confidence, "medium");
        }
    }

    #[test]
    fn preserves_independent_work_after_a_stabilized_barrier() {
        let source = GETTER.replace("return read();", "for (const item of items) {\nawait launch(item);\nawait record(item);\n}\nreturn read();");
        let found = findings(&source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 8);
        assert_eq!(found[0].related_files, ["src/barrier.ts:9"]);
    }
}
