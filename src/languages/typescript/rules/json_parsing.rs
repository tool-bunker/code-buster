use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::languages::functions::{JavascriptFunctionRegion, javascript_function_regions};

static MODULE_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:import[ \t]+(?:[A-Za-z_$]|\{|\*)|export\b)")
        .expect("module declaration regex")
});
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").expect("JavaScript identifier regex"));
static TRY_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btry\s*\{").expect("try block regex"));
static FUNCTION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(").expect("function declaration regex")
});

pub(super) fn caller_handled_lines(runtime: &str, recovery_required: bool) -> BTreeSet<usize> {
    if !recovery_required
        || !runtime.contains("JSON.parse(")
        || !MODULE_DECLARATION.is_match(runtime)
    {
        return BTreeSet::new();
    }
    if IDENTIFIER.find_iter(runtime).any(|token| {
        matches!(token.as_str(), "eval" | "Function")
            && !runtime[..token.start()].trim_end().ends_with('.')
    }) {
        return BTreeSet::new();
    }
    let guards = handled_try_bodies(runtime);
    if guards.is_empty() {
        return BTreeSet::new();
    }
    let functions = javascript_function_regions(runtime);
    let mut proven = BTreeMap::new();
    let mut lines = BTreeMap::new();
    let mut previous_offset = 0;
    let mut line = 0;
    for (offset, _) in runtime.match_indices("JSON.parse(") {
        let owner = functions
            .iter()
            .enumerate()
            .filter(|(_, function)| function.body.contains(&offset))
            .min_by_key(|(_, function)| function.body.len());
        let handled = owner.is_some_and(|(index, function)| {
            let guarded = *proven.entry(index).or_insert_with(|| {
                private_function_is_guarded(runtime, function, &functions, &guards)
            });
            guarded && is_body_level(&runtime[function.body.start..offset])
        });
        line += runtime[previous_offset..offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        previous_offset = offset;
        lines
            .entry(line)
            .and_modify(|all_handled| *all_handled &= handled)
            .or_insert(handled);
    }
    lines
        .into_iter()
        .filter_map(|(line, handled)| handled.then_some(line))
        .collect()
}

fn private_function_is_guarded(
    runtime: &str,
    function: &JavascriptFunctionRegion,
    functions: &[JavascriptFunctionRegion],
    guards: &[Range<usize>],
) -> bool {
    let header = &runtime[function.start..function.body.start];
    let Some(declaration) = FUNCTION_DECLARATION.captures(header) else {
        return false;
    };
    let before = runtime[..function.start].trim_end();
    if !is_body_level(before)
        || before.ends_with(|character: char| !matches!(character, ';' | '}'))
        || runtime[function.body.clone()].contains("=>")
        || functions
            .iter()
            .filter(|other| other.name == function.name)
            .count()
            != 1
    {
        return false;
    }
    let definition = function.start + declaration.get(1).expect("function name capture").start();
    let mut callers = 0;
    for token in IDENTIFIER
        .find_iter(runtime)
        .filter(|token| token.as_str() == function.name)
    {
        if token.start() == definition {
            continue;
        }
        let before = runtime[..token.start()].trim_end();
        if before.ends_with('.') || !runtime[token.end()..].trim_start().starts_with('(') {
            return false;
        }
        if !guards.iter().any(|body| body.contains(&token.start())) {
            return false;
        }
        callers += 1;
    }
    callers > 0
}

fn handled_try_bodies(runtime: &str) -> Vec<Range<usize>> {
    TRY_BLOCK
        .find_iter(runtime)
        .filter_map(|matched| {
            let open = matched.end() - 1;
            let close = super::matching_delimiter(runtime, open, b'{', b'}')?;
            let body = &runtime[open + 1..close];
            if body.contains(['{', '}'])
                || body.contains("=>")
                || IDENTIFIER
                    .find_iter(body)
                    .any(|token| matches!(token.as_str(), "function" | "class"))
            {
                return None;
            }
            let catch_start =
                close + 1 + runtime[close + 1..].find(|c: char| !c.is_whitespace())?;
            let catch = runtime[catch_start..].strip_prefix("catch")?;
            if catch.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
                return None;
            }
            let mut catch_body = catch_start + "catch".len();
            catch_body += runtime[catch_body..].find(|c: char| !c.is_whitespace())?;
            if runtime.as_bytes()[catch_body] == b'(' {
                catch_body = super::matching_delimiter(runtime, catch_body, b'(', b')')? + 1;
                catch_body += runtime[catch_body..].find(|c: char| !c.is_whitespace())?;
            }
            let catch_end = super::matching_delimiter(runtime, catch_body, b'{', b'}')?;
            if IDENTIFIER
                .find_iter(&runtime[catch_body + 1..catch_end])
                .any(|token| token.as_str() == "throw")
            {
                return None;
            }
            Some(open + 1..close)
        })
        .collect()
}

fn is_body_level(prefix: &str) -> bool {
    let mut depth = 0usize;
    for byte in prefix.bytes() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                let Some(remaining) = depth.checked_sub(1) else {
                    return false;
                };
                depth = remaining;
            }
            _ => {}
        }
    }
    depth == 0
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::source_analysis_context::SourceAnalysisContext;

    fn parsing_findings(source: &str) -> Vec<String> {
        let sources = BTreeMap::from([("src/parser.ts".to_owned(), source.to_owned())]);
        super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.code.as_str(),
                    "ts-json-parse-unsafe" | "ts-localstorage-json"
                )
            })
            .map(|finding| finding.code)
            .collect()
    }

    #[test]
    fn accepts_private_synchronous_parsers_with_handled_callers() {
        for ending in [
            "try { decode(first); } catch (error) { respond(error); }\ntry { decode(second); } catch { reject(); }",
            "export async function route() { try { return decode(raw); } catch (error) { return failure(error); } }",
            "// decode(untrusted);\nconst sample = 'decode(untrusted)';\ntry { decode(raw); } catch (error) { reject(error); }",
            "client.eval('return 1');\ntry { decode(raw); } catch (error) { reject(error); }",
        ] {
            let source = format!(
                "import {{ z }} from 'zod';\nfunction decode(raw: string) {{\n if (!raw) {{ throw new Error('empty'); }}\n const decoded = JSON.parse(raw);\n return z.strictObject({{ name: z.string() }}).parse(decoded);\n}}\n{ending}"
            );
            assert!(parsing_findings(&source).is_empty(), "{source}");
        }
    }

    #[test]
    fn retains_unknown_and_deferred_parser_boundaries() {
        for (declaration, body, ending) in [
            ("function decode", "return JSON.parse(raw);", "decode(raw);"),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { decode(first); } catch {}\ndecode(second);",
            ),
            (
                "export function decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } catch {}",
            ),
            (
                "async function decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } catch {}",
            ),
            (
                "function* decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "const alias = decode;\ntry { alias(raw); } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { setTimeout(() => decode(raw)); } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { setTimeout(() => { decode(raw); }); } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { const later = (value = decode(raw)) => value; } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { function later(value = decode(raw)) {} } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { const object = { get value() { return decode(raw); } }; } catch {}",
            ),
            (
                "function decode",
                "return () => JSON.parse(raw);",
                "try { decode(raw); } catch {}",
            ),
            (
                "function decode",
                "return (value = JSON.parse(raw)) => value;",
                "try { decode(raw); } catch {}",
            ),
            (
                "function decode",
                "return { get value() { return JSON.parse(raw); } };",
                "try { decode(raw); } catch {}",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } finally { cleanup(); }",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } catch (error) { throw error; }",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } catch {}\nconst text = `${decode(raw)}`;",
            ),
            (
                "function decode",
                "return JSON.parse(raw);",
                "try { decode(raw); } catch {}\neval(code);",
            ),
            ("function decode", "return JSON.parse(raw);", ""),
        ] {
            let source = format!(
                "import {{ z }} from 'zod';\n{declaration}(raw: string) {{ {body} }}\n{ending}"
            );
            assert_eq!(
                parsing_findings(&source),
                ["ts-json-parse-unsafe"],
                "{source}"
            );
        }
        let script =
            "function decode(raw) { return JSON.parse(raw); }\ntry { decode(raw); } catch {}";
        assert_eq!(parsing_findings(script), ["ts-json-parse-unsafe"]);
    }

    #[test]
    fn requires_evidence_not_schema_names_and_preserves_storage_advice() {
        for name in ["safe", "schema", "zod", "validate"] {
            let source = format!("const {name} = JSON.parse(raw);");
            assert_eq!(
                parsing_findings(&source),
                ["ts-json-parse-unsafe"],
                "{source}"
            );
        }
        let source = "import { z } from 'zod';\nfunction decode() { return JSON.parse(localStorage.getItem('state')); }\ntry { decode(); } catch {}";
        assert_eq!(parsing_findings(source), ["ts-localstorage-json"]);
        let mixed = "import { z } from 'zod';\nfunction decode(raw) { return JSON.parse(raw); } const unchecked = JSON.parse(input);\ntry { decode(raw); } catch {}";
        assert_eq!(parsing_findings(mixed), ["ts-json-parse-unsafe"]);
    }
}
