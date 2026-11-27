use std::ops::Range;
use std::sync::LazyLock;

use crate::languages::functions::JavascriptFunctionRegion;
use regex::Regex;

static DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^function\s+([A-Za-z_$][\w$]*)\s*\(").expect("timer helper declaration regex")
});
static PROMISE_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*return\s+new\s+Promise(?:\s*<[^<>]+>)?\s*\(")
        .expect("timer helper promise regex")
});
static TIMER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(setTimeout|setImmediate)\s*\(").expect("timer helper scheduler regex")
});
static HANDLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*$").expect("timer handle binding regex")
});
static SIGNAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\??\s*:\s*AbortSignal\b")
        .expect("abort signal parameter regex")
});
static CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
        .expect("timer helper call regex")
});
static UNKNOWN_INVOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\?\.|[\]\)>])\s*\(").expect("indirect helper invocation regex")
});

pub(super) fn awaited_lines(
    source: &str,
    syntax: &str,
    functions: &[JavascriptFunctionRegion],
) -> Vec<usize> {
    if !syntax.contains("Promise") || !super::unshadowed_global(syntax, "Promise") {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for function in functions {
        let Some(name) = helper_definition(source, syntax, function, functions) else {
            continue;
        };
        let definition = function.start + name.start();
        let references = super::super::JAVASCRIPT_IDENTIFIERS
            .find_iter(syntax)
            .filter(|token| token.as_str() == name.as_str() && token.start() != definition);
        let previous_lines = lines.len();
        for token in references {
            if syntax[..token.start()].trim_end().ends_with('.')
                || !syntax[token.end()..].trim_start().starts_with('(')
            {
                lines.truncate(previous_lines);
                break;
            }
            if let Some(line) = standalone_await_line(syntax, token) {
                lines.push(line);
            }
        }
    }
    lines
}

fn standalone_await_line(syntax: &str, name: regex::Match<'_>) -> Option<usize> {
    let line_start = syntax[..name.start()].rfind('\n').map_or(0, |at| at + 1);
    if syntax[line_start..name.start()].trim() != "await" {
        return None;
    }
    let open = name.end() + syntax[name.end()..].find(|c: char| !c.is_whitespace())?;
    let close = super::super::matching_delimiter(syntax, open, b'(', b')')?;
    let tail = syntax[close + 1..].trim_start();
    if !tail.is_empty() && !tail.starts_with([';', '}']) {
        return None;
    }
    Some(
        syntax[..name.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
    )
}

fn helper_definition<'a>(
    source: &str,
    syntax: &'a str,
    function: &JavascriptFunctionRegion,
    functions: &[JavascriptFunctionRegion],
) -> Option<regex::Match<'a>> {
    let declaration = DECLARATION.captures(&syntax[function.start..function.body.start])?;
    let executor = wait_executor(source, syntax, function, functions)?;
    if !executor.is_wait(syntax)
        || !module_level(&syntax[..function.start])
        || syntax[..function.start].split_whitespace().next_back() == Some("async")
        || functions
            .iter()
            .filter(|other| other.name == function.name)
            .count()
            != 1
    {
        return None;
    }
    declaration.get(1)
}

fn wait_executor<'a>(
    source: &'a str,
    syntax: &'a str,
    function: &JavascriptFunctionRegion,
    functions: &'a [JavascriptFunctionRegion],
) -> Option<WaitExecutor<'a>> {
    let body = &syntax[function.body.clone()];
    let constructor = PROMISE_RETURN.find(body)?;
    let open = constructor.end() - 1;
    let close = super::super::matching_delimiter(body, open, b'(', b')')?;
    if !matches!(body[close + 1..].trim(), "" | ";") {
        return None;
    }
    let executor = body[open + 1..close].trim_end();
    let executor = executor.strip_suffix(',').unwrap_or(executor);
    let resolver = super::RESOLVER.captures(executor)?;
    let name = resolver.get(1).or_else(|| resolver.get(2))?.as_str();
    let mut timers = TIMER.captures_iter(executor);
    let timer = timers.next()?;
    if timers.next().is_some() || !super::unshadowed_global(syntax, timer.get(1)?.as_str()) {
        return None;
    }
    let handle = HANDLE
        .captures(&executor[..timer.get(0)?.start()])
        .and_then(|value| value.get(1))
        .map(|value| value.as_str());
    let signal = SIGNAL
        .captures(&syntax[function.start..function.body.start])
        .and_then(|value| value.get(1))
        .map(|value| value.as_str());
    let offset = function.body.start + open + 1;
    Some(WaitExecutor {
        syntax: executor,
        source: &source[offset..offset + executor.len()],
        offset,
        body_start: resolver.get(0)?.end(),
        resolver: name,
        handle,
        signal,
        functions,
    })
}

struct WaitExecutor<'a> {
    syntax: &'a str,
    source: &'a str,
    offset: usize,
    body_start: usize,
    resolver: &'a str,
    handle: Option<&'a str>,
    signal: Option<&'a str>,
    functions: &'a [JavascriptFunctionRegion],
}

impl WaitExecutor<'_> {
    fn is_wait(&self, file: &str) -> bool {
        let body_start = self.body_start;
        let body = &self.syntax[body_start..];
        if UNKNOWN_INVOCATION.is_match(body)
            || self.source[body_start..].contains('`')
            || !self.resolver_is_stable(body_start)
        {
            return false;
        }
        if self.signal.is_some()
            && super::super::JAVASCRIPT_IDENTIFIERS
                .find_iter(file)
                .filter(|token| token.as_str() == "AbortSignal")
                .any(|token| !file[..token.start()].trim_end().ends_with(':'))
        {
            return false;
        }
        if super::super::JAVASCRIPT_IDENTIFIERS
            .find_iter(body)
            .any(|token| {
                matches!(
                    token.as_str(),
                    "await"
                        | "yield"
                        | "for"
                        | "while"
                        | "do"
                        | "switch"
                        | "throw"
                        | "try"
                        | "catch"
                        | "new"
                        | "function"
                        | "class"
                )
            })
        {
            return false;
        }
        if body.contains("clearTimeout") && !super::unshadowed_global(file, "clearTimeout") {
            return false;
        }
        CALL.captures_iter(body).all(|call| {
            let matched = call.get(0).expect("executor call capture");
            let open = body_start + matched.end() - 1;
            let Some(close) = super::super::matching_delimiter(self.syntax, open, b'(', b')')
            else {
                return false;
            };
            self.allowed_call(&call[1], open + 1..close)
        })
    }

    fn resolver_is_stable(&self, body_start: usize) -> bool {
        super::super::JAVASCRIPT_IDENTIFIERS
            .find_iter(&self.syntax[body_start..])
            .filter(|token| token.as_str() == self.resolver)
            .all(|token| {
                let start = body_start + token.start();
                let end = body_start + token.end();
                self.syntax[end..].trim_start().starts_with('(')
                    || self.syntax[..start]
                        .trim_end()
                        .strip_suffix('(')
                        .is_some_and(|prefix| {
                            matches!(
                                super::trailing_identifier(prefix.trim_end()),
                                "setTimeout" | "setImmediate"
                            )
                        })
            })
    }

    fn allowed_call(&self, callee: &str, arguments: Range<usize>) -> bool {
        let args = &self.syntax[arguments.clone()];
        if callee == "if" {
            return true;
        }
        if callee == self.resolver {
            return args.trim().is_empty();
        }
        match callee {
            "setTimeout" | "setImmediate" => {
                let callback = args.split_once(',').map_or(args, |(first, _)| first).trim();
                callback == self.resolver || resolver_callback(callback, self.resolver)
            }
            "clearTimeout" => self.handle.is_some_and(|handle| args.trim() == handle),
            _ => self.abort_listener(callee, arguments),
        }
    }

    fn abort_listener(&self, callee: &str, arguments: Range<usize>) -> bool {
        let Some(signal) = self.signal else {
            return false;
        };
        let Some((owner, method)) = callee.rsplit_once('.') else {
            return false;
        };
        if owner.trim_end().trim_end_matches('?').trim() != signal
            || method.trim() != "addEventListener"
        {
            return false;
        }
        let Some((event, _)) = self.source[arguments.clone()].split_once(',') else {
            return false;
        };
        if !matches!(event.trim(), "\"abort\"" | "'abort'") {
            return false;
        }
        let Some((_, remaining)) = self.syntax[arguments].split_once(',') else {
            return false;
        };
        let handler = remaining.split(',').next().unwrap_or_default().trim();
        let uses = super::super::JAVASCRIPT_IDENTIFIERS
            .find_iter(self.syntax)
            .filter(|token| token.as_str() == handler)
            .count();
        uses == 2
            && self.functions.iter().any(|function| {
                function.name == handler
                    && function.start >= self.offset
                    && function.body.start >= self.offset
                    && function.body.end < self.offset + self.syntax.len()
                    && self.syntax[function.start - self.offset..function.body.start - self.offset]
                        .trim_start()
                        .starts_with("const ")
                    && CALL
                        .captures_iter(
                            &self.syntax[function.body.start - self.offset
                                ..function.body.end - self.offset],
                        )
                        .any(|call| {
                            call.get(1)
                                .is_some_and(|callee| callee.as_str() == self.resolver)
                        })
            })
    }
}

fn resolver_callback(callback: &str, resolver: &str) -> bool {
    let Some(body) = callback.strip_prefix("()") else {
        return false;
    };
    let Some(body) = body.trim_start().strip_prefix("=>") else {
        return false;
    };
    let body = body.trim();
    let body = body
        .strip_prefix('{')
        .and_then(|body| body.strip_suffix('}'))
        .unwrap_or(body)
        .trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    body.strip_prefix(resolver)
        .is_some_and(|suffix| suffix.trim() == "()")
}

fn module_level(prefix: &str) -> bool {
    let mut depth = 0i64;
    for byte in prefix.bytes() {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
    }
    depth == 0
}

#[cfg(test)]
mod tests {
    use crate::source_analysis_context::SourceAnalysisContext;
    use std::collections::BTreeMap;

    fn findings(source: &str) -> Vec<crate::findings::Finding> {
        let sources = BTreeMap::from([("src/retry.ts".to_owned(), source.to_owned())]);
        super::super::super::analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .filter(|finding| finding.code == "ts-await-in-loop")
            .collect()
    }

    const WAIT: &str = "function holdOff(ms: number, signal?: AbortSignal): Promise<void> {\nreturn new Promise(resolve => {\nif (signal?.aborted) { resolve(); return; }\nconst timer = setTimeout(() => { resolve(); }, ms);\nconst cancel = () => { clearTimeout(timer); resolve(); };\nsignal?.addEventListener('abort', cancel, { once: true });\n});\n}\nasync function run() {\nfor (const attempt of attempts) {\nawait holdOff(delays[attempt], signal);\n}\n}";

    #[test]
    fn accepts_abort_aware_timer_helpers_without_relying_on_their_names() {
        assert!(findings(WAIT).is_empty());
        assert!(findings(&WAIT.replace("holdOff", "awaitBudget")).is_empty());
        assert!(findings(&WAIT.replace('\n', "\r\n")).is_empty());
        let simple = "function holdOff(ms) { return new Promise(done => setTimeout(done, ms)); }\nasync function run() {\nfor (const item of items) {\nawait holdOff(delay);\n}\n}";
        assert!(findings(simple).is_empty());
    }

    #[test]
    fn retains_helpers_with_work_unknown_callbacks_or_ambiguous_bindings() {
        for source in [
            WAIT.replace("const timer =", "sendRequest();\nconst timer ="),
            WAIT.replace("const timer =", "sendRequest?.();\nconst timer ="),
            WAIT.replace("const timer =", "jobs[index]();\nconst timer ="),
            WAIT.replace("const timer =", "sendRequest<T>();\nconst timer ="),
            WAIT.replace(
                "const timer =",
                "const resolve = sendRequest;\nconst timer =",
            ),
            format!("class AbortSignal {{}}\n{WAIT}"),
            WAIT.replace("resolve(); }, ms", "sendRequest(); }, ms"),
            WAIT.replace(
                "clearTimeout(timer); resolve();",
                "sendRequest(); resolve();",
            ),
            WAIT.replace("'abort'", "'message'"),
            WAIT.replace("signal?: AbortSignal", "signal?: CustomSignal"),
            WAIT.replace("}, ms);", "}, ms);\nwhile (active) {}"),
            WAIT.replace("async function run()", "async function run(holdOff)"),
            format!("const setTimeout = enqueueJob;\n{WAIT}"),
            format!("{WAIT}\nconst alias = holdOff;"),
            WAIT.replace(
                "signal?.addEventListener('abort', cancel, { once: true });",
                "{ const cancel = sendRequest; signal?.addEventListener('abort', cancel, { once: true }); }",
            ),
            WAIT.replace(
                "await holdOff(delays[attempt], signal);",
                "await holdOff(delays[attempt], signal).then(runJob);",
            ),
        ] {
            let found = findings(&source);
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].confidence, "medium");
        }
    }

    #[test]
    fn does_not_exempt_work_merely_named_like_a_wait() {
        let source = "async function retryStep(value) { return send(value); }\nasync function run() {\nfor (const item of items) {\n// await holdOff(delay);\nconst sample = 'return new Promise(done => setTimeout(done, ms))';\nawait retryStep(item);\n}\n}";
        let found = findings(source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 6);
        assert_eq!(found[0].path, "src/retry.ts");
    }
}
