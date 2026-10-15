use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use super::mask_javascript;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources
        .iter()
        .filter(|(path, _)| path.to_ascii_lowercase().ends_with(".svelte"))
    {
        let source = SvelteSource::new(path, source);
        async_on_mount(&source, &mut findings);
        global_listeners(&source, &mut findings);
        intervals(&source, &mut findings);
        dynamic_html(&source, &mut findings);
        unkeyed_animation(&source, &mut findings);
        module_browser_globals(&source, &mut findings);
    }
    findings
}

fn async_on_mount(source: &SvelteSource<'_>, findings: &mut Vec<Finding>) {
    for matched in ASYNC_ON_MOUNT.find_iter(&source.masked) {
        findings.push(finding(
            "svelte-async-onmount-cleanup",
            source,
            matched.start(),
            "onMount uses an async callback and cannot return cleanup synchronously",
            "high",
        ));
    }
}

fn global_listeners(source: &SvelteSource<'_>, findings: &mut Vec<Finding>) {
    for captures in ADD_EVENT_LISTENER.captures_iter(&source.masked) {
        let target = captures
            .get(1)
            .expect("listener target must exist")
            .as_str();
        let removal = Regex::new(&format!(
            r"\b{}\.removeEventListener\s*\(",
            regex::escape(target)
        ))
        .expect("listener removal regex must compile");
        if removal.is_match(&source.masked) {
            continue;
        }
        let matched = captures.get(0).expect("listener match must exist");
        findings.push(finding(
            "svelte-global-listener-without-cleanup",
            source,
            matched.start(),
            &format!("{target}.addEventListener has no matching removal in this component"),
            "high",
        ));
        break;
    }
}

fn intervals(source: &SvelteSource<'_>, findings: &mut Vec<Finding>) {
    let Some(interval) = SET_INTERVAL.find(&source.masked) else {
        return;
    };
    if CLEAR_INTERVAL.is_match(&source.masked) {
        return;
    }
    findings.push(finding(
        "svelte-interval-without-cleanup",
        source,
        interval.start(),
        "setInterval has no matching clearInterval in this component",
        "high",
    ));
}

fn dynamic_html(source: &SvelteSource<'_>, findings: &mut Vec<Finding>) {
    for captures in DYNAMIC_HTML.captures_iter(&source.masked) {
        let expression = captures
            .get(1)
            .expect("dynamic HTML expression must exist")
            .as_str()
            .trim();
        if expression.is_empty() || TRUSTED_HTML.is_match(expression) {
            continue;
        }
        let matched = captures.get(0).expect("dynamic HTML match must exist");
        findings.push(finding(
            "svelte-dynamic-html",
            source,
            matched.start(),
            &format!("{{@html}} renders dynamic content from `{expression}`"),
            "medium",
        ));
    }
}

fn unkeyed_animation(source: &SvelteSource<'_>, findings: &mut Vec<Finding>) {
    for captures in EACH_START.captures_iter(&source.masked) {
        let header = captures
            .get(1)
            .expect("each header must exist")
            .as_str()
            .trim();
        if KEYED_EACH.is_match(header) {
            continue;
        }
        let matched = captures.get(0).expect("each match must exist");
        let remainder = &source.masked[matched.end()..];
        let Some(close) = remainder.find("{/each}") else {
            continue;
        };
        if !ANIMATE_DIRECTIVE.is_match(&remainder[..close]) {
            continue;
        }
        findings.push(finding(
            "svelte-animate-unkeyed-each",
            source,
            matched.start(),
            "an animated each block has no stable key expression",
            "high",
        ));
    }
}

fn module_browser_globals(source: &SvelteSource<'_>, findings: &mut Vec<Finding>) {
    for opening in MODULE_SCRIPT.find_iter(&source.comment_masked) {
        let remainder = &source.comment_masked[opening.end()..];
        let Some(close) = remainder.find("</script>") else {
            continue;
        };
        let body = &source.masked[opening.end()..opening.end() + close];
        for browser_global in BROWSER_GLOBAL.find_iter(body) {
            let absolute = opening.end() + browser_global.start();
            let line_start = source.masked[..absolute]
                .rfind('\n')
                .map_or(0, |offset| offset + 1);
            let prefix = &source.masked[line_start..absolute];
            if GUARDED_BROWSER_GLOBAL.is_match(prefix) {
                continue;
            }
            findings.push(finding(
                "svelte-module-browser-global",
                source,
                absolute,
                "module script accesses a browser-only global during initialization",
                "high",
            ));
            break;
        }
    }
}

struct SvelteSource<'a> {
    path: &'a str,
    source: &'a str,
    comment_masked: String,
    masked: String,
}

impl<'a> SvelteSource<'a> {
    fn new(path: &'a str, source: &'a str) -> Self {
        Self {
            path,
            source,
            comment_masked: mask_javascript(source, false, true),
            masked: mask_javascript(source, true, true),
        }
    }

    fn line_at(&self, offset: usize) -> usize {
        self.source.as_bytes()[..offset]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1
    }
}

fn finding(
    code: &str,
    source: &SvelteSource<'_>,
    offset: usize,
    message: &str,
    confidence: &str,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Svelte rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: source.path.to_owned(),
        line: source.line_at(offset),
        end_line: 0,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static ASYNC_ON_MOUNT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bonMount\s*\(\s*async\b").unwrap());
static ADD_EVENT_LISTENER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(window|document)\.addEventListener\s*\(").unwrap());
static SET_INTERVAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bsetInterval\s*\(").unwrap());
static CLEAR_INTERVAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclearInterval\s*\(").unwrap());
static DYNAMIC_HTML: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{@html\s+([^}]+)\}").unwrap());
static TRUSTED_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:DOMPurify\.)?sanitize\s*\(|^trusted(?:Html|Markup)\b").unwrap()
});
static EACH_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{#each\s+([^}\n]+)\}").unwrap());
static KEYED_EACH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\([^()]+\)\s*$").unwrap());
static ANIMATE_DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\banimate:[A-Za-z_$]").unwrap());
static MODULE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<script\b([^>]*(?:\bmodule\b|context\s*=\s*["']module["'])[^>]*)>"#).unwrap()
});
static BROWSER_GLOBAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:window|document|localStorage|sessionStorage)\b").unwrap());
static GUARDED_BROWSER_GLOBAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:typeof|browser\s*(?:&&|\?))\s*$").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn reports_complete_svelte_rule_family() {
        let source = r#"<script module>
  const width = window.innerWidth;
</script>
<script lang="ts">
  import { onMount } from 'svelte';
  import { flip } from 'svelte/animate';
  let content = $state('');
  onMount(async () => {
    window.addEventListener('resize', resize);
    setInterval(refresh, 1000);
    await refresh();
    return () => refresh();
  });
</script>
{#each rows as row}
  <div animate:flip>{row.name}</div>
{/each}
<section>{@html content}</section>"#;
        let findings = analyze(&BTreeMap::from([(
            "src/Panel.svelte".to_owned(),
            source.to_owned(),
        )]));
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "svelte-animate-unkeyed-each",
                "svelte-async-onmount-cleanup",
                "svelte-dynamic-html",
                "svelte-global-listener-without-cleanup",
                "svelte-interval-without-cleanup",
                "svelte-module-browser-global",
            ])
        );
        assert_eq!(findings.len(), 6);
    }

    #[test]
    fn accepts_cleanup_keys_trusted_html_guards_comments_and_strings() {
        let source = r#"<script module>
  export const prerender = true;
  const width = typeof window;
</script>
<script>
  import { onMount } from 'svelte';
  onMount(() => {
    window.addEventListener('resize', resize);
    const timer = setInterval(refresh, 1000);
    const example = "document.addEventListener('click', click)";
    return () => {
      window.removeEventListener('resize', resize);
      clearInterval(timer);
    };
  });
  // onMount(async () => setInterval(work, 1));
</script>
<!-- {@html content} -->
{#each rows as row (row.id)}
  <div animate:flip>{row.name}</div>
{/each}
<section>{@html sanitize(content)}</section>"#;
        assert!(
            analyze(&BTreeMap::from([(
                "src/Panel.svelte".to_owned(),
                source.to_owned()
            )]))
            .is_empty()
        );
    }
}
