use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use super::mask_javascript;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let pixi_v8 = is_pixi_v8(context.auxiliary_files());
    let mut findings = Vec::new();
    for (path, source) in context
        .sources()
        .iter()
        .filter(|(path, _)| is_javascript_path(path))
    {
        let source = PixiSource::new(path, source);
        if pixi_v8 {
            legacy_interactive(&source, &mut findings);
            legacy_cache(&source, &mut findings);
            unawaited_init(&source, &mut findings);
            numeric_ticker_delta(&source, &mut findings);
        }
        ticker_removal(&source, &mut findings);
        frame_allocations(&source, &mut findings);
    }
    findings
}

fn is_javascript_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn is_pixi_v8(auxiliary_files: &BTreeMap<String, String>) -> bool {
    auxiliary_files.iter().any(|(path, source)| {
        path.to_ascii_lowercase().ends_with("package.json") && PIXI_V8_DEPENDENCY.is_match(source)
    })
}

fn legacy_interactive(source: &PixiSource<'_>, findings: &mut Vec<Finding>) {
    for matched in LEGACY_INTERACTIVE.find_iter(&source.masked) {
        findings.push(finding(
            "pixijs-v8-legacy-interactive",
            source,
            matched.start(),
            "legacy interactive=true is used with PixiJS v8",
            "high",
        ));
    }
}

fn legacy_cache(source: &PixiSource<'_>, findings: &mut Vec<Finding>) {
    for matched in LEGACY_CACHE.find_iter(&source.masked) {
        findings.push(finding(
            "pixijs-v8-cache-as-bitmap",
            source,
            matched.start(),
            "cacheAsBitmap is a legacy API in PixiJS v8",
            "high",
        ));
    }
}

fn unawaited_init(source: &PixiSource<'_>, findings: &mut Vec<Finding>) {
    let applications = APPLICATION_DECLARATION
        .captures_iter(&source.masked)
        .filter_map(|captures| captures.get(1).map(|name| name.as_str()))
        .collect::<Vec<_>>();
    for application in applications {
        for captures in INIT_CALL.captures_iter(&source.masked) {
            let name = captures.get(1).expect("init receiver must exist").as_str();
            if name != application {
                continue;
            }
            let matched = captures.get(0).expect("init call must exist");
            let line_start = source.masked[..matched.start()]
                .rfind('\n')
                .map_or(0, |offset| offset + 1);
            if AWAIT_PREFIX.is_match(&source.masked[line_start..matched.start()]) {
                continue;
            }
            findings.push(finding(
                "pixijs-v8-unawaited-application-init",
                source,
                matched.start(),
                &format!("{name}.init is not awaited"),
                "high",
            ));
        }
    }
}

fn numeric_ticker_delta(source: &PixiSource<'_>, findings: &mut Vec<Finding>) {
    for captures in INLINE_TICKER_CALLBACK.captures_iter(&source.masked) {
        let parameter = captures
            .get(1)
            .expect("ticker callback parameter must exist")
            .as_str();
        let matched = captures.get(0).expect("ticker callback must exist");
        let tail_end = floor_char_boundary(
            &source.masked,
            (matched.end() + 600).min(source.masked.len()),
        );
        let tail = &source.masked[matched.end()..tail_end];
        if TICKER_TIMING.captures_iter(tail).any(|property| {
            property
                .get(1)
                .is_some_and(|receiver| receiver.as_str() == parameter)
        }) {
            continue;
        }
        let used_as_number = NUMERIC_ASSIGNMENT.captures_iter(tail).any(|operation| {
            operation
                .get(1)
                .or_else(|| operation.get(2))
                .is_some_and(|operand| operand.as_str() == parameter)
        });
        if !used_as_number {
            continue;
        }
        findings.push(finding(
            "pixijs-v8-numeric-ticker-delta",
            source,
            matched.start(),
            &format!("ticker callback parameter `{parameter}` is used as a numeric delta"),
            "high",
        ));
    }
}

fn ticker_removal(source: &PixiSource<'_>, findings: &mut Vec<Finding>) {
    let removals = TICKER_REMOVE
        .captures_iter(&source.masked)
        .filter_map(|captures| {
            let receiver = captures.get(1)?.as_str();
            let handler = captures.get(2)?.as_str();
            Some((receiver, handler))
        })
        .collect::<BTreeSet<_>>();
    for captures in TICKER_ADD.captures_iter(&source.masked) {
        let receiver = captures
            .get(1)
            .expect("ticker receiver must exist")
            .as_str();
        let handler = captures.get(2).expect("ticker handler must exist").as_str();
        if removals.contains(&(receiver, handler)) {
            continue;
        }
        let matched = captures.get(0).expect("ticker add must exist");
        findings.push(finding(
            "pixijs-ticker-listener-without-removal",
            source,
            matched.start(),
            &format!("{receiver}.ticker.add({handler}) has no matching removal"),
            "medium",
        ));
    }
}

fn frame_allocations(source: &PixiSource<'_>, findings: &mut Vec<Finding>) {
    for callback in FRAME_CALLBACK.find_iter(&source.masked) {
        let Some(opening) = source.masked[callback.start()..]
            .find('{')
            .map(|offset| callback.start() + offset)
        else {
            continue;
        };
        let Some(close) = matching_brace(&source.masked, opening) else {
            continue;
        };
        let Some(created) = DISPLAY_OBJECT_ALLOCATION.captures(&source.masked[opening + 1..close])
        else {
            continue;
        };
        let object_type = created
            .get(1)
            .expect("display object type must exist")
            .as_str();
        let matched = created
            .get(0)
            .expect("display object allocation must exist");
        findings.push(finding(
            "pixijs-frame-loop-allocation",
            source,
            opening + 1 + matched.start(),
            &format!("ticker callback allocates a new {object_type} every frame"),
            "high",
        ));
    }
}

struct PixiSource<'a> {
    path: &'a str,
    source: &'a str,
    masked: String,
}

impl<'a> PixiSource<'a> {
    fn new(path: &'a str, source: &'a str) -> Self {
        Self {
            path,
            source,
            masked: mask_javascript(source, true, false),
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

fn matching_brace(source: &str, opening: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[opening..].iter().enumerate() {
        if *byte == b'{' {
            depth += 1;
        } else if *byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(opening + offset);
            }
        }
    }
    None
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn finding(
    code: &str,
    source: &PixiSource<'_>,
    offset: usize,
    message: &str,
    confidence: &str,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("PixiJS rule metadata must exist");
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

static PIXI_V8_DEPENDENCY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'](?:pixi\.js|@pixi/[^"']+)["']\s*:\s*["'][^"']*\b8(?:\.|["'])"#).unwrap()
});
static LEGACY_INTERACTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.[ \t]*interactive\s*=\s*true\b").unwrap());
static LEGACY_CACHE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.cacheAsBitmap\b").unwrap());
static APPLICATION_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+Application\b").unwrap()
});
static INIT_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\.init\s*\(").unwrap());
static AWAIT_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bawait\s*$").unwrap());
static INLINE_TICKER_CALLBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.ticker\.add\s*\(\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>").unwrap()
});
static TICKER_TIMING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\.(?:deltaTime|deltaMS|elapsedMS)\b").unwrap()
});
static NUMERIC_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[+*\-/]=\s*([A-Za-z_$][\w$]*)\b|\b([A-Za-z_$][\w$]*)\s*[*\-/])").unwrap()
});
static TICKER_ADD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\.ticker\.add\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]").unwrap()
});
static TICKER_REMOVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\.ticker\.remove\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]").unwrap()
});
static FRAME_CALLBACK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.ticker\.add\s*\([^=]*=>\s*\{").unwrap());
static DISPLAY_OBJECT_ALLOCATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+(Graphics|Text|Sprite|Container)\s*\(").unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str, version: &str) -> Vec<Finding> {
        let sources = BTreeMap::from([("src/game.ts".to_owned(), source.to_owned())]);
        let auxiliary = BTreeMap::from([(
            "package.json".to_owned(),
            format!(r#"{{"dependencies":{{"pixi.js":"{version}"}}}}"#),
        )]);
        let empty_sources = BTreeMap::new();
        let empty_paths = BTreeSet::new();
        analyze(&SourceAnalysisContext::with_auxiliary(
            &sources,
            &empty_sources,
            &empty_paths,
            false,
            &auxiliary,
        ))
    }

    #[test]
    fn reports_complete_pixijs_rule_family() {
        let source = r#"import { Application, Graphics, Text } from 'pixi.js';
const app = new Application();
app.init({ background: '#000' });
button.interactive = true;
world.cacheAsBitmap = true;
function update() {}
app.ticker.add(update);
app.ticker.add((delta) => {
  player.x += delta;
  const graphics = new Graphics();
  const label = new Text({ text: 'score' });
  stage.addChild(graphics, label);
});"#;
        let findings = run(source, "^8.0.0");
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "pixijs-frame-loop-allocation",
                "pixijs-ticker-listener-without-removal",
                "pixijs-v8-cache-as-bitmap",
                "pixijs-v8-legacy-interactive",
                "pixijs-v8-numeric-ticker-delta",
                "pixijs-v8-unawaited-application-init",
            ])
        );
        assert_eq!(findings.len(), 6);
    }

    #[test]
    fn accepts_v8_apis_cleanup_and_retained_objects() {
        let source = r#"import { Application, Graphics } from 'pixi.js';
const app = new Application();
await app.init({ background: '#000' });
button.eventMode = 'static';
world.cacheAsTexture();
const graphics = new Graphics();
function update(ticker) {
  player.x += ticker.deltaTime;
  graphics.x = player.x;
}
app.ticker.add(update);
app.ticker.remove(update);
app.ticker.add((ticker) => {
  player.y += ticker.deltaTime;
});
// sprite.interactive = true;
const note = 'world.cacheAsBitmap = true';"#;
        assert!(run(source, "^8.0.0").is_empty());
    }

    #[test]
    fn ignores_incomplete_ticker_calls() {
        let source = r#"app.ticker.remove(
app.ticker.remove(update
app.ticker.add(
app.ticker.add(update"#;
        assert!(run(source, "^8.0.0").is_empty());
    }

    #[test]
    fn gates_migration_rules_on_explicit_v8_dependency() {
        let source = r#"const app = new Application();
app.init({});
sprite.interactive = true;
world.cacheAsBitmap = true;
app.ticker.add((delta) => { sprite.x += delta; });"#;
        assert!(run(source, "^7.4.0").is_empty());
    }
}
