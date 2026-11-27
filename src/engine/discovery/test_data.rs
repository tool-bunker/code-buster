use super::*;
use crate::function_sources::{
    javascript_relative_imports, mask_javascript_strings_and_comments, relative_javascript_module,
};

pub(super) fn classify(discovery: &mut Discovery) -> Result<(), String> {
    let candidates = discovery
        .sources
        .iter()
        .filter(|(path, source)| {
            data_module_stem(path).is_some()
                && !matches_any(path, &discovery.production)
                && is_literal_data(source)
        })
        .map(|(path, _)| path.as_str())
        .collect::<BTreeSet<_>>();
    if candidates.is_empty() {
        return Ok(());
    }
    let Some(inferred) = test_only_modules(discovery, &candidates)? else {
        return Ok(());
    };
    if !discovery.config.include_tests && !discovery.config.include_all {
        discovery.files.retain(|file| {
            if inferred.contains(&file.path) {
                discovery.excluded_source_files.push(file.clone());
                false
            } else {
                true
            }
        });
        discovery.sources.retain(|path, _| !inferred.contains(path));
        if !inferred.is_empty() {
            *discovery.coverage.entry("selected".to_owned()).or_default() -= inferred.len();
            *discovery.coverage.entry("test".to_owned()).or_default() += inferred.len();
        }
    }
    discovery.inferred_test_files = inferred;
    Ok(())
}

fn test_only_modules(
    discovery: &Discovery,
    candidates: &BTreeSet<&str>,
) -> Result<Option<BTreeSet<String>>, String> {
    let mut test_imports = BTreeSet::new();
    let mut production_mentions = BTreeSet::new();
    let mut stems = BTreeMap::<&str, Vec<&str>>::new();
    for path in candidates {
        stems.entry(module_stem(path)).or_default().push(path);
    }
    for (path, source) in discovery.sources.iter().filter(|(path, _)| is_script(path)) {
        if is_test(discovery, path) {
            collect_test_imports(path, source, candidates, &mut test_imports);
            continue;
        }
        if !collect_runtime_references(path, source, &stems, &mut production_mentions) {
            return Ok(None);
        }
    }
    for file in &discovery.excluded_source_files {
        if !is_script(&file.path) || !is_test(discovery, &file.path) {
            continue;
        }
        let source = fs::read_to_string(discovery.config.root.join(&file.path))
            .map_err(|error| format!("failed to read test imports from {}: {error}", file.path))?;
        collect_test_imports(&file.path, &source, candidates, &mut test_imports);
    }
    Ok(Some(
        test_imports
            .difference(&production_mentions)
            .map(|path| (*path).to_owned())
            .collect(),
    ))
}

fn collect_runtime_references<'a>(
    path: &str,
    source: &str,
    stems: &BTreeMap<&str, Vec<&'a str>>,
    references: &mut BTreeSet<&'a str>,
) -> bool {
    if has_unknown_loader(source) {
        return false;
    }
    let specifiers = crate::dependency_graph::javascript_specifiers(source);
    let reads = FILE_READ_REFERENCE
        .captures_iter(source)
        .filter_map(|capture| capture.get(1).map(|reference| reference.as_str()));
    for reference in specifiers
        .iter()
        .map(String::as_str)
        .chain(javascript_relative_imports(source))
        .chain(reads)
    {
        if reference.contains('\\') {
            return false;
        }
        let reference = reference.split(['?', '#']).next().unwrap_or_default();
        if let Some(targets) = stems.get(module_stem(reference)) {
            references.extend(targets.iter().copied().filter(|target| *target != path));
        }
    }
    true
}

fn has_unknown_loader(source: &str) -> bool {
    if !DYNAMIC_MODULE_LOAD.is_match(source)
        && !source.contains("import.meta.glob")
        && !source.contains("require.context")
    {
        return false;
    }
    if source.contains('`') {
        return true;
    }
    let code = mask_javascript_strings_and_comments(source);
    code.contains("import.meta.glob")
        || code.contains("require.context")
        || DYNAMIC_MODULE_LOAD.find_iter(source).any(|matched| {
            code.as_bytes().get(matched.start()) == source.as_bytes().get(matched.start())
        })
}

fn is_script(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some(
            "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" | "svelte" | "vue" | "html"
        )
    )
}

fn is_test(discovery: &Discovery, path: &str) -> bool {
    !matches_any(path, &discovery.production)
        && (matches_any(path, &discovery.classified_test)
            || classify_file_role(path, &discovery.policy) == SourceRole::Test)
}

fn collect_test_imports<'a>(
    path: &str,
    source: &str,
    candidates: &BTreeSet<&'a str>,
    imports: &mut BTreeSet<&'a str>,
) {
    for import in javascript_relative_imports(source) {
        let Some(base) = relative_javascript_module(path, import) else {
            continue;
        };
        if let Some(target) = candidates.get(base.as_str()) {
            imports.insert(*target);
            continue;
        }
        for extension in ["js", "mjs", "cjs", "ts", "mts", "cts"] {
            if let Some(target) = candidates.get(format!("{base}.{extension}").as_str()) {
                imports.insert(*target);
            }
        }
    }
}

fn module_stem(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

fn data_module_stem(path: &str) -> Option<&str> {
    let (name, extension) = path.rsplit_once('.')?;
    if !matches!(extension, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts") {
        return None;
    }
    let stem = name.rsplit('/').next()?;
    DATA_MODULE_NAME.is_match(stem).then_some(stem)
}

fn is_literal_data(source: &str) -> bool {
    if !source.contains("export") || source.contains('`') {
        return false;
    }
    let masked = mask_javascript_strings_and_comments(source);
    let mut found = false;
    for statement in masked
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some(declaration) = DATA_DECLARATION.find(statement) else {
            return false;
        };
        let opening = declaration.end() - 1;
        let delimiter = statement.as_bytes()[opening];
        let closing = if delimiter == b'{' { b'}' } else { b']' };
        let Some(end) =
            crate::trivial_wrappers::matching_delimiter(statement, opening, delimiter, closing)
        else {
            return false;
        };
        if !statement[end + 1..].trim().is_empty() {
            return false;
        }
        let body = &statement[declaration.end()..];
        if body.contains([
            '(', ')', '+', '*', '/', '=', '<', '>', '!', '&', '|', '?', '%',
        ]) || body.contains("...")
            || !DATA_IDENTIFIER.find_iter(body).all(|token| {
                matches!(token.as_str(), "true" | "false" | "null")
                    || body[token.end()..].trim_start().starts_with(':')
            })
        {
            return false;
        }
        found = true;
    }
    found
}

static DATA_MODULE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:sample|mock|fixture)(?:s?$|[A-Z_-].*)").expect("data module name regex")
});
static DATA_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^export\s+const\s+[A-Za-z_$][\w$]*\s*=\s*[\[{]").expect("data declaration regex")
});
static DATA_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_$][\w$]*").expect("data identifier regex"));
static FILE_READ_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:from|(?:readFile(?:Sync)?|createReadStream|readTextFile)\s*\()\s*["']([^"'\\\r\n]+)["']"#)
        .expect("file read reference regex")
});
static DYNAMIC_MODULE_LOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:import|require)\s*\(\s*[^\s"']"#).expect("dynamic module load regex")
});

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("temporary repository");
        fs::create_dir_all(root.path().join("src/state")).expect("source directory");
        fs::create_dir_all(root.path().join("src/testData")).expect("test data directory");
        for (path, source) in [
            (
                "src/state/sampleEvents.js",
                "export const events = { time: 1650125095862, nested: [true, null, -1.5] };",
            ),
            (
                "src/state/samples.js",
                "export const events = [{ time: 1650125095863 }];",
            ),
            (
                "src/state/sampleShared.js",
                "export const events = { time: 1650125095864 };",
            ),
            (
                "src/state/sampleWorker.js",
                "export const events = { time: loadClock() };",
            ),
            (
                "src/state/sampleQuoted.js",
                "export const events = { time: 1650125095865 };",
            ),
            (
                "src/state/runtime.js",
                "export const events = { time: 1650125095866 };",
            ),
            (
                "src/testData/diagrams.js",
                "export const diagram = { time: 1650125095867 };",
            ),
            (
                "src/main.js",
                "import { events } from 'state/sampleShared';\nexport { events } from './state/runtime';",
            ),
            (
                "src/state/mapper.test.js",
                r#"import {
    events
} from "./sampleEvents";
import { events as samples } from "./samples.js";
import { events as shared } from "./sampleShared";
import { events as worker } from "./sampleWorker";
import { events as runtime } from "./runtime";
// import { events as quoted } from "./sampleQuoted";
const documentation = `
import { events as quoted } from "./sampleQuoted";
`;
const pattern = /import { events } from ".\/sampleQuoted"/;
describe("mapper", () => { consume(events, samples, shared, worker, runtime); });
"#,
            ),
        ] {
            fs::write(root.path().join(path), source).expect("source fixture");
        }
        root
    }

    #[test]
    fn excludes_only_literal_sample_modules_with_real_test_only_imports() {
        let root = repository();
        let mut options = crate::options::PreviewOptions {
            root: root.path().to_owned(),
            ..Default::default()
        };
        let prepared = prepare(&options).expect("default discovery");
        assert_eq!(
            prepared
                .sources
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "src/main.js",
                "src/state/runtime.js",
                "src/state/sampleQuoted.js",
                "src/state/sampleShared.js",
                "src/state/sampleWorker.js",
            ]
        );
        assert_eq!(prepared.coverage.get("test"), Some(&4));
        assert_eq!(
            prepared.inferred_test_files,
            BTreeSet::from([
                "src/state/sampleEvents.js".to_owned(),
                "src/state/samples.js".to_owned(),
            ])
        );
        for (include_tests, include_all) in [(true, false), (false, true)] {
            options.include_tests = include_tests;
            options.include_all = include_all;
            let included = prepare(&options).expect("explicit test inclusion");
            for path in [
                "src/state/sampleEvents.js",
                "src/state/samples.js",
                "src/state/mapper.test.js",
                "src/testData/diagrams.js",
            ] {
                assert!(included.sources.contains_key(path), "{path}");
            }
            assert_eq!(included.inferred_test_files, prepared.inferred_test_files);
        }
        options.include_tests = false;
        options.include_all = false;
        fs::write(
            root.path().join("code-buster.toml"),
            "[classification]\nproduction = ['src/state/sampleEvents.js', 'src/testData/**']\n",
        )
        .expect("production classification");
        let overridden = prepare(&options).expect("production override");
        assert!(overridden.sources.contains_key("src/state/sampleEvents.js"));
        assert!(overridden.sources.contains_key("src/testData/diagrams.js"));
        assert!(!overridden.sources.contains_key("src/state/samples.js"));
    }

    #[test]
    fn retains_sample_data_when_runtime_loading_cannot_be_resolved() {
        for loader in [
            "const modules = import.meta.glob('./state/*.js');",
            "const modules = require.context('./state', true);",
            "const module = import(modulePath);",
            "const text = `${import(modulePath)}`;",
            "export { events } from './state/sampleEvents.js';",
            "const text = readFileSync('./state/sampleEvents.js?raw');",
        ] {
            let root = repository();
            fs::write(root.path().join("src/loader.js"), loader).expect("runtime loader");
            let prepared = prepare(&crate::options::PreviewOptions {
                root: root.path().to_owned(),
                ..Default::default()
            })
            .expect("runtime discovery");
            assert!(
                prepared.sources.contains_key("src/state/sampleEvents.js"),
                "{loader}"
            );
            assert!(
                !prepared
                    .inferred_test_files
                    .contains("src/state/sampleEvents.js"),
                "{loader}"
            );
        }
    }
    #[test]
    fn does_not_treat_other_languages_or_coverage_lists_as_module_loading() {
        let root = tempfile::tempdir().expect("temporary repository");
        fs::create_dir_all(root.path().join("src")).expect("source directory");
        for (name, source) in [
            (
                "sampleEvents.js",
                "export const events = { time: 1650125095862 };",
            ),
            ("mapper.test.js", "import { events } from './sampleEvents';"),
            (
                "Decision.java",
                "class Decision { void validate(boolean valid) { require(valid); } }",
            ),
            (
                "coverage.js",
                r#"const excludedFiles = ["sampleEvents.js"];
const documentation = "import(modulePath)";
// import(modulePath)
"#,
            ),
        ] {
            fs::write(root.path().join("src").join(name), source).expect("source fixture");
        }
        let options = crate::options::PreviewOptions {
            root: root.path().to_owned(),
            ..Default::default()
        };
        let prepared = prepare(&options).expect("mixed-language discovery");
        assert!(prepared.inferred_test_files.contains("src/sampleEvents.js"));
        assert!(prepared.sources.contains_key("src/Decision.java"));
        assert!(prepared.sources.contains_key("src/coverage.js"));
        for consumer in [
            "import {\n events\n} from 'state/sampleEvents';",
            "export {\n events\n} from './sampleEvents.js';",
        ] {
            fs::write(root.path().join("src/runtime.js"), consumer).expect("runtime consumer");
            let included = prepare(&options).expect("production module discovery");
            assert!(
                included.sources.contains_key("src/sampleEvents.js"),
                "{consumer}"
            );
            assert!(
                !included.inferred_test_files.contains("src/sampleEvents.js"),
                "{consumer}"
            );
        }
    }

    #[test]
    fn retains_fixture_candidates_when_consumers_are_outside_the_scan_scope() {
        let root = repository();
        fs::write(
            root.path().join("src/live.ts"),
            "import { events } from './state/sampleEvents';\nconsume(events);\n",
        )
        .expect("runtime consumer");
        for (language, includes, excludes) in [
            (Some("javascript".to_owned()), vec![], vec![]),
            (None, vec!["src/state/**".to_owned()], vec![]),
            (None, vec![], vec!["src/live.ts".to_owned()]),
        ] {
            let prepared = prepare(&crate::options::PreviewOptions {
                root: root.path().to_owned(),
                language,
                includes,
                excludes,
                ..Default::default()
            })
            .expect("restricted discovery");
            assert!(prepared.sources.contains_key("src/state/sampleEvents.js"));
            assert!(
                !prepared
                    .inferred_test_files
                    .contains("src/state/sampleEvents.js")
            );
        }
        fs::write(
            root.path().join("code-buster.toml"),
            "[files]\nignore = ['src/live.ts']\n",
        )
        .expect("custom ignore");
        let ignored = prepare(&crate::options::PreviewOptions {
            root: root.path().to_owned(),
            ..Default::default()
        })
        .expect("ignored consumer discovery");
        assert!(ignored.sources.contains_key("src/state/sampleEvents.js"));
        assert!(
            !ignored
                .inferred_test_files
                .contains("src/state/sampleEvents.js")
        );
    }
}
