use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};

struct ModelShape {
    path: String,
    name: String,
    line: usize,
    fields: BTreeSet<String>,
    parent: Option<String>,
}

pub fn overlapping_models(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let models = collect_models(sources);
    let candidate_index = index_candidates(&models);
    emit_overlaps(&models, group_candidate_pairs(&candidate_index))
}

fn collect_models(sources: &BTreeMap<String, String>) -> Vec<ModelShape> {
    let mut models = Vec::new();
    for (path, source) in sources {
        if !path.ends_with(".dart") {
            continue;
        }
        for captures in CLASS_DECLARATION.captures_iter(source) {
            let (Some(complete), Some(name)) = (captures.get(0), captures.name("name")) else {
                continue;
            };
            let name = name.as_str();
            if name.starts_with('_') {
                continue;
            }
            let opening = complete.end() - 1;
            let Some(closing) = matching_brace(source, opening) else {
                continue;
            };
            let fields = class_fields(&source[opening + 1..closing]);
            if fields.len() < 4 {
                continue;
            }
            models.push(ModelShape {
                path: path.clone(),
                name: name.to_owned(),
                line: line_at(source, complete.start()),
                fields,
                parent: captures
                    .name("parent")
                    .map(|value| value.as_str().to_owned()),
            });
        }
    }
    models
}

fn index_candidates(models: &[ModelShape]) -> BTreeMap<&str, Vec<usize>> {
    let mut index = BTreeMap::<&str, Vec<usize>>::new();
    for (model_index, model) in models.iter().enumerate() {
        for field in &model.fields {
            index.entry(field.as_str()).or_default().push(model_index);
        }
    }
    index
}

fn group_candidate_pairs(
    candidate_index: &BTreeMap<&str, Vec<usize>>,
) -> BTreeMap<(usize, usize), usize> {
    let mut shared_counts = BTreeMap::new();
    for model_indices in candidate_index.values() {
        for left_offset in 0..model_indices.len() {
            let left_index = model_indices[left_offset];
            for &right_index in &model_indices[left_offset + 1..] {
                *shared_counts.entry((left_index, right_index)).or_insert(0) += 1;
            }
        }
    }
    shared_counts
}

struct QualifiedPair {
    shared_count: usize,
    union_size: usize,
}

fn qualify_pair(
    left: &ModelShape,
    right: &ModelShape,
    shared_count: usize,
) -> Option<QualifiedPair> {
    if left.path == right.path
        || left.parent.as_deref() == Some(right.name.as_str())
        || right.parent.as_deref() == Some(left.name.as_str())
    {
        return None;
    }
    let union_size = left.fields.len() + right.fields.len() - shared_count;
    if shared_count < 4 || shared_count * 5 < union_size * 4 {
        return None;
    }
    Some(QualifiedPair {
        shared_count,
        union_size,
    })
}

fn emit_overlaps(
    models: &[ModelShape],
    grouped_pairs: BTreeMap<(usize, usize), usize>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ((left_index, right_index), shared_count) in grouped_pairs {
        let (Some(left), Some(right)) = (models.get(left_index), models.get(right_index)) else {
            continue;
        };
        let Some(pair) = qualify_pair(left, right, shared_count) else {
            continue;
        };
        let mut shared_names = String::new();
        for name in left.fields.intersection(&right.fields) {
            if !shared_names.is_empty() {
                shared_names.push_str(", ");
            }
            shared_names.push_str(name);
        }
        findings.push(Finding {
            code: "dart-overlapping-data-model".to_owned(),
            severity: Severity::Info,
            path: left.path.clone(),
            line: left.line,
            end_line: left.line,
            message: format!(
                "{} and {} duplicate {} data fields",
                left.name, right.name, pair.shared_count
            ),
            confidence: "medium".to_owned(),
            why: "Separate cross-file data models have strongly overlapping fields.".to_owned(),
            suggestion: "Confirm distinct contracts or share a common value object.".to_owned(),
            related_files: vec![format!("{}:{}", right.path, right.line)],
            snippet: format!(
                "shared fields: {shared_names}; overlap: {}/{}",
                pair.shared_count, pair.union_size
            ),
            code_flow: Vec::new(),
        });
    }
    findings
}

struct ClassFieldScanner<'a> {
    lines: std::str::Split<'a, char>,
    depth: isize,
}

impl<'a> ClassFieldScanner<'a> {
    fn new(body: &'a str) -> Self {
        Self {
            lines: body.split('\n'),
            depth: 0,
        }
    }
}

impl<'a> Iterator for ClassFieldScanner<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        for raw in self.lines.by_ref() {
            let line = raw.split("//").next().unwrap_or_default().trim();
            let is_field_declaration = self.depth == 0
                && line.ends_with(';')
                && !line.contains('(')
                && !line.starts_with("static ")
                && !line.starts_with("const ");
            self.depth += raw.bytes().filter(|byte| *byte == b'{').count() as isize;
            self.depth -= raw.bytes().filter(|byte| *byte == b'}').count() as isize;
            if is_field_declaration {
                return Some(line);
            }
        }
        None
    }
}

fn class_fields(body: &str) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for line in ClassFieldScanner::new(body) {
        let declaration = line
            .trim_end_matches(';')
            .split('=')
            .next()
            .unwrap_or_default()
            .trim();
        for (index, part) in declaration.split(',').enumerate() {
            finalize_field(&mut fields, part, index == 0);
        }
    }
    fields
}

fn finalize_field(fields: &mut BTreeSet<String>, declaration: &str, is_first: bool) {
    let mut tokens = declaration.split_whitespace();
    let name = if is_first {
        tokens.next_back()
    } else {
        tokens.next()
    };
    if let Some(name) = name
        && IDENTIFIER.is_match(name)
        && !name.starts_with('_')
        && !matches!(name, "final" | "late" | "var")
    {
        fields.insert(name.to_owned());
    }
}

fn matching_brace(source: &str, opening: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[opening..].iter().enumerate() {
        if *byte == b'{' {
            depth += 1;
        } else if *byte == b'}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(opening + offset);
            }
        }
    }
    None
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

static CLASS_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:(?:abstract|base|final|interface|sealed)[ \t]+)*class[ \t]+(?P<name>[A-Za-z_]\w*)(?:[ \t]+extends[ \t]+(?P<parent>[A-Za-z_]\w*(?:<[^>{}]*>)?))?[^{}]*\{")
        .expect("Dart class declaration regex must compile")
});
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").expect("identifier regex must compile"));
