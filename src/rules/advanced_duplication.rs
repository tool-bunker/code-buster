use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::duplication::{structural_keyword, structural_tokens};
use crate::findings::{Finding, Severity};
use crate::function_sources::FunctionSource;

const MAX_NEAR_DUPLICATE_PAIRS: usize = 30;

struct TokenizedFragment<'a> {
    fragment: &'a FunctionSource,
    tokens: Vec<String>,
}

struct NearDuplicateIndex<'a> {
    candidates: Vec<TokenizedFragment<'a>>,
    buckets: BTreeMap<String, Vec<usize>>,
}

type NearDuplicateGroups = BTreeMap<usize, (usize, f64)>;

#[derive(Clone)]
struct ContractSignature {
    id: String,
    label: String,
    confidence: &'static str,
    offset: usize,
}

struct ContractOccurrence<'a> {
    fragment: &'a FunctionSource,
    signature: ContractSignature,
}

pub fn near_duplicate_functions(fragments: &[FunctionSource]) -> Vec<Finding> {
    let index = index_near_duplicate_candidates(fragments);
    let groups = assemble_near_duplicate_groups(&index);
    emit_near_duplicate_findings(&index.candidates, groups)
}

fn index_near_duplicate_candidates(fragments: &[FunctionSource]) -> NearDuplicateIndex<'_> {
    let mut candidates = Vec::new();
    let mut buckets: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for fragment in fragments {
        let candidate = TokenizedFragment {
            fragment,
            tokens: structural_tokens(&fragment.source),
        };
        if !(20..=400).contains(&candidate.tokens.len())
            || candidate.fragment.source.split('\n').count() < 7
            || (candidate.fragment.name.starts_with("accept")
                && candidate.fragment.name.ends_with("Visitor"))
        {
            continue;
        }
        let candidate_index = candidates.len();
        buckets
            .entry(shape_key(&candidate))
            .or_default()
            .push(candidate_index);
        candidates.push(candidate);
    }
    NearDuplicateIndex {
        candidates,
        buckets,
    }
}

fn qualify_near_duplicate_similarity(
    left: &TokenizedFragment<'_>,
    right: &TokenizedFragment<'_>,
) -> Option<f64> {
    let shortest = left.tokens.len().min(right.tokens.len());
    let longest = left.tokens.len().max(right.tokens.len());
    if shortest as f64 / (longest as f64) < 0.8 {
        return None;
    }
    let similarity = sequence_similarity(&left.tokens, &right.tokens);
    (0.86..0.999).contains(&similarity).then_some(similarity)
}

fn assemble_near_duplicate_groups(index: &NearDuplicateIndex<'_>) -> NearDuplicateGroups {
    let mut groups = BTreeMap::new();
    for bucket in index.buckets.values() {
        for left_position in 0..bucket.len() {
            let left_index = bucket[left_position];
            for &right_index in &bucket[left_position + 1..] {
                let Some(similarity) = qualify_near_duplicate_similarity(
                    &index.candidates[left_index],
                    &index.candidates[right_index],
                ) else {
                    continue;
                };
                if groups
                    .get(&left_index)
                    .is_none_or(|(_, current)| similarity > *current)
                {
                    groups.insert(left_index, (right_index, similarity));
                }
                if groups
                    .get(&right_index)
                    .is_none_or(|(_, current)| similarity > *current)
                {
                    groups.insert(right_index, (left_index, similarity));
                }
            }
        }
    }
    groups
}

fn emit_near_duplicate_findings(
    candidates: &[TokenizedFragment<'_>],
    groups: NearDuplicateGroups,
) -> Vec<Finding> {
    groups
        .into_iter()
        .take(MAX_NEAR_DUPLICATE_PAIRS * 2)
        .map(|(index, (other_index, similarity))| {
            let item = &candidates[index];
            let other = &candidates[other_index];
            let percent = (similarity * 100.0).floor() as usize;
            Finding {
                code: "near-duplicate-function".to_owned(),
                severity: Severity::Info,
                path: item.fragment.path.clone(),
                line: item.fragment.line,
                end_line: item.fragment.end_line,
                message: format!(
                    "{} is {percent}% structurally similar to {}",
                    item.fragment.name, other.fragment.name
                ),
                confidence: if similarity >= 0.93 { "high" } else { "medium" }.to_owned(),
                why: "The functions have nearly the same operations and control flow despite identifier or literal differences.".to_owned(),
                suggestion: "Consider a shared function when these implementations should evolve together."
                    .to_owned(),
                related_files: vec![format!(
                    "{}:{}-{}",
                    other.fragment.path, other.fragment.line, other.fragment.end_line
                )],
                snippet: item
                    .fragment
                    .source
                    .split('\n')
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("\n"),
                code_flow: Vec::new(),
            }
        })
        .collect()
}

pub fn parallel_contract_implementations(fragments: &[FunctionSource]) -> Vec<Finding> {
    let mut ordered: Vec<&FunctionSource> = fragments.iter().collect();
    ordered.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
    });
    let mut groups: BTreeMap<String, Vec<ContractOccurrence<'_>>> = BTreeMap::new();
    for fragment in ordered {
        for signature in contract_signatures(fragment) {
            groups
                .entry(signature.id.clone())
                .or_default()
                .push(ContractOccurrence {
                    fragment,
                    signature,
                });
        }
    }
    let mut findings = Vec::new();
    for occurrences in groups.values() {
        if findings.len() >= MAX_NEAR_DUPLICATE_PAIRS {
            break;
        }
        if occurrences
            .iter()
            .map(|item| item.fragment.path.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            < 2
        {
            continue;
        }
        let primary = &occurrences[0];
        let Some(comparison) = occurrences
            .iter()
            .find(|item| item.fragment.path != primary.fragment.path)
        else {
            continue;
        };
        let similarity = sequence_similarity(
            &structural_tokens(&primary.fragment.source),
            &structural_tokens(&comparison.fragment.source),
        );
        if similarity >= 0.999 {
            continue;
        }
        let percent = (similarity * 100.0).round() as usize;
        findings.push(Finding {
            code: "parallel-contract-implementation".to_owned(),
            severity: Severity::Info,
            path: primary.fragment.path.clone(),
            line: occurrence_line(primary),
            end_line: primary.fragment.end_line,
            message: format!(
                "{} functions independently implement {}; normalized bodies are {percent}% similar",
                occurrences.len(), primary.signature.label
            ),
            confidence: primary.signature.confidence.to_owned(),
            why: "Separate implementations of one external contract can drift when generated or maintained independently.".to_owned(),
            suggestion: "Review whether one implementation should own this contract, then delegate or share its typed decoder and policy.".to_owned(),
            related_files: occurrences
                .iter()
                .skip(1)
                .map(|item| {
                    format!(
                        "{}:{}-{}",
                        item.fragment.path,
                        occurrence_line(item),
                        item.fragment.end_line
                    )
                })
                .collect(),
            snippet: format!(
                "{}: {}; structural similarity {percent}%",
                primary.fragment.name, primary.signature.label
            ),
            code_flow: Vec::new(),
        });
    }
    findings
}

fn shape_key(fragment: &TokenizedFragment<'_>) -> String {
    let extension = Path::new(&fragment.fragment.path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let shape = fragment
        .tokens
        .iter()
        .filter(|token| {
            token.as_str() != "ID"
                && token.as_str() != "NUM"
                && token.as_str() != "STR"
                && (!token.starts_with(|character: char| {
                    character.is_ascii_alphabetic() || character == '_'
                }) || structural_keyword(token))
        })
        .take(12)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",");
    format!("{extension}|{shape}")
}

fn sequence_similarity(left: &[String], right: &[String]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (left_index, left_token) in left.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_token) in right.iter().enumerate() {
            current[right_index + 1] = (previous[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(previous[right_index] + usize::from(left_token != right_token));
        }
        std::mem::swap(&mut previous, &mut current);
    }
    1.0 - previous[right.len()] as f64 / left.len().max(right.len()) as f64
}

fn contract_signatures(fragment: &FunctionSource) -> Vec<ContractSignature> {
    let source = &fragment.source;
    let mut signatures = BTreeMap::new();
    collect_http_signatures(source, &mut signatures);
    collect_json_signature(source, &mut signatures);
    collect_sql_signatures(source, &mut signatures);
    collect_config_signature(source, &mut signatures);
    signatures.into_values().collect()
}

fn collect_http_signatures(source: &str, signatures: &mut BTreeMap<String, ContractSignature>) {
    for captures in HTTP_CONTRACT.captures_iter(source) {
        let (Some(complete), Some(method), Some(endpoint)) =
            (captures.get(0), captures.get(1), captures.get(2))
        else {
            continue;
        };
        let method = method.as_str().to_ascii_uppercase();
        let endpoint = normalize_endpoint(endpoint.as_str());
        if !endpoint.starts_with('/') {
            continue;
        }
        let id = format!("http:{method}:{endpoint}");
        signatures.insert(
            id.clone(),
            ContractSignature {
                id,
                label: format!("HTTP {method} {endpoint}"),
                confidence: "high",
                offset: complete.start(),
            },
        );
    }
}

fn collect_json_signature(source: &str, signatures: &mut BTreeMap<String, ContractSignature>) {
    let json_matches: Vec<_> = JSON_KEY.captures_iter(source).collect();
    let keys: BTreeSet<&str> = json_matches
        .iter()
        .filter_map(|captures| captures.get(1).map(|key| key.as_str()))
        .collect();
    if keys.len() < 3 {
        return;
    }
    let Some(offset) = json_matches
        .first()
        .and_then(|captures| captures.get(0))
        .map(|complete| complete.start())
    else {
        return;
    };
    let ordered = keys.into_iter().collect::<Vec<_>>();
    let schema = ordered.join(",");
    signatures.insert(
        format!("json:{schema}"),
        ContractSignature {
            id: format!("json:{schema}"),
            label: format!("JSON keys {}", ordered.join(", ")),
            confidence: "medium",
            offset,
        },
    );
}

fn collect_sql_signatures(source: &str, signatures: &mut BTreeMap<String, ContractSignature>) {
    for captures in SQL_CONTRACT.captures_iter(source) {
        let (Some(complete), Some(operation), Some(table)) =
            (captures.get(0), captures.get(1), captures.get(2))
        else {
            continue;
        };
        let operation = operation
            .as_str()
            .to_ascii_lowercase()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        if operation == "update" && !SQL_UPDATE_SET.is_match(&source[complete.end()..]) {
            continue;
        }
        let table = table.as_str().to_ascii_lowercase();
        let id = format!("sql:{operation}:{table}");
        signatures.insert(
            id.clone(),
            ContractSignature {
                id,
                label: format!("SQL {operation} on {table}"),
                confidence: "high",
                offset: complete.start(),
            },
        );
    }
}

fn collect_config_signature(source: &str, signatures: &mut BTreeMap<String, ContractSignature>) {
    let config_matches: Vec<_> = CONFIG_KEY.captures_iter(source).collect();
    let environment_keys: BTreeSet<&str> = config_matches
        .iter()
        .filter_map(|captures| {
            captures
                .get(1)
                .or_else(|| captures.get(2))
                .or_else(|| captures.get(3))
                .map(|value| value.as_str())
        })
        .collect();
    if environment_keys.len() < 2 {
        return;
    }
    let Some(offset) = config_matches
        .first()
        .and_then(|captures| captures.get(0))
        .map(|complete| complete.start())
    else {
        return;
    };
    let ordered = environment_keys.into_iter().collect::<Vec<_>>();
    let contract = ordered.join(",");
    signatures.insert(
        format!("config:{contract}"),
        ContractSignature {
            id: format!("config:{contract}"),
            label: format!("configuration keys {}", ordered.join(", ")),
            confidence: "medium",
            offset,
        },
    );
}

fn occurrence_line(occurrence: &ContractOccurrence<'_>) -> usize {
    occurrence.fragment.line
        + occurrence.fragment.source[..occurrence.signature.offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
}

fn normalize_endpoint(endpoint: &str) -> String {
    let without_query = endpoint.split('?').next().unwrap_or_default();
    let interpolated = ENDPOINT_INTERPOLATION.replace_all(without_query, "{value}");
    interpolated
        .split('/')
        .map(|segment| {
            if !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()) {
                "{number}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

static HTTP_CONTRACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(get|post|put|patch|delete)\s*\(\s*(?:Uri\.parse\(\s*)?["']([^"']+)["']"#)
        .expect("HTTP contract regex must compile")
});
static JSON_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:json|map|data|body|payload)\s*\[\s*["']([^"']+)["']\s*\]"#)
        .expect("JSON key regex must compile")
});
static SQL_CONTRACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(select\s+[^;\n]{1,200}?\s+from|insert\s+into|update|delete\s+from)\s+([a-z_][\w.]*)")
        .expect("SQL contract regex must compile")
});
static SQL_UPDATE_SET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s+set\b").expect("SQL update regex must compile"));
static CONFIG_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Platform\.environment|process\.env)\s*(?:\[\s*["']([^"']+)["']\s*\]|\.\s*([A-Za-z_]\w*))|getenv\s*\(\s*["']([^"']+)["']"#)
        .expect("configuration key regex must compile")
});
static ENDPOINT_INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{?[A-Za-z_]\w*\}?").expect("endpoint interpolation regex must compile")
});
