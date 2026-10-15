use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::constant_arguments::code_without_comments_and_strings;
use crate::function_sources::FunctionSource;
use crate::trivial_wrappers::{matching_delimiter, split_top_level};

#[derive(Debug)]
pub(crate) struct Call {
    pub(crate) owner: usize,
    pub(crate) arguments: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct YagniCallIndex<'a> {
    pub(crate) ordered: Vec<&'a FunctionSource>,
    pub(crate) name_counts: BTreeMap<&'a str, usize>,
    pub(crate) reference_counts: BTreeMap<&'a str, usize>,
    pub(crate) stripped_sources: Vec<String>,
    calls: BTreeMap<&'a str, Vec<Call>>,
}

impl<'a> YagniCallIndex<'a> {
    pub(crate) fn new(functions: &'a [FunctionSource]) -> Self {
        let mut index = Self::initialize(functions);
        let names = index.name_counts.keys().copied().collect::<BTreeSet<_>>();
        collect_function_usage(
            &index.ordered,
            &names,
            &mut index.reference_counts,
            &mut index.calls,
            &mut index.stripped_sources,
        );
        index
    }

    fn initialize(functions: &'a [FunctionSource]) -> Self {
        let ordered = deterministically_ordered(functions);
        let mut name_counts = BTreeMap::<&str, usize>::new();
        for function in &ordered {
            *name_counts.entry(&function.name).or_default() += 1;
        }
        let source_count = ordered.len();
        Self {
            ordered,
            name_counts,
            reference_counts: BTreeMap::new(),
            stripped_sources: Vec::with_capacity(source_count),
            calls: BTreeMap::new(),
        }
    }

    pub(crate) fn visible_calls(&self, target: usize, name: &str) -> Vec<&Call> {
        self.calls
            .get(name)
            .into_iter()
            .flatten()
            .filter(|call| call.owner != target)
            .collect()
    }
}

fn deterministically_ordered(functions: &[FunctionSource]) -> Vec<&FunctionSource> {
    let mut ordered = functions.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.path.cmp(&right.path).then(left.line.cmp(&right.line)));
    ordered
}

fn collect_function_usage<'a>(
    ordered: &[&FunctionSource],
    names: &BTreeSet<&'a str>,
    reference_counts: &mut BTreeMap<&'a str, usize>,
    calls: &mut BTreeMap<&'a str, Vec<Call>>,
    stripped_sources: &mut Vec<String>,
) {
    for (owner, function) in ordered.iter().enumerate() {
        let code = code_without_comments_and_strings(function);
        collect_references(&code, names, reference_counts);
        collect_calls(owner, &code, names, calls);
        stripped_sources.push(code);
    }
}

fn collect_references<'a>(
    code: &str,
    names: &BTreeSet<&'a str>,
    reference_counts: &mut BTreeMap<&'a str, usize>,
) {
    for capture in IDENTIFIER.captures_iter(code) {
        let Some(identifier) = capture.get(1) else {
            continue;
        };
        if let Some(canonical) = names.get(identifier.as_str()) {
            *reference_counts.entry(*canonical).or_default() += 1;
        }
    }
}

fn collect_calls<'a>(
    owner: usize,
    code: &str,
    names: &BTreeSet<&'a str>,
    calls: &mut BTreeMap<&'a str, Vec<Call>>,
) {
    for capture in CALL.captures_iter(code) {
        let Some((name, call)) = resolve_call(owner, code, &capture, names) else {
            continue;
        };
        calls.entry(name).or_default().push(call);
    }
}

fn resolve_call<'a>(
    owner: usize,
    code: &str,
    capture: &Captures<'_>,
    names: &BTreeSet<&'a str>,
) -> Option<(&'a str, Call)> {
    let name = names.get(capture.get(1)?.as_str()).copied()?;
    let complete = capture.get(0)?;
    if !call_receiver_is_supported(code, complete.start()) {
        return None;
    }
    let open = complete.end() - 1;
    let close = matching_delimiter(code, open, b'(', b')')?;
    let arguments = call_arguments(&code[open + 1..close]);
    Some((name, Call { owner, arguments }))
}

fn call_receiver_is_supported(code: &str, start: usize) -> bool {
    let mut cursor = start;
    while cursor > 0 && code.as_bytes()[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    if cursor == 0 || code.as_bytes()[cursor - 1] != b'.' {
        return true;
    }
    receiver_ends_in_self(code[..cursor - 1].trim_end())
}

fn call_arguments(raw_arguments: &str) -> Vec<String> {
    if raw_arguments.trim().is_empty() {
        return Vec::new();
    }
    split_top_level(raw_arguments)
        .into_iter()
        .map(|argument| argument.trim().to_owned())
        .collect()
}

fn receiver_ends_in_self(receiver: &str) -> bool {
    ["this", "self"].iter().any(|name| {
        receiver.ends_with(name)
            && receiver[..receiver.len() - name.len()]
                .chars()
                .next_back()
                .is_none_or(|character| !is_identifier(character))
    })
}

fn is_identifier(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
}

static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\b").expect("identifier regex"));
static CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\(").expect("function call regex"));
