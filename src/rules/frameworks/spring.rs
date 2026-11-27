use std::collections::{BTreeMap, BTreeSet};

use super::spring_project::SpringProjects;
use crate::findings::{CodeFlowStep, Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;
use crate::trivial_wrappers::{mask_comments_and_strings, matching_delimiter, split_top_level};

const ASYNC: &str = "org.springframework.scheduling.annotation.Async";
const SCHEDULED: &str = "org.springframework.scheduling.annotation.Scheduled";
const TRANSACTIONAL: &str = "org.springframework.transaction.annotation.Transactional";
const BEAN: &str = "org.springframework.context.annotation.Bean";
const ENABLE_ASYNC: &str = "org.springframework.scheduling.annotation.EnableAsync";
const ENABLE_TRANSACTION: &str =
    "org.springframework.transaction.annotation.EnableTransactionManagement";
const ADVICE_MODE: &str = "org.springframework.context.annotation.AdviceMode";
const ASPECTJ_IMPORT: &str = "org.springframework.context.annotation.AdviceMode.ASPECTJ";
const ADVICE_MODE_WILDCARD: &str = "org.springframework.context.annotation.AdviceMode.*";
const STEREOTYPES: &[&str] = &[
    "org.springframework.stereotype.Component",
    "org.springframework.stereotype.Service",
    "org.springframework.stereotype.Repository",
    "org.springframework.stereotype.Controller",
    "org.springframework.web.bind.annotation.RestController",
    "org.springframework.context.annotation.Configuration",
    "org.springframework.boot.autoconfigure.AutoConfiguration",
    "org.springframework.boot.autoconfigure.SpringBootApplication",
    "org.springframework.boot.SpringBootConfiguration",
];

/// A bounded, file-local declaration index, not a Java type checker. All offsets
/// refer to the original source: the shared lexical mask preserves byte lengths.
pub(crate) fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let projects = SpringProjects::new(context.auxiliary_files());
    let files = context
        .sources()
        .iter()
        .filter_map(|(path, source)| {
            if !path.ends_with(".java") {
                return None;
            }
            let module = projects.module_for(path)?;
            Some(JavaFile::new(path, source, module))
        })
        .collect::<Vec<_>>();
    let declarations = files
        .iter()
        .flat_map(|file| {
            file.declared_names
                .iter()
                .map(move |name| (file.module, file.qualified(name)))
        })
        .collect::<BTreeSet<_>>();
    let mut registered = BTreeSet::new();
    let mut aspectj = BTreeMap::<&str, (bool, bool)>::new();
    for file in &files {
        let bindings = Bindings {
            file,
            declarations: &declarations,
        };
        for class in &file.classes {
            let modes = aspectj.entry(file.module).or_default();
            modes.0 |= class.annotations.iter().any(|annotation| {
                bindings.annotation(annotation, ENABLE_ASYNC) && bindings.aspectj(annotation)
            });
            modes.1 |= class.annotations.iter().any(|annotation| {
                bindings.annotation(annotation, ENABLE_TRANSACTION) && bindings.aspectj(annotation)
            });
            if !bindings.managed(class) {
                continue;
            }
            for method in &class.methods {
                if method
                    .annotations
                    .iter()
                    .any(|annotation| bindings.annotation(annotation, BEAN))
                    && let Some(ty) = bindings.resolve_type(&method.return_type)
                {
                    registered.insert((file.module, ty));
                }
            }
        }
    }
    let mut findings = Vec::new();
    for file in &files {
        let bindings = Bindings {
            file,
            declarations: &declarations,
        };
        let modes = aspectj.get(file.module).copied().unwrap_or_default();
        for class in &file.classes {
            if !bindings.managed(class)
                && !registered.contains(&(file.module, file.qualified(&class.name)))
            {
                continue;
            }
            analyze_class(&bindings, class, modes, &mut findings);
        }
    }
    findings
}

#[derive(Clone, Copy)]
struct Token {
    start: usize,
    end: usize,
}

struct Annotation {
    name: String,
    start: usize,
    arguments: Option<(usize, usize)>,
}

struct Method {
    name: String,
    annotations: Vec<Annotation>,
    return_type: String,
    parameters: usize,
    varargs: bool,
    is_static: bool,
    is_private: bool,
    is_constructor: bool,
    type_parameters: BTreeSet<String>,
    body: Option<(usize, usize)>,
}

struct Class {
    name: String,
    annotations: Vec<Annotation>,
    methods: Vec<Method>,
    type_parameters: BTreeSet<String>,
    inherits: bool,
}

struct JavaFile<'a> {
    path: &'a str,
    source: &'a str,
    module: &'a str,
    masked: String,
    tokens: Vec<Token>,
    pairs: BTreeMap<usize, usize>,
    package: String,
    imports: BTreeMap<String, BTreeSet<String>>,
    wildcards: BTreeSet<String>,
    static_imports: BTreeSet<String>,
    declared_names: BTreeSet<String>,
    classes: Vec<Class>,
}

impl<'a> JavaFile<'a> {
    fn new(path: &'a str, source: &'a str, module: &'a str) -> Self {
        let masked = mask_comments_and_strings(source);
        let tokens = tokenize(&masked);
        let mut pairs = BTreeMap::new();
        let mut stack = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            let text = &masked[token.start..token.end];
            if matches!(text, "(" | "{" | "[") {
                stack.push(index);
            } else if matches!(text, ")" | "}" | "]")
                && let Some(open) = stack.pop()
            {
                let opening = &masked[tokens[open].start..tokens[open].end];
                if matches!((opening, text), ("(", ")") | ("{", "}") | ("[", "]")) {
                    pairs.insert(open, index);
                }
            }
        }
        let mut file = Self {
            path,
            source,
            module,
            masked,
            tokens,
            pairs,
            package: String::new(),
            imports: BTreeMap::new(),
            wildcards: BTreeSet::new(),
            static_imports: BTreeSet::new(),
            declared_names: BTreeSet::new(),
            classes: Vec::new(),
        };
        file.index();
        file
    }

    fn text(&self, index: usize) -> &str {
        self.tokens
            .get(index)
            .map_or("", |token| &self.masked[token.start..token.end])
    }

    fn joined(&self, start: usize, end: usize) -> String {
        (start..end).map(|index| self.text(index)).collect()
    }

    fn qualified(&self, name: &str) -> String {
        if self.package.is_empty() {
            name.to_owned()
        } else {
            format!("{}.{name}", self.package)
        }
    }

    fn annotation(&self, start: usize) -> Option<(Annotation, usize)> {
        if self.text(start) != "@" || !identifier(self.text(start + 1)) {
            return None;
        }
        let mut end = start + 2;
        while self.text(end) == "." && identifier(self.text(end + 1)) {
            end += 2;
        }
        let name = self.joined(start + 1, end);
        let arguments = if self.text(end) == "(" {
            let close = *self.pairs.get(&end)?;
            let range = Some((self.tokens[end].end, self.tokens[close].start));
            end = close + 1;
            range
        } else {
            None
        };
        Some((
            Annotation {
                name,
                start: self.tokens[start].start,
                arguments,
            },
            end,
        ))
    }

    fn index(&mut self) {
        // Include nested/custom declarations in shadow detection, even though
        // only top-level concrete classes are candidates for managed ownership.
        for index in 0..self.tokens.len() {
            if matches!(self.text(index), "class" | "interface" | "enum" | "record")
                && identifier(self.text(index + 1))
                && self.text(index.wrapping_sub(1)) != "."
            {
                self.declared_names.insert(self.text(index + 1).to_owned());
            }
        }
        let mut index = 0;
        let mut annotations = Vec::new();
        let mut is_abstract = false;
        let index_methods = ["Async", "Scheduled", "Transactional", "Bean"]
            .iter()
            .any(|marker| self.masked.contains(marker));
        while index < self.tokens.len() {
            match self.text(index) {
                "package" | "import" => {
                    let package = self.text(index) == "package";
                    let start = index + 1;
                    let end = (start..self.tokens.len())
                        .find(|&i| self.text(i) == ";")
                        .unwrap_or(start);
                    let is_static = self.text(start) == "static";
                    let name = self.joined(start + usize::from(is_static), end);
                    if package {
                        self.package = name;
                    } else if is_static {
                        self.static_imports.insert(name);
                    } else if let Some(prefix) = name.strip_suffix(".*") {
                        self.wildcards.insert(prefix.to_owned());
                    } else if let Some(simple) = name.rsplit('.').next() {
                        self.imports
                            .entry(simple.to_owned())
                            .or_default()
                            .insert(name);
                    }
                    annotations.clear();
                    is_abstract = false;
                    index = end + 1;
                }
                "@" if self.text(index + 1) != "interface" => {
                    if let Some((annotation, end)) = self.annotation(index) {
                        annotations.push(annotation);
                        index = end;
                    } else {
                        index += 1;
                    }
                }
                "class" => {
                    let name = self.text(index + 1).to_owned();
                    let Some(open) =
                        (index + 2..self.tokens.len()).find(|&i| matches!(self.text(i), "{" | ";"))
                    else {
                        break;
                    };
                    let Some(&close) = self.pairs.get(&open) else {
                        break;
                    };
                    if !is_abstract {
                        let type_parameters = self.type_parameters(index + 2, open);
                        let inherits = (index + 2..open)
                            .any(|i| matches!(self.text(i), "extends" | "implements"));
                        let methods = if index_methods {
                            self.methods(open + 1, close, &name)
                        } else {
                            Vec::new()
                        };
                        self.classes.push(Class {
                            name,
                            annotations: std::mem::take(&mut annotations),
                            methods,
                            type_parameters,
                            inherits,
                        });
                    }
                    annotations.clear();
                    is_abstract = false;
                    index = close + 1;
                }
                "interface" | "enum" | "record" | "{" => {
                    let open = if self.text(index) == "{" {
                        Some(index)
                    } else {
                        (index + 1..self.tokens.len()).find(|&i| self.text(i) == "{")
                    };
                    index = open
                        .and_then(|open| self.pairs.get(&open))
                        .map_or(index + 1, |close| close + 1);
                    annotations.clear();
                    is_abstract = false;
                }
                "abstract" => {
                    is_abstract = true;
                    index += 1;
                }
                ";" => {
                    annotations.clear();
                    is_abstract = false;
                    index += 1;
                }
                _ => {
                    index += 1;
                }
            }
        }
    }

    fn type_parameters(&self, start: usize, end: usize) -> BTreeSet<String> {
        if self.text(start) != "<" {
            return BTreeSet::new();
        }
        (start + 1..end)
            .take_while(|&index| self.text(index) != ">")
            .filter(|&index| self.text(index - 1) == "<" || self.text(index - 1) == ",")
            .filter(|&index| identifier(self.text(index)))
            .map(|index| self.text(index).to_owned())
            .collect()
    }

    fn methods(&self, start: usize, end: usize, class_name: &str) -> Vec<Method> {
        let mut methods = Vec::new();
        let mut index = start;
        let mut member_start = start;
        let mut annotations = Vec::new();
        while index < end {
            if self.text(index) == "@"
                && let Some((annotation, next)) = self.annotation(index)
            {
                annotations.push(annotation);
                index = next;
                continue;
            }
            if matches!(
                self.text(index),
                "class" | "interface" | "enum" | "record" | "="
            ) {
                // Fields, anonymous classes and nested types cannot donate
                // annotations or declarations to their enclosing class.
                index = self.member_end(index, end);
                member_start = index;
                annotations.clear();
                continue;
            }
            if self.text(index) == "(" {
                let Some(&close) = self.pairs.get(&index) else {
                    break;
                };
                let name = self.text(index - 1);
                let mut next = close + 1;
                while next < end && !matches!(self.text(next), "{" | ";" | "=") {
                    next += 1;
                }
                if identifier(name) && matches!(self.text(next), "{" | ";") {
                    let (signature, type_parameters) = self.signature(member_start, index - 1);
                    let is_static = signature.iter().any(|&i| self.text(i) == "static");
                    let is_private = signature.iter().any(|&i| self.text(i) == "private");
                    let mut return_type = signature
                        .into_iter()
                        .filter(|&i| !modifier(self.text(i)))
                        .map(|i| self.text(i))
                        .collect::<String>();
                    let is_constructor = name == class_name && return_type.is_empty();
                    let mut suffix = close + 1;
                    while self.text(suffix) == "[" && self.text(suffix + 1) == "]" {
                        return_type.push_str("[]");
                        suffix += 2;
                    }
                    let parameters = &self.masked[self.tokens[index].end..self.tokens[close].start];
                    let parameter_count = if parameters.trim().is_empty() {
                        0
                    } else {
                        split_top_level(parameters).len()
                    };
                    let body = if self.text(next) == "{" {
                        self.pairs.get(&next).map(|&end| (next + 1, end))
                    } else {
                        None
                    };
                    methods.push(Method {
                        name: name.to_owned(),
                        annotations: std::mem::take(&mut annotations),
                        return_type,
                        parameters: parameter_count,
                        varargs: parameters.contains("..."),
                        is_static,
                        is_private,
                        is_constructor,
                        type_parameters,
                        body,
                    });
                }
                index = if self.text(next) == "{" {
                    self.pairs.get(&next).map_or(next + 1, |close| close + 1)
                } else {
                    next + 1
                };
                annotations.clear();
                member_start = index;
                continue;
            }
            if self.text(index) == "{" {
                index = self.pairs.get(&index).map_or(index + 1, |close| close + 1);
                annotations.clear();
                member_start = index;
                continue;
            }
            if self.text(index) == ";" {
                annotations.clear();
                member_start = index + 1;
            }
            index += 1;
        }
        methods
    }

    fn signature(&self, start: usize, end: usize) -> (Vec<usize>, BTreeSet<String>) {
        let mut result = Vec::new();
        let mut index = start;
        while index < end {
            if let Some((_, next)) = self.annotation(index) {
                index = next;
            } else {
                result.push(index);
                index += 1;
            }
        }
        let mut type_parameters = BTreeSet::new();
        let generic = result.iter().position(|&i| !modifier(self.text(i)));
        if let Some(begin) = generic.filter(|&begin| self.text(result[begin]) == "<") {
            let offset = self.tokens[result[begin]].start;
            if let Some(close) = matching_delimiter(&self.masked, offset, b'<', b'>') {
                let finish = result
                    .iter()
                    .position(|&i| self.tokens[i].start == close)
                    .map_or(begin, |finish| finish + 1);
                type_parameters = self.type_parameters(result[begin], end);
                result.drain(begin..finish);
            }
        }
        (result, type_parameters)
    }

    fn member_end(&self, start: usize, end: usize) -> usize {
        let mut index = start;
        while index < end {
            if self.text(index) == ";" {
                return index + 1;
            }
            if matches!(self.text(index), "{" | "(")
                && let Some(&close) = self.pairs.get(&index)
            {
                if self.text(index) == "{" {
                    return close + 1;
                }
                index = close + 1;
                continue;
            }
            index += 1;
        }
        end
    }
}

fn tokenize(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        if bytes[index].is_ascii_alphabetic()
            || matches!(bytes[index], b'_' | b'$')
            || bytes[index] >= 128
        {
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'_' | b'$')
                    || bytes[index] >= 128)
            {
                index += 1;
            }
        } else {
            index += 1;
        }
        tokens.push(Token { start, end: index });
    }
    tokens
}

fn identifier(text: &str) -> bool {
    text.as_bytes().first().is_some_and(|byte| {
        byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') || *byte >= 128
    })
}

fn modifier(text: &str) -> bool {
    matches!(
        text,
        "public"
            | "protected"
            | "private"
            | "static"
            | "final"
            | "abstract"
            | "synchronized"
            | "native"
            | "strictfp"
            | "default"
    )
}

struct Bindings<'a, 'b> {
    file: &'a JavaFile<'b>,
    declarations: &'a BTreeSet<(&'b str, String)>,
}

impl Bindings<'_, '_> {
    fn annotation(&self, annotation: &Annotation, canonical: &str) -> bool {
        self.canonical(&annotation.name, canonical)
    }

    fn canonical(&self, name: &str, canonical: &str) -> bool {
        if let Some((root, _)) = name.split_once('.') {
            return name == canonical
                && !self.file.declared_names.contains(root)
                && !self
                    .declarations
                    .contains(&(self.file.module, self.file.qualified(root)));
        }
        if self.file.declared_names.contains(name) {
            return false;
        }
        if let Some(imports) = self.file.imports.get(name) {
            return imports.len() == 1 && imports.contains(canonical);
        }
        if self
            .declarations
            .contains(&(self.file.module, self.file.qualified(name)))
        {
            return false;
        }
        let Some((package, simple)) = canonical.rsplit_once('.') else {
            return false;
        };
        if name != simple {
            return false;
        }
        if self.file.package == package {
            return true;
        }
        if !self
            .file
            .wildcards
            .iter()
            .all(|package| Self::known_wildcard_package(package))
        {
            return false;
        }
        if name == "PostConstruct"
            && self.file.wildcards.contains("jakarta.annotation")
            && self.file.wildcards.contains("javax.annotation")
        {
            return false;
        }
        package == "java.lang" || self.file.wildcards.contains(package)
    }

    fn known_wildcard_package(package: &str) -> bool {
        matches!(
            package,
            "org.springframework.stereotype"
                | "org.springframework.scheduling.annotation"
                | "org.springframework.transaction.annotation"
                | "org.springframework.context.annotation"
                | "org.springframework.web.bind.annotation"
                | "org.springframework.boot.autoconfigure"
                | "org.springframework.boot"
                | "java.lang"
                | "java.util"
                | "java.util.concurrent"
                | "jakarta.annotation"
                | "javax.annotation"
                | "reactor.core.publisher"
        )
    }

    fn managed(&self, class: &Class) -> bool {
        class.annotations.iter().any(|annotation| {
            STEREOTYPES
                .iter()
                .any(|canonical| self.annotation(annotation, canonical))
        })
    }

    fn resolve_type(&self, ty: &str) -> Option<String> {
        if ty.is_empty() || ty.contains(['<', '[', '>', '?']) {
            return None;
        }
        if ty.contains('.') {
            return Some(ty.to_owned());
        }
        if let Some(imports) = self.file.imports.get(ty) {
            return if imports.len() == 1 {
                imports.first().cloned()
            } else {
                None
            };
        }
        let local = self.file.qualified(ty);
        self.declarations
            .contains(&(self.file.module, local.clone()))
            .then_some(local)
    }

    fn aspectj(&self, annotation: &Annotation) -> bool {
        let Some((start, end)) = annotation.arguments else {
            return false;
        };
        split_top_level(&self.file.masked[start..end])
            .into_iter()
            .any(|argument| {
                let Some((key, value)) = argument.split_once('=') else {
                    return false;
                };
                if key.trim() != "mode" {
                    return false;
                }
                let value = value
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect::<String>();
                if let Some(owner) = value.strip_suffix(".ASPECTJ") {
                    self.canonical(owner, ADVICE_MODE)
                } else {
                    value == "ASPECTJ"
                        && self.file.static_imports.iter().all(|import| {
                            import == ASPECTJ_IMPORT
                                || import == ADVICE_MODE_WILDCARD
                                || !import.ends_with(".ASPECTJ") && !import.ends_with(".*")
                        })
                        && (self.file.static_imports.contains(ASPECTJ_IMPORT)
                            || self.file.static_imports.contains(ADVICE_MODE_WILDCARD))
                        && !self.file.declared_names.contains("ASPECTJ")
                        && !self.file.tokens.iter().enumerate().any(|(index, _)| {
                            self.file.text(index) == "ASPECTJ"
                                && matches!(self.file.text(index + 1), "=" | ";" | ",")
                                && !matches!(self.file.text(index.saturating_sub(1)), "=" | ".")
                        })
                }
            })
    }
}

fn analyze_class(
    bindings: &Bindings<'_, '_>,
    class: &Class,
    modes: (bool, bool),
    findings: &mut Vec<Finding>,
) {
    for method in class
        .methods
        .iter()
        .filter(|method| !method.is_static && !method.is_constructor)
    {
        method_contract_findings(bindings, class, method, modes.0, findings);
        self_invocation_findings(bindings, class, method, modes, findings);
    }
}

fn method_contract_findings(
    bindings: &Bindings<'_, '_>,
    class: &Class,
    method: &Method,
    async_aspectj: bool,
    findings: &mut Vec<Finding>,
) {
    let file = bindings.file;
    if let Some(annotation) = effective_annotation(bindings, class, method, ASYNC) {
        if !method.is_private
            && !method.type_parameters.contains(&method.return_type)
            && unsupported_return(bindings, class, &method.return_type)
        {
            findings.push(finding(
                "spring-async-return-type",
                file,
                annotation.start,
                format!(
                    "@Async method {}.{} has an unsupported return type {}",
                    class.name, method.name, method.return_type
                ),
                "high",
            ));
        }
        if !async_aspectj
            && method
                .annotations
                .iter()
                .any(|annotation| bindings.annotation(annotation, ASYNC))
            && method.annotations.iter().any(|annotation| {
                bindings.annotation(annotation, "jakarta.annotation.PostConstruct")
                    || bindings.annotation(annotation, "javax.annotation.PostConstruct")
            })
        {
            findings.push(finding(
                "spring-async-post-construct",
                file,
                annotation.start,
                format!(
                    "@Async on lifecycle method {}.{} does not apply asynchronous proxy advice during initialization",
                    class.name, method.name
                ),
                "high",
            ));
        }
    }
    if method.parameters > 0
        && let Some(annotation) = method
            .annotations
            .iter()
            .find(|annotation| bindings.annotation(annotation, SCHEDULED))
    {
        findings.push(finding(
            "spring-scheduled-parameters",
            file,
            annotation.start,
            format!(
                "@Scheduled method {}.{} declares parameters",
                class.name, method.name
            ),
            "high",
        ));
    }
}

fn self_invocation_findings(
    bindings: &Bindings<'_, '_>,
    class: &Class,
    method: &Method,
    modes: (bool, bool),
    findings: &mut Vec<Finding>,
) {
    if class.inherits || method.is_private || method.body.is_none() || method.varargs {
        return;
    }
    // No overload resolution is attempted, including inherited overloads.
    if class
        .methods
        .iter()
        .filter(|candidate| candidate.name == method.name)
        .count()
        != 1
    {
        return;
    }
    let file = bindings.file;
    for (canonical, code, aspectj) in [
        (
            TRANSACTIONAL,
            "spring-transactional-self-invocation",
            modes.1,
        ),
        (ASYNC, "spring-async-self-invocation", modes.0),
    ] {
        if aspectj {
            continue;
        }
        let Some(annotation) = effective_annotation(bindings, class, method, canonical) else {
            continue;
        };
        let mut sites = BTreeSet::new();
        for caller in class.methods.iter().filter(|caller| !caller.is_static) {
            if canonical == TRANSACTIONAL
                && preserves_caller_transaction_context(bindings, class, caller, annotation)
            {
                continue;
            }
            sites.extend(self_calls(file, caller, method));
        }
        if sites.is_empty() {
            continue;
        }
        let kind = if canonical == ASYNC {
            "asynchronous"
        } else {
            "transactional"
        };
        let mut result = finding(
            code,
            file,
            annotation.start,
            format!(
                "Same-instance calls to {}.{} bypass its requested {kind} proxy advice; existing caller context may still apply",
                class.name, method.name
            ),
            "medium",
        );
        result.code_flow = sites
            .into_iter()
            .map(|offset| CodeFlowStep {
                path: file.path.to_owned(),
                line: line_at(file.source, offset),
                message: format!("Same-instance call to {}.{}", class.name, method.name),
            })
            .collect();
        findings.push(result);
    }
}

fn preserves_caller_transaction_context(
    bindings: &Bindings<'_, '_>,
    class: &Class,
    caller: &Method,
    target: &Annotation,
) -> bool {
    if caller.is_private
        || caller.is_constructor
        || caller.annotations.iter().any(|annotation| {
            bindings.annotation(annotation, "jakarta.annotation.PostConstruct")
                || bindings.annotation(annotation, "javax.annotation.PostConstruct")
        })
    {
        return false;
    }
    effective_annotation(bindings, class, caller, TRANSACTIONAL)
        .is_some_and(|annotation| equivalent_transactions(bindings.file, target, annotation))
}

fn effective_annotation<'a>(
    bindings: &Bindings<'_, '_>,
    class: &'a Class,
    method: &'a Method,
    canonical: &str,
) -> Option<&'a Annotation> {
    method
        .annotations
        .iter()
        .find(|annotation| bindings.annotation(annotation, canonical))
        .or_else(|| {
            class
                .annotations
                .iter()
                .find(|annotation| bindings.annotation(annotation, canonical))
        })
}

fn unsupported_return(bindings: &Bindings<'_, '_>, class: &Class, ty: &str) -> bool {
    if ty == "void" || ty.is_empty() || class.type_parameters.contains(ty) {
        return false;
    }
    if ty.ends_with("[]") {
        return true;
    }
    if matches!(
        ty,
        "boolean" | "byte" | "short" | "int" | "long" | "float" | "double" | "char"
    ) {
        return true;
    }
    let base = ty.split('<').next().unwrap_or(ty);
    // Unknown user types (including custom Future subtypes) are intentionally
    // unresolved rather than rejected based on their spelling.
    const UNSUPPORTED: &[&str] = &[
        "java.lang.String",
        "java.lang.Object",
        "java.lang.Boolean",
        "java.lang.Byte",
        "java.lang.Short",
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Float",
        "java.lang.Double",
        "java.lang.Character",
        "java.lang.Void",
        "java.lang.Number",
        "java.util.List",
        "java.util.Set",
        "java.util.Map",
        "java.util.Collection",
        "java.util.Optional",
        "java.util.ArrayList",
        "java.util.HashMap",
        "java.util.HashSet",
        "java.util.concurrent.CompletionStage",
        "reactor.core.publisher.Mono",
        "reactor.core.publisher.Flux",
    ];
    UNSUPPORTED
        .iter()
        .any(|canonical| bindings.canonical(base, canonical))
}

fn equivalent_transactions(file: &JavaFile<'_>, left: &Annotation, right: &Annotation) -> bool {
    transaction_settings(file, left)
        .zip(transaction_settings(file, right))
        .is_some_and(|(left, right)| {
            left.get("propagation").is_some_and(|value| {
                matches!(
                    value.as_str(),
                    "REQUIRED" | "SUPPORTS" | "MANDATORY" | "NEVER" | "NOT_SUPPORTED"
                )
            }) && left == right
        })
}

fn transaction_settings(
    file: &JavaFile<'_>,
    annotation: &Annotation,
) -> Option<BTreeMap<String, String>> {
    let mut settings = BTreeMap::from([
        ("transactionManager".to_owned(), "\"\"".to_owned()),
        ("propagation".to_owned(), "REQUIRED".to_owned()),
        ("isolation".to_owned(), "DEFAULT".to_owned()),
        ("timeout".to_owned(), "-1".to_owned()),
        ("timeoutString".to_owned(), "\"\"".to_owned()),
        ("readOnly".to_owned(), "false".to_owned()),
        ("rollbackFor".to_owned(), "{}".to_owned()),
        ("rollbackForClassName".to_owned(), "{}".to_owned()),
        ("noRollbackFor".to_owned(), "{}".to_owned()),
        ("noRollbackForClassName".to_owned(), "{}".to_owned()),
        ("label".to_owned(), "{}".to_owned()),
    ]);
    let Some((start, end)) = annotation.arguments else {
        return Some(settings);
    };
    // Split the lexical mask, then retrieve original literal values by offset.
    let masked = &file.masked[start..end];
    for argument in split_top_level(masked) {
        let relative = argument.as_ptr() as usize - masked.as_ptr() as usize;
        let raw = &file.source[start + relative..start + relative + argument.len()];
        if raw.trim().is_empty() {
            continue;
        }
        let (key, value) = raw
            .split_once('=')
            .map_or(("transactionManager", raw), |(key, value)| {
                (key.trim(), value)
            });
        let key = if key == "value" {
            "transactionManager"
        } else {
            key
        };
        if !settings.contains_key(key) {
            return None;
        }
        let value = value.trim();
        let value = if matches!(key, "propagation" | "isolation") {
            value.rsplit('.').next()?.trim().to_owned()
        } else {
            value.to_owned()
        };
        settings.insert(key.to_owned(), value);
    }
    Some(settings)
}

fn self_calls(file: &JavaFile<'_>, caller: &Method, target: &Method) -> Vec<usize> {
    let Some((start, end)) = caller.body else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut index = start;
    while index < end {
        // Inner/local classes and anonymous constructions have a different
        // receiver. Skip their complete syntax, including constructor callbacks.
        if matches!(
            file.text(index),
            "class" | "interface" | "enum" | "record" | "new"
        ) {
            index = skip_nested_expression(file, index, end);
            continue;
        }
        if file.text(index) == "-" && file.text(index + 1) == ">" {
            index = skip_lambda(file, index + 2, end);
            continue;
        }
        if file.text(index) != target.name || file.text(index + 1) != "(" {
            index += 1;
            continue;
        }
        let previous = index
            .checked_sub(1)
            .map_or("", |previous| file.text(previous));
        let direct = if previous == "." {
            index >= 2
                && file.text(index - 2) == "this"
                && (index < 3 || !matches!(file.text(index - 3), "." | ":"))
        } else {
            !matches!(previous, ":" | "@" | "new" | ">")
        };
        let open = index + 1;
        let Some(&close) = file.pairs.get(&open) else {
            index += 1;
            continue;
        };
        if direct {
            let arity = argument_count(file, open, close);
            if arity == target.parameters {
                result.push(file.tokens[index].start);
            }
        }
        index += 1;
    }
    result
}

fn argument_count(file: &JavaFile<'_>, open: usize, close: usize) -> usize {
    let start = file.tokens[open].end;
    let end = file.tokens[close].start;
    let masked = &file.masked[start..end];
    if !masked.trim().is_empty() {
        return split_top_level(masked).len();
    }
    // A string-only argument is blank in the shared mask; comments alone are
    // not arguments. Look only for the first real token, without reading any
    // literal contents as Java syntax.
    let source = &file.source[start..end];
    let mut remaining = source.trim_start();
    loop {
        if let Some(comment) = remaining.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else {
                return 0;
            };
            remaining = comment[end + 2..].trim_start();
        } else if let Some(comment) = remaining.strip_prefix("//") {
            let Some(end) = comment.find('\n') else {
                return 0;
            };
            remaining = comment[end + 1..].trim_start();
        } else {
            return usize::from(!remaining.is_empty());
        }
    }
}

fn skip_nested_expression(file: &JavaFile<'_>, start: usize, end: usize) -> usize {
    let mut index = start + 1;
    while index < end {
        if file.text(index) == "{" {
            return file.pairs.get(&index).map_or(end, |close| close + 1);
        }
        if matches!(file.text(index), ";" | ",") {
            return index + 1;
        }
        if matches!(file.text(index), "(" | "[")
            && let Some(close) = file.pairs.get(&index)
        {
            index = close + 1;
            continue;
        }
        if file.text(index) == ")" {
            return index;
        }
        index += 1;
    }
    end
}

fn skip_lambda(file: &JavaFile<'_>, start: usize, end: usize) -> usize {
    if file.text(start) == "{" {
        return file.pairs.get(&start).map_or(end, |close| close + 1);
    }
    let mut index = start;
    while index < end {
        if matches!(file.text(index), ";" | "," | ")" | "}") {
            return index;
        }
        if matches!(file.text(index), "(" | "[" | "{")
            && let Some(close) = file.pairs.get(&index)
        {
            index = close + 1;
            continue;
        }
        index += 1;
    }
    end
}

fn line_at(source: &str, offset: usize) -> usize {
    source.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn finding(
    code: &str,
    file: &JavaFile<'_>,
    offset: usize,
    message: String,
    confidence: &str,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Spring rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: file.path.to_owned(),
        line: line_at(file.source, offset),
        end_line: 0,
        message,
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

#[cfg(test)]
#[path = "spring_tests.rs"]
mod tests;
