use std::collections::BTreeSet;
use std::sync::Arc;

use regex_syntax::hir::{Hir, HirKind};

/// Capture accesses that are statically known to succeed.
///
/// All source-wide work is done by [`RegexContracts::new`]. Queries are exact
/// offset lookups so the unwrap/expect reporting path does not rescan the file.
pub(super) struct RegexContracts {
    source_len: usize,
    invariant_call_offsets: BTreeSet<usize>,
}

impl RegexContracts {
    pub(super) fn new(source: &str, masked: &str) -> Self {
        if source.len() != masked.len() {
            return Self {
                source_len: source.len(),
                invariant_call_offsets: BTreeSet::new(),
            };
        }

        let parsed = ParsedSource::new(source, masked);
        let mut analyzer = Analyzer {
            parsed: &parsed,
            bindings: Vec::new(),
            next_serial: 0,
        };
        analyzer.collect_function_parameters();
        analyzer.collect_closure_parameters();
        analyzer.collect_value_declarations();
        analyzer.collect_capture_bindings();
        let invariant_call_offsets = analyzer.collect_invariant_accesses();

        Self {
            source_len: source.len(),
            invariant_call_offsets,
        }
    }

    pub(super) fn capture_access_is_invariant(
        &self,
        source: &str,
        masked: &str,
        call_offset: usize,
    ) -> bool {
        if source.len() != self.source_len || masked.len() != self.source_len {
            return false;
        }
        let Some(tail) = masked.get(call_offset..) else {
            return false;
        };
        (tail.starts_with(".unwrap") || tail.starts_with(".expect"))
            && self.invariant_call_offsets.contains(&call_offset)
    }
}

#[derive(Default)]
struct CaptureContract {
    numbers: BTreeSet<u32>,
    names: BTreeSet<String>,
    hir: Option<Hir>,
}

impl CaptureContract {
    fn from_pattern(pattern: &str) -> Option<Self> {
        let hir = regex_syntax::Parser::new().parse(pattern).ok()?;
        let mut contract = guaranteed_captures(&hir);
        // A successful `captures`/`captures_iter` value always contains the
        // full match, independently of the pattern's explicit groups.
        contract.numbers.insert(0);
        contract.hir = Some(hir);
        Some(contract)
    }

    fn group_zero() -> Self {
        Self {
            numbers: BTreeSet::from([0]),
            names: BTreeSet::new(),
            hir: None,
        }
    }

    fn guarantees(&self, access: &CaptureAccess) -> bool {
        match access {
            CaptureAccess::Number(number) => self.numbers.contains(number),
            CaptureAccess::Name(name) => self.names.contains(name),
        }
    }

    fn guarantees_any(&self, accesses: &[CaptureAccess]) -> bool {
        accesses.iter().any(|access| self.guarantees(access))
            || self
                .hir
                .as_ref()
                .is_some_and(|hir| hir_guarantees_any_capture(hir, accesses))
    }
}

fn guaranteed_captures(hir: &Hir) -> CaptureContract {
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => {
            CaptureContract::default()
        }
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                CaptureContract::default()
            } else {
                guaranteed_captures(&repetition.sub)
            }
        }
        HirKind::Capture(capture) => {
            let mut contract = guaranteed_captures(&capture.sub);
            contract.numbers.insert(capture.index);
            if let Some(name) = &capture.name {
                contract.names.insert(name.to_string());
            }
            contract
        }
        HirKind::Concat(parts) => {
            let mut contract = CaptureContract::default();
            for part in parts {
                let child = guaranteed_captures(part);
                contract.numbers.extend(child.numbers);
                contract.names.extend(child.names);
            }
            contract
        }
        HirKind::Alternation(branches) => {
            let Some((first, rest)) = branches.split_first() else {
                return CaptureContract::default();
            };
            let mut contract = guaranteed_captures(first);
            for branch in rest {
                let child = guaranteed_captures(branch);
                contract
                    .numbers
                    .retain(|number| child.numbers.contains(number));
                contract.names.retain(|name| child.names.contains(name));
            }
            contract
        }
    }
}

/// Returns true only when every successful path through `hir` participates in
/// at least one of the requested capture groups.
fn hir_guarantees_any_capture(hir: &Hir, accesses: &[CaptureAccess]) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => false,
        HirKind::Repetition(repetition) => {
            repetition.min > 0 && hir_guarantees_any_capture(&repetition.sub, accesses)
        }
        HirKind::Capture(capture) => {
            accesses.iter().any(|access| match access {
                CaptureAccess::Number(number) => *number == capture.index,
                CaptureAccess::Name(name) => capture.name.as_deref() == Some(name.as_str()),
            }) || hir_guarantees_any_capture(&capture.sub, accesses)
        }
        HirKind::Concat(parts) => parts
            .iter()
            .any(|part| hir_guarantees_any_capture(part, accesses)),
        HirKind::Alternation(branches) => {
            !branches.is_empty()
                && branches
                    .iter()
                    .all(|branch| hir_guarantees_any_capture(branch, accesses))
        }
    }
}

#[derive(Clone)]
enum BindingValue {
    Regex(Arc<CaptureContract>),
    DynamicRegex,
    Captures(Arc<CaptureContract>),
    Unknown,
}

struct Binding {
    name: String,
    start: usize,
    end: usize,
    scope_depth: usize,
    serial: usize,
    value: BindingValue,
}

struct Analyzer<'a> {
    parsed: &'a ParsedSource<'a>,
    bindings: Vec<Binding>,
    next_serial: usize,
}

impl Analyzer<'_> {
    fn add_binding(&mut self, name: &str, start: usize, scope_id: usize, value: BindingValue) {
        let scope = &self.parsed.scopes[scope_id];
        self.add_binding_range(name, start, scope.close, scope.depth, value);
    }

    fn add_binding_range(
        &mut self,
        name: &str,
        start: usize,
        end: usize,
        scope_depth: usize,
        value: BindingValue,
    ) {
        if name == "_" || start >= end {
            return;
        }
        self.bindings.push(Binding {
            name: name.to_owned(),
            start,
            end,
            scope_depth,
            serial: self.next_serial,
            value,
        });
        self.next_serial += 1;
    }

    fn resolve(&self, name: &str, offset: usize) -> Option<&BindingValue> {
        self.bindings
            .iter()
            .filter(|binding| {
                binding.name == name && binding.start <= offset && offset < binding.end
            })
            .max_by_key(|binding| (binding.scope_depth, binding.start, binding.serial))
            .map(|binding| &binding.value)
    }

    fn collect_closure_parameters(&mut self) {
        for pipe in 0..self.parsed.tokens.len() {
            if !self.looks_like_closure_start(pipe) {
                continue;
            }
            let Some((name, start, end, scope_depth, _)) = self.simple_closure_binding(pipe, None)
            else {
                continue;
            };
            self.add_binding_range(&name, start, end, scope_depth, BindingValue::Unknown);
        }
    }

    fn looks_like_closure_start(&self, pipe: usize) -> bool {
        let tokens = &self.parsed.tokens;
        if !tokens.get(pipe).is_some_and(|token| token.is_symbol(b'|')) {
            return false;
        }
        pipe == 0
            || tokens[pipe - 1].is_ident("move")
            || matches!(
                tokens[pipe - 1].symbol(),
                Some(b'(' | b'[' | b'{' | b',' | b'=' | b';')
            )
    }

    fn simple_closure_binding(
        &self,
        pipe: usize,
        outer_close: Option<usize>,
    ) -> Option<(String, usize, usize, usize, usize)> {
        let tokens = &self.parsed.tokens;
        if !tokens.get(pipe)?.is_symbol(b'|') {
            return None;
        }
        let mut name = pipe + 1;
        while tokens.get(name).is_some_and(|token| {
            token.is_symbol(b'&') || token.is_ident("mut") || token.is_ident("ref")
        }) {
            name += 1;
        }
        let identifier = tokens.get(name)?.identifier()?.to_owned();
        let closing_pipe = name + 1;
        if !tokens
            .get(closing_pipe)
            .is_some_and(|token| token.is_symbol(b'|'))
        {
            return None;
        }
        let body = closing_pipe + 1;
        let body_token = tokens.get(body)?;
        if body_token.is_symbol(b'{') {
            let close = self.parsed.matching(body)?;
            if outer_close.is_some_and(|outer| close >= outer) {
                return None;
            }
            let scope_id = self.parsed.brace_scope[body]?;
            let scope = &self.parsed.scopes[scope_id];
            return Some((identifier, scope.open, scope.close, scope.depth, close + 1));
        }

        let expression_end = self.closure_expression_end(body, outer_close)?;
        let start = body_token.start;
        let end = tokens
            .get(expression_end)
            .map_or(self.parsed.source.len(), |token| token.start);
        let scope_id = self.parsed.scope_at(start);
        Some((
            identifier,
            start,
            end,
            self.parsed.scopes[scope_id].depth,
            expression_end,
        ))
    }

    fn closure_expression_end(&self, start: usize, outer_close: Option<usize>) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let limit = outer_close.unwrap_or(tokens.len());
        let mut index = start;
        while index < limit {
            match tokens[index].symbol() {
                Some(b'(' | b'[' | b'{') => {
                    let close = self.parsed.matching(index)?;
                    if close >= limit {
                        return None;
                    }
                    index = close + 1;
                }
                Some(b',' | b';' | b')' | b']' | b'}') => break,
                _ => index += 1,
            }
        }
        Some(index)
    }

    fn collect_function_parameters(&mut self) {
        let tokens = &self.parsed.tokens;
        for function in 0..tokens.len() {
            if !tokens[function].is_ident("fn") {
                continue;
            }
            let Some(open) =
                (function + 1..tokens.len()).find(|index| tokens[*index].is_symbol(b'('))
            else {
                continue;
            };
            let Some(close) = self.parsed.matching(open) else {
                continue;
            };
            let Some(body) = self.find_function_body(close + 1) else {
                continue;
            };
            let Some(scope_id) = self.parsed.brace_scope[body] else {
                continue;
            };
            let binding_start = tokens[body].end;
            for (start, end) in self.top_level_segments(open + 1, close) {
                let Some(colon) = self.find_top_level_symbol(start, end, b':') else {
                    continue;
                };
                let Some(name) = (start..colon)
                    .rev()
                    .find_map(|index| tokens[index].identifier())
                    .map(ToOwned::to_owned)
                else {
                    continue;
                };
                if !matches!(name.as_str(), "self" | "Self" | "mut" | "ref") {
                    let value = if self.is_regex_type(colon + 1, end) {
                        BindingValue::DynamicRegex
                    } else {
                        BindingValue::Unknown
                    };
                    self.add_binding(&name, binding_start, scope_id, value);
                }
            }
        }
    }

    fn is_regex_type(&self, mut start: usize, end: usize) -> bool {
        let tokens = &self.parsed.tokens;
        if tokens.get(start).is_some_and(|token| token.is_symbol(b'&')) {
            start += 1;
        }
        if tokens.get(start).is_some_and(|token| token.is_ident("mut")) {
            start += 1;
        }
        match end.saturating_sub(start) {
            1 => tokens[start].is_ident("Regex"),
            4 => {
                tokens[start].is_ident("regex")
                    && tokens[start + 1].is_symbol(b':')
                    && tokens[start + 2].is_symbol(b':')
                    && tokens[start + 3].is_ident("Regex")
            }
            _ => false,
        }
    }

    fn find_function_body(&self, start: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let mut index = start;
        while index < tokens.len() {
            if tokens[index].is_symbol(b';') {
                return None;
            }
            if tokens[index].is_symbol(b'{') {
                return self.parsed.matching(index).map(|_| index);
            }
            if matches!(tokens[index].symbol(), Some(b'(' | b'[')) {
                index = self.parsed.matching(index)? + 1;
            } else {
                index += 1;
            }
        }
        None
    }

    fn collect_value_declarations(&mut self) {
        for (declaration, token) in self.parsed.tokens.iter().enumerate() {
            if token.is_ident("let") {
                self.collect_let_declaration(declaration);
            } else if token.is_ident("static") || token.is_ident("const") {
                self.collect_item_declaration(declaration);
            }
        }
    }

    fn collect_let_declaration(&mut self, declaration: usize) {
        let tokens = &self.parsed.tokens;
        if declaration > 0
            && !(tokens[declaration - 1].is_symbol(b'{')
                || tokens[declaration - 1].is_symbol(b';')
                || tokens[declaration - 1].is_symbol(b'}'))
        {
            return;
        }

        let mut name_index = declaration + 1;
        if tokens
            .get(name_index)
            .is_some_and(|token| token.is_ident("mut"))
        {
            name_index += 1;
        }
        let Some(name) = tokens
            .get(name_index)
            .and_then(Token::identifier)
            .map(ToOwned::to_owned)
        else {
            return;
        };
        if !tokens
            .get(name_index + 1)
            .is_some_and(|token| token.is_symbol(b':') || token.is_symbol(b'='))
        {
            return;
        }
        let Some(semicolon) = self.find_statement_semicolon(name_index + 1) else {
            return;
        };
        let Some(equals) = self.find_top_level_symbol(name_index + 1, semicolon, b'=') else {
            return;
        };
        let scope_id = self.parsed.scope_at(tokens[declaration].start);
        let value = self.regex_value_from_initializer(equals + 1, semicolon);
        self.add_binding(&name, tokens[semicolon].end, scope_id, value);
    }

    fn collect_item_declaration(&mut self, declaration: usize) {
        let tokens = &self.parsed.tokens;
        let mut name_index = declaration + 1;
        if tokens
            .get(name_index)
            .is_some_and(|token| token.is_ident("mut"))
        {
            name_index += 1;
        }
        let Some(name) = tokens
            .get(name_index)
            .and_then(Token::identifier)
            .map(ToOwned::to_owned)
        else {
            return;
        };
        let Some(semicolon) = self.find_statement_semicolon(name_index + 1) else {
            return;
        };
        let Some(equals) = self.find_top_level_symbol(name_index + 1, semicolon, b'=') else {
            return;
        };
        let scope_id = self.parsed.scope_at(tokens[declaration].start);
        let value = self.regex_value_from_initializer(equals + 1, semicolon);
        let start = self.parsed.scopes[scope_id].open;
        self.add_binding(&name, start, scope_id, value);
    }

    fn regex_value_from_initializer(&self, start: usize, end: usize) -> BindingValue {
        if let Some(contract) = self.contract_from_initializer(start, end) {
            return BindingValue::Regex(contract);
        }
        if self.regex_expression_end(start, end) == Some(end) {
            return BindingValue::DynamicRegex;
        }
        if start + 1 == end
            && let Some(name) = self.parsed.tokens.get(start).and_then(Token::identifier)
            && let Some(value @ (BindingValue::Regex(_) | BindingValue::DynamicRegex)) =
                self.resolve(name, self.parsed.tokens[start].start)
        {
            return value.clone();
        }
        BindingValue::Unknown
    }

    fn contract_from_initializer(&self, start: usize, end: usize) -> Option<Arc<CaptureContract>> {
        let (contract, next) = self
            .contract_from_regex_expression(start, end)
            .or_else(|| self.contract_from_lazy_initializer(start, end))?;
        (next == end).then_some(contract)
    }

    fn contract_from_regex_expression(
        &self,
        mut start: usize,
        end: usize,
    ) -> Option<(Arc<CaptureContract>, usize)> {
        let tokens = &self.parsed.tokens;
        if tokens.get(start).is_some_and(|token| token.is_symbol(b'&')) {
            start += 1;
        }
        let open = self.constructor_open_at(start)?;
        let close = self.parsed.matching(open)?;
        if close >= end {
            return None;
        }
        let pattern =
            parse_static_string(self.parsed.source, tokens[open].end, tokens[close].start)?;
        let contract = Arc::new(CaptureContract::from_pattern(&pattern)?);
        let next = self.regex_result_end(close, end)?;
        Some((contract, next))
    }

    fn regex_expression_end(&self, mut start: usize, end: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        if tokens.get(start).is_some_and(|token| token.is_symbol(b'&')) {
            start += 1;
        }
        let open = self.constructor_open_at(start)?;
        let close = self.parsed.matching(open)?;
        self.regex_result_end(close, end)
    }

    fn regex_result_end(&self, close: usize, end: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        if close >= end {
            return None;
        }
        let next = close + 1;
        if tokens.get(next).is_some_and(|token| token.is_symbol(b'?')) {
            return Some(next + 1);
        }
        if !tokens.get(next).is_some_and(|token| token.is_symbol(b'.')) {
            return None;
        }
        let method = tokens.get(next + 1)?.identifier()?;
        let open = next + 2;
        if !matches!(method, "unwrap" | "expect")
            || !tokens.get(open).is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        let method_close = self.parsed.matching(open)?;
        (method_close < end).then_some(method_close + 1)
    }

    fn contract_from_lazy_initializer(
        &self,
        start: usize,
        end: usize,
    ) -> Option<(Arc<CaptureContract>, usize)> {
        let wrapper_open = self.lazy_wrapper_open(start, end)?;
        let wrapper_close = self.parsed.matching(wrapper_open)?;
        if wrapper_close >= end {
            return None;
        }
        let (expression, expression_end) =
            self.lazy_closure_expression(wrapper_open, wrapper_close)?;
        let (contract, next) = self.contract_from_regex_expression(expression, expression_end)?;
        (next == expression_end).then_some((contract, wrapper_close + 1))
    }

    fn lazy_wrapper_open(&self, start: usize, end: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let lazy = (start..end).find(|index| tokens[*index].is_ident("LazyLock"))?;
        if lazy != start && !self.is_path_prefix(start, lazy) {
            return None;
        }
        self.new_call_open(lazy + 1)
    }

    fn lazy_closure_expression(
        &self,
        wrapper_open: usize,
        wrapper_close: usize,
    ) -> Option<(usize, usize)> {
        let tokens = &self.parsed.tokens;
        let mut expression = wrapper_open + 1;
        if tokens
            .get(expression)
            .is_some_and(|token| token.is_ident("move"))
        {
            expression += 1;
        }
        if !tokens
            .get(expression)
            .is_some_and(|token| token.is_symbol(b'|'))
            || !tokens
                .get(expression + 1)
                .is_some_and(|token| token.is_symbol(b'|'))
        {
            return None;
        }
        expression += 2;
        if !tokens
            .get(expression)
            .is_some_and(|token| token.is_symbol(b'{'))
        {
            return Some((expression, wrapper_close));
        }
        let expression_end = self.parsed.matching(expression)?;
        Some((expression + 1, expression_end))
    }

    fn is_path_prefix(&self, start: usize, end: usize) -> bool {
        let tokens = &self.parsed.tokens;
        if start >= end {
            return false;
        }
        let mut index = start;
        while index < end {
            if tokens[index].identifier().is_none()
                || !tokens
                    .get(index + 1)
                    .is_some_and(|token| token.is_symbol(b':'))
                || !tokens
                    .get(index + 2)
                    .is_some_and(|token| token.is_symbol(b':'))
            {
                return false;
            }
            index += 3;
        }
        index == end
    }

    fn constructor_open_at(&self, start: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        if tokens
            .get(start)
            .is_some_and(|token| token.is_ident("Regex"))
        {
            return self.new_call_open(start + 1);
        }
        if tokens
            .get(start)
            .is_some_and(|token| token.is_ident("regex"))
            && tokens
                .get(start + 1)
                .is_some_and(|token| token.is_symbol(b':'))
            && tokens
                .get(start + 2)
                .is_some_and(|token| token.is_symbol(b':'))
            && tokens
                .get(start + 3)
                .is_some_and(|token| token.is_ident("Regex"))
        {
            return self.new_call_open(start + 4);
        }
        None
    }

    fn new_call_open(&self, start: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        (tokens.get(start).is_some_and(|token| token.is_symbol(b':'))
            && tokens
                .get(start + 1)
                .is_some_and(|token| token.is_symbol(b':'))
            && tokens
                .get(start + 2)
                .is_some_and(|token| token.is_ident("new"))
            && tokens
                .get(start + 3)
                .is_some_and(|token| token.is_symbol(b'(')))
        .then_some(start + 3)
    }

    fn collect_capture_bindings(&mut self) {
        let token_count = self.parsed.tokens.len();
        for index in 0..token_count {
            if self.parsed.tokens[index].is_ident("for") {
                self.collect_captures_iter_binding(index);
            } else if self.parsed.tokens[index].is_ident("if") {
                self.collect_if_let_binding(index);
            } else if self.parsed.tokens[index].is_ident("let") {
                self.collect_let_else_binding(index);
            }
            if self.capture_receiver_starts_at(index) {
                self.collect_capture_callback_bindings(index);
            }
        }
    }

    fn capture_receiver_starts_at(&self, index: usize) -> bool {
        let tokens = &self.parsed.tokens;
        tokens[index].identifier().is_some()
            && (tokens
                .get(index + 1)
                .is_some_and(|token| token.is_symbol(b'.'))
                || (tokens
                    .get(index + 1)
                    .is_some_and(|token| token.is_symbol(b':'))
                    && tokens
                        .get(index + 2)
                        .is_some_and(|token| token.is_symbol(b':'))))
    }

    fn collect_capture_callback_bindings(&mut self, start: usize) {
        if let Some((contract, close)) = self.capture_call(start, "captures") {
            self.collect_capture_callback_chain(contract, close + 1, false);
        } else if let Some((contract, close)) = self.capture_call(start, "captures_iter") {
            self.collect_capture_callback_chain(contract, close + 1, true);
        }
    }

    fn collect_capture_callback_chain(
        &mut self,
        contract: Arc<CaptureContract>,
        mut dot: usize,
        iterator: bool,
    ) {
        loop {
            let Some((binds_capture, preserves_capture, open, close)) =
                self.capture_callback_step(dot, iterator)
            else {
                return;
            };
            if binds_capture
                && !self.collect_capture_callback_binding(open, close, Arc::clone(&contract))
            {
                return;
            }
            if !preserves_capture {
                return;
            }
            dot = close + 1;
        }
    }

    fn capture_callback_step(
        &self,
        dot: usize,
        iterator: bool,
    ) -> Option<(bool, bool, usize, usize)> {
        let tokens = &self.parsed.tokens;
        if !tokens.get(dot)?.is_symbol(b'.') {
            return None;
        }
        let method = tokens.get(dot + 1)?.identifier()?;
        let open = dot + 2;
        if !tokens.get(open)?.is_symbol(b'(') {
            return None;
        }
        let close = self.parsed.matching(open)?;
        let (binds_capture, preserves_capture) = if iterator {
            match method {
                "take" => (false, true),
                "filter" | "inspect" => (true, true),
                "map" | "filter_map" | "any" | "all" | "find" | "find_map" | "position"
                | "for_each" => (true, false),
                _ => return None,
            }
        } else {
            match method {
                "filter" | "inspect" => (true, true),
                "map" | "and_then" | "is_some_and" => (true, false),
                _ => return None,
            }
        };
        Some((binds_capture, preserves_capture, open, close))
    }

    fn collect_capture_callback_binding(
        &mut self,
        open: usize,
        close: usize,
        contract: Arc<CaptureContract>,
    ) -> bool {
        let tokens = &self.parsed.tokens;
        let mut pipe = open + 1;
        if tokens.get(pipe).is_some_and(|token| token.is_ident("move")) {
            pipe += 1;
        }
        let Some((name, start, end, scope_depth, after)) =
            self.simple_closure_binding(pipe, Some(close))
        else {
            return false;
        };
        let fills_argument = after == close
            || (after + 1 == close && tokens.get(after).is_some_and(|token| token.is_symbol(b',')));
        if !fills_argument {
            return false;
        }
        self.add_binding_range(
            &name,
            start,
            end,
            scope_depth,
            BindingValue::Captures(contract),
        );
        true
    }

    fn collect_captures_iter_binding(&mut self, start: usize) {
        let tokens = &self.parsed.tokens;
        let Some(name) = tokens
            .get(start + 1)
            .and_then(Token::identifier)
            .map(ToOwned::to_owned)
        else {
            return;
        };
        if !tokens
            .get(start + 2)
            .is_some_and(|token| token.is_ident("in"))
        {
            return;
        }
        let expression = start + 3;
        let Some((value, body, scope_id)) = self.capture_binding(expression, "captures_iter")
        else {
            return;
        };
        self.add_binding(&name, tokens[body].end, scope_id, value);
    }

    fn collect_if_let_binding(&mut self, start: usize) {
        let tokens = &self.parsed.tokens;
        if !tokens
            .get(start + 1)
            .is_some_and(|token| token.is_ident("let"))
        {
            return;
        }
        let Some((name, pattern_close)) = self.some_capture_pattern(start + 2) else {
            return;
        };
        if !tokens
            .get(pattern_close + 1)
            .is_some_and(|token| token.is_symbol(b'='))
        {
            return;
        }
        let expression = pattern_close + 2;
        let Some((value, body, scope_id)) = self.capture_binding(expression, "captures") else {
            return;
        };
        self.add_binding(&name, tokens[body].end, scope_id, value);
    }

    fn capture_binding(
        &self,
        expression: usize,
        method: &str,
    ) -> Option<(BindingValue, usize, usize)> {
        let capture_call = self.capture_call(expression, method);
        let body = capture_call.as_ref().map_or_else(
            || self.find_control_body(expression),
            |(_, close)| Some(close + 1),
        )?;
        let tokens = &self.parsed.tokens;
        if !tokens.get(body).is_some_and(|token| token.is_symbol(b'{')) {
            return None;
        }
        let scope_id = self.parsed.brace_scope[body]?;
        let value = capture_call.map_or(BindingValue::Unknown, |(contract, _)| {
            BindingValue::Captures(contract)
        });
        Some((value, body, scope_id))
    }

    fn collect_let_else_binding(&mut self, start: usize) {
        let tokens = &self.parsed.tokens;
        if start > 0
            && !(tokens[start - 1].is_symbol(b'{')
                || tokens[start - 1].is_symbol(b';')
                || tokens[start - 1].is_symbol(b'}'))
        {
            return;
        }
        let Some((name, pattern_close)) = self.some_capture_pattern(start + 1) else {
            return;
        };
        if !tokens
            .get(pattern_close + 1)
            .is_some_and(|token| token.is_symbol(b'='))
        {
            return;
        }
        let expression = pattern_close + 2;
        let capture_call = self.capture_call(expression, "captures");
        let else_keyword = capture_call
            .as_ref()
            .map(|(_, close)| close + 1)
            .filter(|index| {
                tokens
                    .get(*index)
                    .is_some_and(|token| token.is_ident("else"))
            })
            .or_else(|| self.find_top_level_ident(expression, "else"));
        let Some(else_keyword) = else_keyword else {
            return;
        };
        let else_open = else_keyword + 1;
        if !tokens
            .get(else_open)
            .is_some_and(|token| token.is_symbol(b'{'))
        {
            return;
        }
        let Some(else_close) = self.parsed.matching(else_open) else {
            return;
        };
        let semicolon = else_close + 1;
        if !tokens
            .get(semicolon)
            .is_some_and(|token| token.is_symbol(b';'))
        {
            return;
        }
        let scope_id = self.parsed.scope_at(tokens[start].start);
        let value = capture_call.map_or(BindingValue::Unknown, |(contract, _)| {
            BindingValue::Captures(contract)
        });
        self.add_binding(&name, tokens[semicolon].end, scope_id, value);
    }

    fn some_capture_pattern(&self, start: usize) -> Option<(String, usize)> {
        let tokens = &self.parsed.tokens;
        if !tokens
            .get(start)
            .is_some_and(|token| token.is_ident("Some"))
            || !tokens
                .get(start + 1)
                .is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        let close = self.parsed.matching(start + 1)?;
        let mut name = start + 2;
        while tokens
            .get(name)
            .is_some_and(|token| token.is_ident("ref") || token.is_ident("mut"))
        {
            name += 1;
        }
        let identifier = tokens.get(name)?.identifier()?;
        (name + 1 == close).then(|| (identifier.to_owned(), close))
    }

    fn capture_call(&self, start: usize, method: &str) -> Option<(Arc<CaptureContract>, usize)> {
        let (receiver_end, argument_open) = self.receiver_method_call(start, method)?;
        let contract = self.capture_contract_for_receiver(start, receiver_end)?;
        let close = self.parsed.matching(argument_open)?;
        Some((contract, close))
    }

    fn receiver_method_call(&self, start: usize, method: &str) -> Option<(usize, usize)> {
        let tokens = &self.parsed.tokens;
        let mut index = start;
        while index < tokens.len() {
            if tokens[index].is_symbol(b'.')
                && index > start
                && tokens
                    .get(index + 1)
                    .is_some_and(|token| token.is_ident(method))
                && tokens
                    .get(index + 2)
                    .is_some_and(|token| token.is_symbol(b'('))
            {
                return Some((index, index + 2));
            }
            match tokens[index].symbol() {
                Some(b'(' | b'[') => index = self.parsed.matching(index)? + 1,
                Some(b'=' | b';' | b'{' | b'}' | b',') => return None,
                _ if tokens[index].is_ident("else") => return None,
                _ => index += 1,
            }
        }
        None
    }

    fn capture_contract_for_receiver(
        &self,
        start: usize,
        receiver_end: usize,
    ) -> Option<Arc<CaptureContract>> {
        let Some((name, offset)) = self.bare_receiver_name(start, receiver_end) else {
            return Some(Arc::new(CaptureContract::group_zero()));
        };
        match self.resolve(name, offset) {
            Some(BindingValue::Regex(contract)) => Some(Arc::clone(contract)),
            Some(BindingValue::DynamicRegex) | None => {
                Some(Arc::new(CaptureContract::group_zero()))
            }
            Some(BindingValue::Captures(_) | BindingValue::Unknown) => None,
        }
    }

    fn bare_receiver_name(&self, start: usize, end: usize) -> Option<(&str, usize)> {
        let (start, end) = self.bare_receiver_bounds(start, end);
        if start + 1 != end {
            return None;
        }
        let token = self.parsed.tokens.get(start)?;
        Some((token.identifier()?, token.start))
    }

    fn bare_receiver_bounds(&self, mut start: usize, mut end: usize) -> (usize, usize) {
        while start < end {
            if self.is_parenthesized_receiver(start, end) {
                start += 1;
                end -= 1;
                continue;
            }
            if self.is_receiver_prefix(start) {
                start += 1;
                continue;
            }
            break;
        }
        (start, end)
    }

    fn is_parenthesized_receiver(&self, start: usize, end: usize) -> bool {
        self.parsed.tokens[start].is_symbol(b'(') && self.parsed.matching(start) == Some(end - 1)
    }

    fn is_receiver_prefix(&self, index: usize) -> bool {
        let token = &self.parsed.tokens[index];
        matches!(token.symbol(), Some(b'&' | b'*')) || token.is_ident("mut")
    }

    fn direct_capture_access_offset(&self, start: usize) -> Option<usize> {
        if !self.is_expression_start(start) {
            return None;
        }
        let (contract, capture_close) = self.capture_call(start, "captures")?;
        let captures_end = self.result_extraction_end(capture_close + 1)?;
        let tokens = &self.parsed.tokens;
        if !tokens
            .get(captures_end)
            .is_some_and(|token| token.is_symbol(b'.'))
            || !tokens
                .get(captures_end + 1)
                .is_some_and(|token| token.is_ident("get"))
            || !tokens
                .get(captures_end + 2)
                .is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        let argument_open = captures_end + 2;
        let argument_close = self.parsed.matching(argument_open)?;
        let access = self.capture_access("get", argument_open, argument_close)?;
        if !contract.guarantees(&access) {
            return None;
        }
        self.panic_call_offset(argument_close + 1)
    }

    fn result_extraction_end(&self, dot: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        if !tokens.get(dot).is_some_and(|token| token.is_symbol(b'.'))
            || !tokens
                .get(dot + 1)
                .is_some_and(|token| matches!(token.identifier(), Some("unwrap" | "expect")))
            || !tokens
                .get(dot + 2)
                .is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        self.parsed.matching(dot + 2).map(|close| close + 1)
    }

    fn is_expression_start(&self, index: usize) -> bool {
        let tokens = &self.parsed.tokens;
        if index == 0 {
            return true;
        }
        !(tokens[index - 1].is_symbol(b'.')
            || index >= 2 && tokens[index - 1].is_symbol(b':') && tokens[index - 2].is_symbol(b':'))
    }

    fn collect_invariant_accesses(&self) -> BTreeSet<usize> {
        (0..self.parsed.tokens.len())
            .filter_map(|receiver| {
                self.invariant_access_offset(receiver)
                    .or_else(|| self.direct_capture_access_offset(receiver))
            })
            .collect()
    }

    fn invariant_access_offset(&self, receiver: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let name = tokens[receiver].identifier()?;
        if !self.is_bare_identifier(receiver)
            || !tokens
                .get(receiver + 1)
                .is_some_and(|token| token.is_symbol(b'.'))
        {
            return None;
        }
        let method = tokens.get(receiver + 2)?.identifier()?;
        let argument_open = receiver + 3;
        if !matches!(method, "get" | "name")
            || !tokens
                .get(argument_open)
                .is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        let argument_close = self.parsed.matching(argument_open)?;
        let access = self.capture_access(method, argument_open, argument_close)?;
        let BindingValue::Captures(contract) = self.resolve(name, tokens[receiver].start)? else {
            return None;
        };
        let after_access = argument_close + 1;
        if let Some(offset) = self.panic_call_offset(after_access) {
            return contract.guarantees(&access).then_some(offset);
        }
        let (accesses, after_fallbacks) =
            self.collect_capture_fallbacks(name, after_access, access)?;
        if !contract.guarantees_any(&accesses) {
            return None;
        }
        self.panic_call_offset(after_fallbacks)
    }

    fn collect_capture_fallbacks(
        &self,
        receiver_name: &str,
        mut dot: usize,
        first_access: CaptureAccess,
    ) -> Option<(Vec<CaptureAccess>, usize)> {
        if !self.is_capture_fallback_start(dot) {
            return None;
        }
        // Keep the proof tied to the same capture object and to the exact
        // lazy `Option` fallback shape.
        let mut accesses = Vec::with_capacity(2);
        accesses.push(first_access);
        while self.is_capture_fallback_start(dot) {
            let (access, after_fallback) = self.capture_fallback_access(receiver_name, dot)?;
            accesses.push(access);
            dot = after_fallback;
        }
        Some((accesses, dot))
    }

    fn is_capture_fallback_start(&self, dot: usize) -> bool {
        let tokens = &self.parsed.tokens;
        tokens.get(dot).is_some_and(|token| token.is_symbol(b'.'))
            && tokens
                .get(dot + 1)
                .is_some_and(|token| token.is_ident("or_else"))
    }

    fn capture_fallback_access(
        &self,
        receiver_name: &str,
        dot: usize,
    ) -> Option<(CaptureAccess, usize)> {
        let tokens = &self.parsed.tokens;
        let open = dot + 2;
        if !tokens.get(open).is_some_and(|token| token.is_symbol(b'(')) {
            return None;
        }
        let close = self.parsed.matching(open)?;
        let receiver = self.capture_fallback_receiver(open, receiver_name)?;
        let method = tokens.get(receiver + 2)?.identifier()?;
        let argument_open = receiver + 3;
        if !matches!(method, "get" | "name")
            || !tokens
                .get(argument_open)
                .is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        let argument_close = self.parsed.matching(argument_open)?;
        if argument_close + 1 != close {
            return None;
        }
        let access = self.capture_access(method, argument_open, argument_close)?;
        Some((access, close + 1))
    }

    fn capture_fallback_receiver(&self, open: usize, receiver_name: &str) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let receiver = open + 3;
        (tokens
            .get(open + 1)
            .is_some_and(|token| token.is_symbol(b'|'))
            && tokens
                .get(open + 2)
                .is_some_and(|token| token.is_symbol(b'|'))
            && tokens
                .get(receiver)
                .is_some_and(|token| token.is_ident(receiver_name))
            && tokens
                .get(receiver + 1)
                .is_some_and(|token| token.is_symbol(b'.')))
        .then_some(receiver)
    }

    fn panic_call_offset(&self, dot: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let method = tokens.get(dot + 1)?.identifier()?;
        if !tokens.get(dot).is_some_and(|token| token.is_symbol(b'.'))
            || !matches!(method, "unwrap" | "expect")
            || !tokens
                .get(dot + 2)
                .is_some_and(|token| token.is_symbol(b'('))
        {
            return None;
        }
        Some(tokens[dot].start)
    }

    fn capture_access(
        &self,
        method: &str,
        argument_open: usize,
        argument_close: usize,
    ) -> Option<CaptureAccess> {
        let tokens = &self.parsed.tokens;
        let argument = self
            .parsed
            .source
            .get(tokens[argument_open].end..tokens[argument_close].start)?;
        match method {
            "get" => parse_capture_number(argument).map(CaptureAccess::Number),
            "name" => parse_static_string(
                self.parsed.source,
                tokens[argument_open].end,
                tokens[argument_close].start,
            )
            .map(CaptureAccess::Name),
            _ => None,
        }
    }

    fn is_bare_identifier(&self, index: usize) -> bool {
        let tokens = &self.parsed.tokens;
        if index == 0 {
            return true;
        }
        !(tokens[index - 1].is_symbol(b'.')
            || index >= 2 && tokens[index - 1].is_symbol(b':') && tokens[index - 2].is_symbol(b':'))
    }

    fn find_control_body(&self, start: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let mut index = start;
        while index < tokens.len() {
            if tokens[index].is_symbol(b'{') {
                return self.parsed.matching(index).map(|_| index);
            }
            if tokens[index].is_symbol(b';') {
                return None;
            }
            if matches!(tokens[index].symbol(), Some(b'(' | b'[')) {
                index = self.parsed.matching(index)? + 1;
            } else {
                index += 1;
            }
        }
        None
    }

    fn find_top_level_ident(&self, start: usize, expected: &str) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let mut index = start;
        while index < tokens.len() {
            if tokens[index].is_ident(expected) {
                return Some(index);
            }
            if tokens[index].is_symbol(b';') {
                return None;
            }
            if matches!(tokens[index].symbol(), Some(b'(' | b'[' | b'{')) {
                index = self.parsed.matching(index)? + 1;
            } else {
                index += 1;
            }
        }
        None
    }

    fn find_statement_semicolon(&self, start: usize) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let mut index = start;
        while index < tokens.len() {
            if tokens[index].is_symbol(b';') {
                return Some(index);
            }
            if matches!(tokens[index].symbol(), Some(b'(' | b'[' | b'{')) {
                index = self.parsed.matching(index)? + 1;
            } else {
                index += 1;
            }
        }
        None
    }

    fn find_top_level_symbol(&self, start: usize, end: usize, symbol: u8) -> Option<usize> {
        let tokens = &self.parsed.tokens;
        let mut index = start;
        while index < end {
            if tokens[index].is_symbol(symbol) {
                return Some(index);
            }
            if matches!(tokens[index].symbol(), Some(b'(' | b'[' | b'{')) {
                let close = self.parsed.matching(index)?;
                if close >= end {
                    return None;
                }
                index = close + 1;
            } else {
                index += 1;
            }
        }
        None
    }

    fn top_level_segments(&self, start: usize, end: usize) -> Vec<(usize, usize)> {
        let tokens = &self.parsed.tokens;
        let mut segments = Vec::new();
        let mut segment_start = start;
        let mut index = start;
        while index < end {
            if tokens[index].is_symbol(b',') {
                segments.push((segment_start, index));
                segment_start = index + 1;
                index += 1;
            } else if matches!(tokens[index].symbol(), Some(b'(' | b'[' | b'{')) {
                let Some(close) = self.parsed.matching(index) else {
                    break;
                };
                index = close + 1;
            } else {
                index += 1;
            }
        }
        segments.push((segment_start, end));
        segments
    }
}

enum CaptureAccess {
    Number(u32),
    Name(String),
}

fn parse_capture_number(argument: &str) -> Option<u32> {
    let compact = argument.trim();
    let digits = compact.strip_suffix("usize").unwrap_or(compact);
    let mut value = 0u32;
    let mut saw_digit = false;
    for byte in digits.bytes() {
        if byte == b'_' {
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        saw_digit = true;
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    saw_digit.then_some(value)
}

fn parse_static_string(source: &str, start: usize, end: usize) -> Option<String> {
    let mut literal = source.get(start..end)?.trim();
    if let Some(without_reference) = literal.strip_prefix('&') {
        literal = without_reference.trim_start();
    }
    if let Some(without_comma) = literal.strip_suffix(',') {
        literal = without_comma.trim_end();
    }

    if let Some(raw) = decode_raw_string(literal) {
        return Some(raw);
    }
    decode_cooked_string(literal)
}

fn decode_raw_string(literal: &str) -> Option<String> {
    let bytes = literal.as_bytes();
    if bytes.first() != Some(&b'r') {
        return None;
    }
    let mut quote = 1usize;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let hashes = quote - 1;
    let suffix_len = 1 + hashes;
    if bytes.len() < quote + 1 + suffix_len
        || bytes.get(bytes.len() - suffix_len) != Some(&b'"')
        || !bytes[bytes.len() - hashes..]
            .iter()
            .all(|byte| *byte == b'#')
    {
        return None;
    }
    literal
        .get(quote + 1..bytes.len() - suffix_len)
        .map(ToOwned::to_owned)
}

fn decode_cooked_string(literal: &str) -> Option<String> {
    if !literal.starts_with('"') || !literal.ends_with('"') || literal.len() < 2 {
        return None;
    }
    let body = literal.get(1..literal.len() - 1)?;
    let mut chars = body.chars().peekable();
    let mut decoded = String::with_capacity(body.len());
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
        } else if let Some(escaped) = decode_cooked_escape(&mut chars)? {
            decoded.push(escaped);
        }
    }
    Some(decoded)
}

fn decode_cooked_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<Option<char>> {
    match chars.next()? {
        'x' => Some(Some(decode_ascii_escape(chars)?)),
        'u' => Some(Some(decode_unicode_escape(chars)?)),
        '\n' => {
            skip_continuation_whitespace(chars);
            Some(None)
        }
        '\r' => {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            skip_continuation_whitespace(chars);
            Some(None)
        }
        escaped => decode_simple_escape(escaped).map(Some),
    }
}

fn decode_simple_escape(escaped: char) -> Option<char> {
    match escaped {
        '\\' => Some('\\'),
        '"' => Some('"'),
        '\'' => Some('\''),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        '0' => Some('\0'),
        _ => None,
    }
}

fn decode_ascii_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<char> {
    let high = chars.next()?.to_digit(16)?;
    let low = chars.next()?.to_digit(16)?;
    let value = high * 16 + low;
    (value <= 0x7f).then(|| char::from_u32(value)).flatten()
}

fn decode_unicode_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<char> {
    if chars.next()? != '{' {
        return None;
    }
    let mut value = 0u32;
    let mut digits = 0usize;
    loop {
        let next = chars.next()?;
        if next == '}' {
            break;
        }
        if next == '_' {
            continue;
        }
        value = value.checked_mul(16)?.checked_add(next.to_digit(16)?)?;
        digits += 1;
        if digits > 6 {
            return None;
        }
    }
    (digits != 0).then(|| char::from_u32(value)).flatten()
}

fn skip_continuation_whitespace(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars
        .peek()
        .is_some_and(|character| character.is_whitespace())
    {
        chars.next();
    }
}

#[derive(Clone)]
enum TokenKind {
    Identifier(String),
    Symbol(u8),
}

#[derive(Clone)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

impl Token {
    fn identifier(&self) -> Option<&str> {
        match &self.kind {
            TokenKind::Identifier(identifier) => Some(identifier),
            TokenKind::Symbol(_) => None,
        }
    }

    fn symbol(&self) -> Option<u8> {
        match self.kind {
            TokenKind::Identifier(_) => None,
            TokenKind::Symbol(symbol) => Some(symbol),
        }
    }

    fn is_ident(&self, expected: &str) -> bool {
        self.identifier() == Some(expected)
    }

    fn is_symbol(&self, expected: u8) -> bool {
        self.symbol() == Some(expected)
    }
}

struct Scope {
    open: usize,
    close: usize,
    depth: usize,
}

struct ParsedSource<'a> {
    source: &'a str,
    tokens: Vec<Token>,
    pairs: Vec<Option<usize>>,
    scopes: Vec<Scope>,
    brace_scope: Vec<Option<usize>>,
}

impl<'a> ParsedSource<'a> {
    fn new(source: &'a str, masked: &str) -> Self {
        let tokens = tokenize(masked);
        let pairs = delimiter_pairs(&tokens);
        let (scopes, brace_scope) = lexical_scopes(source.len(), &tokens, &pairs);
        Self {
            source,
            tokens,
            pairs,
            scopes,
            brace_scope,
        }
    }

    fn matching(&self, token: usize) -> Option<usize> {
        self.pairs.get(token).copied().flatten()
    }

    fn scope_at(&self, offset: usize) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| scope.open <= offset && offset < scope.close)
            .max_by_key(|(_, scope)| scope.depth)
            .map_or(0, |(index, _)| index)
    }
}

fn tokenize(masked: &str) -> Vec<Token> {
    let bytes = masked.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let word = bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_';
        let end = if word {
            word_end(bytes, index)
        } else {
            index + 1
        };
        let kind = if word {
            TokenKind::Identifier(masked[index..end].to_owned())
        } else {
            TokenKind::Symbol(bytes[index])
        };
        tokens.push(Token {
            kind,
            start: index,
            end,
        });
        index = end;
    }
    tokens
}

fn word_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start + 1;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    end
}

fn delimiter_pairs(tokens: &[Token]) -> Vec<Option<usize>> {
    let mut pairs = vec![None; tokens.len()];
    let mut stack = Vec::<(u8, usize)>::new();
    for (index, token) in tokens.iter().enumerate() {
        match token.symbol() {
            Some(b'(') => stack.push((b')', index)),
            Some(b'[') => stack.push((b']', index)),
            Some(b'{') => stack.push((b'}', index)),
            Some(closing @ (b')' | b']' | b'}')) => {
                if let Some(&(expected, open)) = stack.last()
                    && expected == closing
                {
                    stack.pop();
                    pairs[open] = Some(index);
                    pairs[index] = Some(open);
                }
            }
            _ => {}
        }
    }
    pairs
}

fn lexical_scopes(
    source_len: usize,
    tokens: &[Token],
    pairs: &[Option<usize>],
) -> (Vec<Scope>, Vec<Option<usize>>) {
    let mut scopes = vec![Scope {
        open: 0,
        close: source_len,
        depth: 0,
    }];
    let mut brace_scope = vec![None; tokens.len()];
    let mut stack = Vec::<(usize, usize)>::new();
    for (open, token) in tokens.iter().enumerate() {
        while stack.last().is_some_and(|(close, _)| *close < open) {
            stack.pop();
        }
        if !token.is_symbol(b'{') {
            continue;
        }
        let Some(close) = pairs[open] else {
            continue;
        };
        let parent = stack.last().map_or(0, |(_, scope)| *scope);
        let scope_id = scopes.len();
        scopes.push(Scope {
            open: token.end,
            close: tokens[close].start,
            depth: scopes[parent].depth + 1,
        });
        brace_scope[open] = Some(scope_id);
        stack.push((close, scope_id));
    }
    (scopes, brace_scope)
}

#[cfg(test)]
mod tests {
    use super::RegexContracts;

    #[test]
    fn proves_group_zero_named_and_numbered_captures() {
        let source = r###"
fn scan(input: &str) {
    let pattern = Regex::new(r"^(?P<word>[a-z]+)-(\d+)$").unwrap();
    for captures in pattern.captures_iter(input) {
        captures.get(0).unwrap();
        captures.get(1).unwrap();
        captures.get(2).expect("second group participates");
        captures.name("word").unwrap();
    }
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(&contracts, source, &masked, "captures.get(0).unwrap");
        assert_invariant(&contracts, source, &masked, "captures.get(1).unwrap");
        assert_invariant(&contracts, source, &masked, "captures.get(2).expect");
        assert_invariant(
            &contracts,
            source,
            &masked,
            "captures.name(\"word\").unwrap",
        );
    }

    #[test]
    fn rejects_optional_and_branch_only_captures() {
        let source = r###"
fn scan(input: &str) {
    let pattern = regex::Regex::new(r"^(a)(b)?(?:(c)|(d))$").unwrap();
    if let Some(captures) = pattern.captures(input) {
        captures.get(1).unwrap();
        captures.get(2).unwrap();
        captures.get(3).unwrap();
        captures.get(4).unwrap();
    }
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(&contracts, source, &masked, "captures.get(1).unwrap");
        assert_not_invariant(&contracts, source, &masked, "captures.get(2).unwrap");
        assert_not_invariant(&contracts, source, &masked, "captures.get(3).unwrap");
        assert_not_invariant(&contracts, source, &masked, "captures.get(4).unwrap");
    }

    #[test]
    fn tracks_let_else_capture_scope() {
        let source = r###"
fn scan(input: &str) {
    let pattern = Regex::new(r"(?P<value>[a-z]+)").unwrap();
    let Some(found) = pattern.captures(input) else { return; };
    found.get(0).unwrap();
    found.name("value").unwrap();
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(&contracts, source, &masked, "found.get(0).unwrap");
        assert_invariant(&contracts, source, &masked, "found.name(\"value\").unwrap");
    }

    #[test]
    fn dynamic_regexes_only_guarantee_group_zero() {
        let source = r###"
fn scan(parameter: &Regex, expression: &str, input: &str) {
    if let Some(parameter_capture) = parameter.captures(input) {
        parameter_capture.get(0).unwrap();
        parameter_capture.name("field").unwrap();
    }
    let dynamic = Regex::new(expression).unwrap();
    if let Some(dynamic_capture) = dynamic.captures(input) {
        dynamic_capture.get(0).unwrap();
        dynamic_capture.name("field").unwrap();
    }
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(
            &contracts,
            source,
            &masked,
            "parameter_capture.get(0).unwrap",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "parameter_capture.name(\"field\").unwrap",
        );
        assert_invariant(&contracts, source, &masked, "dynamic_capture.get(0).unwrap");
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "dynamic_capture.name(\"field\").unwrap",
        );
    }

    #[test]
    fn respects_pattern_shadowing() {
        let source = r###"
fn scan(supplied: &Regex, input: &str) {
    let pattern = Regex::new(r"(fixed)").unwrap();
    {
        let pattern = supplied;
        if let Some(inner) = pattern.captures(input) {
            inner.get(1).unwrap();
        }
    }
    if let Some(outer) = pattern.captures(input) {
        outer.get(1).unwrap();
    }
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_not_invariant(&contracts, source, &masked, "inner.get(1).unwrap");
        assert_invariant(&contracts, source, &masked, "outer.get(1).unwrap");
    }

    #[test]
    fn proves_group_zero_from_nonlocal_regex_receivers_and_direct_chains() {
        let source = r###"
fn scan(state: &State, patterns: &mut Patterns, input: &str) {
    if let Some(field_capture) = state.pattern.captures(input) {
        field_capture.get(0).unwrap();
        field_capture.get(1).unwrap();
        field_capture.name("field").unwrap();
    }
    if let Some(path_capture) = crate::patterns::ACTIVE.captures(input) {
        path_capture.get(0).expect("complete static-path match");
        path_capture.get(1).unwrap();
    }
    for iterated in patterns.next().unwrap().captures_iter(input) {
        iterated.get(0).unwrap();
        iterated.name("field").unwrap();
    }
    state.pattern.captures(input).unwrap().get(0).unwrap();
    state.pattern.captures(input).expect("matched").get(1).unwrap();
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(&contracts, source, &masked, "field_capture.get(0).unwrap");
        assert_not_invariant(&contracts, source, &masked, "field_capture.get(1).unwrap");
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "field_capture.name(\"field\").unwrap",
        );
        assert_invariant(&contracts, source, &masked, "path_capture.get(0).expect");
        assert_not_invariant(&contracts, source, &masked, "path_capture.get(1).unwrap");
        assert_invariant(&contracts, source, &masked, "iterated.get(0).unwrap");
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "iterated.name(\"field\").unwrap",
        );
        assert_invariant(
            &contracts,
            source,
            &masked,
            "state.pattern.captures(input).unwrap().get(0).unwrap",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "state.pattern.captures(input).expect(\"matched\").get(1).unwrap",
        );
    }

    #[test]
    fn rejects_unproven_capture_objects_and_preserves_shadowing() {
        let source = r###"
fn scan(pattern: &Regex, ordinary: &Ordinary, captures: &Record, input: &str) {
    captures.get(0).unwrap();
    if let Some(fake) = ordinary.captures(input) {
        fake.get(0).unwrap();
    }
    if let Some(captures) = pattern.captures(input) {
        captures.get(0).unwrap();
        {
            let captures = ordinary.record();
            captures.get(0).expect("shadowed ordinary object");
        }
    }
    let deferred = pattern.captures(input);
    deferred.unwrap().get(0).unwrap();
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_not_invariant(&contracts, source, &masked, "captures.get(0).unwrap");
        assert_not_invariant(&contracts, source, &masked, "fake.get(0).unwrap");
        assert_invariant(
            &contracts,
            source,
            &masked,
            "        captures.get(0).unwrap",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "captures.get(0).expect(\"shadowed ordinary object\")",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "deferred.unwrap().get(0).unwrap",
        );
    }

    #[test]
    fn proves_static_captures_in_option_and_iterator_callbacks() {
        let source = r###"
static CALLBACK_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<word>[a-z]+)-(\d+)$").unwrap()
});

fn scan(input: &str) {
    CALLBACK_PATTERN.captures_iter(input).map(|capture| {
        capture.get(1).unwrap();
        capture.name("word").expect("named group participates");
    });
    CALLBACK_PATTERN
        .captures_iter(input)
        .take(4)
        .any(|limited| limited.get(2).expect("number participates").as_str().is_empty());
    CALLBACK_PATTERN
        .captures(input)
        .and_then(|single| single.name("word").expect("word participates").as_str().parse().ok());
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(&contracts, source, &masked, "capture.get(1).unwrap");
        assert_invariant(
            &contracts,
            source,
            &masked,
            "capture.name(\"word\").expect(\"named group participates\")",
        );
        assert_invariant(
            &contracts,
            source,
            &masked,
            "limited.get(2).expect(\"number participates\")",
        );
        assert_invariant(
            &contracts,
            source,
            &masked,
            "single.name(\"word\").expect(\"word participates\")",
        );
    }

    #[test]
    fn rejects_dynamic_optional_and_shadowed_callback_captures() {
        let source = r###"
static OPTIONAL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?P<maybe>[a-z]+)?$").unwrap());
static FIXED_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([a-z]+)$").unwrap());

fn scan(dynamic: &Regex, records: &[Record], input: &str) {
    dynamic.captures_iter(input).map(|dynamic_capture| {
        dynamic_capture.get(0).unwrap();
        dynamic_capture.get(1).expect("dynamic numbered group");
        dynamic_capture.name("word").expect("dynamic named group");
    });
    OPTIONAL_PATTERN.captures_iter(input).any(|optional_capture| {
        optional_capture
            .name("maybe")
            .expect("optional named group")
            .as_str()
            .is_empty()
    });
    FIXED_PATTERN.captures_iter(input).map(|shadowed| {
        records
            .iter()
            .map(|shadowed| shadowed.get(1).expect("ordinary nested value"))
            .count();
        shadowed.get(1).expect("outer regex capture");
    });
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(&contracts, source, &masked, "dynamic_capture.get(0).unwrap");
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "dynamic_capture.get(1).expect(\"dynamic numbered group\")",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "dynamic_capture.name(\"word\").expect(\"dynamic named group\")",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            ".name(\"maybe\")\n            .expect(\"optional named group\")",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "shadowed.get(1).expect(\"ordinary nested value\")",
        );
        assert_invariant(
            &contracts,
            source,
            &masked,
            "shadowed.get(1).expect(\"outer regex capture\")",
        );
    }

    #[test]
    fn proves_exhaustive_capture_alternatives_and_rejects_unproven_fallbacks() {
        let source = r###"
static ALTERNATIVE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?P<left>a)|(?P<right>b))$").unwrap()
});
static OPTIONAL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(a)?(b)?$").unwrap());
static INCOMPLETE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:(a)|(b)|none)$").unwrap());

fn scan(dynamic: &Regex, ordinary: &Record, input: &str) {
    for captures in ALTERNATIVE_PATTERN.captures_iter(input) {
        captures.get(1).or_else(|| captures.get(2)).unwrap();
        captures
            .name("left")
            .or_else(|| captures.name("right"))
            .expect("one named branch participates");
        {
            let captures = ordinary;
            captures.get(1).or_else(|| captures.get(2)).unwrap();
        }
    }
    for optional in OPTIONAL_PATTERN.captures_iter(input) {
        optional.get(1).or_else(|| optional.get(2)).unwrap();
    }
    for incomplete in INCOMPLETE_PATTERN.captures_iter(input) {
        incomplete.get(1).or_else(|| incomplete.get(2)).unwrap();
    }
    for dynamic_capture in dynamic.captures_iter(input) {
        dynamic_capture
            .get(1)
            .or_else(|| dynamic_capture.get(2))
            .expect("dynamic alternatives are unknown");
    }
    let Some(other) = ALTERNATIVE_PATTERN.captures(input) else { return; };
    for captures in ALTERNATIVE_PATTERN.captures_iter(input) {
        captures.get(1).or_else(|| other.get(2)).unwrap();
    }
}
"###;
        let masked = mask(source);
        let contracts = RegexContracts::new(source, &masked);

        assert_invariant(
            &contracts,
            source,
            &masked,
            "captures.get(1).or_else(|| captures.get(2)).unwrap",
        );
        assert_invariant(
            &contracts,
            source,
            &masked,
            ".name(\"left\")\n            .or_else(|| captures.name(\"right\"))\n            .expect",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "            captures.get(1).or_else(|| captures.get(2)).unwrap",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "optional.get(1).or_else(|| optional.get(2)).unwrap",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "incomplete.get(1).or_else(|| incomplete.get(2)).unwrap",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            ".get(1)\n            .or_else(|| dynamic_capture.get(2))\n            .expect",
        );
        assert_not_invariant(
            &contracts,
            source,
            &masked,
            "captures.get(1).or_else(|| other.get(2)).unwrap",
        );
    }

    fn assert_invariant(contracts: &RegexContracts, source: &str, masked: &str, needle: &str) {
        let offset = panic_call_offset(source, needle);
        assert!(
            contracts.capture_access_is_invariant(source, masked, offset),
            "expected invariant access: {needle}"
        );
    }

    fn assert_not_invariant(contracts: &RegexContracts, source: &str, masked: &str, needle: &str) {
        let offset = panic_call_offset(source, needle);
        assert!(
            !contracts.capture_access_is_invariant(source, masked, offset),
            "unexpected invariant access: {needle}"
        );
    }

    fn panic_call_offset(source: &str, needle: &str) -> usize {
        let start = source.find(needle).expect("test access must exist");
        let relative = needle
            .rfind(".unwrap")
            .or_else(|| needle.rfind(".expect"))
            .expect("test access must include unwrap or expect");
        start + relative
    }

    fn mask(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut masked = bytes.to_vec();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes.get(index..index + 2) == Some(b"//") {
                let start = index;
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                blank(&mut masked, start, index);
            } else if bytes.get(index..index + 2) == Some(b"/*") {
                let start = index;
                index += 2;
                let mut depth = 1usize;
                while index < bytes.len() && depth > 0 {
                    if bytes.get(index..index + 2) == Some(b"/*") {
                        depth += 1;
                        index += 2;
                    } else if bytes.get(index..index + 2) == Some(b"*/") {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                blank(&mut masked, start, index);
            } else if let Some(end) = string_end(bytes, index) {
                blank(&mut masked, index, end);
                index = end;
            } else {
                index += 1;
            }
        }
        String::from_utf8(masked).expect("mask preserves UTF-8")
    }

    fn string_end(source: &[u8], start: usize) -> Option<usize> {
        if source.get(start) == Some(&b'r') {
            let mut quote = start + 1;
            while source.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if source.get(quote) == Some(&b'"') {
                let hashes = quote - start - 1;
                let mut index = quote + 1;
                while index < source.len() {
                    if source[index] == b'"'
                        && (0..hashes).all(|hash| source.get(index + 1 + hash) == Some(&b'#'))
                    {
                        return Some(index + 1 + hashes);
                    }
                    index += 1;
                }
                return Some(source.len());
            }
        }
        if source.get(start) != Some(&b'"') {
            return None;
        }
        let mut index = start + 1;
        while index < source.len() {
            if source[index] == b'\\' {
                index = (index + 2).min(source.len());
            } else {
                let closes = source[index] == b'"';
                index += 1;
                if closes {
                    break;
                }
            }
        }
        Some(index)
    }

    fn blank(bytes: &mut [u8], start: usize, end: usize) {
        for byte in &mut bytes[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
}
