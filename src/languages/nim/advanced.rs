
fn analyze_advanced(context: &LineContext<'_>, state: &mut ScanState, findings: &mut Vec<Finding>) {
    analyze_exported_ref_object(context, state, findings);
    update_import_state(context, state);

    let generic_declaration = is_generic_declaration(context.line);
    analyze_generic_hook(context, state, findings, generic_declaration);
    if generic_declaration && context.line.contains('*') && SERIALIZE_NAME.is_match(context.line) {
        state.has_generic_serialization_wrapper = true;
    }

    analyze_unchecked_dynlib_symbol(context, findings);
    analyze_dynlib_lifetime(context, findings);

    let plugin_mention = context.lower.contains("plugin");
    analyze_proc_only_plugin_api(context, findings, plugin_mention);
    analyze_plugin_hook_kind(context, findings, plugin_mention);
    analyze_context_assignment(context, findings);

    update_json_api_count(context, state);
    record_distinct_type(context, state);
    analyze_serialization_hooks(context, state, findings);

    let httpish = is_httpish(context.lower);
    analyze_http_header_membership(context, findings, httpish);
    analyze_http_header_comparison(context, findings, httpish);
    analyze_websocket_upgrade(context, findings, httpish);
    analyze_protocol_split(context, findings, httpish);

    analyze_exported_template(context, findings);
    analyze_division_by_length(context, findings);
    analyze_float_test_equality(context, findings);
    analyze_open_array_coverage(context, findings);
}

fn analyze_exported_ref_object(
    context: &LineContext<'_>,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    if state.in_exported_ref_object && context.indent <= state.object_indent {
        state.in_exported_ref_object = false;
    }
    if context.line.contains("* = ref object") {
        state.in_exported_ref_object = true;
        state.object_indent = context.indent;
    } else if state.in_exported_ref_object
        && context.line.contains('*')
        && MUTABLE_CONTAINER_FIELD.is_match(context.line)
    {
        add_line(
            findings,
            context,
            "nim-public-mutable-container-field",
            "exported ref object exposes a mutable container field",
            "low",
            Some(Severity::Info),
        );
    }
}

fn update_import_state(context: &LineContext<'_>, state: &mut ScanState) {
    if context.line.starts_with("import ") || context.line.starts_with("from ") {
        state.has_import = true;
    }
}

fn is_generic_declaration(line: &str) -> bool {
    if !line.starts_with("proc ") && !line.starts_with("func ") {
        return false;
    }
    let (Some(open), Some(close), Some(parameter)) =
        (line.find('['), line.find(']'), line.find('('))
    else {
        return false;
    };
    close > open && parameter > close
}

fn analyze_generic_hook(
    context: &LineContext<'_>,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
    generic_declaration: bool,
) {
    if !generic_declaration || !context.line.contains("Hook") {
        return;
    }
    state.generic_hook_count += 1;
    add_line(
        findings,
        context,
        "nim-hook-too-generic",
        "generic hook proc may be too broad",
        "low",
        Some(Severity::Info),
    );
    analyze_generic_hook_signature(context, findings);
    analyze_generic_hook_documentation(context, findings);
}

fn analyze_generic_hook_signature(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if context.line.contains("[T]")
        && (context.line.contains("seq[T]")
            || context.line.contains(": T")
            || context.line.contains("ref T"))
    {
        add_line(
            findings,
            context,
            "nim-generic-hook-same-signature",
            "generic hook signature is likely to duplicate a library hook shape",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_generic_hook_documentation(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let preceding_doc =
        context.index > 0 && context.lines[context.index - 1].trim().starts_with("##");
    if context.line.contains('*') && !preceding_doc && !context.line.contains("##") {
        add_line(
            findings,
            context,
            "nim-generic-hook-missing-doc",
            "exported generic hook lacks overload-resolution documentation",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_unchecked_dynlib_symbol(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.line.contains("cast[") || !context.line.contains("symAddr(") {
        return;
    }
    let nearby = nearby_lines(context.lines, context.index, 1, 1).to_ascii_lowercase();
    if !nearby.contains("nil") {
        add_line(
            findings,
            context,
            "nim-dynlib-unchecked-symbol",
            "dynlib symbol is cast without an obvious nil check",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_dynlib_lifetime(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.line.contains("loadLib(") {
        return;
    }
    let lifetime_is_obvious = context.lines[context.index..]
        .iter()
        .take(9)
        .any(|nearby| {
            nearby.contains("unloadLib")
                || nearby.contains("libs.add")
                || nearby.contains("handles.add")
                || nearby.contains("pluginLibs")
        });
    if !lifetime_is_obvious {
        add_line(
            findings,
            context,
            "nim-dynlib-lifetime",
            "dynlib handle lifetime is not obvious",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_proc_only_plugin_api(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    plugin_mention: bool,
) {
    if plugin_mention
        && (context.line.contains("seq[proc")
            || context.line.contains("openArray[proc")
            || context.line.contains("proc ("))
    {
        add_line(
            findings,
            context,
            "nim-proc-only-plugin-api",
            "plugin API appears to use bare proc callbacks",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_plugin_hook_kind(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    plugin_mention: bool,
) {
    if !plugin_mention
        || !(context.line.contains("seq[proc")
            || context.line.contains("run*: proc")
            || context.line.contains("callback*: proc"))
    {
        return;
    }
    let nearby = nearby_lines(context.lines, context.index, 8, 8).to_ascii_lowercase();
    if !HOOK_KIND.is_match(&nearby) {
        add_line(
            findings,
            context,
            "nim-plugin-hook-without-kind",
            "plugin callback has no obvious hook/stage kind",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_context_assignment(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if context.line.contains('=')
        && CONTEXT_INDEX.is_match(context.lower)
        && SAVE_RENDER_PLUGIN.is_match(context.lower)
        && !SAFE_CONTEXT_WRITE.is_match(context.lower)
    {
        add_line(
            findings,
            context,
            "nim-default-overwrites-context",
            "context/default assignment may overwrite user configuration",
            "low",
            Some(Severity::Info),
        );
    }
}

fn update_json_api_count(context: &LineContext<'_>, state: &mut ScanState) {
    if (context.line.starts_with("proc ")
        || context.line.starts_with("func ")
        || context.line.starts_with("type "))
        && context.line.contains('*')
        && JSON_API_TYPE.is_match(context.line)
    {
        state.json_api_count += 1;
    }
}

fn record_distinct_type(context: &LineContext<'_>, state: &mut ScanState) {
    if let Some(captures) = DISTINCT_TYPE.captures(context.line) {
        state.distinct_types.insert(captures[1].to_owned());
    }
}

#[derive(Clone, Copy)]
struct SerializationHookCandidates {
    dump: bool,
    parse: bool,
}

struct QualifiedSerializationHook<'a> {
    accumulator: &'a str,
    dumps_strings: bool,
}

fn analyze_serialization_hooks(
    context: &LineContext<'_>,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    let Some(candidates) = serialization_hook_candidates(context.line) else {
        return;
    };
    record_serialization_hook_type(context.line, state, candidates);
    let Some(hook) = qualify_serialization_hook(context.line, candidates) else {
        return;
    };
    emit_serialization_hook_findings(context, findings, hook);
}

fn serialization_hook_candidates(line: &str) -> Option<SerializationHookCandidates> {
    if !line.starts_with("proc ") {
        return None;
    }
    let dump = ["dumpHook", "writeHook", "encodeHook"]
        .iter()
        .any(|name| line.contains(name));
    let parse = ["parseHook", "readHook", "decodeHook"]
        .iter()
        .any(|name| line.contains(name));
    (dump || parse).then_some(SerializationHookCandidates { dump, parse })
}

fn is_httpish(lower: &str) -> bool {
    ["header", "connection", "upgrade", "websocket"]
        .iter()
        .any(|word| lower.contains(word))
}

fn analyze_http_header_membership(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    httpish: bool,
) {
    if httpish
        && context.lower.contains(".contains(")
        && ["upgrade", "websocket", "keep-alive"]
            .iter()
            .any(|word| context.lower.contains(word))
        && !context.lower.contains("split(")
        && !context.lower.contains("containslist")
        && !context.lower.contains("strip")
    {
        add_line(
            findings,
            context,
            "nim-http-header-contains",
            "HTTP header membership check may ignore comma-separated values",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_http_header_comparison(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    httpish: bool,
) {
    if httpish
        && (context.line.contains(" == ") || context.line.contains(" != "))
        && ["upgrade", "websocket", "connection"]
            .iter()
            .any(|word| context.lower.contains(word))
        && !["tolowerascii", "cmpignorecase", "normalize"]
            .iter()
            .any(|word| context.lower.contains(word))
    {
        add_line(
            findings,
            context,
            "nim-http-case-sensitive-header-compare",
            "HTTP header/token comparison appears case-sensitive",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_websocket_upgrade(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    httpish: bool,
) {
    if !context.mentions_websocket
        || !httpish
        || !context.lower.contains("connection")
        || !context.lower.contains("upgrade")
        || (!context.line.contains(" == ") && !context.lower.contains(".contains("))
    {
        return;
    }
    let nearby = nearby_lines(context.lines, context.index, 2, 2).to_ascii_lowercase();
    if !nearby.contains("containslist") {
        add_line(
            findings,
            context,
            "nim-websocket-upgrade-fragile",
            "WebSocket upgrade check may not handle `Connection: keep-alive, Upgrade`",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_protocol_split(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    httpish: bool,
) {
    if !httpish || !context.lower.contains(".split(") || !context.line.contains(',') {
        return;
    }
    let following = context.lines[context.index..]
        .iter()
        .take(4)
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    if !following.contains("strip") {
        add_line(
            findings,
            context,
            "nim-protocol-split-without-strip",
            "comma-separated protocol values are split without obvious strip/case normalization",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_exported_template(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.line.starts_with("template ") || !context.line.contains('*') {
        return;
    }
    analyze_template_documentation(context, findings);
    analyze_template_state_mutation(context, findings);
}

fn analyze_template_documentation(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let documented =
        context.index > 0 && context.lines[context.index - 1].trim_start().starts_with("##");
    if !documented && !context.line.contains("##") {
        add_line(
            findings,
            context,
            "nim-exported-template-missing-doc",
            "exported template lacks a doc comment",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_template_state_mutation(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.line.contains("body: untyped") && !context.line.contains("body: typed") {
        return;
    }
    let body = indented_body(context.lines, context.index, context.indent);
    let executes_body = body.iter().any(|next| next.trim() == "body");
    let mutates_state = body.iter().any(|next| {
        let trimmed = next.trim();
        trimmed.contains('.')
            && trimmed.contains(" = ")
            && !["let ", "var ", "const "]
                .iter()
                .any(|prefix| trimmed.starts_with(prefix))
    });
    if !executes_body || !mutates_state {
        return;
    }
    let restores = body.iter().any(|next| {
        let trimmed = next.trim();
        ["try:", "finally:", "defer:"]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
    });
    add_line(
        findings,
        context,
        "nim-template-body-state-mutation",
        "template executes body while mutating shared state",
        "medium",
        Some(if restores {
            Severity::Info
        } else {
            Severity::Warn
        }),
    );
    if !restores {
        add_line(
            findings,
            context,
            "nim-state-restore-without-finally",
            "state is changed around template body without defer/finally",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_division_by_length(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.lower.contains(".len")
        || !without_string_literals(context.line).contains('/')
        || context.lower.contains("max(1")
    {
        return;
    }
    let nearby = nearby_lines(context.lines, context.index, 5, 2);
    if !LEN_GUARD.is_match(&nearby) {
        add_line(
            findings,
            context,
            "nim-divide-by-len-without-empty-check",
            "division by collection length without nearby empty guard",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_float_test_equality(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if context.is_test
        && (context.lower.contains("doassert")
            || context.lower.contains("check ")
            || context.lower.contains("assert "))
        && context.lower.contains(" == ")
        && FLOAT_LITERAL.is_match(&without_string_literals(context.lower))
    {
        add_line(
            findings,
            context,
            "nim-float-test-exact-equality",
            "test appears to use exact equality for floating-point result",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_open_array_coverage(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if (context.line.starts_with("proc ") || context.line.starts_with("func "))
        && context.line.contains('*')
        && context.lower.contains("openarray")
        && (context.source.contains(".len") || context.source.contains("[0]"))
        && !context.source.to_ascii_lowercase().contains("empty")
        && !context.source.contains("[]")
    {
        push_str(
            findings,
            "nim-openarray-missing-empty-test",
            context.path,
            1,
            "exported openArray API has no obvious empty-input coverage nearby",
            "low",
            Some(Severity::Info),
        );
    }
}

fn record_serialization_hook_type(
    line: &str,
    state: &mut ScanState,
    candidates: SerializationHookCandidates,
) {
    let close = line.rfind(')');
    let comma = close.and_then(|close| line[..close].rfind(','));
    let last_parameter = match (comma, close) {
        (Some(comma), Some(close)) => &line[comma + 1..close],
        _ => "",
    };
    let mut type_name = last_parameter
        .split_once(':')
        .map_or("", |(_, kind)| kind)
        .replace('*', "");
    let trimmed_end = type_name.trim_end().len();
    type_name.truncate(trimmed_end);
    let trimmed_start = type_name.len() - type_name.trim_start().len();
    type_name.drain(..trimmed_start);
    if type_name.is_empty() {
        return;
    }
    match (candidates.dump, candidates.parse) {
        (true, true) => {
            state.dump_types.insert(type_name.clone());
            state.parse_types.insert(type_name);
        }
        (true, false) => {
            state.dump_types.insert(type_name);
        }
        (false, true) => {
            state.parse_types.insert(type_name);
        }
        (false, false) => {}
    }
}

fn qualify_serialization_hook(
    line: &str,
    candidates: SerializationHookCandidates,
) -> Option<QualifiedSerializationHook<'_>> {
    let open = line.find('(')?;
    let comma = line[open + 1..].find(',').map(|at| open + 1 + at)?;
    let first_parameter = &line[open + 1..comma];
    if !first_parameter.contains("var string") {
        return None;
    }
    Some(QualifiedSerializationHook {
        accumulator: first_parameter.split(':').next().unwrap_or("").trim(),
        dumps_strings: candidates.dump,
    })
}

fn emit_serialization_hook_findings(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
    hook: QualifiedSerializationHook<'_>,
) {
    for (offset, body_line) in context.lines[context.index + 1..]
        .iter()
        .copied()
        .take_while(|next| next.trim().is_empty() || leading_indent(next) > context.indent)
        .enumerate()
    {
        let inner = without_comment(body_line).trim();
        if overwrites_accumulator(inner, hook.accumulator) {
            push_str(
                findings,
                "nim-hook-overwrites-accumulator",
                context.path,
                context.index + offset + 2,
                "serialization hook assigns to accumulator string",
                "medium",
                Some(Severity::Warn),
            );
        }
        if hook.dumps_strings && appends_unquoted(inner, hook.accumulator) {
            push_str(
                findings,
                "nim-string-serializer-missing-quote",
                context.path,
                context.index + offset + 2,
                "serializer appends raw content without obvious quoting/escaping",
                "low",
                Some(Severity::Info),
            );
        }
    }
}

fn overwrites_accumulator(inner: &str, accumulator: &str) -> bool {
    inner.strip_prefix(accumulator).is_some_and(|remainder| {
        remainder.starts_with(" =") || remainder.starts_with('=')
    })
}

fn appends_unquoted(inner: &str, accumulator: &str) -> bool {
    contains_joined(inner, accumulator, ".add")
        && !contains_ascii_case_insensitive(inner, "escape")
        && !contains_ascii_case_insensitive(inner, "quote")
        && !inner.contains('"')
}

fn contains_joined(value: &str, prefix: &str, suffix: &str) -> bool {
    let width = prefix.len() + suffix.len();
    value.as_bytes().windows(width).any(|window| {
        let (candidate_prefix, candidate_suffix) = window.split_at(prefix.len());
        candidate_prefix == prefix.as_bytes() && candidate_suffix == suffix.as_bytes()
    })
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
}

macro_rules! add_simple_finding {
    ($findings:expr, $context:expr, $code:literal, $message:literal, $confidence:literal, $severity:expr) => {
        add_line(
            $findings,
            $context,
            $code,
            $message,
            $confidence,
            Some($severity),
        )
    };
}

fn analyze_simple(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    analyze_text_formatting(context, findings);
    analyze_test_and_markup(context, findings);
    analyze_pointer_and_input(context, findings);
    analyze_readability(context, findings);
    analyze_allocation_simplifications(context, findings);
    analyze_imports_and_exceptions(context, findings);
    analyze_declaration_simplifications(context, findings);
    analyze_type_usage(context, findings);
    analyze_public_contracts(context, findings);
    analyze_runtime_hazards(context, findings);
}

fn analyze_text_formatting(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    let lower = context.lower;
    if lower.contains("formatfloat") && lower.contains("replace") && line.contains("'.', ','") {
        add_simple_finding!(
            findings,
            context,
            "nim-forced-decimal-comma-output",
            "formatted number is forced to use a decimal comma",
            "high",
            Severity::Info
        );
    }
    if line.contains("replace") && line.contains(r"\t") && SOURCE_TEXT_WORD.is_match(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-global-tab-replace",
            "tabs are replaced across an entire source/text value",
            "medium",
            Severity::Warn
        );
    }
    if lower.contains(".strip") && (lower.contains("chars=") || lower.contains("chars =")) {
        add_simple_finding!(
            findings,
            context,
            "nim-strip-chars-string-set",
            "strip(chars=\"...\") treats the string as a set of characters",
            "medium",
            Severity::Info
        );
    }
}

fn analyze_test_and_markup(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    let lower = context.lower;
    if lower.contains("skip")
        && (context.path.to_ascii_lowercase().contains("test") || lower.contains("test"))
        && !context.raw.contains('#')
    {
        add_simple_finding!(
            findings,
            context,
            "nim-skip-test-without-comment",
            "test appears to be skipped without an explanatory comment",
            "low",
            Severity::Info
        );
    }
    if writes_unescaped_markup(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-xml-output-unescaped",
            "dynamic value is written into XML without visible escaping",
            "medium",
            Severity::Warn
        );
    }
}

fn analyze_pointer_and_input(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    let lower = context.lower;
    if (line.starts_with("proc ") || line.starts_with("func "))
        && (line.contains("ptr ") || line.contains(": pointer"))
        && POINTER_SIZE.is_match(line)
    {
        add_simple_finding!(
            findings,
            context,
            "nim-pointer-with-separate-size",
            "proc takes a pointer and a separate size parameter",
            "low",
            Severity::Info
        );
    }
    if (lower.contains("parseint(readline")
        || lower.contains("parsefloat(readline")
        || lower.contains("parsebool(readline"))
        && !lower.contains("strip")
    {
        add_simple_finding!(
            findings,
            context,
            "nim-readline-without-strip",
            "readLine result is parsed without trimming",
            "medium",
            Severity::Info
        );
    }
}

fn analyze_readability(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let lower = context.lower;
    if lower.contains("not not ") {
        add_simple_finding!(
            findings,
            context,
            "nim-double-negation",
            "double boolean negation reduces readability",
            "low",
            Severity::Info
        );
    }
    if lower.contains("gethomedir()") && lower.contains("strip") {
        add_simple_finding!(
            findings,
            context,
            "nim-home-dir-strip",
            "home directory path is normalized with strip",
            "low",
            Severity::Info
        );
    }
    if lower.contains(".strip")
        && (lower.contains("leading=false") || lower.contains("trailing=false"))
    {
        add_simple_finding!(
            findings,
            context,
            "nim-strip-one-sided-wrapper",
            "one-sided strip is used directly",
            "low",
            Severity::Info
        );
    }
}

fn analyze_allocation_simplifications(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
) {
    let line = context.line;
    let lower = context.lower;
    if lower.contains(".map(") && lower.contains(".filter(") {
        add_simple_finding!(
            findings,
            context,
            "nim-functional-alloc-chain",
            "functional chain creates intermediate sequence allocations",
            "low",
            Severity::Info
        );
    }
    if line.starts_with("let ") && LITERAL_LET.is_match(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-could-be-const",
            "let with a literal value could be const",
            "low",
            Severity::Info
        );
    }
}

fn analyze_imports_and_exceptions(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    if STD_IMPORT.is_match(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-std-import",
            "standard-library import should use std/ prefix",
            "medium",
            Severity::Info
        );
    }
    if line == "except:" || line.starts_with("except CatchableError") {
        add_simple_finding!(
            findings,
            context,
            "nim-broad-except",
            "broad exception handler catches too much",
            "medium",
            Severity::Warn
        );
    }
    if line.starts_with("except ")
        && context.index + 1 < context.lines.len()
        && context.lines[context.index + 1].trim() == "discard"
    {
        add_simple_finding!(
            findings,
            context,
            "nim-empty-except-body",
            "exception handler discards the failure",
            "medium",
            Severity::Warn
        );
    }
    if CAST_USAGE.is_match(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-cast-usage",
            "cast used to reinterpret types",
            "medium",
            Severity::Warn
        );
    }
    if line.starts_with("case ") {
        let nearby = context.lines[context.index + 1..]
            .iter()
            .take(10)
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        if STRING_CASE.is_match(&nearby) {
            add_simple_finding!(
                findings,
                context,
                "nim-case-on-string",
                "case statement branches on a string value",
                "low",
                Severity::Info
            );
        }
    }
}

fn analyze_declaration_simplifications(
    context: &LineContext<'_>,
    findings: &mut Vec<Finding>,
) {
    let line = context.line;
    if REDUNDANT_INIT.is_match(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-redundant-type-init",
            "variable has redundant explicit default initialization",
            "low",
            Severity::Info
        );
    }
    if let Some(captures) = TYPE_PREFIX_PROC.captures(line)
        && captures[1].eq_ignore_ascii_case(&captures[3])
    {
        add_simple_finding!(
            findings,
            context,
            "nim-type-prefix-proc-naming",
            "proc name repeats the first parameter type prefix",
            "low",
            Severity::Info
        );
    }
    if WHILE_INDEX.is_match(line) {
        add_simple_finding!(
            findings,
            context,
            "nim-while-index-loop",
            "index-controlled while loop can use iteration",
            "medium",
            Severity::Info
        );
    }
    if line.starts_with("return ") && !line.starts_with("return if ") {
        add_simple_finding!(
            findings,
            context,
            "nim-return-instead-of-result",
            "return at end of proc could use the result variable",
            "low",
            Severity::Info
        );
    }
}

fn analyze_type_usage(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    if line.contains("not ") && line.contains(".isNil") {
        add_simple_finding!(
            findings,
            context,
            "nim-negated-isnil",
            "negated isNil expression",
            "medium",
            Severity::Info
        );
    }
    if line.starts_with("method ") {
        add_simple_finding!(
            findings,
            context,
            "nim-method-dispatch",
            "runtime method dispatch used",
            "medium",
            Severity::Info
        );
    }
    if NONREF_INHERITANCE.is_match(line) && !line.contains("ref object") {
        add_simple_finding!(
            findings,
            context,
            "nim-nonref-inheritance",
            "non-ref object inheritance used",
            "medium",
            Severity::Warn
        );
    }
}

fn analyze_public_contracts(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    if let Some(captures) = CALLABLE.captures(line)
        && captures[1].matches(',').count() >= 5
    {
        let count = captures[1].matches(',').count() + 1;
        push(
            findings,
            "nim-too-many-parameters",
            context.path,
            context.index + 1,
            format!("proc has {count} parameters (more than 6)"),
            "medium",
            Some(Severity::Warn),
        );
    }
    if EXPORTED_PROC.is_match(line) && !line.contains("{.raises:") {
        add_simple_finding!(
            findings,
            context,
            "nim-missing-raises",
            "exported proc lacks {.raises.} contract",
            "low",
            Severity::Info
        );
    }
    if EXPORTED_PROC.is_match(line)
        && (context.index == 0 || !context.lines[context.index - 1].trim().starts_with("##"))
    {
        add_simple_finding!(
            findings,
            context,
            "nim-missing-doc",
            "exported proc or func lacks a doc comment",
            "low",
            Severity::Info
        );
    }
}

fn analyze_runtime_hazards(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let line = context.line;
    if line.contains("raise newException(Exception") {
        add_simple_finding!(
            findings,
            context,
            "nim-generic-exception-raise",
            "generic Exception raised",
            "medium",
            Severity::Warn
        );
    }
    if PROCESS_EXEC.is_match(line) && (line.contains('&') || line.contains('$')) {
        add_simple_finding!(
            findings,
            context,
            "nim-exec-dynamic-command",
            "process execution uses a dynamically built command",
            "medium",
            Severity::Warn
        );
    }
    if SLEEP_CALL.is_match(line)
        && context.lines[..context.index]
            .iter()
            .rev()
            .take(80)
            .any(|previous| GAME_LOOP_DECLARATION.is_match(previous.trim()))
    {
        add_simple_finding!(
            findings,
            context,
            "nim-sleep-in-game-loop",
            "sleep used in game-loop function",
            "medium",
            Severity::Warn
        );
    }
}
