use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;

pub fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let nim_sources = sources
        .iter()
        .filter(|(path, _)| path.ends_with(".nim") || path.ends_with(".nims"))
        .collect::<Vec<_>>();
    if nim_sources.is_empty() {
        return Vec::new();
    }

    let mut findings = project_findings(&nim_sources);
    for (path, source) in nim_sources {
        findings.extend(scan_file(path, source));
    }
    findings
}

fn project_findings(sources: &[(&String, &String)]) -> Vec<Finding> {
    let source_modules = sources
        .iter()
        .filter(|(path, _)| path.starts_with("src/") && path.ends_with(".nim"))
        .copied()
        .collect::<Vec<_>>();
    let test_files = sources
        .iter()
        .filter(|(path, _)| path.starts_with("tests/") && path.ends_with(".nim"))
        .copied()
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    if !source_modules.is_empty() && test_files.is_empty() {
        findings.push(finding(
            "nim-no-test-suite",
            ".",
            1,
            "Nim project has src modules but no tests directory/files",
            "medium",
            Some(Severity::Warn),
        ));
    }
    let combined_tests = test_files
        .iter()
        .map(|(_, source)| source.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    let named_test_modules = test_files
        .iter()
        .filter_map(|(path, _)| file_stem(path))
        .filter_map(|name| name.strip_prefix("test_").map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for (path, _) in source_modules {
        let Some(module) = file_stem(path) else {
            continue;
        };
        if ["main", "host", "host_release"].contains(&module)
            || named_test_modules.contains(module)
            || combined_tests.contains(&format!("../src/{module}"))
        {
            continue;
        }
        findings.push(finding(
            "nim-missing-test-for-module",
            path,
            1,
            "source module has no matching test_*.nim file",
            "low",
            Some(Severity::Info),
        ));
    }
    findings
}

fn file_stem(path: &str) -> Option<&str> {
    path.rsplit('/').next()?.split('.').next()
}

#[derive(Default)]
struct ScanState {
    loop_indents: Vec<usize>,
    hot_proc_indents: Vec<usize>,
    draw_proc_indents: Vec<usize>,
    loop_collections: Vec<(String, usize)>,
    render_begin_count: usize,
    render_end_count: usize,
    render_proc_line: usize,
    destroyed_entities: BTreeSet<String>,
    camera_modified: bool,
    camera_restored: bool,
    camera_proc_line: usize,
    asset_load_count: usize,
    asset_free_count: usize,
    float_edge_finding_added: bool,
    proc_parameters: Vec<(usize, BTreeSet<String>)>,
    tainted_values: BTreeSet<String>,
    unordered_tables: BTreeSet<String>,
    capture_indents: Vec<usize>,
    in_exported_ref_object: bool,
    object_indent: usize,
    generic_hook_count: usize,
    has_import: bool,
    has_generic_serialization_wrapper: bool,
    json_api_count: usize,
    distinct_types: BTreeSet<String>,
    dump_types: BTreeSet<String>,
    parse_types: BTreeSet<String>,
}

struct FileFacts {
    import_count: usize,
    export_count: usize,
    mutable_declarations: BTreeMap<String, usize>,
}

struct LineContext<'a> {
    path: &'a str,
    source: &'a str,
    lines: &'a [&'a str],
    index: usize,
    raw: &'a str,
    line: &'a str,
    lower: &'a str,
    indent: usize,
    is_test: bool,
    mentions_websocket: bool,
}

fn scan_file(path: &str, source: &str) -> Vec<Finding> {
    let lines = source.split('\n').collect::<Vec<_>>();
    let file_lower = source.to_ascii_lowercase();
    let is_test = path.starts_with("tests/")
        || path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("test_"));
    let mentions_websocket = file_lower.contains("websocket")
        || file_lower.contains("sec-websocket")
        || (file_lower.contains("connection") && file_lower.contains("upgrade"));
    let mut findings = split_recursive_types(path, &lines);
    let mut state = ScanState {
        render_proc_line: 1,
        camera_proc_line: 1,
        ..ScanState::default()
    };
    let mut facts = FileFacts {
        import_count: 0,
        export_count: 0,
        mutable_declarations: BTreeMap::new(),
    };

    for (index, raw) in lines.iter().enumerate() {
        let uncommented = without_comment(raw);
        let line = uncommented.trim();
        let lower_owned = line.to_ascii_lowercase();
        let lower = lower_owned.as_str();
        let indent = leading_indent(raw);
        let context = LineContext {
            path,
            source,
            lines: &lines,
            index,
            raw,
            line,
            lower,
            indent,
            is_test,
            mentions_websocket,
        };
        analyze_file_basics(&context, &mut facts, &mut findings);
        analyze_runtime(&context, &file_lower, &mut state, &mut findings);
        analyze_advanced(&context, &mut state, &mut findings);
        analyze_simple(&context, &mut findings);
    }
    analyze_aggregate(
        path,
        source,
        &lines,
        is_test,
        &file_lower,
        mentions_websocket,
        &state,
        &facts,
        &mut findings,
    );
    findings
}

fn analyze_file_basics(
    context: &LineContext<'_>,
    facts: &mut FileFacts,
    findings: &mut Vec<Finding>,
) {
    analyze_nim_number(context, findings);
    record_nim_declarations(context, facts);
    analyze_nim_import(context, facts, findings);
    analyze_exported_nim_type(context, findings);
    analyze_nim_type_contract(context, findings);
    analyze_nim_template(context, findings);
    analyze_nim_public_proc(context, findings);
}

fn analyze_nim_number(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if has_ungrouped_large_number(context.line) {
        push_str(
            findings,
            "nim-large-number-ungrouped",
            context.path,
            context.index + 1,
            "large numeric literal is not digit-grouped",
            "high",
            Some(Severity::Warn),
        );
    }
}

fn record_nim_declarations(context: &LineContext<'_>, facts: &mut FileFacts) {
    if let Some(captures) = VARIABLE_DECLARATION.captures(context.line) {
        facts
            .mutable_declarations
            .insert(captures[1].to_owned(), context.index);
    }
    if context.line.contains('*') && EXPORTED_DECLARATION.is_match(context.line) {
        facts.export_count += 1;
    }
}

fn analyze_nim_import(
    context: &LineContext<'_>,
    facts: &mut FileFacts,
    findings: &mut Vec<Finding>,
) {
    if !context.line.starts_with("import ") && !context.line.starts_with("from ") {
        return;
    }
    facts.import_count += 1;
    if !context.line.starts_with("import ") {
        return;
    }
    let (Some(open), Some(close)) = (context.line.find('['), context.line.rfind(']')) else {
        return;
    };
    if close <= open {
        return;
    }
    let count = context.line[open + 1..close].split(',').count();
    if count > 8 {
        push(
            findings,
            "nim-broad-import",
            context.path,
            context.index + 1,
            format!("large grouped import with {count} modules"),
            "medium",
            Some(Severity::Info),
        );
    }
}

fn analyze_exported_nim_type(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.line.contains('*') || !EXPORTED_TYPE.is_match(context.line) {
        return;
    }
    if !(context.index > 0 && context.lines[context.index - 1].trim().starts_with("##")) {
        push_str(
            findings,
            "nim-exported-object-without-doc",
            context.path,
            context.index + 1,
            "exported type lacks a doc comment",
            "low",
            Some(Severity::Info),
        );
    }
    if context.line.contains("= tuple") {
        push_str(
            findings,
            "nim-tuple-used-as-domain-type",
            context.path,
            context.index + 1,
            "exported tuple type may be better modeled as an object",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_nim_type_contract(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if context.line.contains("ref object of ") {
        push_str(
            findings,
            "nim-ref-object-inheritance",
            context.path,
            context.index + 1,
            "ref object inheritance used; consider whether composition is simpler",
            "medium",
            Some(Severity::Info),
        );
    }
    if context.line.contains("{.raises")
        && (context.line.contains("CatchableError") || context.line.contains("Exception"))
    {
        push_str(
            findings,
            "nim-raises-catchableerror",
            context.path,
            context.index + 1,
            "raises contract is too broad",
            "medium",
            Some(Severity::Info),
        );
    }
}

fn analyze_nim_template(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if !context.line.starts_with("template ") {
        return;
    }
    let body_length = context.lines[context.index + 1..]
        .iter()
        .take_while(|next| next.trim().is_empty() || leading_indent(next) > context.indent)
        .count();
    if body_length + 1 > 20 {
        push(
            findings,
            "nim-large-template",
            context.path,
            context.index + 1,
            format!("template spans {} lines", body_length + 1),
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_nim_public_proc(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let declaration_paren = context.line.find('(').unwrap_or(context.line.len());
    let exported_proc = (context.line.starts_with("proc ") || context.line.starts_with("func "))
        && context.line[..declaration_paren].contains('*');
    if !exported_proc {
        return;
    }
    if context.line.contains("cstring") {
        push_str(
            findings,
            "nim-cstring-public-api",
            context.path,
            context.index + 1,
            "exported API exposes cstring",
            "medium",
            Some(Severity::Info),
        );
    }
    if RAW_POINTER.is_match(context.line) {
        push_str(
            findings,
            "nim-pointer-public-api",
            context.path,
            context.index + 1,
            "exported API exposes a raw pointer",
            "medium",
            Some(Severity::Info),
        );
    }
    if PUBLIC_VAR_SCALAR.is_match(context.line) {
        push_str(
            findings,
            "nim-public-var-scalar-accessor",
            context.path,
            context.index + 1,
            "exported API returns mutable scalar access",
            "medium",
            Some(Severity::Warn),
        );
    }
    if let Some(captures) = CONSTRUCTOR.captures(context.line) {
        let returned = context.line.rfind(')').is_some_and(|close| {
            RETURN_TYPE
                .captures(&context.line[close + 1..])
                .is_some_and(|returned| returned[1] == captures[1])
        });
        if !returned {
            push_str(
                findings,
                "nim-constructor-name",
                context.path,
                context.index + 1,
                "constructor-style name does not return the matching type",
                "low",
                Some(Severity::Info),
            );
        }
    }
}

fn has_ungrouped_large_number(line: &str) -> bool {
    UNGROUPED_LARGE_NUMBER.is_match(&without_string_literals(line))
}

fn writes_unescaped_markup(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let writes_output =
        lower.starts_with("echo ") || lower.starts_with("echo(") || OUTPUT_WRITE.is_match(&lower);
    if !writes_output || ESCAPE_CALL.is_match(&lower) {
        return false;
    }
    let Some(opening) = OPENING_TAG.captures(line) else {
        return false;
    };
    let whole = opening.get(0).expect("opening tag match must exist");
    let tag = &opening[1];
    let remainder = &line[whole.end()..];
    let Some(closing) = closing_tag_start(remainder, tag) else {
        return false;
    };
    IDENTIFIER_ANY.is_match(&without_quoted_text(&remainder[..closing]))
}

fn has_member(line: &str, receiver: &str, members: &[&str]) -> bool {
    line.match_indices(receiver).any(|(index, _)| {
        let Some(rest) = line[index + receiver.len()..].strip_prefix('.') else {
            return false;
        };
        members.is_empty() || members.iter().any(|member| rest.starts_with(member))
    })
}

fn has_member_call(line: &str, receiver: &str, members: &[&str]) -> bool {
    line.match_indices(receiver).any(|(index, _)| {
        let Some(rest) = line[index + receiver.len()..].strip_prefix('.') else {
            return false;
        };
        members.iter().any(|member| {
            rest.strip_prefix(member)
                .is_some_and(|suffix| suffix.starts_with('('))
        })
    })
}

fn has_assignment(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(index, _)| {
        let starts_at_boundary = index == 0
            || !line.as_bytes()[index - 1].is_ascii_alphanumeric()
                && line.as_bytes()[index - 1] != b'_';
        starts_at_boundary && line[index + name.len()..].trim_start().starts_with('=')
    })
}

fn closing_tag_start(source: &str, tag: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    for index in 0..bytes.len() {
        let quote = bytes[index];
        if quote != b'"' && quote != b'\'' || !source[index + 1..].starts_with("</") {
            continue;
        }
        let name_start = index + 3;
        let name_end = name_start + tag.len();
        if name_end > bytes.len() || !source[name_start..name_end].eq_ignore_ascii_case(tag) {
            continue;
        }
        let remainder = &source[name_end..];
        let whitespace = remainder.len() - remainder.trim_start().len();
        let remainder = &remainder[whitespace..];
        if remainder.starts_with('>')
            && remainder
                .as_bytes()
                .get(1)
                .is_some_and(|closing_quote| *closing_quote == quote)
        {
            return Some(index);
        }
    }
    None
}

#[derive(Default)]
struct QuoteState {
    quote: Option<char>,
    escaped: bool,
}

impl QuoteState {
    fn contains(&mut self, character: char) -> bool {
        let Some(active) = self.quote else {
            if character == '"' || character == '\'' {
                self.quote = Some(character);
                return true;
            }
            return false;
        };

        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == active {
            self.quote = None;
        }
        true
    }
}

fn without_quoted_text(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut quotes = QuoteState::default();
    for character in source.chars() {
        if !quotes.contains(character) {
            result.push(character);
        }
    }
    result
}

fn without_string_literals(line: &str) -> String {
    let mut code = String::with_capacity(line.len());
    let mut quotes = QuoteState::default();
    for character in line.chars() {
        code.push(if quotes.contains(character) {
            ' '
        } else {
            character
        });
    }
    code
}

fn without_comment(line: &str) -> &str {
    let mut quotes = QuoteState::default();
    let end = line
        .char_indices()
        .find_map(|(index, character)| {
            let quoted = quotes.contains(character);
            (character == '#' && !quoted).then_some(index)
        })
        .unwrap_or(line.len());
    &line[..end]
}

fn indented_body<'a>(lines: &'a [&str], index: usize, indent: usize) -> Vec<&'a str> {
    lines[index + 1..]
        .iter()
        .copied()
        .take_while(|next| next.trim().is_empty() || leading_indent(next) > indent)
        .collect()
}

fn nearby_lines(lines: &[&str], index: usize, before: usize, after: usize) -> String {
    let start = index.saturating_sub(before);
    let end = (index + after + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn leading_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn pop_scopes(indent: usize, scopes: &mut Vec<usize>) {
    while scopes.last().is_some_and(|scope| indent <= *scope) {
        scopes.pop();
    }
}

fn add_line(
    findings: &mut Vec<Finding>,
    context: &LineContext<'_>,
    code: &str,
    message: &str,
    confidence: &str,
    severity: Option<Severity>,
) {
    push_str(
        findings,
        code,
        context.path,
        context.index + 1,
        message,
        confidence,
        severity,
    );
}

fn push_str(
    findings: &mut Vec<Finding>,
    code: &str,
    path: &str,
    line: usize,
    message: &str,
    confidence: &str,
    severity: Option<Severity>,
) {
    findings.push(finding(code, path, line, message, confidence, severity));
}

fn push(
    findings: &mut Vec<Finding>,
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
    severity: Option<Severity>,
) {
    findings.push(finding(code, path, line, &message, confidence, severity));
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: &str,
    confidence: &str,
    _severity: Option<Severity>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Nim rule metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

struct CachedRegex {
    compiled: LazyLock<Option<Regex>>,
}

impl CachedRegex {
    fn is_match(&self, haystack: &str) -> bool {
        LazyLock::force(&self.compiled)
            .as_ref()
            .is_some_and(|regex| regex.is_match(haystack))
    }

    fn captures<'h>(&self, haystack: &'h str) -> Option<regex::Captures<'h>> {
        LazyLock::force(&self.compiled)
            .as_ref()
            .and_then(|regex| regex.captures(haystack))
    }

    fn captures_iter<'a>(
        &'a self,
        haystack: &'a str,
    ) -> impl Iterator<Item = regex::Captures<'a>> + 'a {
        LazyLock::force(&self.compiled)
            .as_ref()
            .into_iter()
            .flat_map(move |regex| regex.captures_iter(haystack))
    }
}

macro_rules! regexes {
    ($($name:ident = $pattern:literal;)+) => {$(
        static $name: CachedRegex = CachedRegex {
            compiled: LazyLock::new(|| Regex::new($pattern).ok()),
        };
    )+};
}

regexes! {
    UNGROUPED_LARGE_NUMBER = r"(?:^|[^A-Za-z0-9_.])[0-9]{7,}(?:$|[^A-Za-z0-9_.])";
    VARIABLE_DECLARATION = r"^var\s+([A-Za-z_]\w*)";
    EXPORTED_DECLARATION = r"^(?:proc|func|method|template|iterator|type|[A-Za-z_]\w*\*\s*(?::|=))";
    EXPORTED_TYPE = r"=\s*(?:ref\s+)?object|=\s*tuple|=\s*enum|=\s*distinct";
    RAW_POINTER = r"(?:\bptr\s+|:\s*ptr\b|\bpointer\b)";
    PUBLIC_VAR_SCALAR = r"\)\s*:\s*var\s+(?:int|bool|float|string|char)\b";
    CONSTRUCTOR = r"^(?:proc|func)\s+(?:init|new)([A-Z][A-Za-z0-9_]*)\*?\s*\(";
    RETURN_TYPE = r"^\s*:\s*(?:ref\s+)?([A-Za-z_]\w*)\b";
    UPDATE_WORD = r"update|render|draw|tick|fixedupdate";
    DT_USE = r"\bdt\b|delta";
    FLOAT_API = r"float|pow|sqrt|ln\(|exp\(";
    FLOAT_EDGE = r"nan|inf|epsilon|-0\.0|underflow|overflow";
    HOT_PROC = r"forward|backward|infer|predict|update|render|draw|tick|process";
    LAYOUT_TYPE = r"tensor|matrix|ndarray";
    LAYOUT_WORD = r"layout|stride|batch|channel|feature";
    LAYOUT_DOC = r"shape|layout|stride|batch|channel";
    CAPTURE_START = r"^(?:captureStdout|captureStderr|captureOutput|redirectStdout)";
    TAINTED_ASSIGNMENT = r"(?i)^(?:let|var)\s+([A-Za-z_]\w*)\s*=.*(?:readLine|paramStr|getEnv)";
    TABLE_DECLARATION = r"^(?:let|var)\s+([A-Za-z_]\w*)\s*=.*initTable\[";
    EXEC_CALL = r"execCmd|execShellCmd|startProcess";
    LOOP_COLLECTION = r"\bin\s+([A-Za-z_]\w*)";
    HOT_ALLOCATION = r"newseq|newstring|newtensor|zeros\(|ones\(|inittable|initorderedtable|=\s*@\[\]|\.clone";
    GAME_ALLOCATION = r"newseq|newstring|inittable|initorderedtable|parsejson|=\s*@\[\]";
    BLOCKING_IO = r"readfile|writefile|execprocess|execcmd|request\(|downloadfile";
    ENTITY_WORD = r"entity|entities|particle|projectile|sprite|object";
    GROWTH_LIMIT = r"setlen|delete|del\(|remove|max|limit|cap";
    ASSET_LOAD_CALL = r"loadtexture|loadimage|loadsound|loadmusic|loadfont|loadasset";
    RANDOM_CALL = r"\brand(?:om)?\s*\(";
    SAVE_PROC = r"save|serialize|persist|writestate|writedata";
    SAVE_WRITE = r"writefile\(|encode\(|marshal\(|tojson|dump\(";
    ENTITY_LIFECYCLE = r"\.(?:alive\s*=\s*false|dead\s*=\s*true|destroyed\s*=\s*true|active\s*=\s*false)";
    ENTITY_RECEIVER = r"([A-Za-z_]\w*)\.";
    COMPONENT_LOOKUP = r"obtain\(|getcomponent\(|findcomponent\(|lookup\(|getentity\(|findentity\(|getbyid\(|acquire\(";
    ASSIGNED_VALUE = r"(?:let|var)\s+([A-Za-z_]\w*)\s*=";
    COLLISION_CALL = r"dist\(|distance\(|intersect\(|collide\(|overlap\(|aabb\(|hitbox\(";
    BROAD_PHASE = r"grid|spatial|hash|quadtree|broad|bvh|partition|bucket";
    CAMERA_MUTATION = r"(?:cam|camera)\.(?:x|y|zoom)\s*(?:\+?=)|(?:cam|camera)\.(?:translate|rotate|scale|setpos|move)\(";
    CAMERA_RESTORE = r"(?:cam|camera)\.(?:reset|restore|identity|pop)\(|resettransform";
    ASSET_WORD = r"texture|image|sound|audio|font|mesh|model|shader|sprite|music|asset";
    ASSET_FREE = r"unload|free|release\(|destroy\(|dispose\(";
    ASSET_FREE_WORD = r"texture|image|sound|audio|font|mesh|model|shader|sprite|music|asset|all";
    DRAW_PRIMITIVE = r"drawtext\(|drawrect\(|drawcircle\(|drawline\(|drawtexture\(";
    DEBUG_WORD = r"fps|debug|trace|prof|memory|alloc";
    SCREEN_DIMENSION = r"screenwidth|screenheight|windowwidth|windowheight";
    SCREEN_NUMBER = r"\b(?:320|360|480|540|640|720|768|1080|1280|1440|1920)\b";
    CONFIG_WORD = r"config|cfg";
    PHYSICS_WORD = r"velocity|accel|force|gravity|physics|integrate|simulate";
    DRAW_IN_UPDATE = r"drawtext\(|drawrect\(|drawcircle\(|drawline\(|drawtexture\(|render\(";
    PHYSICS_FLOAT = r"\d\.\d|\.x\b|\.y\b|pos\.|vel\.|speed|gravity|\.mass|\.force";
    DISTANCE_CALL = r"\b(?:dist|distance)\(";
    RAND_SIMULATION = r"\b(?:rand|random)\(";
    WALL_CLOCK = r"gettime\(|\bnow\(|epochtime\(|getmonotonic";
    INPUT_CALL = r"keydown\(|keyup\(|keypressed\(";
    SOUND_CALL = r"playsound\(|playmusic\(|playsfx\(";
    SAVE_CALL = r"writefile\(|savefile\(|\.save\(|savestate\(";
    RENDER_BEGIN = r"beginscissor|beginclip|begincanvas|beginblend";
    RENDER_END = r"endscissor|endclip|endcanvas|finishcanvas";
    IDENTIFIER = r"^[A-Za-z_]\w*$";
    MUTABLE_CONTAINER_FIELD = r":\s*(?:seq|Table|OrderedTable|HashSet)\[";
    SERIALIZE_NAME = r"(?i)tojson|dump|serialize|encode";
    HOOK_KIND = r"hook|runat|stage|kind";
    CONTEXT_INDEX = r"(?:context|plugincontext|ctx|config|defaults)\[";
    SAVE_RENDER_PLUGIN = r"save|render|plugin|default";
    SAFE_CONTEXT_WRITE = r"haskey|mgetorput|contains";
    JSON_API_TYPE = r"JsonNode|JsonValue|:\s*(?:var\s+)?Value\b|seq\[Value\]|Table\[string,\s*Value\]";
    DISTINCT_TYPE = r"^(?:type\s+)?([A-Za-z_]\w*)\*?\s*=\s*distinct\s+";
    LEN_GUARD = r"len\s*(?:==|!=|>)\s*0";
    FLOAT_LITERAL = r"(?:\d\.\d|\bnan\b|\binf\b)";
    SOURCE_TEXT_WORD = r"(?i)source|content|text|raw|file";
    POINTER_SIZE = r"\b(?:len|size|count)?\w*\s*:\s*int";
    LITERAL_LET = r"=\s*(?:\d|true|false)";
    STD_IMPORT = r"^(?:import|from)\s+(?:os|strutils|sequtils|tables|sets|json|times)(?:\b|,)";
    CAST_USAGE = r"\bcast\s*\[";
    STRING_CASE = r#"\bof\s+["']"#;
    REDUNDANT_INIT = r#"^var\s+\w+\s*:\s*(int|string|float\w*|bool)\s*=\s*(0|""|0\.0|false)$"#;
    TYPE_PREFIX_PROC = r"^(?:proc|func)\s+([A-Za-z_]\w*)_([A-Za-z_]\w*)\s*\(\s*\w+\s*:\s*(?:var\s+|ref\s+|ptr\s+)?([A-Za-z_]\w*)";
    WHILE_INDEX = r"^while\s+\w+\s*<\s*\w+\.len";
    NONREF_INHERITANCE = r"=\s*object\s+of\s+";
    CALLABLE = r"^(?:proc|func|method)\s+[^\(]+\(([^)]*)\)";
    EXPORTED_PROC = r"^(?:proc|func)\s+\w+\*";
    PROCESS_EXEC = r"\b(?:execCmd|execShellCmd|execProcess|startProcess)\s*\(";
    SLEEP_CALL = r"\bsleep\s*\(";
    GAME_LOOP_DECLARATION = r"^(?:proc|func)\s+(?:update|draw|tick)";
    TYPE_NAME = r"(?m)^\s+([A-Za-z_]\w*)\*?\s*=";
    OUTPUT_WRITE = r"(?:^|\.)write(?:line)?\s*\(";
    ESCAPE_CALL = r"\b(?:[a-z_]\w*\.)?(?:(?:xml|html)escape(?:attr)?|escape(?:html|xml|attr)?)\s*\(";
    OPENING_TAG = r#"["']<([A-Za-z][A-Za-z0-9:._-]*)(?:\s[^>]*)?>["']"#;
    IDENTIFIER_ANY = r"\b[A-Za-z_]\w*\b";
}

include!("runtime.rs");
include!("advanced.rs");
include!("aggregate.rs");
include!("tests.rs");
