use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let project = Project::new(context.sources());
    if project.routes.is_empty() && project.sources.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    route_contract_findings(&project, &mut findings);
    authentication_findings(&project, &mut findings);
    transport_findings(&project, &mut findings);
    database_findings(&project, &mut findings);
    architecture_findings(&project, &mut findings);
    changed_route_findings(context, &project, &mut findings);
    findings
}

struct PySource<'a> {
    path: &'a str,
    code: &'a str,
    lines: Vec<&'a str>,
    functions: Vec<Function<'a>>,
}

impl PySource<'_> {
    fn line_at(&self, offset: usize) -> usize {
        self.code.as_bytes()[..offset]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1
    }

    fn around(&self, offset: usize) -> &str {
        let start = floor_char_boundary(self.code, offset.saturating_sub(180));
        let end = ceil_char_boundary(self.code, (offset + 180).min(self.code.len()));
        &self.code[start..end]
    }
}

struct Function<'a> {
    name: &'a str,
    signature: &'a str,
    body: &'a str,
    line: usize,
    offset: usize,
}

struct Route<'a> {
    path: &'a str,
    line: usize,
    method: &'a str,
    url: &'a str,
    decorator: &'a str,
    signature: &'a str,
    body: &'a str,
}

struct RouteModule<'route, 'source> {
    routes: Vec<&'route Route<'source>>,
    domains: Vec<&'source str>,
}

struct AuthenticationCandidate<'a> {
    path: &'a str,
    line: usize,
    kind: AuthenticationCandidateKind<'a>,
}

enum AuthenticationCandidateKind<'a> {
    MissingDependency {
        method: &'a str,
        url: &'a str,
        decorator: &'a str,
        signature: &'a str,
    },
    RoleCheckAfterAccess {
        method: &'a str,
        url: &'a str,
        access: usize,
        role: usize,
    },
    PlaintextPassword {
        context: &'a str,
    },
    InsecureJwtDecode {
        call: &'a str,
    },
}

struct DatabaseCandidate<'a> {
    path: &'a str,
    line: usize,
    kind: DatabaseCandidateKind<'a>,
}

enum DatabaseCandidateKind<'a> {
    SessionLifecycle {
        function_name: &'a str,
        body: &'a str,
    },
    TransactionFailure {
        function_name: &'a str,
        body: &'a str,
    },
    QueryInLoop,
    UnboundedQuery {
        expression: &'a str,
    },
}

struct ArchitectureViolation<'a> {
    code: &'static str,
    path: &'a str,
    line: usize,
    message: String,
    confidence: &'static str,
}

struct RouteContractQualification {
    missing_response_model: bool,
    body_with_no_content_status: bool,
    body_with_get: bool,
    unvalidated_dict_body: bool,
    blocking_async_route: bool,
    broad_http_exception: bool,
    sensitive_error_detail: bool,
    request_data_logging: bool,
    missing_error_response_docs: bool,
}

struct Project<'a> {
    sources: Vec<PySource<'a>>,
    routes: Vec<Route<'a>>,
    joined: String,
}

impl<'a> Project<'a> {
    fn new(sources: &'a BTreeMap<String, String>) -> Self {
        let sources = sources
            .iter()
            .filter(|(path, _)| path.ends_with(".py"))
            .map(|(path, code)| {
                let lines = code.split('\n').collect::<Vec<_>>();
                let functions = extract_functions(code, &lines);
                PySource {
                    path,
                    code,
                    lines,
                    functions,
                }
            })
            .collect::<Vec<_>>();
        let joined = sources
            .iter()
            .map(|source| source.code)
            .collect::<Vec<_>>()
            .join("\n");
        let routes = sources.iter().flat_map(extract_routes).collect();
        Self {
            sources,
            routes,
            joined,
        }
    }
}

fn route_contract_findings(project: &Project<'_>, findings: &mut Vec<Finding>) {
    for route in &project.routes {
        let qualification = qualify_route_contract(route);
        add_route_contract_findings(route, &qualification, findings);
    }
}

fn qualify_route_contract(route: &Route<'_>) -> RouteContractQualification {
    RouteContractQualification {
        missing_response_model: is_missing_response_model(route),
        body_with_no_content_status: has_body_with_no_content_status(route),
        body_with_get: has_body_with_get(route),
        unvalidated_dict_body: has_unvalidated_dict_body(route),
        blocking_async_route: is_blocking_async_route(route),
        broad_http_exception: has_broad_http_exception(route),
        sensitive_error_detail: has_sensitive_error_detail(route),
        request_data_logging: has_request_data_logging(route),
        missing_error_response_docs: is_missing_error_response_docs(route),
    }
}

fn is_missing_response_model(route: &Route<'_>) -> bool {
    !route.decorator.contains("response_model=")
        && !RETURN_ANNOTATION.is_match(route.signature)
        && OBJECT_RETURN.is_match(route.body)
}

fn has_body_with_no_content_status(route: &Route<'_>) -> bool {
    STATUS_204.is_match(route.decorator) && returns_non_none(route.body)
}

fn has_body_with_get(route: &Route<'_>) -> bool {
    route.method == "get" && BODY_ARGUMENT.is_match(route.signature)
}

fn has_unvalidated_dict_body(route: &Route<'_>) -> bool {
    DICT_BODY.is_match(route.signature)
}

fn is_blocking_async_route(route: &Route<'_>) -> bool {
    route.signature.trim_start().starts_with("async def ") && BLOCKING_CALL.is_match(route.body)
}

fn has_broad_http_exception(route: &Route<'_>) -> bool {
    BROAD_EXCEPTION.is_match(route.body) && route.body.contains("HTTPException(")
}

fn has_sensitive_error_detail(route: &Route<'_>) -> bool {
    SENSITIVE_DETAIL.is_match(route.body) || sensitive_f_string(route.body)
}

fn has_request_data_logging(route: &Route<'_>) -> bool {
    REQUEST_LOGGING.is_match(route.body)
}

fn is_missing_error_response_docs(route: &Route<'_>) -> bool {
    route.body.contains("HTTPException(") && !route.decorator.contains("responses=")
}

fn add_route_contract_findings(
    route: &Route<'_>,
    qualification: &RouteContractQualification,
    findings: &mut Vec<Finding>,
) {
    let label = route_label(route);
    if qualification.missing_response_model {
        add(
            findings,
            "fastapi-route-missing-response-model",
            route.path,
            route.line,
            format!("{label} returns an object without a response model"),
            "high",
        );
    }
    if qualification.body_with_no_content_status {
        add(
            findings,
            "fastapi-route-status-code-mismatch",
            route.path,
            route.line,
            format!("{label} declares 204 but returns a body"),
            "high",
        );
    }
    if qualification.body_with_get {
        add(
            findings,
            "fastapi-route-body-with-get",
            route.path,
            route.line,
            format!("GET {} declares a request body", route.url),
            "high",
        );
    }
    if qualification.unvalidated_dict_body {
        add(
            findings,
            "fastapi-unvalidated-dict-body",
            route.path,
            route.line,
            format!("{label} accepts an unvalidated dictionary body"),
            "high",
        );
    }
    if qualification.blocking_async_route {
        add(
            findings,
            "fastapi-sync-blocking-route",
            route.path,
            route.line,
            format!("{label} performs blocking work in an async route"),
            "high",
        );
    }
    if qualification.broad_http_exception {
        add(
            findings,
            "fastapi-broad-http-exception",
            route.path,
            route.line,
            format!("{label} translates a broad exception into HTTPException"),
            "high",
        );
    }
    if qualification.sensitive_error_detail {
        add(
            findings,
            "fastapi-sensitive-error-detail",
            route.path,
            route.line,
            format!("{label} returns raw exception detail"),
            "high",
        );
    }
    if qualification.request_data_logging {
        add(
            findings,
            "fastapi-request-data-logging",
            route.path,
            route.line,
            format!("{label} logs raw request or credential data"),
            "high",
        );
    }
    if qualification.missing_error_response_docs {
        add(
            findings,
            "fastapi-missing-error-response-docs",
            route.path,
            route.line,
            format!("{label} raises HTTPException without documented responses"),
            "high",
        );
    }
}

fn authentication_findings(project: &Project<'_>, findings: &mut Vec<Finding>) {
    collect_authentication_candidates(project, |candidate| {
        if violates_authentication_policy(&candidate) {
            emit_authentication_finding(candidate, findings);
        }
    });
}

fn collect_authentication_candidates<'a>(
    project: &'a Project<'_>,
    mut collect: impl FnMut(AuthenticationCandidate<'a>),
) {
    if AUTH_ESTABLISHED.is_match(&project.joined) {
        collect_missing_authentication_candidates(&project.routes, &mut collect);
    }
    collect_role_check_candidates(&project.routes, &mut collect);
    for source in &project.sources {
        collect_password_candidates(source, &mut collect);
        collect_jwt_candidates(source, &mut collect);
    }
}

fn collect_missing_authentication_candidates<'a>(
    routes: &'a [Route<'_>],
    collect: &mut impl FnMut(AuthenticationCandidate<'a>),
) {
    for route in routes
        .iter()
        .filter(|route| matches!(route.method, "post" | "put" | "patch" | "delete"))
    {
        collect(AuthenticationCandidate {
            path: route.path,
            line: route.line,
            kind: AuthenticationCandidateKind::MissingDependency {
                method: route.method,
                url: route.url,
                decorator: route.decorator,
                signature: route.signature,
            },
        });
    }
}

fn collect_role_check_candidates<'a>(
    routes: &'a [Route<'_>],
    collect: &mut impl FnMut(AuthenticationCandidate<'a>),
) {
    for route in routes {
        let access = DATABASE_ACCESS
            .find(route.body)
            .map(|matched| matched.start());
        let role = ROLE_CHECK.find(route.body).map(|matched| matched.start());
        if let Some((access, role)) = access.zip(role) {
            collect(AuthenticationCandidate {
                path: route.path,
                line: route.line,
                kind: AuthenticationCandidateKind::RoleCheckAfterAccess {
                    method: route.method,
                    url: route.url,
                    access,
                    role,
                },
            });
        }
    }
}

fn collect_password_candidates<'a>(
    source: &'a PySource<'_>,
    collect: &mut impl FnMut(AuthenticationCandidate<'a>),
) {
    for matched in PASSWORD_ASSIGNMENT.find_iter(source.code) {
        collect(AuthenticationCandidate {
            path: source.path,
            line: source.line_at(matched.start()),
            kind: AuthenticationCandidateKind::PlaintextPassword {
                context: source.around(matched.start()),
            },
        });
    }
}

fn collect_jwt_candidates<'a>(
    source: &'a PySource<'_>,
    collect: &mut impl FnMut(AuthenticationCandidate<'a>),
) {
    for captures in JWT_DECODE.captures_iter(source.code) {
        let (Some(matched), Some(call)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        collect(AuthenticationCandidate {
            path: source.path,
            line: source.line_at(matched.start()),
            kind: AuthenticationCandidateKind::InsecureJwtDecode {
                call: call.as_str(),
            },
        });
    }
}

fn violates_authentication_policy(candidate: &AuthenticationCandidate<'_>) -> bool {
    match &candidate.kind {
        AuthenticationCandidateKind::MissingDependency {
            decorator,
            signature,
            ..
        } => !AUTH_DEPENDENCY.is_match(&format!("{decorator}{signature}")),
        AuthenticationCandidateKind::RoleCheckAfterAccess { access, role, .. } => role > access,
        AuthenticationCandidateKind::PlaintextPassword { context } => {
            !PASSWORD_HASH.is_match(context)
        }
        AuthenticationCandidateKind::InsecureJwtDecode { call } => {
            !call.contains("algorithms=") || DISABLED_SIGNATURE.is_match(call)
        }
    }
}

fn emit_authentication_finding(
    candidate: AuthenticationCandidate<'_>,
    findings: &mut Vec<Finding>,
) {
    let (code, message, confidence) = match candidate.kind {
        AuthenticationCandidateKind::MissingDependency { method, url, .. } => (
            "fastapi-missing-auth-dependency",
            format!(
                "{} {} has no authentication dependency",
                method.to_ascii_uppercase(),
                url
            ),
            "medium",
        ),
        AuthenticationCandidateKind::RoleCheckAfterAccess { method, url, .. } => (
            "fastapi-role-check-after-resource-access",
            format!(
                "{} {} checks authorization after database access",
                method.to_ascii_uppercase(),
                url
            ),
            "high",
        ),
        AuthenticationCandidateKind::PlaintextPassword { .. } => (
            "fastapi-plaintext-password",
            "request password is assigned without visible hashing".to_owned(),
            "high",
        ),
        AuthenticationCandidateKind::InsecureJwtDecode { .. } => (
            "fastapi-insecure-jwt-decode",
            "JWT decode has no explicit verified algorithms allowlist".to_owned(),
            "high",
        ),
    };
    add(
        findings,
        code,
        candidate.path,
        candidate.line,
        message,
        confidence,
    );
}

fn transport_findings(project: &Project<'_>, findings: &mut Vec<Finding>) {
    for source in &project.sources {
        for matched in PERMISSIVE_CORS.find_iter(source.code) {
            add(
                findings,
                "fastapi-permissive-cors",
                source.path,
                source.line_at(matched.start()),
                "CORS allows every origin".to_owned(),
                "high",
            );
        }
    }
    if project.routes.len() >= 5 && !RATE_LIMIT.is_match(&project.joined) {
        let first = &project.routes[0];
        add(
            findings,
            "fastapi-missing-rate-limit",
            first.path,
            first.line,
            format!(
                "{} routes have no visible rate-limiting boundary",
                project.routes.len()
            ),
            "medium",
        );
    }
    if project.routes.len() >= 3 && !SECURITY_HEADERS.is_match(&project.joined) {
        let first = &project.routes[0];
        add(
            findings,
            "fastapi-missing-security-headers",
            first.path,
            first.line,
            "FastAPI application has no visible security-header middleware".to_owned(),
            "medium",
        );
    }
}

fn database_findings(project: &Project<'_>, findings: &mut Vec<Finding>) {
    collect_database_candidates(project, |candidate| {
        if violates_database_policy(&candidate) {
            emit_database_finding(candidate, findings);
        }
    });
}

fn collect_database_candidates<'a>(
    project: &Project<'a>,
    mut collect: impl FnMut(DatabaseCandidate<'a>),
) {
    for source in &project.sources {
        collect_function_database_candidates(source, &mut collect);
        collect_query_in_loop_candidates(source, &mut collect);
        collect_unbounded_query_candidates(source, &mut collect);
    }
}

fn collect_function_database_candidates<'a>(
    source: &PySource<'a>,
    collect: &mut impl FnMut(DatabaseCandidate<'a>),
) {
    for function in &source.functions {
        if SESSION_CREATION.is_match(function.body) {
            collect(DatabaseCandidate {
                path: source.path,
                line: function.line,
                kind: DatabaseCandidateKind::SessionLifecycle {
                    function_name: function.name,
                    body: function.body,
                },
            });
        }
        if function.body.contains(".commit(") && EXCEPT.is_match(function.body) {
            collect(DatabaseCandidate {
                path: source.path,
                line: function.line,
                kind: DatabaseCandidateKind::TransactionFailure {
                    function_name: function.name,
                    body: function.body,
                },
            });
        }
    }
}

fn collect_query_in_loop_candidates<'a>(
    source: &PySource<'a>,
    collect: &mut impl FnMut(DatabaseCandidate<'a>),
) {
    for line in query_in_loop_lines(&source.lines) {
        collect(DatabaseCandidate {
            path: source.path,
            line,
            kind: DatabaseCandidateKind::QueryInLoop,
        });
    }
}

fn collect_unbounded_query_candidates<'a>(
    source: &PySource<'a>,
    collect: &mut impl FnMut(DatabaseCandidate<'a>),
) {
    for matched in UNBOUNDED_QUERY.find_iter(source.code) {
        collect(DatabaseCandidate {
            path: source.path,
            line: source.line_at(matched.start()),
            kind: DatabaseCandidateKind::UnboundedQuery {
                expression: matched.as_str(),
            },
        });
    }
}

fn violates_database_policy(candidate: &DatabaseCandidate<'_>) -> bool {
    match &candidate.kind {
        DatabaseCandidateKind::SessionLifecycle { body, .. } => !SESSION_CLEANUP.is_match(body),
        DatabaseCandidateKind::TransactionFailure { body, .. } => !body.contains(".rollback("),
        DatabaseCandidateKind::QueryInLoop => true,
        DatabaseCandidateKind::UnboundedQuery { expression } => !QUERY_BOUND.is_match(expression),
    }
}

fn emit_database_finding(candidate: DatabaseCandidate<'_>, findings: &mut Vec<Finding>) {
    let (code, message) = match candidate.kind {
        DatabaseCandidateKind::SessionLifecycle { function_name, .. } => (
            "fastapi-db-session-not-closed",
            format!("{function_name} creates a database session without closing it"),
        ),
        DatabaseCandidateKind::TransactionFailure { function_name, .. } => (
            "fastapi-transaction-without-rollback",
            format!("{function_name} handles a commit failure without rollback"),
        ),
        DatabaseCandidateKind::QueryInLoop => (
            "fastapi-query-in-loop",
            "database query executes inside a loop".to_owned(),
        ),
        DatabaseCandidateKind::UnboundedQuery { .. } => (
            "fastapi-unbounded-query",
            "query materializes an unrestricted result set".to_owned(),
        ),
    };
    add(
        findings,
        code,
        candidate.path,
        candidate.line,
        message,
        "high",
    );
}

fn architecture_findings(project: &Project<'_>, findings: &mut Vec<Finding>) {
    let modules = classify_route_modules(&project.routes);
    collect_architecture_violations(project, &modules, |violation| {
        add(
            findings,
            violation.code,
            violation.path,
            violation.line,
            violation.message,
            violation.confidence,
        );
    });
}

fn classify_route_modules<'route, 'source>(
    routes: &'route [Route<'source>],
) -> BTreeMap<&'source str, RouteModule<'route, 'source>> {
    let mut modules = BTreeMap::new();
    for route in routes {
        let module = modules.entry(route.path).or_insert_with(|| RouteModule {
            routes: Vec::new(),
            domains: Vec::new(),
        });
        module.routes.push(route);
        let Some(domain) = top_level_route_domain(route.url) else {
            continue;
        };
        if !module.domains.contains(&domain) {
            module.domains.push(domain);
        }
    }
    modules
}

fn top_level_route_domain(url: &str) -> Option<&str> {
    url.split('/')
        .find(|part| !part.is_empty() && !part.starts_with('{'))
}

fn collect_architecture_violations<'source>(
    project: &Project<'source>,
    modules: &BTreeMap<&'source str, RouteModule<'_, 'source>>,
    mut collect: impl FnMut(ArchitectureViolation<'source>),
) {
    collect_background_task_violations(&project.routes, &mut collect);
    collect_global_cache_violations(&project.sources, &mut collect);
    collect_route_module_violations(modules, &mut collect);
    collect_settings_bypass_violations(project, &mut collect);
}

fn collect_background_task_violations<'source>(
    routes: &[Route<'source>],
    collect: &mut impl FnMut(ArchitectureViolation<'source>),
) {
    for route in routes {
        for captures in BACKGROUND_TASK.captures_iter(route.body) {
            let Some(task) = captures.get(1).map(|capture| capture.as_str()) else {
                continue;
            };
            if !HEAVY_TASK.is_match(task) {
                continue;
            }
            collect(ArchitectureViolation {
                code: "fastapi-background-task-heavy-work",
                path: route.path,
                line: route.line,
                message: format!("BackgroundTasks schedules likely heavy work `{task}`"),
                confidence: "medium",
            });
        }
    }
}

fn collect_global_cache_violations<'source>(
    sources: &[PySource<'source>],
    collect: &mut impl FnMut(ArchitectureViolation<'source>),
) {
    for source in sources {
        for captures in GLOBAL_CACHE.captures_iter(source.code) {
            let (Some(matched), Some(name)) = (captures.get(0), captures.get(1)) else {
                continue;
            };
            collect(ArchitectureViolation {
                code: "fastapi-global-mutable-cache",
                path: source.path,
                line: source.line_at(matched.start()),
                message: format!(
                    "module-level mutable cache `{}` is process-local",
                    name.as_str()
                ),
                confidence: "high",
            });
        }
    }
}

fn collect_route_module_violations<'source>(
    modules: &BTreeMap<&'source str, RouteModule<'_, 'source>>,
    collect: &mut impl FnMut(ArchitectureViolation<'source>),
) {
    for module in modules.values() {
        if module.domains.len() < 3 || module.routes.len() < 6 {
            continue;
        }
        let Some(route) = module.routes.first() else {
            continue;
        };
        collect(ArchitectureViolation {
            code: "fastapi-route-domain-sprawl",
            path: route.path,
            line: route.line,
            message: format!(
                "route module owns {} unrelated top-level domains: {}",
                module.domains.len(),
                module.domains.join(", ")
            ),
            confidence: "medium",
        });
    }
}

fn collect_settings_bypass_violations<'source>(
    project: &Project<'source>,
    collect: &mut impl FnMut(ArchitectureViolation<'source>),
) {
    if !SETTINGS_ESTABLISHED.is_match(&project.joined) {
        return;
    }
    for route in &project.routes {
        if !ENVIRONMENT_READ.is_match(route.body) {
            continue;
        }
        collect(ArchitectureViolation {
            code: "fastapi-settings-bypass",
            path: route.path,
            line: route.line,
            message: format!(
                "{} reads environment variables directly",
                route_label(route)
            ),
            confidence: "high",
        });
    }
}

fn changed_route_findings(
    context: &SourceAnalysisContext<'_>,
    project: &Project<'_>,
    findings: &mut Vec<Finding>,
) {
    if !context.has_changed_base() || context.changed_paths().is_empty() {
        return;
    }
    let changed_tests = context
        .changed_paths()
        .iter()
        .filter(|path| {
            TEST_DIRECTORY.is_match(path) && API_TEST_PATH.is_match(&path.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    for route in project
        .routes
        .iter()
        .filter(|route| context.changed_paths().contains(route.path))
    {
        let concepts = route
            .url
            .split('/')
            .filter(|part| part.len() >= 3 && !part.starts_with('{'))
            .collect::<Vec<_>>();
        if !changed_tests.iter().any(|test| {
            let lower = test.to_ascii_lowercase();
            concepts.iter().any(|concept| lower.contains(concept))
        }) {
            add(
                findings,
                "fastapi-route-without-integration-test",
                route.path,
                route.line,
                format!(
                    "changed {} {} has no related changed API test",
                    route.method.to_ascii_uppercase(),
                    route.url
                ),
                "medium",
            );
        }
    }
}

fn extract_functions<'a>(code: &'a str, lines: &[&'a str]) -> Vec<Function<'a>> {
    let mut result = Vec::new();
    let mut line_offsets = Vec::with_capacity(lines.len());
    let mut offset = 0;
    for line in lines {
        line_offsets.push(offset);
        offset += line.len() + 1;
    }
    for captures in FUNCTION_DECLARATION.captures_iter(code) {
        let (Some(matched), Some(name)) = (captures.get(0), captures.get(2)) else {
            continue;
        };
        let start_line = line_at(code, matched.start());
        let indent = leading_indent(lines[start_line - 1]);
        let mut end_line = lines.len();
        for (line_index, raw) in lines.iter().enumerate().skip(start_line) {
            if raw.trim().is_empty() {
                continue;
            }
            let next_indent = leading_indent(raw);
            if next_indent <= indent && !raw.trim_start().starts_with('@') {
                end_line = line_index;
                break;
            }
        }
        let body_end = if end_line == lines.len() {
            code.len()
        } else {
            line_offsets[end_line].saturating_sub(1)
        };
        result.push(Function {
            name: name.as_str(),
            signature: matched.as_str(),
            body: &code[matched.start()..body_end],
            line: start_line,
            offset: matched.start(),
        });
    }
    result
}

fn extract_routes<'a>(source: &PySource<'a>) -> Vec<Route<'a>> {
    let mut routes = Vec::new();
    for captures in ROUTE_DECORATOR.captures_iter(source.code) {
        let (Some(matched), Some(method), Some(opening_quote), Some(url), Some(closing_quote)) = (
            captures.get(0),
            captures.get(1),
            captures.get(2),
            captures.get(3),
            captures.get(4),
        ) else {
            continue;
        };
        if opening_quote.as_str() != closing_quote.as_str() {
            continue;
        }
        let Some(function) = source.functions.iter().find(|function| {
            function.offset >= matched.end() && function.offset - matched.end() < 500
        }) else {
            continue;
        };
        routes.push(Route {
            path: source.path,
            line: source.line_at(matched.start()),
            method: method.as_str(),
            url: url.as_str(),
            decorator: matched.as_str(),
            signature: function.signature,
            body: function.body,
        });
    }
    routes
}

fn query_in_loop_lines(lines: &[&str]) -> Vec<usize> {
    let mut result = Vec::new();
    for (index, header) in lines.iter().enumerate() {
        if !LOOP_HEADER.is_match(header) {
            continue;
        }
        let loop_indent = leading_indent(header);
        let stop = (index + 10).min(lines.len());
        for (candidate, raw) in lines.iter().enumerate().take(stop).skip(index + 1) {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if leading_indent(raw) <= loop_indent {
                break;
            }
            if LOOP_QUERY.is_match(trimmed) {
                result.push(candidate + 1);
                break;
            }
        }
    }
    result
}

fn returns_non_none(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed
            .strip_prefix("return")
            .is_some_and(|rest| !rest.is_empty() && !rest.trim_start().starts_with("None"))
    })
}

fn sensitive_f_string(body: &str) -> bool {
    body.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("detail=f\"")
            || lower.contains("detail = f\"")
            || lower.contains("detail=f'")
            || lower.contains("detail = f'")
    }) && SENSITIVE_EXCEPTION_FIELD.is_match(body)
}

fn route_label(route: &Route<'_>) -> String {
    format!("{} {}", route.method.to_ascii_uppercase(), route.url)
}

fn leading_indent(line: &str) -> usize {
    line.chars()
        .take_while(|character| matches!(character, ' ' | '\t'))
        .count()
}

fn line_at(source: &str, offset: usize) -> usize {
    source.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn floor_char_boundary(source: &str, mut offset: usize) -> usize {
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

fn ceil_char_boundary(source: &str, mut offset: usize) -> usize {
    while !source.is_char_boundary(offset) {
        offset += 1;
    }
    offset
}

fn add(
    findings: &mut Vec<Finding>,
    code: &str,
    path: &str,
    line: usize,
    message: String,
    confidence: &str,
) {
    let metadata = rule_catalog::metadata(code).expect("FastAPI rule metadata must exist");
    findings.push(Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("catalog severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    });
}

struct FallibleRegex(LazyLock<Option<Regex>>);

impl FallibleRegex {
    fn is_match(&self, haystack: &str) -> bool {
        let Some(regex) = LazyLock::force(&self.0).as_ref() else {
            return false;
        };
        regex.is_match(haystack)
    }

    fn find<'h>(&self, haystack: &'h str) -> Option<regex::Match<'h>> {
        LazyLock::force(&self.0)
            .as_ref()
            .and_then(|regex| regex.find(haystack))
    }

    fn find_iter<'a>(&'a self, haystack: &'a str) -> impl Iterator<Item = regex::Match<'a>> + 'a {
        LazyLock::force(&self.0)
            .as_ref()
            .into_iter()
            .flat_map(|regex| regex.find_iter(haystack))
    }

    fn captures_iter<'a>(
        &'a self,
        haystack: &'a str,
    ) -> impl Iterator<Item = regex::Captures<'a>> + 'a {
        LazyLock::force(&self.0)
            .as_ref()
            .into_iter()
            .flat_map(|regex| regex.captures_iter(haystack))
    }
}

macro_rules! regexes {
    ($($name:ident = $pattern:literal;)+) => {$(
        static $name: FallibleRegex =
            FallibleRegex(LazyLock::new(|| Regex::new($pattern).ok()));
    )+};
}

regexes! {
    RETURN_ANNOTATION = r"->\s*(?:[A-Z][\w.\[\], ]+|list\[|dict\[)";
    OBJECT_RETURN = r"\breturn\s+(?:\{|dict\s*\(|JSONResponse\s*\()";
    STATUS_204 = r"status_code\s*=\s*(?:204|status\.HTTP_204_NO_CONTENT)";
    BODY_ARGUMENT = r"\bBody\s*\(";
    DICT_BODY = r"\b\w+\s*:\s*(?:dict|Dict)(?:\[[^]]+\])?\s*(?:=\s*Body\s*\([^)]*\))?";
    BLOCKING_CALL = r"\b(?:requests\.(?:get|post|put|delete)|time\.sleep|subprocess\.(?:run|call)|open)\s*\(";
    BROAD_EXCEPTION = r"except\s+(?:Exception|BaseException)(?:\s+as\s+\w+)?\s*:";
    SENSITIVE_DETAIL = r"detail\s*=\s*(?:str|repr)\s*\(";
    SENSITIVE_EXCEPTION_FIELD = r"\{\s*(?:exc|error|e)\s*\}";
    REQUEST_LOGGING = r"\b(?:log|logger)\.(?:debug|info|warning|error)\s*\([^\n]*(?:request\.(?:body|json|headers|query_params)|password|token)";
    AUTH_ESTABLISHED = r"\b(?:OAuth2PasswordBearer|get_current_(?:user|principal)|HTTPBearer|SecurityScopes)\b";
    AUTH_DEPENDENCY = r"\b(?:Depends|Security)\s*\(";
    DATABASE_ACCESS = r"\b(?:session|db)\.(?:execute|query|get)\s*\(";
    ROLE_CHECK = r"\b(?:has_role|require_role|current_user\.(?:role|roles|is_admin))\b";
    PASSWORD_ASSIGNMENT = r"(?i)\bpassword\s*=\s*(?:payload|request|user_in|data)\.password\b";
    PASSWORD_HASH = r"(?i)\b(?:hash|bcrypt|argon|password_hasher)\b";
    JWT_DECODE = r"\b(?:jwt|jose\.jwt)\.decode\s*\(([^\n]*)";
    DISABLED_SIGNATURE = r#"verify_signature["']?s*:s*False"#;
    PERMISSIVE_CORS = r#"allow_origins\s*=\s*\[\s*["']\*["']"#;
    RATE_LIMIT = r"(?i)\b(?:Limiter|RateLimiter|slowapi|rate_limit|throttle)\b";
    SECURITY_HEADERS = r"\b(?:SecurityHeadersMiddleware|TrustedHostMiddleware|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security)\b";
    SESSION_CREATION = r"\b\w+\s*=\s*(?:Session|SessionLocal|AsyncSession)\s*\(";
    SESSION_CLEANUP = r"\b(?:with|async with)\b|\.close\s*\(|finally\s*:";
    EXCEPT = r"\bexcept\b";
    UNBOUNDED_QUERY = r"\.(?:query\([^\n]+\)|execute\(\s*select\([^\n]+\))[^\n]*(?:\.all\s*\(\)|\.scalars\s*\(\)\.all\s*\(\))";
    QUERY_BOUND = r"\.(?:limit|offset)\s*\(";
    BACKGROUND_TASK = r"background_tasks\.add_task\s*\(\s*([A-Za-z_]\w*)";
    HEAVY_TASK = r"(?i)(?:generate|render|resize|convert|train|export|process_(?:video|image|report)|rebuild)";
    GLOBAL_CACHE = r"(?im)^(\w*(?:cache|store)\w*)\s*(?::[^=]+)?=\s*(?:\{\}|dict\s*\(\)|\[\])";
    SETTINGS_ESTABLISHED = r"\b(?:BaseSettings|SettingsConfigDict|class\s+Settings)\b";
    ENVIRONMENT_READ = r"\b(?:os\.getenv|os\.environ\[)";
    TEST_DIRECTORY = r"(^|/)(?:test|tests)(/|$)";
    API_TEST_PATH = r"(?:api|integration|route|endpoint|client)";
    FUNCTION_DECLARATION = r"(?m)^(async\s+)?def\s+([A-Za-z_]\w*)\s*\([^\n]*\)(?:\s*->\s*[^:]+)?\s*:";
    ROUTE_DECORATOR = r#"(?m)^\s*@(?:\w+\.)?(get|post|put|patch|delete)\s*\(\s*(["'])([^"']+)(["'])([^\n]*)\)\s*$"#;
    LOOP_HEADER = r"^\s*for\s+[^:]+:\s*$";
    LOOP_QUERY = r"^(?:\w+\.)?(?:execute|query|get)\s*\(";
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::analyze;
    use crate::source_analysis_context::SourceAnalysisContext;

    fn codes(source: &str) -> BTreeSet<String> {
        let sources = BTreeMap::from([("app/api.py".to_owned(), source.to_owned())]);
        analyze(&SourceAnalysisContext::unchanged(&sources))
            .into_iter()
            .map(|finding| finding.code)
            .collect()
    }

    #[test]
    fn reports_route_contract_and_authentication_hazards() {
        let findings = codes(
            r#"from fastapi import Body, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer
import requests
import jwt
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
@app.get("/search")
async def search(payload: dict = Body(...)):
    requests.get("https://example.test")
    try:
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
@app.delete("/users/{id}", status_code=204)
def remove_user(id: int):
    user = db.query(User).get(id)
    if not current_user.is_admin:
        deny()
    password = payload.password
    return jwt.decode(payload.token, SECRET)
"#,
        );
        for code in [
            "fastapi-route-missing-response-model",
            "fastapi-route-status-code-mismatch",
            "fastapi-route-body-with-get",
            "fastapi-unvalidated-dict-body",
            "fastapi-sync-blocking-route",
            "fastapi-broad-http-exception",
            "fastapi-sensitive-error-detail",
            "fastapi-missing-auth-dependency",
            "fastapi-role-check-after-resource-access",
            "fastapi-plaintext-password",
            "fastapi-insecure-jwt-decode",
            "fastapi-missing-error-response-docs",
        ] {
            assert!(findings.contains(code), "missing {code}: {findings:?}");
        }
    }

    #[test]
    fn reports_transport_database_and_architecture_hazards() {
        let findings = codes(
            r#"from fastapi import BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings
import os
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])
user_cache = {}
@app.get("/users")
def users(request):
    logger.info(request.headers)
    return []
@app.post("/users")
def create_user(background_tasks: BackgroundTasks):
    background_tasks.add_task(process_video, "input.mp4")
    return os.getenv("REGION")
@app.get("/orders")
def orders(): return []
@app.post("/orders")
def create_order(): return None
@app.get("/reports")
def reports(): return []
@app.post("/reports")
def create_report(): return None
class Settings(BaseSettings):
    region: str
def get_db():
    session = SessionLocal()
    yield session
def save(items):
    try:
        session.commit()
    except DatabaseError:
        raise
    for item in items:
        session.query(Item).get(item.id)
    return session.query(Item).all()
"#,
        );
        for code in [
            "fastapi-permissive-cors",
            "fastapi-missing-rate-limit",
            "fastapi-missing-security-headers",
            "fastapi-request-data-logging",
            "fastapi-db-session-not-closed",
            "fastapi-transaction-without-rollback",
            "fastapi-query-in-loop",
            "fastapi-unbounded-query",
            "fastapi-background-task-heavy-work",
            "fastapi-global-mutable-cache",
            "fastapi-route-domain-sprawl",
            "fastapi-settings-bypass",
        ] {
            assert!(findings.contains(code), "missing {code}: {findings:?}");
        }
    }

    #[test]
    fn accepts_explicit_safe_route_contracts() {
        let findings = codes(
            r#"from fastapi import APIRouter, Depends
router = APIRouter()
@router.get("/users/{id}", response_model=UserOut, responses={404: {"model": Error}})
async def read_user(id: int, principal: User = Depends(get_current_user)) -> UserOut:
    if not principal.can_read(id):
        raise HTTPException(status_code=404, detail="not found")
    return await repository.get_user(id)
"#,
        );
        for code in [
            "fastapi-route-missing-response-model",
            "fastapi-route-body-with-get",
            "fastapi-unvalidated-dict-body",
            "fastapi-sync-blocking-route",
            "fastapi-missing-auth-dependency",
            "fastapi-sensitive-error-detail",
            "fastapi-missing-error-response-docs",
        ] {
            assert!(!findings.contains(code), "unexpected {code}: {findings:?}");
        }
    }

    #[test]
    fn bounds_query_in_loop_by_indentation_and_scan_window() {
        let sources = BTreeMap::from([(
            "app/db.py".to_owned(),
            r#"def load(items):
    for item in items:
        prepare(item)
        session.execute(select(Item))
    session.query(Item).get(1)
    for delayed in items:
        prepare(delayed)
        step_one()
        step_two()
        step_three()
        step_four()
        step_five()
        step_six()
        step_seven()
        step_eight()
        session.query(Item).get(delayed.id)
"#
            .to_owned(),
        )]);
        let findings = analyze(&SourceAnalysisContext::unchanged(&sources));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "fastapi-query-in-loop")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![4]
        );
    }

    #[test]
    fn reports_changed_route_without_related_api_test() {
        let sources = BTreeMap::from([(
            "app/users.py".to_owned(),
            "@router.get(\"/users/{id}\")\ndef read_user(id: int):\n    return User(id=id)\n"
                .to_owned(),
        )]);
        let base = BTreeMap::new();
        let changed = BTreeSet::from(["app/users.py".to_owned()]);
        let context = SourceAnalysisContext::new(&sources, &base, &changed, true);
        let findings = analyze(&context);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "fastapi-route-without-integration-test")
                .count(),
            1
        );
    }
}
