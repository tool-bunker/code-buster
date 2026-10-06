// FastAPI framework checks use conservative route and project evidence without imposing one architecture.

import '../core/models.dart';
import '../core/regexp_cache.dart';
import '../core/rule.dart';

const List<String> fastApiQualityRuleIds = <String>[
  'fastapi-route-missing-response-model',
  'fastapi-route-status-code-mismatch',
  'fastapi-route-body-with-get',
  'fastapi-unvalidated-dict-body',
  'fastapi-sync-blocking-route',
  'fastapi-broad-http-exception',
  'fastapi-sensitive-error-detail',
  'fastapi-missing-auth-dependency',
  'fastapi-role-check-after-resource-access',
  'fastapi-plaintext-password',
  'fastapi-insecure-jwt-decode',
  'fastapi-permissive-cors',
  'fastapi-missing-rate-limit',
  'fastapi-missing-security-headers',
  'fastapi-request-data-logging',
  'fastapi-db-session-not-closed',
  'fastapi-transaction-without-rollback',
  'fastapi-query-in-loop',
  'fastapi-unbounded-query',
  'fastapi-background-task-heavy-work',
  'fastapi-global-mutable-cache',
  'fastapi-route-domain-sprawl',
  'fastapi-settings-bypass',
  'fastapi-missing-error-response-docs',
  'fastapi-route-without-integration-test',
];

final Map<String, RuleMetadata>
fastApiQualityRuleMetadata = <String, RuleMetadata>{
  for (final String id in fastApiQualityRuleIds)
    id: RuleMetadata(
      id: id,
      version: id == 'fastapi-query-in-loop' ? 2 : 1,
      defaultSeverity: RuleSeverity.info,
      group:
          id.contains(
            cachedRegExp(r'auth|password|jwt|cors|security|sensitive'),
          )
          ? 'security'
          : 'maintainability',
      title: _title(id),
      why: _why(id),
      suggestion: _suggestion(id),
      semanticMaturity: RuleSemanticMaturity.project,
      taxonomy: <FindingTaxonomy>{
        if (id.contains(
          cachedRegExp(r'auth|password|jwt|cors|security|sensitive'),
        ))
          FindingTaxonomy.security
        else
          FindingTaxonomy.maintainability,
      },
      languages: const <String>['python'],
      frameworks: const <String>{'fastapi'},
      limitations: const <String>[
        'Only explicit FastAPI decorators, common middleware, SQLAlchemy, JWT, and dependency patterns are resolved.',
        'Framework wrappers, generated routes, runtime registrations, and external infrastructure cannot be resolved.',
      ],
    ),
};

String _title(String id) =>
    'Review ${id.substring('fastapi-'.length).replaceAll('-', ' ')}';
String _why(String id) => switch (id) {
  'fastapi-route-missing-response-model' =>
    'An undocumented response shape weakens validation and the generated OpenAPI contract.',
  'fastapi-route-status-code-mismatch' =>
    'A 204 response must not carry a response body.',
  'fastapi-route-body-with-get' =>
    'GET request bodies are inconsistently supported by clients, proxies, and documentation tools.',
  'fastapi-unvalidated-dict-body' =>
    'An untyped dictionary bypasses Pydantic field validation and API schema detail.',
  'fastapi-sync-blocking-route' =>
    'Blocking work inside an async route stalls the event-loop worker.',
  'fastapi-broad-http-exception' =>
    'Collapsing every exception into one HTTP response hides programming and infrastructure failures.',
  'fastapi-sensitive-error-detail' =>
    'Returning exception text can expose credentials, queries, paths, and internal implementation details.',
  'fastapi-missing-auth-dependency' =>
    'A mutating route in an authenticated API has no visible authentication dependency.',
  'fastapi-role-check-after-resource-access' =>
    'Authorization performed after data access can expose resource existence or perform work before denial.',
  'fastapi-plaintext-password' =>
    'Persisting a request password directly exposes credentials if storage is compromised.',
  'fastapi-insecure-jwt-decode' =>
    'JWT decoding without an explicit algorithm policy can accept unintended token configurations.',
  'fastapi-permissive-cors' =>
    'Wildcard origins can expose authenticated or sensitive APIs to untrusted sites.',
  'fastapi-missing-rate-limit' =>
    'A substantial public API has no visible request-throttling boundary.',
  'fastapi-missing-security-headers' =>
    'The application has no visible middleware establishing baseline security headers.',
  'fastapi-request-data-logging' =>
    'Logging raw request content can retain credentials, tokens, and personal data.',
  'fastapi-db-session-not-closed' =>
    'A database session that is not closed can exhaust the connection pool.',
  'fastapi-transaction-without-rollback' =>
    'A failed commit without rollback leaves the session transaction unusable.',
  'fastapi-query-in-loop' =>
    'Database access inside a loop creates an N+1 query pattern.',
  'fastapi-unbounded-query' =>
    'Loading an unrestricted result set can exhaust memory and database capacity.',
  'fastapi-background-task-heavy-work' =>
    'FastAPI BackgroundTasks run in the application process and are unsuitable for obviously heavy work.',
  'fastapi-global-mutable-cache' =>
    'A process-local mutable cache is inconsistent across workers and can grow without coordination.',
  'fastapi-route-domain-sprawl' =>
    'One route module owns several unrelated top-level API domains.',
  'fastapi-settings-bypass' =>
    'Reading environment variables directly bypasses the project settings boundary and validation.',
  'fastapi-missing-error-response-docs' =>
    'Raised HTTP errors are absent from the generated OpenAPI response contract.',
  'fastapi-route-without-integration-test' =>
    'A changed route has no concept-related changed integration or API test.',
  _ =>
    'The explicit FastAPI pattern weakens the API contract or runtime behavior.',
};

String _suggestion(String id) => switch (id) {
  'fastapi-route-missing-response-model' =>
    'Declare response_model or a precise return annotation.',
  'fastapi-route-body-with-get' =>
    'Use query/path parameters or a non-GET operation for a request body.',
  'fastapi-unvalidated-dict-body' => 'Use a typed Pydantic request model.',
  'fastapi-sync-blocking-route' =>
    'Use an async client or move blocking work to a thread or worker.',
  'fastapi-missing-auth-dependency' =>
    'Attach the established authentication dependency with Depends or Security.',
  'fastapi-plaintext-password' =>
    'Hash passwords with the established password hasher before persistence.',
  'fastapi-insecure-jwt-decode' =>
    'Pass a fixed algorithms allowlist and keep signature verification enabled.',
  'fastapi-permissive-cors' =>
    'List trusted origins explicitly and avoid wildcard credentials.',
  'fastapi-db-session-not-closed' =>
    'Close the session from a finally block or context-managed dependency.',
  'fastapi-transaction-without-rollback' =>
    'Rollback the session before translating or rethrowing the failure.',
  'fastapi-query-in-loop' =>
    'Batch or eager-load the related data outside the loop.',
  'fastapi-unbounded-query' => 'Add pagination or an explicit result limit.',
  'fastapi-settings-bypass' =>
    'Read validated values from the project settings dependency.',
  'fastapi-missing-error-response-docs' =>
    'Declare expected error models and status codes in responses.',
  'fastapi-route-without-integration-test' =>
    'Add or update an API-level test for the changed route behavior.',
  _ =>
    'Use the explicit FastAPI contract or boundary appropriate to this finding.',
};

final class FastApiQualityRule extends SelfContainedRule {
  FastApiQualityRule(String id)
    : super(fastApiQualityRuleMetadata.requiredValue(id));

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final _Project project = _Project(context);
    return project
        .findings(metadata.id)
        .map(
          (finding) => report(
            context,
            path: finding.path,
            line: finding.line,
            message: finding.message,
            confidence: finding.confidence,
          ),
        );
  }
}

final class _Finding {
  const _Finding(
    this.path,
    this.line,
    this.message, {
    this.confidence = 'high',
  });
  final String path;
  final int line;
  final String message;
  final String confidence;
}

final class _Route {
  const _Route({
    required this.path,
    required this.line,
    required this.method,
    required this.url,
    required this.decorator,
    required this.signature,
    required this.body,
  });
  final String path;
  final int line;
  final String method;
  final String url;
  final String decorator;
  final String signature;
  final String body;
}

final class _Project {
  _Project(this.context) {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.py')) continue;
      sources.add(_PySource(entry.key, entry.value));
    }
    routes.addAll(sources.expand(_routes));
    joined = sources.map((source) => source.code).join('\n');
  }

  final RuleContext context;
  final List<_PySource> sources = <_PySource>[];
  final List<_Route> routes = <_Route>[];
  late final String joined;

  // code-buster-ignore complex-function: rule-ID dispatch keeps one parsed FastAPI project model and executes only the selected independent case.
  Iterable<_Finding> findings(String id) sync* {
    switch (id) {
      case 'fastapi-route-missing-response-model':
        for (final _Route route in routes) {
          if (!route.decorator.contains('response_model=') &&
              !cachedRegExp(
                r'->\s*(?:[A-Z][\w.\[\], ]+|list\[|dict\[)',
              ).hasMatch(route.signature) &&
              cachedRegExp(
                r'\breturn\s+(?:\{|dict\s*\(|JSONResponse\s*\()',
              ).hasMatch(route.body)) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} returns an object without a response model',
            );
          }
        }
      case 'fastapi-route-status-code-mismatch':
        for (final _Route route in routes) {
          if (cachedRegExp(
                r'status_code\s*=\s*(?:204|status\.HTTP_204_NO_CONTENT)',
              ).hasMatch(route.decorator) &&
              cachedRegExp(r'\breturn\s+(?!None\b)').hasMatch(route.body)) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} declares 204 but returns a body',
            );
          }
        }
      case 'fastapi-route-body-with-get':
        for (final _Route route in routes.where(
          (route) => route.method == 'get',
        )) {
          if (cachedRegExp(r'\bBody\s*\(').hasMatch(route.signature)) {
            yield _Finding(
              route.path,
              route.line,
              'GET ${route.url} declares a request body',
            );
          }
        }
      case 'fastapi-unvalidated-dict-body':
        for (final _Route route in routes) {
          if (cachedRegExp(
            r'\b\w+\s*:\s*(?:dict|Dict)(?:\[[^]]+\])?\s*(?:=\s*Body\s*\([^)]*\))?',
          ).hasMatch(route.signature)) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} accepts an unvalidated dictionary body',
            );
          }
        }
      case 'fastapi-sync-blocking-route':
        for (final _Route route in routes) {
          if (route.signature.trimLeft().startsWith('async def ') &&
              cachedRegExp(
                r'\b(?:requests\.(?:get|post|put|delete)|time\.sleep|subprocess\.(?:run|call)|open)\s*\(',
              ).hasMatch(route.body)) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} performs blocking work in an async route',
            );
          }
        }
      case 'fastapi-broad-http-exception':
        for (final _Route route in routes) {
          if (cachedRegExp(
                r'except\s+(?:Exception|BaseException)(?:\s+as\s+\w+)?\s*:',
              ).hasMatch(route.body) &&
              route.body.contains('HTTPException(')) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} translates a broad exception into HTTPException',
            );
          }
        }
      case 'fastapi-sensitive-error-detail':
        for (final _Route route in routes) {
          if (cachedRegExp(
            r'detail\s*=\s*(?:str|repr)\s*\(|detail\s*=\s*f["'
            '].*{s*(?:exc|error|e)s*}',
          ).hasMatch(route.body)) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} returns raw exception detail',
            );
          }
        }
      case 'fastapi-missing-auth-dependency':
        final bool authEstablished = cachedRegExp(
          r'\b(?:OAuth2PasswordBearer|get_current_(?:user|principal)|HTTPBearer|SecurityScopes)\b',
        ).hasMatch(joined);
        if (authEstablished) {
          for (final _Route route in routes.where(
            (route) => const <String>{
              'post',
              'put',
              'patch',
              'delete',
            }.contains(route.method),
          )) {
            if (!cachedRegExp(
              r'\b(?:Depends|Security)\s*\(',
            ).hasMatch('${route.decorator}${route.signature}')) {
              yield _Finding(
                route.path,
                route.line,
                '${route.method.toUpperCase()} ${route.url} has no authentication dependency',
                confidence: 'medium',
              );
            }
          }
        }
      case 'fastapi-role-check-after-resource-access':
        for (final _Route route in routes) {
          final int access = route.body.indexOf(
            cachedRegExp(r'\b(?:session|db)\.(?:execute|query|get)\s*\('),
          );
          final int role = route.body.indexOf(
            cachedRegExp(
              r'\b(?:has_role|require_role|current_user\.(?:role|roles|is_admin))\b',
            ),
          );
          if (access >= 0 && role > access) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} checks authorization after database access',
            );
          }
        }
      case 'fastapi-plaintext-password':
        for (final _PySource source in sources) {
          for (final RegExpMatch match in cachedRegExp(
            r'\bpassword\s*=\s*(?:payload|request|user_in|data)\.password\b',
            caseSensitive: false,
          ).allMatches(source.code)) {
            final String nearby = source.around(match.start);
            if (!cachedRegExp(
              r'\b(?:hash|bcrypt|argon|password_hasher)\b',
              caseSensitive: false,
            ).hasMatch(nearby)) {
              yield _Finding(
                source.path,
                source.lineAt(match.start),
                'request password is assigned without visible hashing',
              );
            }
          }
        }
      case 'fastapi-insecure-jwt-decode':
        for (final _PySource source in sources) {
          for (final RegExpMatch match in cachedRegExp(
            r'\b(?:jwt|jose\.jwt)\.decode\s*\(([^\n]*)',
          ).allMatches(source.code)) {
            final String call = match.requiredGroup(1);
            if (!call.contains('algorithms=') ||
                cachedRegExp(
                  r'verify_signature["'
                  ']?s*:s*False',
                ).hasMatch(call)) {
              yield _Finding(
                source.path,
                source.lineAt(match.start),
                'JWT decode has no explicit verified algorithms allowlist',
              );
            }
          }
        }
      case 'fastapi-permissive-cors':
        for (final _PySource source in sources) {
          for (final RegExpMatch match in cachedRegExp(
            r'''allow_origins\s*=\s*\[\s*["'][*]["']''',
          ).allMatches(source.code)) {
            yield _Finding(
              source.path,
              source.lineAt(match.start),
              'CORS allows every origin',
            );
          }
        }
      case 'fastapi-missing-rate-limit':
        if (routes.length >= 5 &&
            !cachedRegExp(
              r'\b(?:Limiter|RateLimiter|slowapi|rate_limit|throttle)\b',
              caseSensitive: false,
            ).hasMatch(joined)) {
          final _Route first = routes.first;
          yield _Finding(
            first.path,
            first.line,
            '${routes.length} routes have no visible rate-limiting boundary',
            confidence: 'medium',
          );
        }
      case 'fastapi-missing-security-headers':
        if (routes.length >= 3 &&
            !cachedRegExp(
              r'\b(?:SecurityHeadersMiddleware|TrustedHostMiddleware|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security)\b',
            ).hasMatch(joined)) {
          final _Route first = routes.first;
          yield _Finding(
            first.path,
            first.line,
            'FastAPI application has no visible security-header middleware',
            confidence: 'medium',
          );
        }
      case 'fastapi-request-data-logging':
        for (final _Route route in routes) {
          if (cachedRegExp(
            r'\b(?:log|logger)\.(?:debug|info|warning|error)\s*\([^\n]*(?:request\.(?:body|json|headers|query_params)|password|token)',
          ).hasMatch(route.body)) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} logs raw request or credential data',
            );
          }
        }
      case 'fastapi-db-session-not-closed':
        for (final _PySource source in sources) {
          for (final _Function function in source.functions) {
            if (cachedRegExp(
                  r'\b\w+\s*=\s*(?:Session|SessionLocal|AsyncSession)\s*\(',
                ).hasMatch(function.body) &&
                !cachedRegExp(
                  r'\b(?:with|async with)\b|\.close\s*\(|finally\s*:',
                ).hasMatch(function.body)) {
              yield _Finding(
                source.path,
                function.line,
                '${function.name} creates a database session without closing it',
              );
            }
          }
        }
      case 'fastapi-transaction-without-rollback':
        for (final _PySource source in sources) {
          for (final _Function function in source.functions) {
            if (function.body.contains('.commit(') &&
                cachedRegExp(r'\bexcept\b').hasMatch(function.body) &&
                !function.body.contains('.rollback(')) {
              yield _Finding(
                source.path,
                function.line,
                '${function.name} handles a commit failure without rollback',
              );
            }
          }
        }
      case 'fastapi-query-in-loop':
        for (final _PySource source in sources) {
          for (final int line in _queryInLoopLines(source.lines)) {
            yield _Finding(
              source.path,
              line,
              'database query executes inside a loop',
            );
          }
        }
      case 'fastapi-unbounded-query':
        for (final _PySource source in sources) {
          for (final RegExpMatch match in cachedRegExp(
            r'\.(?:query\([^\n]+\)|execute\(\s*select\([^\n]+\))[^\n]*(?:\.all\s*\(\)|\.scalars\s*\(\)\.all\s*\(\))',
          ).allMatches(source.code)) {
            final String call = match.group(0)!;
            if (!cachedRegExp(r'\.(?:limit|offset)\s*\(').hasMatch(call)) {
              yield _Finding(
                source.path,
                source.lineAt(match.start),
                'query materializes an unrestricted result set',
              );
            }
          }
        }
      case 'fastapi-background-task-heavy-work':
        for (final _Route route in routes) {
          for (final RegExpMatch match in cachedRegExp(
            r'background_tasks\.add_task\s*\(\s*([A-Za-z_]\w*)',
          ).allMatches(route.body)) {
            if (cachedRegExp(
              r'(?:generate|render|resize|convert|train|export|process_(?:video|image|report)|rebuild)',
              caseSensitive: false,
            ).hasMatch(match.requiredGroup(1))) {
              yield _Finding(
                route.path,
                route.line,
                'BackgroundTasks schedules likely heavy work `${match.requiredGroup(1)}`',
                confidence: 'medium',
              );
            }
          }
        }
      case 'fastapi-global-mutable-cache':
        for (final _PySource source in sources) {
          for (final RegExpMatch match in cachedRegExp(
            r'^(\w*(?:cache|store)\w*)\s*(?::[^=]+)?=\s*(?:\{\}|dict\s*\(\)|\[\])',
            caseSensitive: false,
            multiLine: true,
          ).allMatches(source.code)) {
            yield _Finding(
              source.path,
              source.lineAt(match.start),
              'module-level mutable cache `${match.group(1)}` is process-local',
            );
          }
        }
      case 'fastapi-route-domain-sprawl':
        final Map<String, List<_Route>> byFile = <String, List<_Route>>{};
        for (final _Route route in routes) {
          byFile.putIfAbsent(route.path, () => <_Route>[]).add(route);
        }
        for (final List<_Route> fileRoutes in byFile.values) {
          final Set<String> domains = fileRoutes
              .map(
                (route) =>
                    route.url
                        .split('/')
                        .where(
                          (part) => part.isNotEmpty && !part.startsWith('{'),
                        )
                        .firstOrNull ??
                    '',
              )
              .where((part) => part.isNotEmpty)
              .toSet();
          if (domains.length >= 3 && fileRoutes.length >= 6) {
            yield _Finding(
              fileRoutes.first.path,
              fileRoutes.first.line,
              'route module owns ${domains.length} unrelated top-level domains: ${domains.join(', ')}',
              confidence: 'medium',
            );
          }
        }
      case 'fastapi-settings-bypass':
        final bool settingsEstablished = cachedRegExp(
          r'\b(?:BaseSettings|SettingsConfigDict|class\s+Settings)\b',
        ).hasMatch(joined);
        if (settingsEstablished) {
          for (final _Route route in routes) {
            if (cachedRegExp(
              r'\b(?:os\.getenv|os\.environ\[)',
            ).hasMatch(route.body)) {
              yield _Finding(
                route.path,
                route.line,
                '${route.method.toUpperCase()} ${route.url} reads environment variables directly',
              );
            }
          }
        }
      case 'fastapi-missing-error-response-docs':
        for (final _Route route in routes) {
          if (route.body.contains('HTTPException(') &&
              !route.decorator.contains('responses=')) {
            yield _Finding(
              route.path,
              route.line,
              '${route.method.toUpperCase()} ${route.url} raises HTTPException without documented responses',
            );
          }
        }
      case 'fastapi-route-without-integration-test':
        if (context.config.changedBase.isEmpty ||
            context.changedPaths.isEmpty) {
          return;
        }
        final List<String> changedTests = context.changedPaths
            .where(
              (path) =>
                  cachedRegExp(r'(^|/)(?:test|tests)(/|$)').hasMatch(path) &&
                  cachedRegExp(
                    r'(?:api|integration|route|endpoint|client)',
                  ).hasMatch(path.toLowerCase()),
            )
            .toList();
        for (final _Route route in routes.where(
          (route) => context.changedPaths.contains(route.path),
        )) {
          final Set<String> concepts = route.url
              .split('/')
              .where((part) => part.length >= 3 && !part.startsWith('{'))
              .toSet();
          if (!changedTests.any(
            (test) => concepts.any(test.toLowerCase().contains),
          )) {
            yield _Finding(
              route.path,
              route.line,
              'changed ${route.method.toUpperCase()} ${route.url} has no related changed API test',
              confidence: 'medium',
            );
          }
        }
    }
  }
}

Iterable<int> _queryInLoopLines(List<String> lines) sync* {
  final RegExp loop = cachedRegExp(r'^\s*for\s+[^:]+:\s*$');
  final RegExp query = cachedRegExp(r'^(?:\w+\.)?(?:execute|query|get)\s*\(');
  for (var index = 0; index < lines.length; index++) {
    final String header = lines[index];
    if (!loop.hasMatch(header)) continue;
    final int loopIndent = header.length - header.trimLeft().length;
    final int stop = (index + 10).clamp(0, lines.length);
    for (var candidate = index + 1; candidate < stop; candidate++) {
      final String raw = lines[candidate];
      final String trimmed = raw.trim();
      if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
      final int indent = raw.length - raw.trimLeft().length;
      if (indent <= loopIndent) break;
      if (query.hasMatch(trimmed)) {
        yield candidate + 1;
        break;
      }
    }
  }
}

final class _PySource {
  _PySource(this.path, this.raw) : lines = raw.split('\n'), code = raw {
    functions = _functions(this);
  }
  final String path;
  final String raw;
  final List<String> lines;
  final String code;
  late final List<_Function> functions;
  int lineAt(int offset) =>
      '\n'.allMatches(code.substring(0, offset)).length + 1;
  String around(int offset) => code.substring(
    (offset - 180).clamp(0, code.length),
    (offset + 180).clamp(0, code.length),
  );
}

final class _Function {
  const _Function(this.name, this.signature, this.body, this.line);
  final String name;
  final String signature;
  final String body;
  final int line;
}

List<_Function> _functions(_PySource source) {
  final List<_Function> result = <_Function>[];
  final RegExp declaration = cachedRegExp(
    r'^(async\s+)?def\s+([A-Za-z_]\w*)\s*\([^\n]*\)(?:\s*->\s*[^:]+)?\s*:',
    multiLine: true,
  );
  final List<RegExpMatch> matches = declaration
      .allMatches(source.code)
      .toList();
  for (var index = 0; index < matches.length; index++) {
    final RegExpMatch match = matches[index];
    final int startLine = source.lineAt(match.start);
    final int indent =
        source.lines[startLine - 1].length -
        source.lines[startLine - 1].trimLeft().length;
    var endLine = source.lines.length;
    for (var line = startLine; line < source.lines.length; line++) {
      final String raw = source.lines[line];
      if (raw.trim().isEmpty) continue;
      final int nextIndent = raw.length - raw.trimLeft().length;
      if (nextIndent <= indent && !raw.trimLeft().startsWith('@')) {
        endLine = line;
        break;
      }
    }
    result.add(
      _Function(
        match.group(2)!,
        match.group(0)!,
        source.lines.sublist(startLine - 1, endLine).join('\n'),
        startLine,
      ),
    );
  }
  return result;
}

Iterable<_Route> _routes(_PySource source) sync* {
  final RegExp decorator = cachedRegExp(
    r'''^\s*@(?:\w+\.)?(get|post|put|patch|delete)\s*\(\s*(["'])([^"']+)\2([^\n]*)\)\s*$''',
    multiLine: true,
  );
  for (final RegExpMatch match in decorator.allMatches(source.code)) {
    final _Function? function = source.functions.cast<_Function?>().firstWhere(
      (function) =>
          function != null &&
          source.code.indexOf(function.signature, match.end) >= 0 &&
          source.code.indexOf(function.signature, match.end) - match.end < 500,
      orElse: () => null,
    );
    if (function == null) continue;
    yield _Route(
      path: source.path,
      line: source.lineAt(match.start),
      method: match.group(1)!,
      url: match.group(3)!,
      decorator: match.group(0)!,
      signature: function.signature,
      body: function.body,
    );
  }
}
