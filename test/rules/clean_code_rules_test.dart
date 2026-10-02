import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/generic/clean_code_rules.dart';
import 'package:test/test.dart';

void main() {
  RuleContext context(
    Map<String, String> sources, {
    AnalysisConfig config = const AnalysisConfig(root: '.'),
    Set<String> changedPaths = const <String>{},
    Map<String, String> baseSources = const <String, String>{},
  }) => RuleContext(
    config: config,
    sources: sources,
    language: 'repository',
    changedPaths: changedPaths,
    baseSources: baseSources,
  );

  test('reports public mutable state but accepts hidden and final fields', () {
    final List<Finding> findings = PublicMutableStateRule()
        .analyze(
          context(<String, String>{
            'lib/account.dart': '''
class Account {
  int balance = 0;
  final String id = 'stable';
  int _cached = 0;
}
''',
            'lib/scanner.dart': '''
class _Scanner {
  int offset = 0;
}
''',
            'src/User.java': '''
class User {
  public String name;
  public final String id = "stable";
}
''',
            'src/session.ts': '''
class Session {
  token: string = '';
  readonly id: string = '';
  private secret: string = '';
}
''',
            'src/github.ts': '''
class GitHubError {
  constructor(
    kind: string,
    options: { message?: string } = {}
  ) {}
}

function applyStyle(
  source: string,
  markMatches = false
) {}
''',
          }),
        )
        .toList();

    expect(
      findings.map((finding) => finding.message).join('\n'),
      allOf(contains('balance'), contains('name'), contains('token')),
    );
    expect(findings, hasLength(3));
  });

  test('reports disabled source comments but accepts explanatory prose', () {
    final List<Finding> findings = CommentedOutCodeRule()
        .analyze(
          context(const <String, String>{
            'lib/service.dart': '''
// final result = legacy.load();
// Keep this ordering because the server requires it.
// Example: call load before save.
''',
          }),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });

  test('reports exposed placeholder names but accepts tiny locals', () {
    final List<Finding> findings = PlaceholderIdentifierRule()
        .analyze(
          context(const <String, String>{
            'src/api.ts':
                'export class Foo {}\nfunction small() { const obj = make(); }',
          }),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('Foo'));
  });

  test('reports functions coordinating three unrelated boundaries', () {
    final List<Finding> findings = MixedBoundaryResponsibilityRule()
        .analyze(
          context(const <String, String>{
            'lib/registration.dart': '''
void registerUser() {
  validate();
  database.save(user);
  client.post(request);
  File('audit').writeAsString(event);
  normalize();
  updateCache();
  notifyUser();
  finish();
}
''',
          }),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(
      findings.single.message,
      contains('persistence, network, filesystem'),
    );
  });

  test('reports repeated policy literals across production files', () {
    final List<Finding> findings = RepeatedPolicyLiteralRule()
        .analyze(
          context(const <String, String>{
            'lib/upload.dart': 'if (size > 30) reject();',
            'lib/download.dart': 'if (size >= 30) stop();',
            'test/upload_test.dart': 'expect(limit, 30);',
          }),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('`30`'));
    expect(findings.single.relatedFiles, <String>['lib/download.dart']);
  });

  test('ignores coincidental collection-length thresholds', () {
    final List<Finding> findings = RepeatedPolicyLiteralRule()
        .analyze(
          context(const <String, String>{
            'lib/parser.dart': '''
if (fields.length >= 4) parseHeader();
if (fields.length >= 4) parseRecord();
if (fields.length >= 4) parseFooter();
''',
            'lib/schema.dart': 'if (fields.length >= 4) validateSchema();',
          }),
        )
        .toList();

    expect(findings, isEmpty);
  });
  test('ignores bare count thresholds across unrelated domains', () {
    final List<Finding> findings = RepeatedPolicyLiteralRule()
        .analyze(
          context(const <String, String>{
            'lib/parser.dart': 'if (count >= 3) parseHeader();',
            'lib/schema.dart': 'if (count >= 3) validateSchema();',
          }),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test(
    'ignores parser character codes and unrelated numbers on comparisons',
    () {
      final List<Finding> findings = RepeatedPolicyLiteralRule()
          .analyze(
            context(const <String, String>{
              'lib/a.dart':
                  'if (codeUnit == 123) parse(47); if (token == 123) parse(47);',
              'lib/b.dart': 'if (character == 123) parse(47);',
            }),
          )
          .toList();

      expect(findings, isEmpty);
    },
  );

  test('does not merge unrelated policy concepts sharing a number', () {
    final List<Finding> findings = RepeatedPolicyLiteralRule()
        .analyze(
          context(const <String, String>{
            'lib/size.dart': 'if (size > 30) reject();',
            'lib/retries.dart': 'if (attempts >= 30) stop();',
            'lib/layout.dart': 'if (width > 30) wrap();',
          }),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test('reports a lone file naming outlier among peers', () {
    final Map<String, String> sources = <String, String>{
      for (final String name in <String>[
        'user_service.dart',
        'order_service.dart',
        'mail_service.dart',
        'audit_service.dart',
        'cache_service.dart',
      ])
        'lib/services/$name': '',
      'lib/services/PaymentService.dart': '',
    };

    final List<Finding> findings = InconsistentPeerFileNamingRule()
        .analyze(context(sources))
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/services/PaymentService.dart');
  });
  test('accepts conventional role-based peer file names', () {
    final Map<String, String> sources = <String, String>{
      for (final String name in <String>[
        'user_service.dart',
        'order_service.dart',
        'mail_service.dart',
        'audit_service.dart',
        'cache_service.dart',
      ])
        'lib/services/$name': '',
      'lib/services/rules.dart': '',
    };

    expect(InconsistentPeerFileNamingRule().analyze(context(sources)), isEmpty);
  });

  test('requires a concept-related changed test for a changed public API', () {
    const Map<String, String> sources = <String, String>{
      'lib/user_service.dart': 'class UserService { void save() {} }',
    };
    const AnalysisConfig config = AnalysisConfig(
      root: '.',
      changedBase: 'HEAD',
    );

    expect(
      ChangedPublicApiWithoutTestRule().analyze(
        context(
          sources,
          config: config,
          changedPaths: const <String>{'lib/user_service.dart'},
        ),
      ),
      hasLength(1),
    );
    expect(
      ChangedPublicApiWithoutTestRule().analyze(
        context(
          sources,
          config: config,
          changedPaths: const <String>{
            'lib/user_service.dart',
            'test/user_service_test.dart',
          },
        ),
      ),
      isEmpty,
    );
  });

  test('reports substantial changed-function complexity growth only', () {
    const String before = 'void decide() { act(); }';
    const String after = '''
void decide() {
  if (a) act();
  if (b) act();
  if (c) act();
  if (d) act();
  if (e) act();
  if (f) act();
  if (g) act();
  if (h) act();
  if (i) act();
}
''';
    final List<Finding> findings = ChangedComplexityRegressionRule()
        .analyze(
          context(
            const <String, String>{'lib/decision.dart': after},
            config: const AnalysisConfig(root: '.', changedBase: 'HEAD'),
            baseSources: const <String, String>{'lib/decision.dart': before},
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('from 1 to 10'));
  });
}
