import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/generic/generated_code_risks.dart';
import 'package:test/test.dart';

void main() {
  const AnalysisConfig config = AnalysisConfig(root: '.');

  test('reports only repository-relative comment density outliers', () {
    final Map<String, String> sources = <String, String>{
      for (var file = 0; file < 4; file++)
        'lib/ordinary_$file.dart': List<String>.generate(
          24,
          (int line) => 'final value$line = $line;',
        ).join('\n'),
      'lib/narrated.dart': <String>[
        for (var line = 0; line < 16; line++) '// explanation number $line',
        for (var line = 0; line < 8; line++) 'final value$line = $line;',
      ].join('\n'),
    };

    final List<Finding> findings = ExcessiveCommentDensityRule()
        .analyze(
          RuleContext(config: config, sources: sources, language: 'repository'),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/narrated.dart');
    expect(findings.single.message, contains('repository median 0%'));
  });

  test('includes documentation comments in source density', () {
    final Map<String, String> sources = <String, String>{
      for (var file = 0; file < 4; file++)
        'lib/ordinary_$file.dart': List<String>.generate(
          24,
          (int line) => 'final value$line = $line;',
        ).join('\n'),
      'lib/documented.dart': <String>[
        for (var line = 0; line < 8; line++) '/// API field $line',
        for (var line = 0; line < 56; line++) 'final value$line = $line;',
      ].join('\n'),
    };

    final List<Finding> findings = ExcessiveCommentDensityRule()
        .analyze(
          RuleContext(config: config, sources: sources, language: 'repository'),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/documented.dart');
  });

  test('reports first-person implementation narration but not rationale', () {
    const RuleContext context = RuleContext(
      config: config,
      sources: <String, String>{
        'lib/source.dart': '''// First, we load the cache.
loadCache();
// Keep this order because the server signs canonical bytes.
signPayload();
/// Next, we describe the public API.
void api() {}
''',
        'test/source_test.dart': '// Now we invoke the subject.\ninvoke();',
      },
      language: 'repository',
    );

    final List<Finding> findings = NarratingImplementationCommentRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });

  test(
    'reports narrow adjacent restatements and preserves intent comments',
    () {
      const RuleContext context = RuleContext(
        config: config,
        sources: <String, String>{
          'lib/source.dart': '''// Return result.
return result;
// Increment count
count++;
// Set timeout
this.timeout = timeout;
// Retry because the endpoint is eventually consistent.
retry();
/// Returns the public result.
Object result() => value;
''',
        },
        language: 'repository',
      );

      final List<Finding> findings = TrivialCommentRestatementRule()
          .analyze(context)
          .toList();

      expect(findings.map((Finding finding) => finding.line), <int>[1, 3, 5]);
    },
  );

  test('reports only unchanged single-method Dart delegation', () {
    const RuleContext context = RuleContext(
      config: config,
      sources: <String, String>{
        'lib/pass_through.dart': '''class UserService {
  final UserRepository repository;
  UserService(this.repository);
  Future<User> getUser(String id) => repository.getUser(id);
}
''',
        'lib/policy.dart': '''class UserPolicy {
  final UserRepository repository;
  UserPolicy(this.repository);
  Future<User> getUser(String id) => repository.getUser(validate(id));
}
''',
        'lib/multi.dart': '''class UserCache {
  final UserRepository repository;
  UserCache(this.repository);
  Future<User> getUser(String id) => repository.getUser(id);
  void clear() => repository.clear();
}
''',
      },
      language: 'repository',
    );

    final List<Finding> findings = SingleMethodDelegatingClassRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/pass_through.dart');
    expect(findings.single.message, contains('UserService'));
  });

  test('reports repeated substantial schemas across production files', () {
    const RuleContext context = RuleContext(
      config: config,
      sources: <String, String>{
        'lib/request.dart': '''final request = {
  'id': id,
  'name': name,
  'email': email,
  'role': role,
  'active': active,
};''',
        'lib/response.dart': '''final response = {
  "active": value.active,
  "role": value.role,
  "email": value.email,
  "name": value.name,
  "id": value.id,
};''',
        'test/request_test.dart': '''final fixture = {
  'id': 1, 'name': 'a', 'email': 'a@b.c', 'role': 'user', 'active': true,
};''',
        'lib/small.dart': "final value = {'id': id, 'name': name};",
      },
      language: 'repository',
    );

    final List<Finding> findings = ParallelSchemaDefinitionRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/request.dart');
    expect(findings.single.relatedFiles, <String>['lib/response.dart:1']);
  });

  test('does not equate schemas with different key sets', () {
    const RuleContext context = RuleContext(
      config: config,
      sources: <String, String>{
        'lib/first.dart':
            "{'id': 1, 'name': 2, 'email': 3, 'role': 4, 'active': 5}",
        'lib/second.dart':
            "{'id': 1, 'name': 2, 'email': 3, 'role': 4, 'created': 5}",
      },
      language: 'repository',
    );

    expect(ParallelSchemaDefinitionRule().analyze(context), isEmpty);
  });
}
