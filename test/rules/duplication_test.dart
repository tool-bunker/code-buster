import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/duplication/duplication.dart';
import 'package:test/test.dart';

void main() {
  const DuplicationAnalysis analysis = DuplicationAnalysis();

  test(
    'reports normalized exact duplicate blocks at original source lines',
    () {
      final List<Finding> findings = analysis.exactBlocks(<String, String>{
        'lib/a.dart': '''
void first() {
  // The reported range must retain this ignored source line.
  final value = 1;
  save(value);
  return;
}
''',
        'lib/b.dart': '''
void second() {
  // A different ignored comment must not affect exact matching.
  final   value = 1;
  save(value);
  return;
}
''',
      }, minLines: 3);

      expect(findings, hasLength(1));
      expect(findings.single.path, 'lib/a.dart');
      expect(findings.first.line, 3);
      expect(findings.first.relatedFiles, <String>['lib/b.dart:3-5']);
      expect(findings.first.message, contains('fingerprint='));
    },
  );

  test('does not report duplicated block-comment license headers', () {
    final String license = <String>[
      '/*',
      for (var index = 0; index < 20; index++) ' * license line $index',
      ' */',
      'void unique() {}',
    ].join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'lib/a.dart': license,
      'lib/b.dart': license,
    }, minLines: 15);

    expect(findings, isEmpty);
  });

  test('does not report duplicated Lua long-bracket documentation', () {
    const String documentation = '''
--[=[
shared API contract line one
shared API contract line two
shared API contract line three
shared API contract line four
]=]
''';
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'lib/a.lua': '${documentation}local uniqueA = 1',
      'lib/b.luau': '${documentation}local uniqueB = 2',
    }, minLines: 3);

    expect(findings, isEmpty);
  });

  test('still reports duplicated Lua code after long-bracket comments', () {
    const String first = '''
--[[
shared documentation
shared example
]]
local value = source()
save(value)
return value
''';
    final List<Finding> findings = analysis.exactBlocks(const <String, String>{
      'lib/a.lua': first,
      'lib/b.luau': first,
    }, minLines: 3);

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
    expect(findings.single.relatedFiles, <String>['lib/b.luau:5-7']);
  });

  test('does not report duplicated Python hash-comment license headers', () {
    final String license = List<String>.generate(
      20,
      (int index) => '# license line $index',
    ).join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'tools/a.py': '$license\nunique_a = 1',
      'tools/b.py': '$license\nunique_b = 2',
    }, minLines: 15);

    expect(findings, isEmpty);
  });

  test('does not report duplicated literal data tables as code blocks', () {
    final String words = <String>[
      'const words = <String>[',
      for (var index = 0; index < 20; index++) "  'word$index',",
      '];',
    ].join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'lib/a.dart': words,
      'lib/b.dart': words,
    }, minLines: 10);

    expect(findings, isEmpty);
  });

  test('does not report duplicated numeric data-table rows as code', () {
    final String bytes = <String>[
      'const unsigned char payload[] = {',
      for (var row = 0; row < 12; row++)
        '  0x3d, 0xf4, 0x0e, 0x53, 0x1d, 0xf3, 0xbf, 0xb2,',
      '};',
    ].join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'include/a.h': bytes,
      'include/b.h': bytes,
    }, minLines: 10);

    expect(findings, isEmpty);
  });

  test('does not report repeated numeric tuple rows as duplicate code', () {
    final String vectors = <String>[
      'static const float vectors[][3] = {',
      for (var index = 0; index < 24; index++)
        '  { 0.0f, 0.0f, -1.0f }, /* channel $index */',
      '};',
    ].join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'channels.c': vectors,
    }, minLines: 15);

    expect(findings, isEmpty);
  });

  test('does not report repeated null-sentinel table rows as code', () {
    final String aliases = <String>[
      'static const char *aliases[] = {',
      for (var index = 0; index < 24; index++) '  NULL, /* alias $index */',
      '};',
    ].join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'format.c': aliases,
    }, minLines: 15);

    expect(findings, isEmpty);
  });

  test('does not compare overlapping windows in one repeated table run', () {
    final String vtable = <String>[
      'static void* handlers[] = {',
      ...List<String>.filled(25, '  NotImplemented,'),
      '};',
    ].join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'handlers.c': vtable,
    }, minLines: 15);

    expect(findings, isEmpty);
  });

  test('does not report exhaustive switch-label runs as duplicate code', () {
    final String labels = List<String>.generate(
      16,
      (int index) => '    case 0x${index.toRadixString(16).padLeft(2, '0')}:',
    ).join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'parser-a.cpp':
          '''
int parse_a(int value) {
  switch (value) {
$labels
      return decode_a(value);
  }
}
''',
      'parser-b.cpp':
          '''
int parse_b(int value) {
  switch (value) {
$labels
      return decode_b(value);
  }
}
''',
    }, minLines: 10);

    expect(findings, isEmpty);
  });

  test('does not treat migration history snapshots as source duplication', () {
    final List<Finding> findings = const DuplicationAnalysis()
        .exactBlocks(const <String, String>{
          'a/migrations/001/migration.sql':
              'CREATE TABLE a;\nCREATE INDEX b;\nCOMMIT;',
          'b/migrations/002/migration.sql':
              'CREATE TABLE a;\nCREATE INDEX b;\nCOMMIT;',
        }, minLines: 3);

    expect(findings, isEmpty);
  });

  test('coalesces adjacent windows into one maximal duplicate block', () {
    final String block = List<String>.generate(
      30,
      (int index) => 'final value$index = source$index;',
    ).join('\n');
    final List<Finding> findings = analysis.exactBlocks(<String, String>{
      'lib/a.dart': block,
      'lib/b.dart': block,
    }, minLines: 5);

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('duplicate block of 30 lines'));
    expect(findings.single.relatedFiles, <String>['lib/b.dart:1-30']);
  });

  test('normalizes identifiers and literals but keeps operation names', () {
    final List<String> first = DuplicationAnalysis.structuralTokens(
      'if ready { save(parseJson(readFile(userPath)), 30); return; }',
    );
    final List<String> second = DuplicationAnalysis.structuralTokens(
      'if ready { save(parseJson(readFile(productPath)), 60); return; }',
    );

    expect(
      DuplicationAnalysis.sequenceSimilarity(first, second),
      greaterThan(0.9),
    );
    expect(
      DuplicationAnalysis.sequenceSimilarity(
        DuplicationAnalysis.structuralTokens('if ready { save(value); }'),
        DuplicationAnalysis.structuralTokens(
          'for item in queue { send(item); retry(); }',
        ),
      ),
      lessThan(0.86),
    );
  });

  test(
    'reports structurally similar function fragments in both directions',
    () {
      final List<Finding> findings = analysis
          .nearDuplicateFunctions(const <FunctionSource>[
            FunctionSource(
              path: 'lib/users.dart',
              name: 'loadUser',
              line: 1,
              endLine: 5,
              source: '''
void loadUser() {
  if (ready && enabled) {
    final user = parseJson(readFile(userPath));
    save(user, 30);
    return;
  }
}
''',
            ),
            FunctionSource(
              path: 'lib/products.dart',
              name: 'loadProduct',
              line: 1,
              endLine: 5,
              source: '''
void loadProduct() {
  if (ready && enabled) {
    final product = parseJson(readFile(productPath));
    save(product, 60);
    return;
  }
}
''',
            ),
          ]);

      expect(findings, hasLength(2));
      expect(
        findings.map((Finding finding) => finding.code),
        everyElement('near-duplicate-function'),
      );
      expect(findings.first.relatedFiles.single, 'lib/products.dart:1-5');
    },
  );

  test('finds independent implementations of external contracts', () {
    final List<Finding>
    findings = analysis.parallelContractImplementations(const <FunctionSource>[
      FunctionSource(
        path: 'lib/users_api.dart',
        name: 'loadUsers',
        line: 10,
        endLine: 14,
        source:
            "Future loadUsers() async { final response = await client.get('/users'); return decode(response); }",
      ),
      FunctionSource(
        path: 'lib/accounts_api.dart',
        name: 'fetchAccounts',
        line: 20,
        endLine: 25,
        source:
            "Future fetchAccounts() async { metrics.increment(); return api.get('/users'); }",
      ),
      FunctionSource(
        path: 'lib/user_model.dart',
        name: 'readUser',
        line: 30,
        endLine: 35,
        source:
            "User readUser(map) => User(map['id'], map['name'], map['email']);",
      ),
      FunctionSource(
        path: 'lib/account_model.dart',
        name: 'decodeAccount',
        line: 40,
        endLine: 47,
        source:
            "Account decodeAccount(json) { validate(json); return Account(email: json['email'], id: json['id'], label: json['name']); }",
      ),
      FunctionSource(
        path: 'lib/user_store.dart',
        name: 'findUsers',
        line: 50,
        endLine: 54,
        source: "Future findUsers() => db.query('SELECT id, name FROM users');",
      ),
      FunctionSource(
        path: 'lib/report_store.dart',
        name: 'loadUserReport',
        line: 60,
        endLine: 66,
        source:
            "Future loadUserReport() { audit(); return sql.rawQuery('select email from users'); }",
      ),
      FunctionSource(
        path: 'lib/server_config.dart',
        name: 'serverConfig',
        line: 70,
        endLine: 75,
        source:
            "Config serverConfig() => Config(Platform.environment['HOST'], Platform.environment['PORT']);",
      ),
      FunctionSource(
        path: 'lib/runtime_config.dart',
        name: 'runtimeConfig',
        line: 80,
        endLine: 86,
        source:
            "Config runtimeConfig() { trace(); return Config(Platform.environment['PORT'], Platform.environment['HOST']); }",
      ),
    ]);

    expect(findings, hasLength(4));
    expect(
      findings.map((Finding finding) => finding.code),
      everyElement('parallel-contract-implementation'),
    );
    expect(
      findings.map((Finding finding) => finding.message).join('\n'),
      allOf(
        contains('HTTP GET /users'),
        contains('JSON keys email, id, name'),
        contains('SQL select on users'),
        contains('configuration keys HOST, PORT'),
      ),
    );
    expect(
      findings,
      everyElement(
        predicate<Finding>((finding) {
          return finding.relatedFiles.isNotEmpty &&
              finding.snippet.contains('structural similarity');
        }),
      ),
    );
  });

  test('does not infer a shared contract from weak or local evidence', () {
    final List<Finding> findings = analysis
        .parallelContractImplementations(const <FunctionSource>[
          FunctionSource(
            path: 'lib/a.dart',
            name: 'first',
            line: 1,
            endLine: 1,
            source: "String first(map) => map['id'];",
          ),
          FunctionSource(
            path: 'lib/a.dart',
            name: 'second',
            line: 2,
            endLine: 2,
            source: "String second(json) => json['id'];",
          ),
          FunctionSource(
            path: 'lib/b.dart',
            name: 'third',
            line: 1,
            endLine: 1,
            source: "String third(data) => data['id'];",
          ),
          FunctionSource(
            path: 'lib/messages.dart',
            name: 'suggestion',
            line: 1,
            endLine: 1,
            source: "String suggestion() => 'Review and update code safely';",
          ),
          FunctionSource(
            path: 'lib/help.dart',
            name: 'help',
            line: 1,
            endLine: 1,
            source: "String help() => 'Update code after validation';",
          ),
        ]);

    expect(findings, isEmpty);
  });

  test('reports a compound condition repeated within one file', () {
    final List<Finding> findings = analysis.repeatedConditions(<String, String>{
      'lib/a.dart': '''
if (user.active && user.role == "admin") {}
if (user.active && user.role == "admin") {}
if (user.active && user.role == "admin") {}
''',
    });

    expect(findings, hasLength(1));
    expect(
      findings.first.message,
      'complex condition is repeated in 3 locations',
    );
    expect(findings.first.relatedFiles, <String>[
      'lib/a.dart:2',
      'lib/a.dart:3',
    ]);
  });

  test('does not merge different conditions with the same token shape', () {
    final List<Finding> findings = analysis.repeatedConditions(<String, String>{
      'lib/a.dart': '''
if (cu == carriageReturn || cu == lineFeed) {}
if (cu == rightBrace || cu == rightBracket) {}
if (quote == doubleQuote || quote == singleQuote) {}
''',
    });

    expect(findings, isEmpty);
  });

  test('does not merge structurally similar policies across files', () {
    final List<Finding> findings = analysis.repeatedConditions(<String, String>{
      'lib/a.dart': 'if (user.active && user.role == "admin") {}',
      'lib/b.dart': 'if (account.active && account.role == "admin") {}',
      'lib/c.dart': 'if (member.active && member.role == "admin") {}',
    });

    expect(findings, isEmpty);
  });
}
