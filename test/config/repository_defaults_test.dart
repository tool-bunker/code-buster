import 'dart:io';

import 'package:code_buster/src/config/repository_defaults.dart';
import 'package:test/test.dart';

void main() {
  test('classifies integration fixes and native unit-test conventions', () {
    expect(
      RepositoryDefaults.classify('dev/integration_tests/app/lib/main.dart'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('packages/widget/test_fixes/fix.dart'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('packages/shared/test_integration/load.dart'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('packages/auth/storybook/main.dart'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('example_flutter_app/lib/main.dart'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('src/Product.Tests.Benchmarks/Program.cs'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('src/Product.Benchmarks/Program.cs'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('pkg/cfg/testcases/unreachable_ast.dart'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('packages/codemod/__testfixtures__/input.js'),
      'test',
    );
    expect(RepositoryDefaults.classify('docs_src/tutorial/app.py'), 'example');
    expect(RepositoryDefaults.classify('evals/case.ts'), 'example');
    expect(
      RepositoryDefaults.classify('packages/next/src/compiled/react.js'),
      'vendored',
    );
    expect(
      RepositoryDefaults.classify(
        'module/src/javaRestTest/java/RestSqlTestCase.java',
      ),
      'test',
    );
    expect(RepositoryDefaults.classify('demo/lib/main.dart'), 'example');
    expect(
      RepositoryDefaults.infer('.').ignores,
      containsAll(<String>['**/*_unittests.cc', '**/*_test.cpp']),
    );
  });

  test('tolerates malformed UTF-8 in fixture manifests', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-malformed-manifest-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/fixtures/package.json')
      ..createSync(recursive: true)
      ..writeAsBytesSync(<int>[0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
    File('${root.path}/app/package.json')
      ..createSync(recursive: true)
      ..writeAsStringSync('{"dependencies":{"react":"latest"}}');

    expect(RepositoryDefaults.infer(root.path).profiles, contains('react'));
  });

  test('detects Flutter SDK auxiliary repositories', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-flutter-sdk-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/bin/flutter').createSync(recursive: true);
    File('${root.path}/packages/flutter/pubspec.yaml')
      ..createSync(recursive: true)
      ..writeAsStringSync('dependencies:\n  flutter:\n    sdk: flutter\n');

    final RepositoryDefaults defaults = RepositoryDefaults.infer(root.path);
    expect(defaults.profiles, contains('flutter-sdk'));
    expect(
      defaults.ignores,
      containsAll(<String>[
        'dev/devicelab/**',
        'dev/integration_tests/**',
        'engine/src/flutter/testing/**',
      ]),
    );
  });

  test('detects PostgreSQL regression SQL as test input', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-postgresql-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/configure.ac').createSync(recursive: true);
    Directory('${root.path}/src/backend').createSync(recursive: true);
    Directory('${root.path}/contrib/amcheck/sql').createSync(recursive: true);

    final RepositoryDefaults defaults = RepositoryDefaults.infer(root.path);

    expect(defaults.profiles, contains('postgresql'));
    expect(defaults.ignores, contains('contrib/*/sql/**'));
  });

  test('ignores generated migration definition snapshots generically', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-migration-definitions-',
    );
    addTearDown(() => root.deleteSync(recursive: true));

    final RepositoryDefaults defaults = RepositoryDefaults.infer(root.path);
    expect(defaults.ignores, contains('**/migrations/**/definition.sql'));
  });

  test('detects nested framework manifests and classifies source roles', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-profiles-');
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/packages/app/pubspec.yaml')
      ..createSync(recursive: true)
      ..writeAsStringSync('dependencies:\n  flutter:\n    sdk: flutter\n');
    File('${root.path}/web/package.json')
      ..createSync(recursive: true)
      ..writeAsStringSync('{"dependencies":{"react":"latest"}}');
    File('${root.path}/server/App.csproj')
      ..createSync(recursive: true)
      ..writeAsStringSync('<Project />');

    final RepositoryDefaults defaults = RepositoryDefaults.infer(root.path);
    expect(defaults.profiles, <String>['dotnet', 'flutter', 'react']);
    expect(RepositoryDefaults.classify('lib/main.dart'), 'production');
    expect(RepositoryDefaults.classify('test/main_test.dart'), 'test');
    expect(RepositoryDefaults.classify('examples/demo/main.dart'), 'example');
    expect(RepositoryDefaults.classify('vendor/library.js'), 'vendored');
    expect(RepositoryDefaults.classify('src/widget_test.go'), 'test');
    expect(RepositoryDefaults.classify('src/widget.spec.ts'), 'test');
    expect(
      RepositoryDefaults.classify('module/src/it/java/AppIT.java'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('module/src/testFixtures/java/Data.java'),
      'test',
    );
    expect(RepositoryDefaults.classify('api/service.pb.go'), 'generated');
    expect(
      RepositoryDefaults.classify(
        'protocol/generated/dart/lib/denial.wire_generated.dart',
      ),
      'generated',
    );
    expect(
      RepositoryDefaults.matches('tools/release/publish.dart', 'tools/**'),
      isTrue,
    );
  });
}
