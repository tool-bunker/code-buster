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
      RepositoryDefaults.classify('packages/isar_test/lib/helper.dart'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('packages/latest/lib/helper.dart'),
      'production',
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
      RepositoryDefaults.classify('ScreenToGif.Test/Facts/Upload.cs'),
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
    expect(RepositoryDefaults.classify('internal/testenv/command.go'), 'test');
    expect(RepositoryDefaults.classify(r'internal\testenv\command.go'), 'test');
    expect(RepositoryDefaults.classify('lib/cloud_env_test.dart'), 'test');
    expect(RepositoryDefaults.classify(r'lib\cloud_env_test.dart'), 'test');
    expect(
      RepositoryDefaults.classify('lib/cloud_env_testing.dart'),
      'production',
    );
    expect(
      RepositoryDefaults.classify('internal/testenvironment/runner.go'),
      'production',
    );
    expect(
      RepositoryDefaults.classify('cli/commands/build/android.dart'),
      'production',
    );
    expect(
      RepositoryDefaults.classify(r'cli\commands\build\android.dart'),
      'production',
    );
    expect(
      RepositoryDefaults.classify('packages/app/build/app.dart'),
      'generated',
    );
    expect(RepositoryDefaults.classify('docs_src/tutorial/app.py'), 'example');
    expect(RepositoryDefaults.classify('tests-unit/api/test_api.py'), 'test');
    expect(
      RepositoryDefaults.classify('script_examples/basic_api.py'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('src/script_exampleservice/service.py'),
      'production',
    );
    expect(RepositoryDefaults.classify('evals/case.ts'), 'example');
    expect(
      RepositoryDefaults.classify('src/xdocs-examples/resources/Example.java'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('src/order-examples/Example.java'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('src/exampleservice/Service.java'),
      'production',
    );
    expect(
      RepositoryDefaults.classify('crates/globset/benches/bench.rs'),
      'example',
    );
    expect(
      RepositoryDefaults.classify('crates/searcher/src/testutil.rs'),
      'test',
    );
    expect(
      RepositoryDefaults.classify('test_suite/no_std/src/main.rs'),
      'test',
    );
    expect(
      RepositoryDefaults.classify(
        'templates/project/lib/src/{{#auth}}endpoint.dart',
      ),
      'example',
    );
    expect(
      RepositoryDefaults.classify('lib/templates/renderer.dart'),
      'production',
    );
    expect(
      RepositoryDefaults.classify('packages/next/src/compiled/react.js'),
      'vendored',
    );
    expect(
      RepositoryDefaults.classify(
        'tools/serverpod_cli/lib/src/vendored/semver.dart',
      ),
      'vendored',
    );
    expect(
      RepositoryDefaults.classify(
        r'packages\plugin\rust_builder\cargokit\build_tool\lib\main.dart',
      ),
      'vendored',
    );
    expect(
      RepositoryDefaults.classify('lib/cargokit_adapter.dart'),
      'production',
    );
    expect(
      RepositoryDefaults.classify(
        'module/src/javaRestTest/java/RestSqlTestCase.java',
      ),
      'test',
    );
    expect(RepositoryDefaults.classify('demo/lib/main.dart'), 'example');
    expect(RepositoryDefaults.classify('src/client.backup.ts'), 'generated');
    expect(RepositoryDefaults.classify(r'src\client.BACKUP.TSX'), 'generated');
    expect(RepositoryDefaults.classify('src/backup.ts'), 'production');
    expect(
      RepositoryDefaults.infer('.').ignores,
      containsAll(<String>[
        '**/*_unittests.cc',
        '**/*_test.cpp',
        '**/*.Test/**',
        '**/test.ts',
        '**/*-examples/**',
        '**/*_test/**',
        '**/*_test.dart',
        '**/cargokit/**',
      ]),
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
    expect(defaults.frameworks, <String>{'flutter'});
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

  test('detects FastAPI from Python dependency manifests', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-fastapi-');
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/services/api/pyproject.toml')
      ..createSync(recursive: true)
      ..writeAsStringSync('dependencies = ["fastapi>=0.115", "uvicorn"]');

    final RepositoryDefaults defaults = RepositoryDefaults.infer(root.path);

    expect(defaults.profiles, contains('fastapi'));
    expect(defaults.frameworks, contains('fastapi'));
  });

  test('detects Svelte and PixiJS from JavaScript manifests', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-web-frameworks-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/package.json').writeAsStringSync(
      '{"dependencies":{"svelte":"^5.0.0","pixi.js":"^8.0.0"}}',
    );

    final RepositoryDefaults defaults = RepositoryDefaults.infer(root.path);

    expect(defaults.profiles, containsAll(<String>['svelte', 'pixijs']));
    expect(defaults.frameworks, containsAll(<String>{'svelte', 'pixijs'}));
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
    expect(defaults.frameworks, <String>{'flutter', 'react'});
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
