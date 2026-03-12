import 'package:analyzer/dart/ast/ast.dart';
import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  test('reports cycles between Dart packages instead of package files', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('dart')
        .analyze(<String, String>{
          'packages/alpha/lib/a.dart': "import 'package:beta/b.dart';",
          'packages/beta/lib/b.dart': "import 'package:alpha/a.dart';",
        }, AnalysisConfig(root: '.'))
        .findings;

    expect(findings, hasLength(1));
    expect(findings.single.code, 'dart-package-cycle');
    expect(findings.single.message, contains('alpha -> beta -> alpha'));
  });

  test('normalizes final formal parameters for analyzer compatibility', () {
    final DartParseResult parsed = DartSourceParser().parseDetailed(
      sourceFixture(
        'dart/normalizes_final_formal_parameters_for_analyzer_compatibility/source.dart',
      ),
    );

    expect(parsed.diagnostics, isEmpty);
  });

  test('extracts Dart functions, methods, and constructors from parsed ASTs', () {
    final DartSourceParser parser = DartSourceParser();
    final CompilationUnit unit = parser.parseCompilationUnit(
      sourceFixture(
        'dart/extracts_dart_functions_methods_and_constructors_from_parsed_asts/source.dart',
      ),
    );

    final List<FunctionSource> functions = parser.functionsParsed(
      <String, CompilationUnit>{'lib/main.dart': unit},
    );

    expect(functions.map((FunctionSource function) => function.name), <String>[
      'topLevel',
      'Worker.named',
      'run',
    ]);
    expect(functions.first.line, 1);
    expect(functions.last.source, contains('while (ready)'));
  });

  test('parses and extracts Dart 3.13 primary constructors', () {
    final DartSourceParser parser = DartSourceParser();
    final DartParseResult parsed = parser.parseDetailed(
      sourceFixture(
        'dart/parses_and_extracts_dart_3_13_primary_constructors/source.dart',
      ),
    );

    expect(parsed.diagnostics, isEmpty);
    final DartUnit summary = parser.summarize(parsed.unit);
    expect(summary.publicDeclarations, <String>['Counter', 'Origin', 'Point']);
    final List<FunctionSource> functions = parser.functionsParsed(
      <String, CompilationUnit>{'lib/models.dart': parsed.unit},
    );
    expect(functions, hasLength(1));
    expect(functions.single.name, 'Counter');
    expect(functions.single.source, contains('if (value < 0)'));
  });

  test('parses Dart import export directives and public declarations', () {
    final DartUnit unit = DartSourceParser().parse(
      sourceFixture(
        'dart/parses_dart_import_export_directives_and_public_declarations/source.dart',
      ),
    );

    expect(unit.imports, <String>['dart:async', 'service.dart']);
    expect(unit.exports, <String>['models.dart']);
    expect(unit.parts, <String>['generated.dart']);
    expect(unit.publicDeclarations, <String>['Widget', 'answer', 'run']);
  });

  test(
    'resolves local relative package and export directives into graph edges',
    () {
      final DependencyGraph graph =
          DartGraphAdapter(
            root: '/project',
            packageName: 'code_buster',
          ).build(<String, String>{
            'lib/main.dart': sourceFixture(
              'dart/resolves_local_relative_package_and_export_directives_into_graph_edges/main.dart',
            ),
            'lib/service.dart': '',
            'lib/models.dart': '',
            'lib/exported.dart': '',
            'lib/part.dart': 'part of "main.dart";',
          });

      expect(graph.dependenciesOf('lib/main.dart'), <String>[
        'lib/exported.dart',
        'lib/models.dart',
        'lib/part.dart',
        'lib/service.dart',
      ]);
      expect(graph.dependenciesOf('lib/service.dart'), isEmpty);
    },
  );

  test('does not resolve files outside the discovered project graph', () {
    final DependencyGraph graph = DartGraphAdapter(
      root: '/project',
      packageName: 'code_buster',
    ).build(<String, String>{'lib/main.dart': "import '../outside.dart';"});

    expect(graph.dependenciesOf('lib/main.dart'), isEmpty);
  });
}
