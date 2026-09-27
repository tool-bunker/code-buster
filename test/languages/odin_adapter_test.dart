import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/languages/odin/odin_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('resolves relative Odin package imports and ignores collections', () {
    final DependencyGraph graph = OdinAdapter().buildGraph(<String, String>{
      'app/main.odin': '''package main
import "core:fmt"
import math "../math"
import _ "../support"
''',
      'math/vector.odin': 'package math',
      'math/matrix.odin': 'package math',
      'support/init.odin': 'package support',
    });

    expect(graph.dependenciesOf('app/main.odin'), <String>[
      'math/matrix.odin',
      'math/vector.odin',
      'support/init.odin',
    ]);
    expect(graph.dependenciesOf('math/vector.odin'), isEmpty);
  });

  test('extracts named Odin procedures with brace-delimited bodies', () {
    final List<FunctionSource> functions = OdinAdapter()
        .functions(<String, String>{
          'main.odin': '''package main

main :: proc() {
    text := `not_a_proc :: proc() {}`
    if true {
        run()
    }
}

@(private)
helper :: proc "c" (value: int) -> int {
    /* nested { comment /* proc */ } */
    return value + 1
}
''',
        });

    expect(functions.map((FunctionSource function) => function.name), <String>[
      'main',
      'helper',
    ]);
    expect(functions.map((FunctionSource function) => function.line), <int>[
      3,
      11,
    ]);
    expect(functions.first.source, contains('if true'));
    expect(functions.last.source, contains('return value + 1'));
  });

  test('registers Odin discovery and plugin analysis', () {
    final LanguageDefinition definition = LanguageRegistry.dartFirst().lookup(
      'odinlang',
    )!;
    expect(definition.id, 'odin');
    expect(definition.extensions, <String>{'.odin'});

    final LanguageAnalysis analysis = LanguagePluginRegistry.standard()
        .require('odin')
        .analyze(<String, String>{
          'main.odin': 'package main\nmain :: proc() {}',
        }, const AnalysisConfig(root: '.'));

    expect(analysis.functions.single.name, 'main');
    expect(analysis.graph.nodes, <String>{'main.odin'});
  });
}
