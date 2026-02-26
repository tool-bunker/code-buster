import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  final DependencyGraph graph = DependencyGraph(<String, Iterable<String>>{
    'lib/main.dart': <String>['lib/service.dart'],
    'lib/service.dart': <String>['lib/model.dart'],
    'lib/model.dart': <String>[],
    'lib/orphan.dart': <String>[],
  });
  final GraphAnalysis analysis = GraphAnalysis(graph);

  test('selects configured roots and computes reachability', () {
    expect(analysis.defaultRoots(<String>['lib/main.dart']), <String>{
      'lib/main.dart',
    });
    expect(analysis.reachableFrom(<String>['lib/main.dart']), <String>{
      'lib/main.dart',
      'lib/service.dart',
      'lib/model.dart',
    });
  });

  test('returns a stable shortest dependency path', () {
    expect(analysis.shortestPath('lib/main.dart', 'lib/model.dart'), <String>[
      'lib/main.dart',
      'lib/service.dart',
      'lib/model.dart',
    ]);
    expect(analysis.shortestPath('lib/model.dart', 'lib/main.dart'), isEmpty);
  });

  test('falls back to main then the first stable graph node', () {
    expect(analysis.defaultRoots(const <String>[]), <String>{'lib/main.dart'});

    final GraphAnalysis noMain = GraphAnalysis(
      DependencyGraph(<String, Iterable<String>>{
        'z.dart': <String>[],
        'a.dart': <String>[],
      }),
    );
    expect(noMain.defaultRoots(const <String>[]), <String>{'a.dart'});
  });

  test('discards dependency self-edges', () {
    final DependencyGraph graph = DependencyGraph(<String, Iterable<String>>{
      'lib/a.py': <String>['lib/a.py'],
    });

    expect(graph.dependenciesOf('lib/a.py'), isEmpty);
    expect(GraphAnalysis(graph).cycleFindings(), isEmpty);
  });

  test('emits every cycle once with stable detail', () {
    final GraphAnalysis cycles = GraphAnalysis(
      DependencyGraph(<String, Iterable<String>>{
        'lib/a.dart': <String>['lib/b.dart'],
        'lib/b.dart': <String>['lib/c.dart'],
        'lib/c.dart': <String>['lib/a.dart'],
      }),
    );

    expect(cycles.cycles(), <List<String>>[
      <String>['lib/a.dart', 'lib/b.dart', 'lib/c.dart', 'lib/a.dart'],
    ]);
    final Finding finding = cycles.cycleFindings().single;
    expect(finding.severity, RuleSeverity.warn);
    expect(finding.confidence, 'medium');
    expect(
      finding.message,
      'circular dependency: a.dart -> b.dart -> c.dart -> a.dart',
    );

    final Finding nonDart = GraphAnalysis(
      DependencyGraph(<String, Iterable<String>>{
        'src/a.nim': <String>['src/b.nim'],
        'src/b.nim': <String>['src/a.nim'],
      }),
    ).cycleFindings().single;
    expect(nonDart.severity, RuleSeverity.error);
    expect(nonDart.confidence, 'high');
  });

  test('collapses overlapping cycles into one component finding', () {
    final List<Finding> findings = GraphAnalysis(
      DependencyGraph(<String, Iterable<String>>{
        'lib/a.dart': <String>['lib/b.dart', 'lib/c.dart'],
        'lib/b.dart': <String>['lib/a.dart'],
        'lib/c.dart': <String>['lib/a.dart'],
      }),
    ).cycleFindings();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'cycle');
  });

  test(
    'reports unreachable eligible files but preserves a single-file project',
    () {
      final List<Finding> findings = analysis.deadFileFindings(
        roots: <String>['lib/main.dart'],
        eligibleNodes: graph.nodes,
      );

      expect(findings.map((Finding finding) => finding.path), <String>[
        'lib/orphan.dart',
      ]);
      expect(
        analysis.deadFileFindings(
          roots: <String>['lib/main.dart'],
          eligibleNodes: <String>['lib/orphan.dart'],
        ),
        isEmpty,
      );
    },
  );

  test('does not infer dead files from an unrelated language root', () {
    final GraphAnalysis mixedLanguage = GraphAnalysis(
      DependencyGraph(<String, Iterable<String>>{
        'src/main.c': <String>[],
        'scripts/benchmark.lua': <String>[],
        'scripts/report.lua': <String>[],
      }),
    );

    expect(
      mixedLanguage.deadFileFindings(
        roots: <String>['src/main.c'],
        eligibleNodes: <String>['scripts/benchmark.lua', 'scripts/report.lua'],
      ),
      isEmpty,
    );
  });
}
