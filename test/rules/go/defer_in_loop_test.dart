import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/defer_in_loop.dart';
import 'package:test/test.dart';

import '../../support/source_fixture.dart';

void main() {
  test('reports defer inside a loop but not outside', () {
    final List<Finding> findings = const GoDeferInLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.go': sourceFixture(
                'go/rules/defer_in_loop_test/reports_defer_inside_a_loop_but_not_outside/main.go',
              ),
            },
            language: 'go',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('scopes defer inside an immediately invoked function per iteration', () {
    final List<Finding> findings = const GoDeferInLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'cleanup.go': '''
func cleanupAll(cleanups []func()) {
  for len(cleanups) > 0 {
    func() {
      defer recoverCleanup()
      cleanups[len(cleanups)-1]()
    }()
  }
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test('still reports a nested loop inside an invoked function', () {
    final List<Finding> findings = const GoDeferInLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'nested.go': '''
func run(groups [][]Resource) {
  for _, group := range groups {
    func() {
      for _, resource := range group {
        defer resource.Close()
      }
    }()
  }
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('ignores defer when the iteration cannot continue afterward', () {
    final List<Finding> findings = const GoDeferInLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'terminal.go': '''
func terminal(items []Item) error {
  for _, item := range items {
    if item.cached {
      resource := item.open()
      defer resource.Close()
      item.consume(resource)
    }
    return nil
  }
  for _, item := range items {
    resource := item.open()
    defer resource.Close()
    break
  }
  return nil
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test('reports defer when only a nested branch exits', () {
    final List<Finding> findings = const GoDeferInLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'conditional.go': '''
func process(items []Item) error {
  for _, item := range items {
    resource := item.open()
    defer resource.Close()
    if item.done {
      return nil
    }
    item.process(resource)
  }
  return nil
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });
}
