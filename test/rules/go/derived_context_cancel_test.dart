import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/derived_context_cancel.dart';
import 'package:test/test.dart';

void main() {
  test('reports discarded and unused derived-context cancel functions', () {
    final List<Finding> findings = const GoDerivedContextCancelRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'worker.go': '''
package worker

func discarded(parent context.Context) {
  ctx, _ := context.WithTimeout(parent, timeout)
  run(ctx)
}

func unused(parent context.Context) {
  ctx, stop := context.WithCancel(parent)
  run(ctx)
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 9]);
    expect(findings.map((Finding finding) => finding.code).toSet(), <String>{
      'go-derived-context-cancel-not-called',
    });
    expect(
      findings.every((Finding finding) => finding.confidence == 'high'),
      isTrue,
    );
  });

  test('accepts called, deferred, and transferred cancel functions', () {
    final Iterable<Finding> findings = const GoDerivedContextCancelRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'worker.go': '''
package worker

func deferred(parent context.Context) {
  ctx, cancel := context.WithTimeout(parent, timeout)
  defer cancel()
  run(ctx)
}

func called(parent context.Context) {
  ctx, stop := context.WithCancelCause(parent)
  run(ctx)
  stop(nil)
}

func transferred(parent context.Context) (context.Context, context.CancelFunc) {
  ctx, cancel := context.WithCancel(parent)
  return ctx, cancel
}
''',
            },
            language: 'go',
          ),
        );

    expect(findings, isEmpty);
  });

  test('ignores context-looking text in non-Go files', () {
    final Iterable<Finding> findings = const GoDerivedContextCancelRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'notes.txt': 'ctx, cancel := context.WithCancel(parent)',
            },
            language: 'go',
          ),
        );

    expect(findings, isEmpty);
  });
}
