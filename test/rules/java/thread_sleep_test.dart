import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/thread_sleep.dart';
import 'package:test/test.dart';

void main() {
  test('reports direct thread sleeping but ignores quoted examples', () {
    final List<Finding> findings = javaThreadSleepRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': '''Thread.sleep(100);
String example = "Thread.sleep(100)";
''',
            },
            language: 'java',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });
}
