import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/print_stacktrace.dart';
import 'package:test/test.dart';

void main() {
  test('reports direct stacktrace printing but ignores quoted examples', () {
    final List<Finding> findings = javaPrintStacktraceRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': '''error.printStackTrace();
String example = "error.printStackTrace()";
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
