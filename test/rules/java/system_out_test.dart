import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/system_out.dart';
import 'package:test/test.dart';

void main() {
  test('reports console logging but ignores quoted examples', () {
    final List<Finding> findings = javaSystemOutRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': '''System.out.println(value);
String example = "System.err.println(value)";
''',
            },
            language: 'java',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'java-system-out');
    expect(findings.single.line, 1);
    expect(findings.single.suggestion, "Use the project's logging framework.");
  });

  test('ignores console output in Java test sources', () {
    final List<Finding> findings = javaSystemOutRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'src/main/java/App.java': 'System.out.println("running");',
              'src/test/java/AppTest.java': 'System.out.println("fixture");',
              'tests/Integration.java': 'System.err.println("diagnostic");',
            },
            language: 'java',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'src/main/java/App.java');
  });
}
