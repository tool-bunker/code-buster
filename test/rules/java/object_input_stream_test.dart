import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/object_input_stream.dart';
import 'package:test/test.dart';

void main() {
  test('reports native deserialization but ignores quoted examples', () {
    final List<Finding> findings = javaObjectInputStreamRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': '''ObjectInputStream input = open();
String example = "ObjectInputStream input";
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
