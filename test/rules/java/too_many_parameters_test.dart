import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/too_many_parameters.dart';
import 'package:test/test.dart';

void main() {
  test('reports methods above seven parameters', () {
    const String source = '''
class Orders {
  void acceptable(Map<String, Integer> values, int b, int c, int d, int e, int f, int g) {
  }

  void excessive(int a, int b, int c, int d, int e, int f, int g, int h) {
  }
}
''';

    final List<Finding> findings = const JavaTooManyParametersRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: const <String, String>{'Orders.java': source},
            language: 'java',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
    expect(findings.single.message, contains('8 parameters'));
  });
}
