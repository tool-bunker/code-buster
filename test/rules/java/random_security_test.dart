import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/random_security.dart';
import 'package:test/test.dart';

void main() {
  test('reports Random for sensitive values but accepts non-sensitive use', () {
    final List<Finding> findings = const JavaRandomSecurityRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java': '''Random tokenRandom = new Random();
Random animationRandom = new Random();
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
