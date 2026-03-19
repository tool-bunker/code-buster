import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/package_cycle.dart';
import 'package:test/test.dart';

void main() {
  test('reports cycles between Java packages instead of nominal files', () {
    final List<Finding> findings = const JavaPackageCycleRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'src/a/A.java': '''package app.a;
import app.b.B;
class A { B value; }
''',
              'src/b/B.java': '''package app.b;
import app.a.A;
class B { A value; }
''',
            },
            language: 'java',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'java-package-cycle');
    expect(findings.single.path, anyOf('app/a', 'app/b'));
  });
}
