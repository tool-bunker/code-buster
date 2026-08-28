import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/testing/runtime_bootstrap.dart';
import 'package:test/test.dart';

void main() {
  test('reports a Dart entrypoint repeatedly launched from tests', () {
    final List<Finding> findings = const TestRepeatedRuntimeBootstrapRule()
        .analyze(
          _context(<String, String>{
            'test/first_test.dart': _dartLaunch,
            'test/second_test.dart': _dartLaunch,
            'test/third_test.dart': _dartLaunch,
          }),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'test-repeated-runtime-bootstrap');
    expect(findings.single.message, contains('dart'));
    expect(findings.single.message, contains('bin/tool.dart'));
    expect(findings.single.message, contains('3 times'));
  });

  test('detects repeated Cargo, Go, and Gradle bootstraps', () {
    final List<Finding> findings = const TestRepeatedRuntimeBootstrapRule()
        .analyze(
          _context(<String, String>{
            'tests/one.py': '''
subprocess.run(["cargo", "run", "--bin", "server"])
os.system("go run cmd/check.go")
os.system("./gradlew test")
''',
            'tests/two.py': '''
subprocess.run(["cargo", "run", "--bin", "server"])
os.system("go run cmd/check.go")
os.system("./gradlew test")
''',
            'tests/three.py': '''
subprocess.run(["cargo", "run", "--bin", "server"])
os.system("go run cmd/check.go")
os.system("./gradlew test")
''',
          }),
        )
        .toList();

    expect(
      findings.map((Finding finding) => finding.message),
      containsAll(<Matcher>[
        contains('cargo'),
        contains('go'),
        contains('gradlew'),
      ]),
    );
  });

  test('ignores production launches and distinct test targets', () {
    final List<Finding> findings = const TestRepeatedRuntimeBootstrapRule()
        .analyze(
          _context(<String, String>{
            'lib/launcher.dart': 'const command = "dart run bin/tool.dart";',
            'test/tools_test.dart': '''
const first = "dart run bin/one.dart";
const second = "dart run bin/two.dart";
const third = "dart run bin/three.dart";
''',
          }),
        )
        .toList();

    expect(findings, isEmpty);
  });
}

const String _dartLaunch = '''
final result = await Process.run(
  Platform.resolvedExecutable,
  <String>["bin/tool.dart", "--version"],
);
''';

RuleContext _context(Map<String, String> sources) => RuleContext(
  config: AnalysisConfig(root: '.'),
  sources: sources,
  language: 'repository',
);
