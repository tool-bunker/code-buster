import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/shell_command.dart';
import 'package:test/test.dart';

void main() {
  test('reports shell command boundaries but accepts direct execution', () {
    final List<Finding> findings = goShellCommandRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.go': '''exec.Command("sh", "-c", input)
exec.CommandContext(ctx, "/bin/bash", "-c", input)
exec.Command("python", "-c", "import pygments")
exec.Command("tool", input)
''',
            },
            language: 'go',
          ),
        )
        .toList();
    expect(findings, hasLength(2));
    expect(
      findings
          .expand((Finding finding) => finding.codeFlow)
          .map((CodeFlowStep step) => step.message),
      everyElement('shell command execution sink'),
    );
  });
}
