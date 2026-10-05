import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('focused commands request only their finding families', () {
    final complexity = AnalysisExecutionPlan(
      command: CodeBusterCommand.complexity,
      config: const AnalysisConfig(root: '/project'),
    );

    expect(complexity.allows('complex-function'), isTrue);
    expect(complexity.allows('goto-statement'), isTrue);
    expect(complexity.allows('duplicate-block'), isFalse);
    expect(complexity.allows('constant-argument-parameter'), isFalse);
  });

  test('--only narrows a summary before rule execution', () {
    final plan = AnalysisExecutionPlan(
      command: CodeBusterCommand.summary,
      config: const AnalysisConfig(root: '/project'),
      only: 'constant-argument-parameter',
    );

    expect(plan.allows('constant-argument-parameter'), isTrue);
    expect(plan.allows('unused-configuration-option'), isFalse);
    expect(plan.allows('duplicate-block'), isFalse);
  });

  test('disabled rules and groups do not enter execution', () {
    final plan = AnalysisExecutionPlan(
      command: CodeBusterCommand.summary,
      config: const AnalysisConfig(
        root: '/project',
        disabledRules: <String>{'duplicate-block'},
        groupModes: <String, RuleMode>{'maintainability': RuleMode.off},
      ),
    );

    expect(plan.allows('duplicate-block'), isFalse);
    expect(plan.allows('constant-argument-parameter'), isFalse);
  });
}
