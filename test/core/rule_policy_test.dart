import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('explicit metadata taxonomy drives semantic grouping', () {
    expect(
      RulePolicy.taxonomyGroupFor('architecture-layer-cycle'),
      'architecture',
    );
    expect(
      RulePolicy.taxonomyGroupFor('ai-untrusted-prompt-construction'),
      'security',
    );
    expect(
      RulePolicy.taxonomyGroupFor('go-http-client-no-timeout'),
      'reliability',
    );
  });

  test('exception logging convention is advisory rather than security', () {
    const AnalysisConfig config = AnalysisConfig(root: '.');

    expect(RulePolicy.taxonomyGroupFor('py-logging-exception'), 'style');
    expect(RulePolicy(config).modeFor('py-logging-exception'), RuleMode.count);
  });
}
