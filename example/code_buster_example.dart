import 'package:code_buster/code_buster.dart';

void main() {
  final RuleRegistry registry = RuleRegistry(<CodeBusterRule>[
    const TodoRule(),
  ]);
  final CodeBusterRule rule = registry['example-todo']!;
  final List<Finding> findings = rule
      .analyze(
        const RuleContext(
          config: AnalysisConfig(root: '.'),
          sources: <String, String>{'lib/example.dart': '// TODO: explain'},
          language: 'dart',
        ),
      )
      .toList(growable: false);
  for (final Finding finding in findings) {
    print('${finding.path}:${finding.line} ${finding.message}');
  }
}

final class TodoRule implements CodeBusterRule {
  const TodoRule();

  @override
  RuleMetadata get metadata => const RuleMetadata(
    id: 'example-todo',
    defaultSeverity: RuleSeverity.info,
    group: 'project',
    title: 'Document TODO ownership',
    why: 'Unowned TODO comments are difficult to prioritize.',
    suggestion: 'Add an owner and issue reference.',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = source.value.split('\n');
      for (var index = 0; index < lines.length; index++) {
        if (!lines[index].contains('TODO')) continue;
        yield Finding(
          code: metadata.id,
          severity: metadata.defaultSeverity,
          path: source.key,
          line: index + 1,
          message: 'TODO has no tracked owner',
        );
      }
    }
  }
}
