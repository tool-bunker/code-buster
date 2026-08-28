import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  List<Finding> analyze(String source) => LanguagePluginRegistry.standard()
      .require('dart')
      .analyze(
        <String, String>{'lib/view.dart': source},
        const AnalysisConfig(
          root: '.',
          severityOverrides: <String, RuleSeverity>{
            'flutter-repeated-sizedbox-spacing': RuleSeverity.info,
          },
        ),
      )
      .findings
      .where(
        (Finding finding) =>
            finding.code == 'flutter-repeated-sizedbox-spacing',
      )
      .toList();

  test('reports uniform Column and Row SizedBox gaps once per layout', () {
    final List<Finding> findings = analyze('''
Widget build() {
  return Column(
    children: [
      const Header(),
      const SizedBox(height: 12),
      const Content(),
      const SizedBox(height: 12),
      const Footer(),
    ],
  );
}

Widget toolbar() {
  return Row(
    children: [
      const BackButton(),
      const SizedBox(width: AppSpacing.md),
      const Title(),
      const SizedBox(width: AppSpacing.md),
      const Actions(),
    ],
  );
}
''');

    expect(findings, hasLength(2));
    expect(findings.map((Finding finding) => finding.line), <int>[2, 14]);
    expect(findings.first.message, contains('2 identical 12 vertical'));
    expect(findings.last.message, contains('Row.spacing'));
  });

  test('ignores exceptional, incomplete, and mixed gaps', () {
    final List<Finding> findings = analyze('''
final oneGap = Column(children: [
  const Header(),
  const SizedBox(height: 12),
  const Content(),
]);

final missingGap = Column(children: [
  const Header(),
  const SizedBox(height: 12),
  const Content(),
  const Footer(),
  const SizedBox(height: 12),
  const Actions(),
]);

final mixed = Column(children: [
  const Header(),
  const SizedBox(height: 8),
  const Content(),
  const SizedBox(height: 24),
  const Footer(),
]);

final leading = Column(children: [
  const SizedBox(height: 12),
  const Header(),
  const SizedBox(height: 12),
  const Content(),
  const SizedBox(height: 12),
]);
''');

    expect(findings, isEmpty);
  });

  test('ignores dynamic children and constrained SizedBox widgets', () {
    final List<Finding> findings = analyze('''
final dynamic = Column(children: [
  for (final item in items) ItemTile(item),
  const SizedBox(height: 12),
  const Footer(),
  const SizedBox(height: 12),
  const Actions(),
]);

final constrained = Column(children: [
  const Header(),
  const SizedBox(height: 12, width: 20),
  const Content(),
  const SizedBox(height: 12, width: 20),
  const Footer(),
]);

final childBox = Column(children: [
  const Header(),
  const SizedBox(height: 12, child: Divider()),
  const Content(),
  const SizedBox(height: 12, child: Divider()),
  const Footer(),
]);
''');

    expect(findings, isEmpty);
  });

  test('ignores layouts that already define spacing', () {
    final List<Finding> findings = analyze('''
final view = Column(
  spacing: 12,
  children: [
    const Header(),
    const SizedBox(height: 12),
    const Content(),
    const SizedBox(height: 12),
    const Footer(),
  ],
);
''');

    expect(findings, isEmpty);
  });
}
