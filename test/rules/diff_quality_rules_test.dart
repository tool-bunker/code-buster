import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/generic/diff_quality_rules.dart';
import 'package:test/test.dart';

void main() {
  RuleContext changed(
    String after,
    String before, {
    Set<String> paths = const <String>{'lib/upload.dart'},
    Map<String, String> extraSources = const <String, String>{},
    Map<String, String> extraBase = const <String, String>{},
  }) => RuleContext(
    config: const AnalysisConfig(root: '.', changedBase: 'HEAD'),
    sources: <String, String>{'lib/upload.dart': after, ...extraSources},
    language: 'repository',
    changedPaths: paths,
    baseSources: <String, String>{'lib/upload.dart': before, ...extraBase},
  );

  test('reports style drift and broad refactoring beside behavior', () {
    const String before = '''
void upload(bool ready) {
  print('one');
  print('two');
  print('three');
  print('four');
  print('five');
  print('six');
}
''';
    const String after = '''
void upload(bool ready) {
  if (!ready) return;
  print("one");
  print("two");
  print("three");
  print("four");
  print("five");
  print("six");
}
''';
    final RuleContext context = changed(after, before);

    expect(StyleDriftInDiffRule().analyze(context), hasLength(1));
    expect(BroadRefactorInFocusedChangeRule().analyze(context), hasLength(1));
  });

  test('accepts a surgical behavior change without style churn', () {
    const String before = 'bool valid(String value) => value.isNotEmpty;';
    const String after = '''
bool valid(String value) {
  if (value.trim().isEmpty) return false;
  return value.isNotEmpty;
}
''';
    final RuleContext context = changed(after, before);

    expect(StyleDriftInDiffRule().analyze(context), isEmpty);
    expect(BroadRefactorInFocusedChangeRule().analyze(context), isEmpty);
  });

  test('requires a concept-related changed test for behavior', () {
    const String before = 'bool upload(String value) => true;';
    const String after = '''
bool upload(String value) {
  if (value.isEmpty) return false;
  return value.startsWith('https:');
}
''';
    expect(
      ChangedBehaviorWithoutTestRule().analyze(changed(after, before)),
      hasLength(1),
    );

    final RuleContext covered = changed(
      after,
      before,
      paths: const <String>{'lib/upload.dart', 'test/upload_test.dart'},
      extraSources: const <String, String>{
        'test/upload_test.dart': 'void main() { testUpload(); }',
      },
      extraBase: const <String, String>{'test/upload_test.dart': ''},
    );
    expect(ChangedBehaviorWithoutTestRule().analyze(covered), isEmpty);
  });

  test('reports speculative optional feature bundles', () {
    const String after = '''
void save({
  bool validate = true,
  bool notify = false,
  bool retry = false,
}) {
  validator.check();
}
''';
    expect(
      OptionalFeatureBundleRule().analyze(changed(after, '')),
      hasLength(1),
    );
    expect(
      OptionalFeatureBundleRule().analyze(
        changed('void save({bool validate = true}) {}', ''),
      ),
      isEmpty,
    );
  });

  test('reports declaration-heavy changes with little behavior', () {
    const String after = '''
interface class DiscountStrategy {}
class PercentageDiscount implements DiscountStrategy {}
class DiscountConfig {}
''';
    expect(
      AbstractionCostExceedsUseRule().analyze(changed(after, '')),
      hasLength(1),
    );
    expect(
      AbstractionCostExceedsUseRule().analyze(
        changed('double discount(double value) => value * .1;', ''),
      ),
      isEmpty,
    );
  });

  test('skips intent heuristics for broad repository migrations', () {
    final Map<String, String> sources = <String, String>{
      for (var index = 0; index < 6; index++)
        'lib/change_$index.dart': 'if (changed) return;',
    };
    final Map<String, String> base = <String, String>{
      for (var index = 0; index < 6; index++) 'lib/change_$index.dart': '',
    };
    final RuleContext context = RuleContext(
      config: const AnalysisConfig(root: '.', changedBase: 'HEAD'),
      sources: sources,
      language: 'repository',
      changedPaths: sources.keys.toSet(),
      baseSources: base,
    );

    expect(ChangedBehaviorWithoutTestRule().analyze(context), isEmpty);
    expect(OptionalFeatureBundleRule().analyze(context), isEmpty);
  });

  test('reports a newly added unused private declaration', () {
    final RuleContext context = changed(
      'int _prepare(int value) => compute(value);',
      '',
    );

    expect(NewUnusedDeclarationRule().analyze(context), hasLength(1));
  });

  test('reports a new forwarding wrapper with one caller', () {
    const String after = '''
int _prepare(int value) => compute(value);
int save(int value) => _prepare(value);
''';
    final List<Finding> findings = SingleCallerWrapperRule()
        .analyze(changed(after, ''))
        .toList();

    final RuleContext reused = changed('''
int _prepare(int value) => compute(value);
int save(int value) => _prepare(value);
int preview(int value) => _prepare(value);
''', '');
    expect(SingleCallerWrapperRule().analyze(reused), isEmpty);
    expect(findings, hasLength(1));
    expect(findings.single.message, contains('_prepare'));
  });

  test('reports changed functions disconnected from their peers', () {
    const String after = '''
int load(int value) => parse(value);
int parse(int value) => value + 1;
int rename(int value) => value + 2;
int archive(int value) => value + 3;
''';
    final List<Finding> findings = UnrelatedSymbolChurnRule()
        .analyze(changed(after, ''))
        .toList();

    expect(
      findings.map((finding) => finding.message).join('\n'),
      allOf(contains('rename'), contains('archive')),
    );
    expect(findings, hasLength(2));
  });

  test('reports newly added APIs with three Boolean options', () {
    final RuleContext risky = changed(
      'void save({bool merge = true, bool validate = true, bool notify = false}) {}',
      '',
    );
    final RuleContext focused = changed(
      'void save({bool validate = true, int retries = 0}) {}',
      '',
    );

    expect(BooleanOptionExplosionRule().analyze(risky), hasLength(1));
    expect(BooleanOptionExplosionRule().analyze(focused), isEmpty);
  });
}
