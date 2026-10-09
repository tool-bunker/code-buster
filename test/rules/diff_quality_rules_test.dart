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
    Map<String, String> auxiliaryFiles = const <String, String>{},
  }) => RuleContext(
    config: const AnalysisConfig(root: '.', changedBase: 'HEAD'),
    sources: <String, String>{'lib/upload.dart': after, ...extraSources},
    language: 'repository',
    changedPaths: paths,
    baseSources: <String, String>{'lib/upload.dart': before, ...extraBase},
    auxiliaryFiles: auxiliaryFiles,
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

  test('reports stale references after a public contract is removed', () {
    final RuleContext context = changed(
      'String uploadAsset(String value) => value;',
      'String upload(String value) => value;',
      extraSources: const <String, String>{
        'lib/caller.dart': "import 'upload.dart';\nvoid run() => upload('x');",
      },
      extraBase: const <String, String>{
        'lib/caller.dart': "import 'upload.dart';\nvoid run() => upload('x');",
      },
    );

    final List<Finding> findings = StaleContractReferenceRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'stale-contract-reference');
    expect(findings.single.path, 'lib/caller.dart');
    expect(findings.single.line, 2);
    expect(findings.single.confidence, 'high');
    expect(findings.single.relatedFiles, <String>['lib/upload.dart']);
  });

  test('ignores private removals and references in comments or strings', () {
    expect(
      StaleContractReferenceRule().analyze(
        changed(
          'String renamed(String value) => value;',
          'String _localOnly(String value) => value;',
          extraSources: const <String, String>{
            'lib/caller.dart': '_localOnly(value);',
          },
        ),
      ),
      isEmpty,
    );
    expect(
      StaleContractReferenceRule().analyze(
        changed(
          'String renamed(String value) => value;',
          'String upload(String value) => value;',
          extraSources: const <String, String>{
            'lib/caller.dart':
                "// upload(value);\nconst example = 'upload(value)';",
          },
        ),
      ),
      isEmpty,
    );
  });

  test('reports a single-line high-risk change without a related test', () {
    final List<Finding> findings = RiskyChangeWithoutTestRule()
        .analyze(
          changed(
            'double refund(double amount, double fee) => amount - fee;',
            'double refund(double amount, double fee) => amount;',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'risky-change-without-test');
    expect(findings.single.line, 1);
    expect(findings.single.message, contains('money'));
  });

  test('accepts tested high-risk changes and low-risk or masked text', () {
    final RuleContext covered = changed(
      'Object decodeOrder(String source) => jsonDecode(source);',
      'Object decodeOrder(String source) => source;',
      paths: const <String>{'lib/upload.dart', 'test/upload_test.dart'},
      extraSources: const <String, String>{
        'test/upload_test.dart': 'void main() { testDecodeOrder(); }',
      },
      extraBase: const <String, String>{'test/upload_test.dart': ''},
    );
    expect(RiskyChangeWithoutTestRule().analyze(covered), isEmpty);
    expect(
      RiskyChangeWithoutTestRule().analyze(
        changed(
          "int count = oldCount + 1;\nconst note = 'parse(input)';",
          'int count = oldCount;',
        ),
      ),
      isEmpty,
    );
  });

  test('reports new behavior duplicated from an unchanged function', () {
    final RuleContext context = changed(
      "String upload(String input) => input.trim().toLowerCase().replaceAll(' ', '-');",
      '',
      extraSources: const <String, String>{
        'lib/slug.dart':
            "String slugify(String value) => value.trim().toLowerCase().replaceAll(' ', '-');",
      },
      extraBase: const <String, String>{
        'lib/slug.dart':
            "String slugify(String value) => value.trim().toLowerCase().replaceAll(' ', '-');",
      },
    );

    final List<Finding> findings = ChangedDuplicateImplementationRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'changed-duplicate-implementation');
    expect(findings.single.path, 'lib/upload.dart');
    expect(findings.single.line, 1);
    expect(findings.single.confidence, 'high');
    expect(findings.single.relatedFiles, <String>['lib/slug.dart']);
  });

  test('accepts distinct and trivial new function bodies', () {
    const Map<String, String> existing = <String, String>{
      'lib/slug.dart':
          "String slugify(String value) => value.trim().toLowerCase().replaceAll(' ', '-');",
    };
    expect(
      ChangedDuplicateImplementationRule().analyze(
        changed(
          "String upload(String input) => input.trim().toUpperCase().replaceAll(' ', '_');",
          '',
          extraSources: existing,
          extraBase: existing,
        ),
      ),
      isEmpty,
    );
    expect(
      ChangedDuplicateImplementationRule().analyze(
        changed(
          'int upload(int value) => value + 1;',
          '',
          extraSources: const <String, String>{
            'lib/math.dart': 'int increment(int input) => input + 1;',
          },
        ),
      ),
      isEmpty,
    );
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
  test('reports equivalent caller-side guards around a shared function', () {
    final RuleContext context = changed(
      'void upload(String? value) { if (value != null) parse(value); }',
      '',
      paths: const <String>{'lib/upload.dart', 'lib/preview.dart'},
      extraSources: const <String, String>{
        'lib/preview.dart':
            'void preview(String? input) { if (input != null) parse(input); }',
        'lib/parser.ts': 'export function parse(value: string): void {}',
      },
      extraBase: const <String, String>{
        'lib/preview.dart': '',
        'lib/parser.ts': 'export function parse(value: string): void {}',
      },
    );

    final List<Finding> findings = CallerSideGuardDuplicationRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('parse'));
  });

  test('accepts one guard different policies and external callees', () {
    expect(
      CallerSideGuardDuplicationRule().analyze(
        changed(
          'void upload(String? value) { if (value != null) parse(value); }',
          '',
          extraSources: const <String, String>{
            'lib/parser.dart': 'void parse(String value) {}',
          },
          extraBase: const <String, String>{
            'lib/parser.dart': 'void parse(String value) {}',
          },
        ),
      ),
      isEmpty,
    );
    expect(
      CallerSideGuardDuplicationRule().analyze(
        changed(
          'void upload(String? value) { if (value != null) parse(value); }',
          '',
          paths: const <String>{'lib/upload.dart', 'lib/preview.dart'},
          extraSources: const <String, String>{
            'lib/preview.dart':
                'void preview(String input) { if (input.isNotEmpty) parse(input); }',
            'lib/parser.dart': 'void parse(String value) {}',
          },
          extraBase: const <String, String>{
            'lib/preview.dart': '',
            'lib/parser.dart': 'void parse(String value) {}',
          },
        ),
      ),
      isEmpty,
    );
    expect(
      CallerSideGuardDuplicationRule().analyze(
        changed(
          'void upload(String? value) { if (value != null) external(value); }',
          '',
          paths: const <String>{'lib/upload.dart', 'lib/preview.dart'},
          extraSources: const <String, String>{
            'lib/preview.dart':
                'void preview(String? input) { if (input != null) external(input); }',
          },
          extraBase: const <String, String>{'lib/preview.dart': ''},
        ),
      ),
      isEmpty,
    );
    expect(
      CallerSideGuardDuplicationRule().analyze(
        changed(
          'const note = "if (value != null) parse(value);";',
          '',
          paths: const <String>{'lib/upload.dart', 'lib/preview.dart'},
          extraSources: const <String, String>{
            'lib/preview.dart': '// if (input != null) parse(input);',
            'lib/parser.dart': 'void parse(String value) {}',
          },
          extraBase: const <String, String>{
            'lib/preview.dart': '',
            'lib/parser.dart': 'void parse(String value) {}',
          },
        ),
      ),
      isEmpty,
    );
  });

  test('reports a new dependency used once for a native capability', () {
    final RuleContext context = changed(
      '''
import leftPad from 'left-pad';
export const code = leftPad('7', 3, '0');
''',
      '',
      paths: const <String>{'lib/upload.dart', 'package.json'},
      auxiliaryFiles: const <String, String>{
        'package.json': '{"dependencies":{"left-pad":"^1.3.0"}}',
        '@base/package.json': '{"dependencies":{}}',
      },
    );

    final List<Finding> findings = ThinDependencyForTrivialCapabilityRule()
        .analyze(context)
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('String.padStart'));
  });

  test('reports redundant Node dependencies only with runtime evidence', () {
    RuleContext nodeFetch(String engine) => changed(
      "import fetch from 'node-fetch';\nfetch(url);",
      '',
      paths: const <String>{'lib/upload.dart', 'package.json'},
      auxiliaryFiles: <String, String>{
        'package.json':
            '{"engines":{"node":"$engine"},"dependencies":{"node-fetch":"^3.3.2"}}',
        '@base/package.json':
            '{"engines":{"node":"$engine"},"dependencies":{}}',
      },
    );

    final List<Finding> findings = ThinDependencyForTrivialCapabilityRule()
        .analyze(nodeFetch('>=18'))
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.message, contains('global fetch'));
    expect(
      ThinDependencyForTrivialCapabilityRule().analyze(nodeFetch('>=16')),
      isEmpty,
    );
    expect(
      ThinDependencyForTrivialCapabilityRule().analyze(nodeFetch('*')),
      isEmpty,
    );
  });

  test('accepts existing reused and unmapped dependencies', () {
    RuleContext dependencyContext(
      String source,
      String current,
      String previous,
    ) => changed(
      source,
      '',
      paths: const <String>{'lib/upload.dart', 'package.json'},
      auxiliaryFiles: <String, String>{
        'package.json': current,
        '@base/package.json': previous,
      },
    );

    expect(
      ThinDependencyForTrivialCapabilityRule().analyze(
        dependencyContext(
          "import leftPad from 'left-pad';\nleftPad('7', 3);",
          '{"dependencies":{"left-pad":"^1.3.0"}}',
          '{"dependencies":{"left-pad":"^1.2.0"}}',
        ),
      ),
      isEmpty,
    );
    expect(
      ThinDependencyForTrivialCapabilityRule().analyze(
        dependencyContext(
          "import leftPad from 'left-pad';\nleftPad('7', 3);\nleftPad('8', 3);",
          '{"dependencies":{"left-pad":"^1.3.0"}}',
          '{"dependencies":{}}',
        ),
      ),
      isEmpty,
    );
    expect(
      ThinDependencyForTrivialCapabilityRule().analyze(
        dependencyContext(
          "import merge from 'deepmerge';\nmerge(left, right);",
          '{"dependencies":{"deepmerge":"^4.3.1"}}',
          '{"dependencies":{}}',
        ),
      ),
      isEmpty,
    );
  });
}
