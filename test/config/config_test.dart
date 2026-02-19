import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('loads explicit duplication comparison modes', () {
    for (final (String value, DuplicationMode expected)
        in <(String, DuplicationMode)>[
          ('exact', DuplicationMode.exact),
          ('normalized', DuplicationMode.normalized),
          ('semantic', DuplicationMode.semantic),
        ]) {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '.',
        source: '[analysis]\nduplication_mode = "$value"',
      );
      expect(config.duplicationMode, expected);
    }
    expect(
      CodeBusterConfigLoader.validate('[analysis]\nduplication_mode = "fuzzy"'),
      contains('unsupported duplication mode: fuzzy'),
    );
  });

  test('applies reusable strict and security quality profiles', () {
    final AnalysisConfig strict = CodeBusterConfigLoader.loadFromString(
      root: '.',
      source: '''[quality]
profile = "strict"
gates = ["errors == 0", "debt_minutes_per_file <= 3"]
''',
    );
    expect(strict.qualityProfile, 'strict');
    expect(strict.complexityThreshold, 8);
    expect(strict.cognitiveThreshold, 12);
    expect(strict.minDuplicationLines, 10);
    expect(strict.ruleGroups, containsAll(<String>['core', 'security']));
    expect(strict.qualityGates, <String>[
      'errors == 0',
      'debt_minutes_per_file <= 3',
    ]);

    final AnalysisConfig security = CodeBusterConfigLoader.loadFromString(
      root: '.',
      source: '[quality]\nprofile = "security"',
    );
    expect(security.ruleGroups, containsAll(<String>['core', 'security']));
    expect(
      CodeBusterConfigLoader.validate('[quality]\nprofile = "unknown"'),
      contains('unsupported quality profile: unknown'),
    );
    expect(
      CodeBusterConfigLoader.validate(
        '[quality]\ngates = ["execute(user_code)"]',
      ),
      contains('unsupported quality gate condition: execute(user_code)'),
    );
    expect(
      CodeBusterConfigLoader.validate(
        '[quality]\ngates = ["advisory.performance < 20"]',
      ),
      isEmpty,
    );
  });

  test('parses semantic group and per-rule modes', () {
    final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
      root: '.',
      source: '''
[rules.groups]
performance = "count"
architecture = "off"

[rules.mode]
complex-function = "report"
dead-file = "off"
''',
    );

    expect(config.groupModes['performance'], RuleMode.count);
    expect(config.groupModes['architecture'], RuleMode.off);
    expect(config.ruleModes['complex-function'], RuleMode.report);
    expect(config.ruleModes['dead-file'], RuleMode.off);
    expect(config.disabledRules, contains('dead-file'));
    expect(RulePolicy(config).modeFor('complex-function'), RuleMode.report);
    expect(RulePolicy(config).modeFor('dead-file'), RuleMode.off);
  });

  test('validates MVVM profile names and nested keys', () {
    expect(
      CodeBusterConfigLoader.validate('[rules.groups]\nsubjective = "count"'),
      contains(contains('Unknown Code Buster semantic rule group: subjective')),
    );
    expect(
      CodeBusterConfigLoader.validate('''
[architecture]
profile = "mvc"
[architecture.mvvm]
controllers = ["lib/controllers/**"]
'''),
      containsAll(<String>[
        'unsupported architecture profile: mvc',
        'unknown configuration key: architecture.mvvm.controllers',
      ]),
    );
  });

  test('loads explicit classification overrides', () {
    final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
      root: '/project',
      source: '''[classification]
production = ["tools/release/**"]
test = ["verification/**"]
generated = ["src/schema_output/**"]
''',
    );

    expect(config.classificationProduction, <String>['tools/release/**']);
    expect(config.classificationTest, <String>['verification/**']);
    expect(config.classificationGenerated, <String>['src/schema_output/**']);
  });

  test('loads the opt-in Dart MVVM architecture profile', () {
    final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
      root: '.',
      source: '''
languages = ["dart"]
[architecture]
profile = "dart-mvvm"
[architecture.mvvm]
views = ["lib/presentation/**"]
view_models = ["lib/state/**"]
models = ["lib/domain/**"]
repositories = ["lib/data/**"]
strict_view_model_boundary = false
''',
    );

    expect(config.dartMvvmEnabled, isTrue);
    expect(config.mvvmViews, <String>['lib/presentation/**']);
    expect(config.mvvmViewModels, <String>['lib/state/**']);
    expect(config.mvvmModels, <String>['lib/domain/**']);
    expect(config.mvvmRepositories, <String>['lib/data/**']);
    expect(config.mvvmStrictViewModelBoundary, isFalse);
  });

  group('CodeBusterConfigLoader', () {
    test('preserves quoted commas hashes and legacy escaped separators', () {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '/project',
        source: '''
lang = "dart"
ignore_patterns = ["generated,legacy", "value#fragment"]
pattern_rules = ["quoted|warn|foo\\|bar,baz|message|suggestion"]
''',
      );

      expect(config.language, 'dart');
      expect(config.ignorePatterns, <String>[
        'generated,legacy',
        'value#fragment',
      ]);
      expect(config.patternRules, hasLength(1));
      expect(config.patternRules.single.pattern, 'foo|bar,baz');
    });

    test('loads severity overrides and disabled rules', () {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '/project',
        source: '''
[severity]
duplicate-block = "warning"
dead-file = "off"
''',
      );

      expect(config.severityOverrides['duplicate-block'], RuleSeverity.warn);
      expect(config.disabledRules, <String>{'dead-file'});
    });

    test('loads nested structure settings and compatible defaults', () {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '/project',
        source: '''
entry_points = ["bin/cb.dart"]
max_function_lines = 80

[structure]
source_roots = ["lib", "bin"]
max_top_level_files = 30
allowed_top_level = ["tool"]
required_dirs = ["lib", "test"]
''',
      );

      expect(config.entryPoints, <String>['bin/cb.dart']);
      expect(config.maxFunctionLines, 80);
      expect(config.structureSourceRoots, <String>['lib', 'bin']);
      expect(config.structureMaxTopLevelFiles, 30);
      expect(config.structureAllowedTopLevel, <String>['tool']);
      expect(config.structureRequiredDirectories, <String>['lib', 'test']);
    });

    test('loads the current sectioned configuration schema', () {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '/project',
        source: '''
languages = ["dart", "python"]

[analysis]
duplication_min_lines = 7
complexity_threshold = 12
cognitive_complexity_threshold = 18
max_file_lines = 900
max_function_lines = 70
csharp_dead_code = true

[files]
include = ["lib/**"]
exclude = ["vendor/**"]
ignore = ["generated/**"]
entry_points = ["bin/main.dart"]

[rules]
enabled_groups = ["core", "security"]
patterns = ["project-rule|error|unsafe|Avoid unsafe"]

[rules.severity]
dead-file = "off"
complex-function = "error"

[structure]
source_roots = ["lib"]
max_root_files = 3
allowed_root_files = ["tool"]
required_directories = ["lib", "test"]

[review]
changed_base = "origin/main"
''',
      );

      expect(config.languages, <String>['dart', 'python']);
      expect(config.minDuplicationLines, 7);
      expect(config.complexityThreshold, 12);
      expect(config.cognitiveThreshold, 18);
      expect(config.maxFileLines, 900);
      expect(config.maxFunctionLines, 70);
      expect(config.csharpDeadCode, isTrue);
      expect(config.includes, <String>['lib/**']);
      expect(config.groupModes['correctness'], RuleMode.report);
      expect(config.groupModes['maintainability'], RuleMode.report);
      expect(config.groupModes['security'], RuleMode.report);
      expect(config.excludes, <String>['vendor/**']);
      expect(config.ignorePatterns, <String>['generated/**']);
      expect(config.entryPoints, <String>['bin/main.dart']);
      expect(config.ruleGroups, containsAll(<String>['core', 'security']));
      expect(config.patternRules.single.id, 'project-rule');
      expect(config.disabledRules, <String>{'dead-file'});
      expect(config.severityOverrides['complex-function'], RuleSeverity.error);
      expect(config.structureMaxTopLevelFiles, 3);
      expect(config.structureAllowedTopLevel, <String>['tool']);
      expect(config.structureRequiredDirectories, <String>['lib', 'test']);
      expect(config.changedBase, 'origin/main');
    });

    test('accepts legacy top-level structure aliases', () {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '/project',
        source: '''
structure_source_roots = ["src"]
structure_max_top_level_files = 4
structure_allowed_top_level = ["tool"]
structure_required_dirs = ["src", "tests"]
''',
      );

      expect(config.structureSourceRoots, <String>['src']);
      expect(config.structureMaxTopLevelFiles, 4);
      expect(config.structureAllowedTopLevel, <String>['tool']);
      expect(config.structureRequiredDirectories, <String>['src', 'tests']);
    });

    test('rejects type mismatches instead of silently accepting them', () {
      expect(
        () => CodeBusterConfigLoader.loadFromString(
          root: '/project',
          source: 'complexity_threshold = "many"',
        ),
        throwsFormatException,
      );
    });

    test('validates unknown keys and malformed value types', () {
      expect(
        CodeBusterConfigLoader.validate(CodeBusterConfigLoader.starterConfig()),
        isEmpty,
      );
      expect(
        CodeBusterConfigLoader.validate('''
languages = ["dart"]
[analysis]
complexity_threshold = "high"
mystery = true
[unknown]
value = 1
'''),
        containsAll(<String>[
          'unknown configuration key: analysis.mystery',
          'unknown configuration key: unknown',
        ]),
      );
      expect(CodeBusterConfigLoader.validate('[analysis\n'), isNotEmpty);
    });

    test('emits a starter configuration that it can parse', () {
      final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
        root: '/project',
        source: CodeBusterConfigLoader.starterConfig(),
      );

      expect(config.language, 'auto');
      expect(config.entryPoints, isEmpty);
      expect(config.minDuplicationLines, 15);
      expect(config.ruleGroups, contains('core'));
    });

    test(
      'migrates legacy keys while preserving comments and creates backup',
      () async {
        const String legacy = '''# project policy
lang = "dart"
complexity_threshold = 8
entry_points = ["bin/main.dart"]

[structure]
max_top_level_files = 4

[severity]
dead-file = "off"
''';
        final String migrated = CodeBusterConfigMigrator.migrate(legacy);
        expect(migrated, contains('# project policy'));
        expect(migrated, contains('languages = ["dart"]'));
        expect(migrated, contains('analysis.complexity_threshold = 8'));
        expect(migrated, contains('files.entry_points = ["bin/main.dart"]'));
        expect(migrated, contains('max_root_files = 4'));
        expect(migrated, contains('[rules.severity]'));

        final Directory root = await Directory.systemTemp.createTemp(
          'code-buster-migrate-',
        );
        addTearDown(() => root.delete(recursive: true));
        final File config = File('${root.path}/code-buster.toml')
          ..writeAsStringSync(legacy);
        expect(
          CodeBusterConfigMigrator.migrateFile(root.path, dryRun: true),
          isTrue,
        );
        expect(config.readAsStringSync(), legacy);
        expect(CodeBusterConfigMigrator.migrateFile(root.path), isTrue);
        expect(File('${config.path}.bak').readAsStringSync(), legacy);
        expect(CodeBusterConfigMigrator.migrateFile(root.path), isFalse);
      },
    );

    test('returns defaults when no configuration file exists', () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-',
      );
      addTearDown(root.delete);

      final AnalysisConfig config = CodeBusterConfigLoader.loadFromRoot(
        root.path,
      );

      expect(config.root, root.path);
      expect(config.language, 'auto');
      expect(config.ruleGroups, contains('core'));
    });
  });
}
