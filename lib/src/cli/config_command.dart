// Configuration inspection, validation, and migration belong together because they all operate on the same effective settings.

import 'dart:convert';
import 'dart:io';

import '../config/config.dart';
import '../config/repository_defaults.dart';
import '../core/models.dart';
import '../discovery/language_versions.dart';
import '../reporting/reporting.dart';
import 'cli_command.dart';
import 'cli_contract.dart';

/// Validates, migrates, and displays effective configuration.
final class ConfigCommand implements CliCommandHandler {
  /// Creates the configuration command.
  const ConfigCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.config,
  };

  @override
  int execute(CodeBusterCliOptions options) => _config(options);
}

int _config(CodeBusterCliOptions options) {
  final String root = Directory(options.root).absolute.path;
  final File file = File('$root${Platform.pathSeparator}code-buster.toml');
  if (options.target == 'validate') {
    if (!file.existsSync()) {
      stderr.writeln('error: configuration not found: ${file.path}');
      return 2;
    }
    final List<String> diagnostics = CodeBusterConfigLoader.validate(
      file.readAsStringSync(),
    );
    if (diagnostics.isEmpty) {
      stdout.writeln('Code Buster configuration is valid');
      return 0;
    }
    for (final String diagnostic in diagnostics) {
      stderr.writeln('error: $diagnostic');
    }
    return 2;
  }
  if (options.target == 'explain') {
    final RepositoryDefaults defaults = RepositoryDefaults.infer(
      root,
      includeTests: options.includeAll || options.includeTests,
      includeExamples: options.includeAll || options.includeExamples,
      includeVendored: options.includeAll || options.includeVendored,
    );
    final bool configured = file.existsSync();
    final AnalysisConfig effective = CodeBusterConfigLoader.loadFromRoot(root);
    final List<String> formatterFiles = <String>[
      for (final String name in <String>[
        '.editorconfig',
        '.prettierrc',
        '.prettierrc.json',
        'biome.json',
      ])
        if (File('$root${Platform.pathSeparator}$name').existsSync()) name,
    ];
    final Map<String, String> languageVersions = const LanguageVersionDetector()
        .detect(root);
    final Map<String, Object> explanation = <String, Object>{
      'config_file': configured ? file.path : 'none',
      'scope': options.includeAll
          ? 'all'
          : <String>[
              'production',
              if (options.includeTests) 'tests',
              if (options.includeExamples) 'examples',
              if (options.includeVendored) 'vendored',
            ].join('+'),
      'detected_profiles': defaults.profiles,
      'language_versions': languageVersions,
      'formatter_files': formatterFiles,
      'effective': <String, Object>{
        'languages': effective.languages.isEmpty
            ? <String>[effective.language]
            : effective.languages,
        'duplication_min_lines': effective.minDuplicationLines,
        'duplication_mode': effective.duplicationMode.name,
        'quality_profile': effective.qualityProfile,
        'quality_gates': effective.qualityGates,
        'complexity_threshold': effective.complexityThreshold,
        'cognitive_threshold': effective.cognitiveThreshold,
        'rule_groups': _orderedRuleGroups(effective.ruleGroups),
        'group_modes': <String, String>{
          for (final String group in effective.groupModes.keys.toList()..sort())
            group: effective.groupModes[group]!.configValue,
        },
        'rule_modes': <String, String>{
          for (final String rule in effective.ruleModes.keys.toList()..sort())
            rule: effective.ruleModes[rule]!.configValue,
        },
        'classification.production': effective.classificationProduction,
        'classification.test': effective.classificationTest,
        'classification.generated': effective.classificationGenerated,
      },
      'setting_source': configured
          ? 'built-in defaults with code-buster.toml overrides'
          : 'built-in language/framework defaults',
      'production_ignores': options.includeAll
          ? const <String>[]
          : defaults.ignores,
      'precedence': const <String>[
        'code-buster defaults',
        'language/framework detection',
        'repository formatter files',
        'code-buster.toml',
        'CLI overrides',
      ],
    };
    if (options.format == ReportFormat.json) {
      stdout.writeln(jsonEncode(explanation));
    } else {
      stdout.writeln('config_file=${explanation['config_file']}');
      stdout.writeln('scope=${explanation['scope']}');
      stdout.writeln(
        'detected_profiles=${defaults.profiles.isEmpty ? 'none' : defaults.profiles.join(',')}',
      );
      stdout.writeln(
        'language_versions=${languageVersions.isEmpty ? 'none' : languageVersions.entries.map((MapEntry<String, String> entry) => '${entry.key}:${entry.value}').join(',')}',
      );
      stdout.writeln(
        'formatter_files=${formatterFiles.isEmpty ? 'none' : formatterFiles.join(',')}',
      );
      stdout.writeln('setting_source=${explanation['setting_source']}');
      final Map<String, Object> settings =
          explanation['effective'] as Map<String, Object>;
      for (final MapEntry<String, Object> setting in settings.entries) {
        stdout.writeln('${setting.key}=${setting.value}');
      }
      stdout.writeln(
        'production_ignores=${(explanation['production_ignores'] as List<String>).join(',')}',
      );
      stdout.writeln(
        'precedence=${(explanation['precedence'] as List<String>).join(' -> ')}',
      );
    }
    return 0;
  }
  if (options.target == 'migrate') {
    if (!file.existsSync()) {
      stderr.writeln('configuration not found: ${file.path}');
      return 2;
    }
    final String original = file.readAsStringSync();
    final String migrated = CodeBusterConfigMigrator.migrate(original);
    if (migrated == original) {
      stdout.writeln('Code Buster configuration is already current');
    } else if (options.dryRun) {
      stdout.write(migrated);
    } else {
      CodeBusterConfigMigrator.migrateFile(root);
      stdout.writeln('migrated ${file.path}');
      stdout.writeln('backup: ${file.path}.bak');
    }
    return 0;
  }
  final AnalysisConfig config = CodeBusterConfigLoader.loadFromRoot(root)
      .copyWith(
        root: root,
        language: options.language.isEmpty ? null : options.language,
        languages: options.languages.isEmpty ? null : options.languages,
      );
  if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'root': config.root,
        'config_file': '$root${Platform.pathSeparator}code-buster.toml',
        'languages': config.languages.isEmpty
            ? <String>[config.language]
            : config.languages,
        'min_duplication_lines': config.minDuplicationLines,
        'duplication_mode': config.duplicationMode.name,
        'quality_profile': config.qualityProfile,
        'quality_gates': config.qualityGates,
        'complexity_threshold': config.complexityThreshold,
        'cognitive_threshold': config.cognitiveThreshold,
        'max_file_lines': config.maxFileLines,
        'ignore_patterns': config.ignorePatterns,
        'entry_points': config.entryPoints,
        'pattern_rules': config.patternRules.length,
        'rule_groups': _orderedRuleGroups(config.ruleGroups),
        'group_modes': <String, String>{
          for (final String group in config.groupModes.keys.toList()..sort())
            group: config.groupModes[group]!.configValue,
        },
        'rule_modes': <String, String>{
          for (final String rule in config.ruleModes.keys.toList()..sort())
            rule: config.ruleModes[rule]!.configValue,
        },
        'severity_off': config.disabledRules.toList()..sort(),
        'include': config.includes,
        'exclude': config.excludes,
        'only': options.only,
        'changed_base': config.changedBase,
        'changed_lines': config.changedLines,
        'structure_source_roots': config.structureSourceRoots,
        'structure_max_top_level_files': config.structureMaxTopLevelFiles,
        'structure_allowed_top_level': config.structureAllowedTopLevel,
        'structure_required_dirs': config.structureRequiredDirectories,
        'architecture_layers': config.architectureLayers,
        'architecture_allowed_dependencies':
            config.architectureAllowedDependencies,
        'architecture_denied_dependencies':
            config.architectureDeniedDependencies,
        if (config.dartMvvmEnabled) ...<String, Object>{
          'architecture_profile': config.architectureProfile,
          'mvvm_views': config.mvvmViews,
          'mvvm_view_models': config.mvvmViewModels,
          'mvvm_models': config.mvvmModels,
          'mvvm_repositories': config.mvvmRepositories,
          'mvvm_strict_view_model_boundary': config.mvvmStrictViewModelBoundary,
        },
      }),
    );
  } else {
    stdout.writeln('root=${config.root}');
    stdout.writeln('lang=${config.language}');
    stdout.writeln('min_duplication_lines=${config.minDuplicationLines}');
    stdout.writeln('duplication_mode=${config.duplicationMode.name}');
    stdout.writeln('quality_profile=${config.qualityProfile}');
    stdout.writeln('quality_gates=${config.qualityGates.join(',')}');
    stdout.writeln('complexity_threshold=${config.complexityThreshold}');
    stdout.writeln('cognitive_threshold=${config.cognitiveThreshold}');
    stdout.writeln('max_file_lines=${config.maxFileLines}');
    stdout.writeln('ignore_patterns=${config.ignorePatterns.join(',')}');
    stdout.writeln('entry_points=${config.entryPoints.join(',')}');
    for (final String group in config.groupModes.keys.toList()..sort()) {
      stdout.writeln(
        'rules.groups.$group=${config.groupModes[group]!.configValue}',
      );
    }
    for (final String rule in config.ruleModes.keys.toList()..sort()) {
      stdout.writeln('rules.mode.$rule=${config.ruleModes[rule]!.configValue}');
    }
  }
  return 0;
}

List<String> _orderedRuleGroups(Set<String> groups) {
  const List<String> preferred = <String>[
    'core',
    'dart-style',
    'yagni',
    'design',
    'security',
    'style',
    'nim-style',
    'nim-advanced',
    'game-engine',
    'architecture',
    'zerocost',
    'idiomatic',
    'suspicious',
    'strings',
    'sql',
    'regex',
  ];
  return <String>[
    ...preferred.where(groups.contains),
    ...(groups.difference(preferred.toSet()).toList()..sort()),
  ];
}
