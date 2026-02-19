// Invalid keys and incompatible values should fail before analysis, with messages tied to the configuration users can edit.

/// Validates parsed Code Buster configuration tables and values.
final class CodeBusterConfigValidator {
  /// Returns deterministic diagnostics for [values].
  static List<String> validate(
    Map<String, dynamic> values, {
    required void Function() verifyLoad,
  }) {
    const Map<String, Set<String>?> schema = <String, Set<String>?>{
      'analysis': <String>{
        'duplication_min_lines',
        'duplication_mode',
        'complexity_threshold',
        'cognitive_complexity_threshold',
        'max_file_lines',
        'max_function_lines',
        'csharp_dead_code',
      },
      'files': <String>{'include', 'exclude', 'ignore', 'entry_points'},
      'classification': <String>{'production', 'test', 'generated'},
      'rules': <String>{
        'enabled_groups',
        'groups',
        'mode',
        'patterns',
        'severity',
      },
      'structure': <String>{
        'source_roots',
        'max_root_files',
        'max_top_level_files',
        'allowed_root_files',
        'allowed_top_level',
        'required_directories',
        'required_dirs',
      },
      'architecture': <String>{
        'profile',
        'layers',
        'allowed_dependencies',
        'denied_dependencies',
        'mvvm',
      },
      'review': <String>{'changed_base', 'fail_on_findings'},
      'quality': <String>{'profile', 'gates'},
    };
    const Set<String> legacy = <String>{
      'lang',
      'entry_points',
      'ignore_patterns',
      'min_duplication_lines',
      'complexity_threshold',
      'cognitive_threshold',
      'max_file_lines',
      'max_function_lines',
      'csharp_dead_code',
      'rule_groups',
      'pattern_rules',
      'severity',
      'structure_source_roots',
      'structure_max_top_level_files',
      'structure_allowed_top_level',
      'structure_required_dirs',
    };
    final List<String> diagnostics = <String>[];
    for (final MapEntry<String, dynamic> entry in values.entries) {
      if (entry.key == 'languages' || legacy.contains(entry.key)) continue;
      final Set<String>? keys = schema[entry.key];
      if (keys == null) {
        diagnostics.add('unknown configuration key: ${entry.key}');
        continue;
      }
      if (entry.value is! Map<String, dynamic>) {
        diagnostics.add('expected table: ${entry.key}');
        continue;
      }
      for (final String key in (entry.value as Map<String, dynamic>).keys) {
        if (!keys.contains(key)) {
          diagnostics.add('unknown configuration key: ${entry.key}.$key');
        }
      }
    }
    final Map<String, dynamic> quality = _table(values, 'quality');
    final String qualityProfile = _string(
      quality,
      'profile',
      fallback: 'standard',
    );
    if (!const <String>{
      'standard',
      'strict',
      'security',
    }.contains(qualityProfile)) {
      diagnostics.add('unsupported quality profile: $qualityProfile');
    }
    final Object? rawGates = quality['gates'];
    if (rawGates is List) {
      for (final Object? gate in rawGates) {
        if (gate is String && !_qualityGatePattern.hasMatch(gate)) {
          diagnostics.add('unsupported quality gate condition: $gate');
        }
      }
    }
    final Map<String, dynamic> analysis = _table(values, 'analysis');
    final String duplicationMode = _string(
      analysis,
      'duplication_mode',
      fallback: 'exact',
    );
    if (!const <String>{
      'exact',
      'normalized',
      'semantic',
    }.contains(duplicationMode)) {
      diagnostics.add('unsupported duplication mode: $duplicationMode');
    }
    final Map<String, dynamic> architecture = _table(values, 'architecture');
    final String profile = _string(architecture, 'profile', fallback: '');
    if (profile.isNotEmpty && profile != 'dart-mvvm') {
      diagnostics.add('unsupported architecture profile: $profile');
    }
    final Map<String, dynamic> mvvm = _table(architecture, 'mvvm');
    const Set<String> mvvmKeys = <String>{
      'views',
      'view_models',
      'models',
      'repositories',
      'strict_view_model_boundary',
    };
    for (final String key in mvvm.keys) {
      if (!mvvmKeys.contains(key)) {
        diagnostics.add('unknown configuration key: architecture.mvvm.$key');
      }
    }
    try {
      verifyLoad();
    } on Object catch (error) {
      diagnostics.add(error.toString());
    }
    return diagnostics;
  }

  static final RegExp _qualityGatePattern = RegExp(
    r'^\s*[a-z][a-z0-9_.]*\s*(?:==|!=|<=|>=|<|>)\s*\d+(?:\.\d+)?\s*$',
  );

  static Map<String, dynamic> _table(Map<String, dynamic> values, String key) {
    final dynamic value = values[key];
    return value is Map<String, dynamic> ? value : <String, dynamic>{};
  }

  static String _string(
    Map<String, dynamic> values,
    String key, {
    required String fallback,
  }) {
    final dynamic value = values[key];
    return value is String ? value : fallback;
  }
}
