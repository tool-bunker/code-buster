// Configuration syntax evolves; this migrator makes old files explicit and reviewable instead of silently changing their meaning.

import 'dart:io';

/// Comment-preserving migration from legacy flat configuration keys.
final class CodeBusterConfigMigrator {
  /// Migrates [source] while preserving comments, blank lines, and ordering.
  static String migrate(String source) {
    var section = '';
    final StringBuffer output = StringBuffer();
    final List<String> lines = source.split('\n');
    if (source.endsWith('\n')) lines.removeLast();
    for (final String rawLine in lines) {
      var line = rawLine;
      final String trimmed = line.trim();
      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        section = trimmed.substring(1, trimmed.length - 1);
        if (section == 'severity') {
          section = 'rules.severity';
          line = line.replaceFirst('[severity]', '[rules.severity]');
        }
        output.writeln(line);
        continue;
      }
      if (trimmed.isEmpty ||
          trimmed.startsWith('#') ||
          !trimmed.contains('=')) {
        output.writeln(line);
        continue;
      }
      final int separator = trimmed.indexOf('=');
      final String key = trimmed.substring(0, separator).trim();
      var value = trimmed.substring(separator + 1).trim();
      var replacement = key;
      if (section.isEmpty) {
        replacement = switch (key) {
          'lang' || 'languages' => 'languages',
          'complexity_threshold' => 'analysis.complexity_threshold',
          'cognitive_threshold' => 'analysis.cognitive_complexity_threshold',
          'min_duplication_lines' => 'analysis.duplication_min_lines',
          'max_file_lines' ||
          'max_function_lines' ||
          'csharp_dead_code' => 'analysis.$key',
          'entry_points' => 'files.entry_points',
          'ignore_patterns' => 'files.ignore',
          'include' || 'exclude' => 'files.$key',
          'rule_groups' => 'rules.enabled_groups',
          'pattern_rules' => 'rules.patterns',
          _ => key,
        };
        if ((key == 'lang' || key == 'languages') && !value.startsWith('[')) {
          value = '[$value]';
        }
      } else if (section == 'structure') {
        replacement = switch (key) {
          'max_top_level_files' => 'max_root_files',
          'allowed_top_level' => 'allowed_root_files',
          'required_dirs' => 'required_directories',
          _ => key,
        };
      }
      final String indent = line.substring(
        0,
        line.length - line.trimLeft().length,
      );
      output.writeln('$indent$replacement = $value');
    }
    final String result = output.toString();
    return source.endsWith('\n')
        ? result
        : result.substring(0, result.length - 1);
  }

  /// Migrates the project configuration, making a `.bak` copy when changed.
  static bool migrateFile(String root, {bool dryRun = false}) {
    final File file = File('$root${Platform.pathSeparator}code-buster.toml');
    if (!file.existsSync()) {
      throw FileSystemException('configuration not found', file.path);
    }
    final String original = file.readAsStringSync();
    final String migrated = migrate(original);
    if (migrated == original) return false;
    if (!dryRun) {
      File('${file.path}.bak').writeAsStringSync(original);
      file.writeAsStringSync(migrated);
    }
    return true;
  }
}
