// Walking a real repository involves ignores, symlinks, binary files, generated code, and explicit overrides; this is the single traversal path.

import 'dart:io';

import 'package:path/path.dart' as path;

import '../config/repository_defaults.dart';
import '../core/models.dart';
import '../plugins/languages.dart';
import 'source_classifier.dart';

const Set<String> _defaultIgnoredDirectories = <String>{
  '.git',
  '.svn',
  'node_modules',
  'obj',
  'dist',
  'build',
  '.idea',
  '.vscode',
};

bool _isCompiledBundleDirectory(String name) =>
    name.toLowerCase().endsWith('.framework');

/// A discovered file and the language adapter responsible for it.
final class SourceFile {
  /// Creates one discovered source file.
  const SourceFile({
    required this.absolutePath,
    required this.relativePath,
    required this.language,
  });

  /// Normalized absolute filesystem path.
  final String absolutePath;

  /// Slash-separated path relative to the analysis root.
  final String relativePath;

  /// Canonical registered language identifier.
  final String language;
}

/// One inclusive range of changed source lines.
final class ChangedLineRange {
  /// Creates an inclusive line range.
  const ChangedLineRange(this.start, this.end);

  /// One-based first changed line.
  final int start;

  /// One-based last changed line.
  final int end;

  /// Whether [line] overlaps this range.
  bool contains(int line) => line >= start && line <= end;
}

/// Minimal nested `.gitignore` rule represented relative to its containing directory.
final class GitIgnoreRule {
  /// Creates a gitignore rule.
  const GitIgnoreRule({
    required this.base,
    required this.pattern,
    required this.negated,
    required this.directoryOnly,
  });

  /// Project-relative directory that contains the `.gitignore` file.
  final String base;

  /// Rule pattern without a leading negation or surrounding slashes.
  final String pattern;

  /// Whether the rule restores a path ignored by an earlier rule.
  final bool negated;

  /// Whether the rule applies only to directories.
  final bool directoryOnly;
}

/// Evidence explaining why one source was classified as generated.
final class GeneratedSourceProvenance {
  /// Creates generated-source classification evidence.
  const GeneratedSourceProvenance({
    required this.path,
    required this.reason,
    required this.source,
  });

  /// Project-relative source path.
  final String path;

  /// Matched convention or marker.
  final String reason;

  /// Policy layer that supplied the classification.
  final String source;

  /// Converts evidence to a machine-readable representation.
  Map<String, String> toJson() => <String, String>{
    'path': path,
    'reason': reason,
    'source': source,
  };
}

/// Deterministic source discovery and Git changed-scope resolution.
final class SourceDiscovery {
  /// Creates discovery using [config] and registered [languages].
  SourceDiscovery({required this.config, required this.languages});

  /// Effective project settings.
  final AnalysisConfig config;

  /// Registered source language metadata.
  final LanguageRegistry languages;

  static const SourceClassifier _classifier = SourceClassifier();

  final Map<String, int> _coverage = <String, int>{};
  final List<GeneratedSourceProvenance> _generatedProvenance =
      <GeneratedSourceProvenance>[];

  /// Aggregated accounting from the latest [discover] call.
  Map<String, int> get coverage => Map<String, int>.unmodifiable(_coverage);

  /// Generated source evidence from the latest [discover] call.
  List<GeneratedSourceProvenance> get generatedProvenance =>
      List<GeneratedSourceProvenance>.unmodifiable(_generatedProvenance);

  void _recordCoverage(String reason) =>
      _coverage.update(reason, (int value) => value + 1, ifAbsent: () => 1);

  /// Finds all source files matching configured language and scope filters.
  List<SourceFile> discover() {
    _coverage.clear();
    _generatedProvenance.clear();
    final Set<String> changed = config.changedBase.isEmpty
        ? const <String>{}
        : changedFiles();
    final List<LanguageDefinition> selectedLanguages = _selectedLanguages();
    final Set<String> extensions = selectedLanguages
        .expand((LanguageDefinition definition) => definition.extensions)
        .toSet();
    final LanguageDefinition? selectedLua = selectedLanguages
        .where((LanguageDefinition definition) => definition.id == 'lua')
        .firstOrNull;
    final List<GitIgnoreRule> gitRules = _loadGitIgnoreRules();
    final List<SourceFile> result = <SourceFile>[];

    void walk(Directory directory) {
      final List<FileSystemEntity> entries =
          directory.listSync(followLinks: false)..sort(
            (FileSystemEntity a, FileSystemEntity b) =>
                a.path.compareTo(b.path),
          );
      for (final FileSystemEntity entry in entries) {
        final String name = path.basename(entry.path);
        final String relative = _relative(entry.path);
        if (entry is Directory) {
          if (_defaultIgnoredDirectories.contains(name) ||
              name.startsWith('.')) {
            continue;
          }
          if (_isCompiledBundleDirectory(name)) {
            _countExcludedDirectory(entry, extensions, 'generated');
            continue;
          }
          if (config.classificationProduction.isEmpty &&
              _matchesIgnore('$relative/')) {
            _countExcludedDirectory(
              entry,
              extensions,
              RepositoryDefaults.classify(relative),
            );
            continue;
          }
          if (_isGitIgnored('$relative/', true, gitRules)) {
            _countExcludedDirectory(entry, extensions, 'git_ignored');
            continue;
          }
          walk(entry);
          continue;
        }
        final bool forcedProduction = _matchesAny(
          relative,
          config.classificationProduction,
        );
        final bool forcedGenerated = _matchesAny(
          relative,
          config.classificationGenerated,
        );
        if (entry is! File) continue;
        final String extension = path.extension(entry.path).toLowerCase();
        final LanguageDefinition? shebangLanguage =
            extension.isEmpty &&
                selectedLua != null &&
                _classifier.hasLuaShebang(entry)
            ? selectedLua
            : null;
        if (!extensions.contains(extension) && shebangLanguage == null) {
          if (_classifier.looksLikeUnsupportedSource(extension)) {
            _recordCoverage('unsupported');
          } else if (_classifier.looksBinary(extension)) {
            _recordCoverage('binary');
          }
          continue;
        }
        final bool generatedByName = _classifier.isGeneratedByName(relative);
        final bool generatedByHeader = _classifier.hasGeneratedHeader(entry);
        final bool generatedByMinification = _classifier.isMinifiedBundle(
          entry,
          extension,
        );
        if (forcedGenerated ||
            (!forcedProduction &&
                (generatedByName ||
                    generatedByHeader ||
                    generatedByMinification) &&
                !_isExplicitlyGitIncluded(relative, gitRules))) {
          _recordCoverage('generated');
          _generatedProvenance.add(
            GeneratedSourceProvenance(
              path: relative,
              reason: forcedGenerated
                  ? 'matched classification.generated override'
                  : generatedByName
                  ? 'matched generated filename convention'
                  : generatedByHeader
                  ? 'matched generated source header'
                  : 'matched minified bundle content',
              source: forcedGenerated
                  ? 'code-buster.toml'
                  : 'built-in generated policy',
            ),
          );
          continue;
        }
        if (!forcedProduction && !_shouldInclude(relative, gitRules)) {
          final String classification = RepositoryDefaults.classify(relative);
          _recordCoverage(
            _isGitIgnored(relative, false, gitRules)
                ? 'git_ignored'
                : classification == 'production'
                ? 'policy_ignored'
                : classification,
          );
          continue;
        }
        if (config.changedBase.isNotEmpty && !changed.contains(relative)) {
          _recordCoverage('unchanged');
          continue;
        }
        final LanguageDefinition? language =
            shebangLanguage ??
            languages.definitions
                .where(
                  (LanguageDefinition definition) =>
                      definition.extensions.contains(extension),
                )
                .firstOrNull;
        if (language != null) {
          _recordCoverage('selected');
          result.add(
            SourceFile(
              absolutePath: path.normalize(path.absolute(entry.path)),
              relativePath: relative,
              language: language.id,
            ),
          );
        }
      }
    }

    walk(Directory(config.root));
    result.sort(
      (SourceFile a, SourceFile b) => a.relativePath.compareTo(b.relativePath),
    );
    return List<SourceFile>.unmodifiable(result);
  }

  void _countExcludedDirectory(
    Directory directory,
    Set<String> extensions,
    String classification,
  ) {
    final String reason = switch (classification) {
      'test' || 'example' || 'vendored' || 'generated' => classification,
      _ => 'policy_ignored',
    };
    for (final FileSystemEntity entity in directory.listSync(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is File &&
          extensions.contains(path.extension(entity.path).toLowerCase())) {
        _recordCoverage(reason);
        if (reason == 'generated') {
          _generatedProvenance.add(
            GeneratedSourceProvenance(
              path: _relative(entity.path),
              reason: 'inside generated output directory',
              source: 'built-in generated policy',
            ),
          );
        }
      }
    }
  }

  bool _matchesAny(String relative, List<String> patterns) =>
      patterns.any((String pattern) => _globMatches(relative, pattern));

  bool _isExplicitlyGitIncluded(String relative, List<GitIgnoreRule> rules) {
    final String normalized = _normalizeRelative(relative);
    for (final GitIgnoreRule rule in rules.reversed) {
      if (!rule.negated ||
          (rule.base.isNotEmpty &&
              normalized != rule.base &&
              !normalized.startsWith('${rule.base}/'))) {
        continue;
      }
      final String local = rule.base.isEmpty
          ? normalized
          : normalized == rule.base
          ? ''
          : normalized.substring(rule.base.length + 1);
      if (_globMatches(local, rule.pattern) ||
          local
              .split('/')
              .any((String segment) => _globMatches(segment, rule.pattern))) {
        return true;
      }
    }
    return false;
  }

  /// Returns changed project-relative source file paths for [AnalysisConfig.changedBase].
  Set<String> changedFiles() {
    if (config.changedBase.isEmpty || config.changedBase.startsWith('-')) {
      return const <String>{};
    }
    final Set<String> result = <String>{};
    final ProcessResult diff = _git(<String>[
      'diff',
      '--name-only',
      config.changedBase,
      '--',
    ]);
    if (diff.exitCode == 0) {
      _addExistingChangedPaths(result, diff.stdout as String);
    }
    if (config.changedBase == 'HEAD') {
      final ProcessResult untracked = _git(<String>[
        'ls-files',
        '--others',
        '--exclude-standard',
      ]);
      if (untracked.exitCode == 0) {
        _addExistingChangedPaths(result, untracked.stdout as String);
      }
    }
    return Set<String>.unmodifiable(result);
  }

  /// Returns changed line ranges keyed by project-relative path.
  Map<String, List<ChangedLineRange>> changedLineRanges() {
    if (config.changedBase.isEmpty || config.changedBase.startsWith('-')) {
      return const <String, List<ChangedLineRange>>{};
    }
    final Map<String, List<ChangedLineRange>> result =
        <String, List<ChangedLineRange>>{};
    if (config.changedBase == 'HEAD') {
      final ProcessResult untracked = _git(<String>[
        'ls-files',
        '--others',
        '--exclude-standard',
      ]);
      if (untracked.exitCode == 0) {
        for (final String rawPath in (untracked.stdout as String).split('\n')) {
          final String relative = _normalizeRelative(rawPath.trim());
          final File file = File(path.join(config.root, relative));
          if (relative.isNotEmpty && file.existsSync()) {
            result[relative] = <ChangedLineRange>[
              ChangedLineRange(
                1,
                file.readAsLinesSync().length.clamp(1, 1 << 30),
              ),
            ];
          }
        }
      }
    }

    final ProcessResult diff = _git(<String>[
      'diff',
      '--unified=0',
      config.changedBase,
      '--',
    ]);
    if (diff.exitCode != 0) {
      return _immutableRanges(result);
    }
    String current = '';
    final RegExp hunk = RegExp(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@');
    for (final String line in (diff.stdout as String).split('\n')) {
      if (line.startsWith('+++ b/')) {
        current = _normalizeRelative(line.substring(6).trim());
        continue;
      }
      final RegExpMatch? match = hunk.firstMatch(line);
      if (match == null || current.isEmpty) {
        continue;
      }
      final int start = int.parse(match.group(1)!);
      final int count = int.parse(match.group(2) ?? '1');
      if (count > 0) {
        result
            .putIfAbsent(current, () => <ChangedLineRange>[])
            .add(ChangedLineRange(start, start + count - 1));
      }
    }
    return _immutableRanges(result);
  }

  List<LanguageDefinition> _selectedLanguages() {
    final Iterable<String> requested = config.languages.isEmpty
        ? <String>[config.language]
        : config.languages;
    return languages.select(requested).toList(growable: false);
  }

  bool _shouldInclude(String relative, List<GitIgnoreRule> gitRules) {
    if (_matchesIgnore(relative) ||
        _matchesPrefixes(relative, config.excludes)) {
      return false;
    }
    if (config.includes.isNotEmpty &&
        !_matchesPrefixes(relative, config.includes)) {
      return false;
    }
    return !_isGitIgnored(relative, false, gitRules);
  }

  bool _matchesIgnore(String relative) =>
      _matchesPrefixes(relative, config.ignorePatterns);

  bool _matchesPrefixes(String relative, Iterable<String> patterns) {
    final String normalized = _normalizeRelative(relative);
    for (final String rawPattern in patterns) {
      final String pattern = _normalizeRelative(
        rawPattern.trim(),
      ).replaceAll(RegExp(r'^/+|/+$'), '');
      final bool wildcard = pattern.contains('*');
      if (pattern.isNotEmpty &&
          ((wildcard && _globMatches(normalized, pattern)) ||
              (!wildcard &&
                  (normalized.startsWith(pattern) ||
                      normalized.contains('/$pattern'))))) {
        return true;
      }
    }
    return false;
  }

  List<GitIgnoreRule> _loadGitIgnoreRules() {
    final List<File> files = <File>[];

    void collect(Directory directory) {
      for (final FileSystemEntity entry in directory.listSync(
        followLinks: false,
      )) {
        final String name = path.basename(entry.path);
        if (entry is Directory) {
          if (!_defaultIgnoredDirectories.contains(name)) {
            collect(entry);
          }
        } else if (entry is File && name == '.gitignore') {
          files.add(entry);
        }
      }
    }

    collect(Directory(config.root));
    files.sort((File a, File b) => a.path.compareTo(b.path));
    final List<GitIgnoreRule> rules = <GitIgnoreRule>[];
    for (final File file in files) {
      final String base = _relative(path.dirname(file.path));
      for (final String rawLine in file.readAsLinesSync()) {
        final String line = rawLine.trim();
        if (line.isEmpty || line.startsWith('#')) {
          continue;
        }
        final bool negated = line.startsWith('!');
        final String withoutNegation = negated ? line.substring(1) : line;
        rules.add(
          GitIgnoreRule(
            base: base == '.' ? '' : base,
            pattern: withoutNegation.replaceAll(RegExp(r'^/+|/+$'), ''),
            negated: negated,
            directoryOnly: withoutNegation.endsWith('/'),
          ),
        );
      }
    }
    return rules;
  }

  bool _isGitIgnored(
    String relative,
    bool isDirectory,
    List<GitIgnoreRule> rules,
  ) {
    final String normalized = _normalizeRelative(
      relative,
    ).replaceAll(RegExp(r'/$'), '');
    var ignored = false;
    for (final GitIgnoreRule rule in rules) {
      if (rule.base.isNotEmpty &&
          normalized != rule.base &&
          !normalized.startsWith('${rule.base}/')) {
        continue;
      }
      final String local = rule.base.isEmpty
          ? normalized
          : normalized == rule.base
          ? ''
          : normalized.substring(rule.base.length + 1);
      final bool matches = rule.pattern.contains('*')
          ? _globMatches(local, rule.pattern) ||
                local
                    .split('/')
                    .any(
                      (String segment) => _globMatches(segment, rule.pattern),
                    )
          : local == rule.pattern ||
                local.startsWith('${rule.pattern}/') ||
                local.split('/').contains(rule.pattern);
      if (matches &&
          (!rule.directoryOnly ||
              isDirectory ||
              local.startsWith('${rule.pattern}/'))) {
        ignored = !rule.negated;
      }
    }
    return ignored;
  }

  bool _globMatches(String text, String pattern) {
    final StringBuffer expression = StringBuffer('^');
    for (var index = 0; index < pattern.length; index++) {
      if (pattern[index] == '*') {
        if (index + 1 < pattern.length && pattern[index + 1] == '*') {
          if (index + 2 < pattern.length && pattern[index + 2] == '/') {
            expression.write('(?:.*/)?');
            index += 2;
          } else {
            expression.write('.*');
            index++;
          }
        } else {
          expression.write('[^/]*');
        }
      } else {
        expression.write(RegExp.escape(pattern[index]));
      }
    }
    expression.write(r'$');
    return RegExp(expression.toString()).hasMatch(text);
  }

  void _addExistingChangedPaths(Set<String> paths, String output) {
    for (final String rawPath in output.split('\n')) {
      final String relative = _normalizeRelative(rawPath.trim());
      if (relative.isNotEmpty &&
          File(path.join(config.root, relative)).existsSync()) {
        paths.add(relative);
      }
    }
  }

  ProcessResult _git(List<String> arguments) => Process.runSync(
    'git',
    <String>['-C', config.root, ...arguments],
    stdoutEncoding: const SystemEncoding(),
    stderrEncoding: const SystemEncoding(),
  );

  String _relative(String value) =>
      _normalizeRelative(path.relative(value, from: config.root));

  String _normalizeRelative(String value) => value.replaceAll('\\', '/');
}

Map<String, List<ChangedLineRange>> _immutableRanges(
  Map<String, List<ChangedLineRange>> ranges,
) => Map<String, List<ChangedLineRange>>.unmodifiable(
  ranges.map(
    (String path, List<ChangedLineRange> values) =>
        MapEntry(path, List<ChangedLineRange>.unmodifiable(values)),
  ),
);
