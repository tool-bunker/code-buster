// Manifest constraints provide useful runtime context, so this parser collects them without making language adapters understand package files.

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;

/// Detects declared language and runtime constraints without invoking toolchains.
final class LanguageVersionDetector {
  /// Creates the stateless detector.
  const LanguageVersionDetector();

  /// Reads conventional manifests below [root] in deterministic path order.
  Map<String, String> detect(String root) {
    final List<File> manifests =
        Directory(root)
            .listSync(recursive: true, followLinks: false)
            .whereType<File>()
            .where(
              (File file) => _manifestNames.contains(path.basename(file.path)),
            )
            .where((File file) => !_ignored(file.path, root))
            .toList()
          ..sort((File left, File right) => left.path.compareTo(right.path));
    final Map<String, String> result = <String, String>{};
    for (final File file in manifests) {
      final String name = path.basename(file.path);
      final String source = utf8.decode(
        file.readAsBytesSync(),
        allowMalformed: true,
      );
      switch (name) {
        case 'pubspec.yaml':
          _put(result, 'dart', _yamlConstraint(source, 'sdk'));
        case 'package.json':
          _packageJson(result, source);
        case 'go.mod':
          _put(
            result,
            'go',
            RegExp(
              r'^\s*go\s+(\S+)',
              multiLine: true,
            ).firstMatch(source)?.group(1),
          );
        case 'pyproject.toml':
          _put(
            result,
            'python',
            RegExp(
              r'''requires-python\s*=\s*["']([^"']+)''',
            ).firstMatch(source)?.group(1),
          );
        case 'pom.xml':
          _put(
            result,
            'java',
            RegExp(
              r'<maven\.compiler\.(?:release|source)>\s*([^<]+)',
            ).firstMatch(source)?.group(1)?.trim(),
          );
        case 'gradle.properties':
          _put(
            result,
            'java',
            RegExp(
              r'^\s*(?:javaVersion|java_version)\s*=\s*(\S+)',
              multiLine: true,
            ).firstMatch(source)?.group(1),
          );
      }
    }
    return Map<String, String>.unmodifiable(result);
  }

  void _packageJson(Map<String, String> result, String source) {
    try {
      final Object? decoded = jsonDecode(source);
      if (decoded is! Map<String, Object?>) return;
      final Object? engines = decoded['engines'];
      if (engines is Map<String, Object?>) {
        _put(result, 'node', engines['node']?.toString());
      }
      for (final String section in <String>[
        'dependencies',
        'devDependencies',
      ]) {
        final Object? dependencies = decoded[section];
        if (dependencies is Map<String, Object?>) {
          _put(result, 'typescript', dependencies['typescript']?.toString());
        }
      }
    } on FormatException {
      // Configuration diagnostics will own malformed manifest reporting.
    }
  }

  String? _yamlConstraint(String source, String key) => RegExp(
    '^\\s{2}${RegExp.escape(key)}:\\s*["\']?([^"\'\\n]+)',
    multiLine: true,
  ).firstMatch(source)?.group(1)?.trim();

  void _put(Map<String, String> result, String language, String? version) {
    if (version != null && version.isNotEmpty) {
      result.putIfAbsent(language, () => version);
    }
  }

  bool _ignored(String filePath, String root) {
    final String relative = path
        .relative(filePath, from: root)
        .replaceAll('\\', '/');
    return relative
        .split('/')
        .any(
          const <String>{
            '.git',
            '.dart_tool',
            'node_modules',
            'build',
            'dist',
            'target',
          }.contains,
        );
  }

  static const Set<String> _manifestNames = <String>{
    'pubspec.yaml',
    'package.json',
    'go.mod',
    'pyproject.toml',
    'pom.xml',
    'gradle.properties',
  };
}
