// Repositories advertise their shape through manifests and directories, allowing sensible exclusions without a mandatory config file.

import 'dart:convert';

import 'dart:io';

/// Built-in repository classification inferred without project configuration.
final class RepositoryDefaults {
  /// Creates inferred defaults with provenance labels.
  const RepositoryDefaults({required this.profiles, required this.ignores});

  /// Detected language/framework profiles, including nested projects.
  final List<String> profiles;

  /// Production-scope ignore globs.
  final List<String> ignores;

  /// Infers production-oriented defaults from manifests and conventional paths.
  factory RepositoryDefaults.infer(
    String root, {
    bool includeTests = false,
    bool includeExamples = false,
    bool includeVendored = false,
  }) {
    final Set<String> profiles = <String>{};
    final Directory directory = Directory(root).absolute;
    if (directory.existsSync()) {
      for (final File file
          in directory
              .listSync(recursive: true, followLinks: false)
              .whereType<File>()) {
        final String relative = file.path
            .substring(directory.absolute.path.length)
            .replaceAll('\\', '/')
            .replaceFirst(RegExp(r'^/'), '');
        if (_manifestExcluded(relative)) continue;
        final String name = file.uri.pathSegments.last.toLowerCase();
        if (name == 'pubspec.yaml') {
          final String source = _readManifest(file);
          profiles.add(source.contains('flutter:') ? 'flutter' : 'dart');
        } else if (name == 'package.json') {
          final String source = _readManifest(file);
          profiles.add(
            source.contains(RegExp(r'''["'](?:react|react-dom)["']\s*:'''))
                ? 'react'
                : 'javascript/node',
          );
        } else if (name.endsWith('.sln') ||
            name.endsWith('.slnx') ||
            name.endsWith('.csproj')) {
          profiles.add('dotnet');
        }
      }
    }

    if (File('${directory.path}/bin/flutter').existsSync() &&
        File('${directory.path}/packages/flutter/pubspec.yaml').existsSync()) {
      profiles.add('flutter-sdk');
    }
    if (File('${directory.path}/configure.ac').existsSync() &&
        Directory('${directory.path}/src/backend').existsSync() &&
        Directory('${directory.path}/contrib').existsSync()) {
      profiles.add('postgresql');
    }
    final List<String> ignores = <String>[];
    if (!includeTests) ignores.addAll(_testIgnores);
    if (!includeExamples) ignores.addAll(_exampleIgnores);
    if (!includeVendored) ignores.addAll(_vendorIgnores);
    ignores.addAll(const <String>[
      '**/.dart_tool/**',
      '**/*.generated.*',
      '**/*.gen.go',
      '**/*.pb.go',
      '**/*.pb.cc',
      '**/*.pb.h',
      '**/migrations/**/definition.sql',
    ]);
    if (profiles.contains('flutter') && !includeTests) {
      ignores.add('**/integration_test/**');
    }
    if (profiles.contains('flutter-sdk')) {
      if (!includeTests) {
        ignores.addAll(const <String>[
          'dev/a11y_assessments/**',
          'dev/devicelab/**',
          'dev/integration_tests/**',
          'dev/manual_tests/**',
          'engine/src/flutter/testing/**',
        ]);
      }
      if (!includeExamples) ignores.add('dev/benchmarks/**');
    }
    if (profiles.contains('react') && !includeTests) {
      ignores.add('**/__fixtures__/**');
    }
    if (profiles.contains('dotnet') && !includeTests) {
      ignores.add('**/TestResults/**');
    }
    if (profiles.contains('postgresql') && !includeTests) {
      ignores.add('contrib/*/sql/**');
    }
    return RepositoryDefaults(
      profiles: List<String>.unmodifiable(profiles.toList()..sort()),
      ignores: List<String>.unmodifiable(ignores),
    );
  }

  /// Whether [relative] matches a slash-separated glob [pattern].
  static bool matches(String relative, String pattern) {
    final String expression = RegExp.escape(pattern.replaceAll('\\', '/'))
        .replaceAll(r'\*\*/', r'(?:.*/)?')
        .replaceAll(r'\*\*', r'.*')
        .replaceAll(r'\*', r'[^/]*')
        .replaceAll(r'\?', r'[^/]');
    return RegExp('^$expression\$').hasMatch(relative.replaceAll('\\', '/'));
  }

  /// Classifies a project-relative path for diagnostics and inspection.
  static String classify(String relative) {
    final String normalized = relative.replaceAll('\\', '/').toLowerCase();
    final List<String> segments = normalized.split('/');
    final String name = segments.last;
    bool has(Set<String> names) => segments.any(names.contains);
    if (RegExp(
      r'(?:_test\.(?:go|py|rs)|_spec\.rb|\.(?:test|spec)\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)|tests?\.java|\.snap)$',
    ).hasMatch(name)) {
      return 'test';
    }
    if (name.contains('.generated.') ||
        name.contains('_generated.') ||
        name.endsWith('.gen.go') ||
        name.endsWith('.pb.go') ||
        name.endsWith('.pb.cc') ||
        name.endsWith('.pb.h')) {
      return 'generated';
    }
    if (RegExp(
      r'(?:^|/)src/[^/]*test(?:fixtures)?(?:/|$)',
    ).hasMatch(normalized)) {
      return 'test';
    }
    if (normalized.contains('/src/it/') ||
        normalized.endsWith('/src/it') ||
        normalized == 'src/it' ||
        normalized.contains('/src/testfixtures/') ||
        normalized.endsWith('/src/testfixtures') ||
        normalized == 'src/testfixtures') {
      return 'test';
    }
    if (has(const <String>{
          'test',
          'tests',
          '__tests__',
          'testassets',
          'test_assets',
          'integration_test',
          'integration_tests',
          'test_integration',
          'test_fixes',
          'testcase',
          'testcases',
          '__testfixtures__',
          'test_profile',
          'test_release',
          'automated_tests',
          'testing',
          'manual_tests',
          'testresults',
          '__fixtures__',
          'fixture',
          'fixtures',
        }) ||
        segments.any(
          (String segment) =>
              segment.endsWith('.tests') ||
              segment.endsWith('.unittests') ||
              segment.endsWith('.integrationtests') ||
              segment.contains('.tests.'),
        )) {
      return 'test';
    }
    if (has(const <String>{
          'example',
          'examples',
          'sample',
          'samples',
          'demo',
          'demos',
          'docs_src',
          'bench',
          'benchmark',
          'benchmarks',
          'storybook',
          'evals',
        }) ||
        segments.any(
          (String segment) =>
              segment.startsWith('example_') ||
              segment.endsWith('.benchmark') ||
              segment.endsWith('.benchmarks'),
        )) {
      return 'example';
    }
    if (has(const <String>{'vendor', 'third_party', 'compiled'})) {
      return 'vendored';
    }
    if (has(const <String>{'build', 'dist', 'obj', '.dart_tool'})) {
      return 'generated';
    }
    return 'production';
  }

  static bool _manifestExcluded(String relative) {
    final String normalized = '/${relative.toLowerCase()}/';
    return const <String>[
      '/.git/',
      '/node_modules/',
      '/build/',
      '/dist/',
      '/obj/',
      '/vendor/',
      '/third_party/',
      '/.dart_tool/',
    ].any(normalized.contains);
  }

  static const List<String> _testIgnores = <String>[
    '**/test/**',
    '**/tests/**',
    '**/integration_tests/**',
    '**/test_integration/**',
    '**/*_integration_test_support/**',
    '**/test_fixes/**',
    '**/test_profile/**',
    '**/test_release/**',
    '**/automated_tests/**',
    '**/testing/**',
    '**/manual_tests/**',
    '**/*Tests/**',
    '**/*.Tests*/**',
    '**/*.UnitTests/**',
    '**/*.IntegrationTests/**',
    '**/testcase/**',
    '**/testcases/**',
    '**/__testfixtures__/**',
    '**/__tests__/**',
    '**/fixture/**',
    '**/fixtures/**',
    '**/testassets/**',
    '**/TestAssets/**',
    '**/test_assets/**',
    '**/src/*Test/**',
    '**/src/*test/**',
    '**/testdata/**',
    '**/src/it/**',
    '**/src/testFixtures/**',
    '**/__snapshots__/**',
    '**/*.snap',
    '**/*_test.go',
    '**/*_test.py',
    '**/*_test.rs',
    '**/*_test.cc',
    '**/*_test.cpp',
    '**/*_unittest.cc',
    '**/*_unittests.cc',
    '**/*_unittest.cpp',
    '**/*_unittests.cpp',
    '**/*_spec.rb',
    '**/*Test.java',
    '**/*Tests.java',
    '**/*.test.js',
    '**/*.test.jsx',
    '**/*.test.mjs',
    '**/*.test.cjs',
    '**/*.test.ts',
    '**/*.test.tsx',
    '**/*.test.mts',
    '**/*.test.cts',
    '**/*.spec.js',
    '**/*.spec.jsx',
    '**/*.spec.mjs',
    '**/*.spec.cjs',
    '**/*.spec.ts',
    '**/*.spec.tsx',
    '**/*.spec.mts',
    '**/*.spec.cts',
  ];
  static const List<String> _exampleIgnores = <String>[
    '**/example/**',
    '**/examples/**',
    '**/docs_src/**',
    '**/evals/**',
    '**/example_*/**',
    '**/sample/**',
    '**/samples/**',
    '**/Samples/**',
    '**/demo/**',
    '**/demos/**',
    '**/Demo/**',
    '**/Demos/**',
    '**/bench/**',
    '**/Bench/**',
    '**/benchmark/**',
    '**/Benchmark/**',
    '**/benchmarks/**',
    '**/Benchmarks/**',
    '**/*.Benchmark/**',
    '**/*.Benchmarks/**',
    '**/storybook/**',
  ];
  static const List<String> _vendorIgnores = <String>[
    '**/vendor/**',
    '**/third_party/**',
    '**/compiled/**',
  ];
  static String _readManifest(File file) =>
      utf8.decode(file.readAsBytesSync(), allowMalformed: true);
}
