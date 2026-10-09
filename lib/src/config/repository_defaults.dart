// Repositories advertise their shape through manifests and directories, allowing sensible exclusions without a mandatory config file.

import 'dart:convert';
import 'dart:io';

import '../core/regexp_cache.dart';

/// Built-in repository classification inferred without project configuration.
final class RepositoryDefaults {
  /// Creates inferred defaults with provenance labels.
  const RepositoryDefaults({
    required this.profiles,
    required this.frameworks,
    required this.ignores,
  });

  /// Detected language/framework profiles, including nested projects.
  final List<String> profiles;

  /// Detected application frameworks that activate framework rule overlays.
  final Set<String> frameworks;

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
            .replaceFirst(cachedRegExp(r'^/'), '');
        if (_manifestExcluded(relative)) continue;
        final String name = file.uri.pathSegments.last.toLowerCase();
        if (name == 'pubspec.yaml') {
          final String source = _readManifest(file);
          profiles.add(source.contains('flutter:') ? 'flutter' : 'dart');
        } else if (name == 'package.json') {
          final String source = _readManifest(file);
          var detectedFramework = false;
          if (cachedRegExp(
            r'''["'](?:react|react-dom)["']\s*:''',
          ).hasMatch(source)) {
            profiles.add('react');
            detectedFramework = true;
          }
          if (cachedRegExp(
            r'''["'](?:svelte|@sveltejs/kit)["']\s*:''',
          ).hasMatch(source)) {
            profiles.add('svelte');
            detectedFramework = true;
          }
          if (cachedRegExp(
            r'''["'](?:pixi\.js|@pixi/[^"']+)["']\s*:''',
          ).hasMatch(source)) {
            profiles.add('pixijs');
            detectedFramework = true;
          }
          if (!detectedFramework) profiles.add('javascript/node');
        } else if (const <String>{
          'requirements.txt',
          'pyproject.toml',
          'poetry.lock',
          'pdm.lock',
        }.contains(name)) {
          final String source = _readManifest(file);
          if (cachedRegExp(
            r'''(^|[\s"'=])fastapi(?:[\s"'<>=~^]|$)''',
            caseSensitive: false,
          ).hasMatch(source)) {
            profiles.add('fastapi');
          }
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
      '**/*.backup.js',
      '**/*.backup.jsx',
      '**/*.backup.mjs',
      '**/*.backup.cjs',
      '**/*.backup.ts',
      '**/*.backup.tsx',
      '**/*.backup.mts',
      '**/*.backup.cts',
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
      frameworks: Set<String>.unmodifiable(<String>{
        if (profiles.contains('flutter') || profiles.contains('flutter-sdk'))
          'flutter',
        if (profiles.contains('react')) 'react',
        if (profiles.contains('fastapi')) 'fastapi',
        if (profiles.contains('svelte')) 'svelte',
        if (profiles.contains('pixijs')) 'pixijs',
      }),
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
    return cachedRegExp(
      '^$expression\$',
    ).hasMatch(relative.replaceAll('\\', '/'));
  }

  /// Classifies a project-relative path for diagnostics and inspection.
  static String classify(String relative) {
    final String normalized = relative.replaceAll('\\', '/').toLowerCase();
    final List<String> segments = normalized.split('/');
    final String name = segments.last;
    final Set<String> segmentSet = segments.toSet();
    final int flavors = _pathFlavors(segments);

    if ((flavors & _underscoreTestFlavor) != 0 || _isTestFileName(name)) {
      return 'test';
    }
    if (_isGeneratedFileName(name)) return 'generated';
    if (_isTestPath(normalized, name, segmentSet, flavors)) return 'test';
    if (_isExamplePath(segments, segmentSet, flavors)) return 'example';
    if (_hasSegment(segmentSet, const <String>{
      'vendor',
      'vendored',
      'third_party',
      'compiled',
      'cargokit',
    })) {
      return 'vendored';
    }
    if (_isGeneratedDirectory(segments, segmentSet)) return 'generated';
    return 'production';
  }

  static const int _underscoreTestFlavor = 1;
  static const int _testFlavor = 2;
  static const int _exampleFlavor = 4;

  static int _pathFlavors(List<String> segments) {
    var result = 0;
    for (final String segment in segments) {
      if (segment.endsWith('_test')) result |= _underscoreTestFlavor;
      if (segment.endsWith('.test') ||
          segment.endsWith('.tests') ||
          segment.endsWith('.unittest') ||
          segment.endsWith('.unittests') ||
          segment.endsWith('.integrationtest') ||
          segment.endsWith('.integrationtests') ||
          segment.contains('.tests.') ||
          segment == 'test-unit' ||
          segment == 'tests-unit' ||
          segment == 'unit-tests') {
        result |= _testFlavor;
      }
      if (segment.startsWith('example_') ||
          segment.endsWith('_examples') ||
          segment.endsWith('-examples') ||
          segment.endsWith('.benchmark') ||
          segment.endsWith('.benchmarks')) {
        result |= _exampleFlavor;
      }
    }
    return result;
  }

  static bool _isTestFileName(String name) => cachedRegExp(
    r'(?:_test\.(?:dart|go|py|rs)|_spec\.rb|\.(?:test|spec)\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)|tests?\.java|\.snap)$',
  ).hasMatch(name);

  static bool _isGeneratedFileName(String name) =>
      name.contains('.generated.') ||
      name.contains('_generated.') ||
      cachedRegExp(
        r'\.backup\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$',
      ).hasMatch(name) ||
      name.endsWith('.gen.go') ||
      name.endsWith('.pb.go') ||
      name.endsWith('.pb.cc') ||
      name.endsWith('.pb.h');

  static bool _isTestPath(
    String normalized,
    String name,
    Set<String> segments,
    int flavors,
  ) =>
      cachedRegExp(r'^(?:test_?util|test_?helpers?)\.[^.]+$').hasMatch(name) ||
      cachedRegExp(
        r'(?:^|/)src/[^/]*test(?:fixtures)?(?:/|$)',
      ).hasMatch(normalized) ||
      normalized.contains('/src/it/') ||
      normalized.endsWith('/src/it') ||
      normalized == 'src/it' ||
      normalized.contains('/src/testfixtures/') ||
      normalized.endsWith('/src/testfixtures') ||
      normalized == 'src/testfixtures' ||
      _hasSegment(segments, const <String>{
        'test',
        'tests',
        '__tests__',
        'test_suite',
        'testassets',
        'testenv',
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
      (flavors & _testFlavor) != 0;

  static bool _isExamplePath(
    List<String> path,
    Set<String> segments,
    int flavors,
  ) =>
      path.first == 'templates' ||
      _hasSegment(segments, const <String>{
        'example',
        'examples',
        'sample',
        'samples',
        'demo',
        'demos',
        'docs_src',
        'benches',
        'bench',
        'benchmark',
        'benchmarks',
        'storybook',
        'evals',
      }) ||
      (flavors & _exampleFlavor) != 0;

  static bool _isGeneratedDirectory(List<String> path, Set<String> segments) {
    final int buildIndex = path.indexOf('build');
    final bool sourceBuildDirectory =
        buildIndex > 0 &&
        const <String>{
          'command',
          'commands',
          'cmd',
          'cmds',
        }.contains(path[buildIndex - 1]);
    return (!sourceBuildDirectory && buildIndex >= 0) ||
        _hasSegment(segments, const <String>{'dist', 'obj', '.dart_tool'});
  }

  static bool _hasSegment(Set<String> segments, Set<String> names) =>
      segments.any(names.contains);

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
    '**/*_test/**',
    '**/tests/**',
    '**/test_suite/**',
    '**/testenv/**',
    '**/testutil.*',
    '**/test_util.*',
    '**/testhelper.*',
    '**/test_helper.*',
    '**/testhelpers.*',
    '**/test_helpers.*',
    '**/test.ts',
    '**/test.tsx',
    '**/test.js',
    '**/test.jsx',
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
    '**/*.Test/**',
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
    '**/*_test.dart',
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
    '**/*-examples/**',
    '**/sample/**',
    '**/samples/**',
    '**/Samples/**',
    '**/demo/**',
    '**/demos/**',
    '**/Demo/**',
    '**/Demos/**',
    '**/benches/**',
    '**/bench/**',
    '**/Bench/**',
    '**/benchmark/**',
    '**/Benchmark/**',
    '**/benchmarks/**',
    '**/Benchmarks/**',
    '**/*.Benchmark/**',
    '**/*.Benchmarks/**',
    '**/storybook/**',
    'templates/**',
  ];
  static const List<String> _vendorIgnores = <String>[
    '**/vendor/**',
    '**/vendored/**',
    '**/third_party/**',
    '**/compiled/**',
    '**/cargokit/**',
  ];
  static String _readManifest(File file) =>
      utf8.decode(file.readAsBytesSync(), allowMalformed: true);
}
