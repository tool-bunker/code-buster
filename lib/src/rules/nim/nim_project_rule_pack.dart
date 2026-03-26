// Package layout, exports, assets, and module relationships are project-level Nim concerns that cannot be judged one line at a time.

import '../../core/models.dart';

/// Detects project-level Nim test-suite and module-coverage findings.
final class NimProjectRulePack {
  /// Executes project-level checks that do not require line scanner state.
  List<Finding> analyze(Map<String, String> sources) {
    final List<Finding> result = <Finding>[];
    final List<String> sourceModules = sources.keys
        .where(
          (String path) => path.startsWith('src/') && path.endsWith('.nim'),
        )
        .toList();
    final List<String> testFiles = sources.keys
        .where(
          (String path) => path.startsWith('tests/') && path.endsWith('.nim'),
        )
        .toList();
    if (sourceModules.isNotEmpty && testFiles.isEmpty) {
      result.add(
        const Finding(
          code: 'nim-no-test-suite',
          severity: RuleSeverity.warn,
          path: '.',
          line: 1,
          endLine: 1,
          message: 'Nim project has src modules but no tests directory/files',
          confidence: 'medium',
          why:
              'A visible test suite makes regressions easier to catch and gives agents concrete validation targets.',
          suggestion:
              'Add tests/test_<module>.nim files and wire them into nimble test or CI.',
        ),
      );
    }
    final String combinedTests = testFiles
        .map((String path) => sources[path]!)
        .join('\n')
        .toLowerCase();
    final Set<String> namedTestModules = testFiles
        .map((String path) => path.split('/').last.split('.').first)
        .where((String name) => name.startsWith('test_'))
        .map((String name) => name.substring(5))
        .toSet();
    for (final String path in sourceModules) {
      final String module = path.split('/').last.split('.').first;
      if (<String>{'main', 'host', 'host_release'}.contains(module)) continue;
      if (!namedTestModules.contains(module) &&
          !combinedTests.contains('../src/$module')) {
        result.add(
          Finding(
            code: 'nim-missing-test-for-module',
            severity: RuleSeverity.info,
            path: path,
            line: 1,
            endLine: 1,
            message: 'source module has no matching test_*.nim file',
            confidence: 'low',
            why:
                'A matching test file is a simple convention that improves module-level coverage discoverability.',
            suggestion:
                'Add tests/test_$module.nim or include this module in an existing focused test suite.',
          ),
        );
      }
    }
    return List<Finding>.unmodifiable(result);
  }
}
