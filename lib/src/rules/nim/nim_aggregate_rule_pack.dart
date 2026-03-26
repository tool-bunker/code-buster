// Repository-wide Nim checks compare files and declarations, so they run after individual source scans have produced common facts.

import '../../core/models.dart';

/// Emits findings derived from state accumulated across an entire Nim file.
final class NimAggregateRulePack {
  /// Executes end-of-file lifecycle, API, serialization, and style checks.
  List<Finding> analyze({
    required String path,
    required String source,
    required List<String> lines,
    required bool isTest,
    required String fileLower,
    required bool mentionsWebSocket,
    required bool cameraModified,
    required bool cameraRestored,
    required int cameraProcLine,
    required int assetLoadCount,
    required int assetFreeCount,
    required int renderBeginCount,
    required int renderEndCount,
    required int renderProcLine,
    required List<({int line, Set<String> params})> procParameters,
    required int genericHookCount,
    required bool hasImport,
    required bool hasGenericSerializationWrapper,
    required int jsonApiCount,
    required int importCount,
    required int exportCount,
    required Set<String> distinctTypes,
    required Set<String> dumpTypes,
    required Set<String> parseTypes,
    required Map<String, int> mutableDeclarations,
  }) {
    final List<Finding> result = <Finding>[];
    if (importCount > 15) {
      result.add(
        Finding(
          code: 'nim-god-module',
          severity: RuleSeverity.warn,
          path: path,
          line: 1,
          endLine: 1,
          message: 'module has $importCount import statements',
          confidence: 'medium',
          why:
              'A module with many imports may be doing too much; consider splitting it.',
          suggestion:
              'Split the module by responsibility or consolidate imports.',
        ),
      );
    }
    if (exportCount > 25) {
      result.add(
        Finding(
          code: 'nim-many-exports',
          severity: RuleSeverity.warn,
          path: path,
          line: 1,
          endLine: 1,
          message: 'module exports $exportCount symbols',
          confidence: 'medium',
          why:
              'Many public symbols can indicate a god module or overly broad API surface.',
          suggestion:
              'Split the module or keep helper symbols private when possible.',
        ),
      );
    }
    if (path.startsWith('tests/')) {
      final String fileName = path.split('/').last.split('.').first;
      if (!fileName.startsWith('test_') &&
          !fileName.startsWith('tests_') &&
          !fileName.startsWith('t') &&
          !<String>{
            'alltests',
            'testutils',
            'full_test_suite',
          }.contains(fileName)) {
        result.add(
          Finding(
            code: 'nim-test-naming',
            severity: RuleSeverity.info,
            path: path,
            line: 1,
            endLine: 1,
            message:
                'test file does not follow common t*.nim/test_*.nim/tests_*.nim convention',
            confidence: 'low',
            why:
                'Consistent test file naming helps test runners and CI find and execute tests, while allowing common suite/helper names.',
            suggestion:
                'Rename to t$fileName.nim, test_$fileName.nim, tests_$fileName.nim, or mark the file as a test helper.',
          ),
        );
      }
    }
    if (cameraModified && !cameraRestored) {
      result.add(
        Finding(
          code: 'nim-camera-transform-leak',
          severity: RuleSeverity.warn,
          path: path,
          line: cameraProcLine,
          endLine: cameraProcLine,
          message: 'camera modified in draw proc but not restored',
          confidence: 'medium',
          why:
              "Camera transforms left modified can corrupt the next frame's rendering.",
          suggestion:
              'Reset/restore the camera transform before the draw proc ends.',
        ),
      );
    }
    if (assetLoadCount > 2 && assetFreeCount == 0) {
      result.add(
        Finding(
          code: 'nim-asset-loaded-not-freed',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message: 'module loads assets but has no matching unload/free calls',
          confidence: 'low',
          why:
              'Assets loaded without unloading can leak GPU/memory resources over time.',
          suggestion:
              'Add unload/free/release calls for loaded assets, or document the lifecycle.',
        ),
      );
    }
    if (renderBeginCount > renderEndCount) {
      result.add(
        Finding(
          code: 'nim-render-state-not-restored',
          severity: RuleSeverity.warn,
          path: path,
          line: renderProcLine,
          endLine: renderProcLine,
          message: 'render state begin without matching restore',
          confidence: 'medium',
          why:
              'Begin scissor/clip/canvas/blend calls without matching end/restore can corrupt subsequent rendering.',
          suggestion:
              'Ensure every begin* has a matching end*/restore in the same proc.',
        ),
      );
    }
    if (procParameters.length >= 3) {
      final Map<String, int> pairCounts = <String, int>{};
      for (final procedure in procParameters) {
        final List<String> names = procedure.params.toList()..sort();
        for (var left = 0; left < names.length; left++) {
          for (var right = left + 1; right < names.length; right++) {
            final String pair = '${names[left]}\u0000${names[right]}';
            pairCounts[pair] = (pairCounts[pair] ?? 0) + 1;
          }
        }
      }
      for (final procedure in procParameters) {
        final List<String> names = procedure.params.toList()..sort();
        var sharedPairs = 0;
        for (var left = 0; left < names.length; left++) {
          for (var right = left + 1; right < names.length; right++) {
            if ((pairCounts['${names[left]}\u0000${names[right]}'] ?? 0) >= 3) {
              sharedPairs++;
            }
          }
        }
        if (names.length >= 4 && sharedPairs >= 3) {
          result.add(
            Finding(
              code: 'nim-parameter-cluster-spread',
              severity: RuleSeverity.info,
              path: path,
              line: procedure.line,
              endLine: procedure.line,
              message:
                  'proc shares a parameter cluster with other procs in this module',
              confidence: 'low',
              why:
                  'When the same group of parameters appears across multiple procs, changes ripple everywhere. A parameter object centralizes the concept.',
              suggestion:
                  'Group the shared parameters into a single object/tuple type and pass that instead.',
            ),
          );
        }
      }
    }
    if (genericHookCount > 0 && hasImport) {
      result.add(
        Finding(
          code: 'nim-imported-hook-ambiguity-risk',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message: 'module imports dependencies and defines generic hook procs',
          confidence: 'low',
          why:
              'Generic local hooks plus imported default hooks can become ambiguous when unresolved overloads are instantiated elsewhere.',
          suggestion:
              'Keep generic hook call sites local, make hooks concrete, or qualify calls intentionally.',
        ),
      );
    }
    if (genericHookCount > 0 && hasGenericSerializationWrapper) {
      result.add(
        Finding(
          code: 'nim-generic-hook-cross-module-call',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message:
              'module defines generic hooks and an exported generic serialization wrapper',
          confidence: 'low',
          why:
              'Generic wrappers can instantiate hook lookup from other modules, changing overload resolution behavior.',
          suggestion:
              'Prefer non-generic wrappers for concrete types or keep hook definitions and generic calls in the same module.',
        ),
      );
    }
    if (jsonApiCount >= 3) {
      result.add(
        Finding(
          code: 'nim-json-heavy-api',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message:
              'public API exposes JSON/render value types in several places',
          confidence: 'low',
          why:
              'Heavy JsonNode/render Value use in public APIs can leak serialization concerns into internal models.',
          suggestion:
              'Prefer typed Nim models internally and convert to JsonNode/render values at the boundary.',
        ),
      );
    }
    if (mentionsWebSocket &&
        !isTest &&
        !(fileLower.contains('keep-alive, upgrade') &&
            source.contains('Upgrade'))) {
      result.add(
        Finding(
          code: 'nim-websocket-tests-missing-header-variants',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message:
              'WebSocket/protocol code has no obvious comma-separated/case-variant header coverage nearby',
          confidence: 'low',
          why:
              'Browser and proxy implementations can vary header token casing and combine tokens in comma-separated values.',
          suggestion:
              'Add tests for `Connection: keep-alive, Upgrade`, lowercase/uppercase variants, and whitespace around tokens.',
        ),
      );
    }
    for (final String type in distinctTypes) {
      if (dumpTypes.contains(type) == parseTypes.contains(type)) continue;
      result.add(
        Finding(
          code: 'nim-distinct-serialization-asymmetry',
          severity: RuleSeverity.info,
          path: path,
          line: 1,
          endLine: 1,
          message: dumpTypes.contains(type)
              ? 'distinct type has dump/encode hook but no matching parse/decode hook'
              : 'distinct type has parse/decode hook but no matching dump/encode hook',
          confidence: 'low',
          why:
              'One-way serialization hooks can surprise callers when round-tripping data from JSON or other formats.',
          suggestion: dumpTypes.contains(type)
              ? 'Add the matching parse/decode hook or document that the conversion is intentionally one-way.'
              : 'Add the matching dump/encode hook or document that the conversion is intentionally one-way.',
        ),
      );
    }
    for (final MapEntry<String, int> declaration
        in mutableDeclarations.entries) {
      final RegExp assignment = RegExp(
        '\\b${RegExp.escape(declaration.key)}\\s*=',
      );
      final int assignments = lines.where(assignment.hasMatch).length;
      if (assignments <= 1) {
        result.add(
          Finding(
            code: 'nim-prefer-let',
            severity: RuleSeverity.info,
            path: path,
            line: declaration.value + 1,
            endLine: declaration.value + 1,
            message: 'review whether var can be let',
            confidence: 'low',
            why:
                'Nim style prefers let for values that do not change within scope.',
            suggestion: 'Use let unless the variable is reassigned or mutated.',
          ),
        );
      }
    }
    return result;
  }
}
