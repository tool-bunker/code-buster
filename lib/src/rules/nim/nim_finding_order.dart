// Nim compatibility reports have a historical canonical order, and preserving it prevents noisy output and baseline churn.

import '../../core/models.dart';

/// Preserves canonical Nim finding phase and tie ordering.
final class NimFindingOrder {
  const NimFindingOrder._();

  /// Compares findings by path, line, canonical phase, and tie order.
  static int compare(Finding left, Finding right) {
    final bool leftProject =
        left.path == '.' || left.code == 'nim-missing-test-for-module';
    final bool rightProject =
        right.path == '.' || right.code == 'nim-missing-test-for-module';
    if (leftProject != rightProject) return leftProject ? -1 : 1;
    final int pathOrder = left.path.compareTo(right.path);
    if (pathOrder != 0) return pathOrder;
    final int phaseOrder = (_canonicalPhase[left.code] ?? 1000).compareTo(
      _canonicalPhase[right.code] ?? 1000,
    );
    if (phaseOrder != 0) return phaseOrder;
    final int lineOrder = left.line.compareTo(right.line);
    if (lineOrder != 0) return lineOrder;
    return (_canonicalTieOrder[left.code] ?? 1000).compareTo(
      _canonicalTieOrder[right.code] ?? 1000,
    );
  }

  static const Map<String, int> _canonicalPhase = <String, int>{
    'nim-missing-test-for-module': 0,
    'nim-no-test-suite': 0,
    'nim-exported-object-without-doc': 10,
    'nim-tuple-used-as-domain-type': 10,
    'nim-ref-object-inheritance': 10,
    'nim-missing-raises': 10,
    'nim-missing-doc': 10,
    'nim-broad-except': 10,
    'nim-split-recursive-types': 11,
    'nim-exported-template-missing-doc': 20,
    'nim-template-body-state-mutation': 20,
    'nim-state-restore-without-finally': 20,
    'nim-average-openarray-risk': 50,
    'nim-divide-by-len-without-empty-check': 50,
    'nim-float-tests-missing-edge-cases': 51,
    'nim-openarray-missing-empty-test': 52,
    'nim-float-test-exact-equality': 50,
    'nim-hook-overwrites-accumulator': 80,
    'nim-distinct-serialization-asymmetry': 81,
    'nim-update-blocking-io': 100,
    'nim-draw-loads-asset': 100,
    'nim-input-in-draw': 110,
    'nim-per-frame-string-format': 110,
    'nim-sound-every-frame': 110,
    'nim-render-state-not-restored': 111,
    'nim-entity-access-after-destroy': 120,
    'nim-nil-component-access': 120,
    'nim-physics-variable-timestep': 120,
    'nim-draw-call-in-update': 120,
    'nim-hardcoded-screen-size': 120,
    'nim-debug-draw-not-gated': 120,
    'nim-save-missing-version': 121,
    'nim-camera-transform-leak': 122,
    'nim-asset-loaded-not-freed': 123,
    'nim-too-many-parameters': 130,
    'nim-could-be-const': 140,
    'nim-cast-usage': 150,
    'nim-return-instead-of-result': 150,
    'nim-unordered-table-output': 170,
    'nim-tainted-exec': 171,
    'nim-exec-dynamic-command': 172,
    'nim-std-import': 180,
    'nim-broad-import': 180,
    'nim-prefer-let': 180,
  };

  static const Map<String, int> _canonicalTieOrder = <String, int>{
    'nim-exported-object-without-doc': 0,
    'nim-tuple-used-as-domain-type': 1,
    'nim-ref-object-inheritance': 2,
    'nim-missing-raises': 3,
    'nim-missing-doc': 4,
    'nim-broad-except': 5,
    'nim-exported-template-missing-doc': 0,
    'nim-template-body-state-mutation': 1,
    'nim-state-restore-without-finally': 2,
  };
}
