// Dart MVVM checks connect typed declarations to architectural roles, complementing the repository-level dependency profile.

import '../../core/models.dart';
import '../architecture/mvvm_architecture.dart';

/// Dart semantic checks for the opt-in MVVM architecture profile.
final class DartMvvmRuleAnalysis {
  /// Analyzes classified Dart source responsibilities.
  List<Finding> findings(Map<String, String> sources, AnalysisConfig config) {
    if (!config.dartMvvmEnabled) return const <Finding>[];
    final MvvmPathClassifier classifier = MvvmPathClassifier(config);
    final List<Finding> result = <Finding>[];
    for (final String path in sources.keys.toList()..sort()) {
      final String source = sources[path]!;
      switch (classifier.classify(path)) {
        case MvvmLayer.model:
          _checkModel(path, source, result);
        case MvvmLayer.viewModel:
          _checkViewModel(path, source, result);
        case MvvmLayer.view:
        case MvvmLayer.repository:
        case null:
          break;
      }
    }
    return List<Finding>.unmodifiable(result);
  }

  void _checkModel(String path, String source, List<Finding> result) {
    final RegExp uiImport = RegExp(
      r'''import\s+['"]package:flutter/(?:material|widgets|cupertino)\.dart['"]''',
    );
    final RegExpMatch? match = uiImport.firstMatch(source);
    if (match != null) {
      result.add(
        _finding(
          code: 'mvvm-model-imports-ui',
          severity: RuleSeverity.error,
          path: path,
          source: source,
          offset: match.start,
          message: 'Model imports a Flutter presentation library',
          why:
              'Models should remain independent of Flutter widgets and presentation concerns.',
          suggestion:
              'Move presentation conversion into the View or ViewModel and keep the Model platform-independent.',
        ),
      );
    }
  }

  void _checkViewModel(String path, String source, List<Finding> result) {
    final List<
      ({
        RegExp pattern,
        String code,
        String message,
        String why,
        String suggestion,
      })
    >
    checks = <({RegExp pattern, String code, String message, String why, String suggestion})>[
      (
        pattern: RegExp(r'\bBuildContext\b'),
        code: 'mvvm-viewmodel-ui-context',
        message: 'ViewModel depends on BuildContext',
        why:
            'BuildContext couples ViewModel behavior to the Flutter widget tree and makes it harder to test independently.',
        suggestion:
            'Expose state or a one-shot event and let the View perform context-dependent behavior.',
      ),
      (
        pattern: RegExp(
          r'\b(?:Widget|PreferredSizeWidget)\s+(?:get\s+)?[A-Za-z_]\w*',
        ),
        code: 'mvvm-viewmodel-returns-widget',
        message: 'ViewModel exposes a Widget',
        why:
            'Constructing widgets is a View responsibility and couples state logic to rendering.',
        suggestion: 'Expose typed state and construct the Widget in the View.',
      ),
      (
        pattern: RegExp(
          r'\b(?:Navigator\s*\.|showDialog\s*\(|showModalBottomSheet\s*\(|ScaffoldMessenger\s*\.)',
        ),
        code: 'mvvm-viewmodel-performs-navigation',
        message: 'ViewModel performs context-dependent presentation behavior',
        why:
            'Navigation, dialogs, sheets, and snackbars belong to the View boundary.',
        suggestion:
            'Publish a navigation or presentation event for the View to handle.',
      ),
    ];
    for (final check in checks) {
      final RegExpMatch? match = check.pattern.firstMatch(source);
      if (match == null) continue;
      result.add(
        _finding(
          code: check.code,
          severity: RuleSeverity.warn,
          path: path,
          source: source,
          offset: match.start,
          message: check.message,
          why: check.why,
          suggestion: check.suggestion,
        ),
      );
    }
  }

  Finding _finding({
    required String code,
    required RuleSeverity severity,
    required String path,
    required String source,
    required int offset,
    required String message,
    required String why,
    required String suggestion,
  }) {
    final int line = '\n'.allMatches(source.substring(0, offset)).length + 1;
    return Finding(
      code: code,
      severity: severity,
      path: path,
      line: line,
      endLine: line,
      message: message,
      confidence: 'high',
      why: why,
      suggestion: suggestion,
    );
  }
}
