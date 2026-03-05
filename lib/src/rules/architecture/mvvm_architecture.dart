// MVVM projects use recognizable view, view-model, and model boundaries; this rule validates those dependencies when the profile is enabled.

import '../../core/models.dart';
import '../../graph/graph.dart';

/// MVVM responsibility assigned to a Dart source path.
enum MvvmLayer {
  /// Flutter presentation code.
  view,

  /// Presentation state and orchestration.
  viewModel,

  /// Platform-independent domain data and behavior.
  model,

  /// Data access implementation or abstraction.
  repository,
}

/// Classifies paths using configurable MVVM glob patterns.
final class MvvmPathClassifier {
  /// Creates a classifier from resolved analysis configuration.
  MvvmPathClassifier(this.config);

  /// MVVM configuration.
  final AnalysisConfig config;

  static const List<String> _defaultViews = <String>[
    'lib/**/views/**',
    'lib/**/pages/**',
    'lib/**/screens/**',
    'lib/**/*_view.dart',
    'lib/**/*_page.dart',
    'lib/**/*_screen.dart',
  ];
  static const List<String> _defaultViewModels = <String>[
    'lib/**/view_models/**',
    'lib/**/viewmodels/**',
    'lib/**/*_view_model.dart',
    'lib/**/*_viewmodel.dart',
  ];
  static const List<String> _defaultModels = <String>[
    'lib/**/models/**',
    'lib/**/domain/**',
    'lib/**/*_model.dart',
  ];
  static const List<String> _defaultRepositories = <String>[
    'lib/**/repositories/**',
    'lib/**/data/**',
    'lib/**/*_repository.dart',
  ];

  /// Returns the first matching MVVM responsibility.
  MvvmLayer? classify(String path) {
    final String normalized = path.replaceAll('\\', '/');
    if (_matches(
      normalized,
      _patterns(config.mvvmViewModels, _defaultViewModels),
    )) {
      return MvvmLayer.viewModel;
    }
    if (_matches(normalized, _patterns(config.mvvmViews, _defaultViews))) {
      return MvvmLayer.view;
    }
    if (_matches(
      normalized,
      _patterns(config.mvvmRepositories, _defaultRepositories),
    )) {
      return MvvmLayer.repository;
    }
    if (_matches(normalized, _patterns(config.mvvmModels, _defaultModels))) {
      return MvvmLayer.model;
    }
    return null;
  }

  List<String> _patterns(List<String> configured, List<String> defaults) =>
      configured.isEmpty ? defaults : configured;

  bool _matches(String path, List<String> patterns) =>
      patterns.any((String pattern) => _glob(pattern).hasMatch(path));

  RegExp _glob(String pattern) {
    final String normalized = pattern.replaceAll('\\', '/');
    final StringBuffer expression = StringBuffer('^');
    for (var index = 0; index < normalized.length; index++) {
      final String character = normalized[index];
      if (character == '*' &&
          index + 1 < normalized.length &&
          normalized[index + 1] == '*') {
        if (index + 2 < normalized.length && normalized[index + 2] == '/') {
          expression.write('(?:.*/)?');
          index += 2;
        } else {
          expression.write('.*');
          index++;
        }
      } else if (character == '*') {
        expression.write('[^/]*');
      } else if (character == '?') {
        expression.write('[^/]');
      } else {
        expression.write(RegExp.escape(character));
      }
    }
    expression.write(r'$');
    return RegExp(expression.toString());
  }
}

/// Enforces dependency direction for the opt-in Dart MVVM profile.
final class MvvmArchitectureAnalysis {
  /// Creates MVVM graph analysis.
  MvvmArchitectureAnalysis(this.graph, this.config)
    : classifier = MvvmPathClassifier(config);

  /// Resolved project graph.
  final DependencyGraph graph;

  /// Resolved analysis configuration.
  final AnalysisConfig config;

  /// Path classifier shared with semantic checks.
  final MvvmPathClassifier classifier;

  /// Reports forbidden dependencies between classified files.
  List<Finding> findings() {
    if (!config.dartMvvmEnabled) return const <Finding>[];
    final List<Finding> result = <Finding>[];
    for (final String source in graph.nodes.toList()..sort()) {
      final MvvmLayer? sourceLayer = classifier.classify(source);
      if (sourceLayer == null) continue;
      for (final String target in graph.dependenciesOf(source)) {
        final MvvmLayer? targetLayer = classifier.classify(target);
        if (targetLayer == null || sourceLayer == targetLayer) continue;
        final String? reason = _forbidden(sourceLayer, targetLayer);
        if (reason == null) continue;
        result.add(
          Finding(
            code: 'mvvm-forbidden-dependency',
            severity: RuleSeverity.error,
            path: source,
            line: 1,
            endLine: 1,
            message:
                '${_label(sourceLayer)} must not depend on ${_label(targetLayer)}',
            confidence: 'high',
            why: reason,
            suggestion:
                'Move the dependency behind the ViewModel or invert it through a model/repository abstraction.',
            relatedFiles: <String>[target],
          ),
        );
      }
    }
    return result;
  }

  String? _forbidden(MvvmLayer source, MvvmLayer target) => switch (source) {
    MvvmLayer.view =>
      config.mvvmStrictViewModelBoundary && target == MvvmLayer.repository
          ? 'Views should delegate data access and orchestration to a ViewModel.'
          : null,
    MvvmLayer.viewModel =>
      target == MvvmLayer.view
          ? 'ViewModels should remain independent of presentation classes.'
          : null,
    MvvmLayer.model =>
      target == MvvmLayer.view ||
              target == MvvmLayer.viewModel ||
              target == MvvmLayer.repository
          ? 'Models should not depend on presentation or data-access layers.'
          : null,
    MvvmLayer.repository =>
      target == MvvmLayer.view || target == MvvmLayer.viewModel
          ? 'Repositories should expose data through model abstractions without presentation dependencies.'
          : null,
  };

  String _label(MvvmLayer layer) => switch (layer) {
    MvvmLayer.view => 'View',
    MvvmLayer.viewModel => 'ViewModel',
    MvvmLayer.model => 'Model',
    MvvmLayer.repository => 'Repository',
  };
}
