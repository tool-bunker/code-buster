// Several Dart findings are produced in one analyzer pass; this wrapper exposes each result through the normal rule registry.

import 'package:analyzer/dart/ast/ast.dart';

import '../../core/models.dart';
import '../../core/rule.dart';
import 'dart_rule_analysis.dart';

/// One independently registered rule backed by the shared parsed Dart scan.
final class DartAggregatedRule extends SelfContainedRule {
  /// Creates a Dart rule with canonical metadata.
  DartAggregatedRule(String id) : super(_metadata(id));

  static final Expando<Map<AnalysisConfig, List<Finding>>> _findingsByRun =
      Expando<Map<AnalysisConfig, List<Finding>>>('dart-rule-findings');

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, CompilationUnit> units = context
        .requireLanguageAnalysis<Map<String, CompilationUnit>>();
    final Map<AnalysisConfig, List<Finding>> byConfig =
        _findingsByRun[units] ??= <AnalysisConfig, List<Finding>>{};
    final List<Finding> findings = byConfig.putIfAbsent(
      context.config,
      () => DartRuleAnalysis().findingsParsed(
        context.sources,
        units,
        config: context.config,
        maxLineLength: 0,
      ),
    );
    return findings
        .where((Finding finding) => finding.code == metadata.id)
        .map(
          (Finding finding) => context.report(
            metadata: metadata,
            path: finding.path,
            line: finding.line,
            endLine: finding.endLine,
            message: finding.message,
            confidence: finding.confidence,
            relatedFiles: finding.relatedFiles,
            snippet: finding.snippet,
            codeFlow: finding.codeFlow,
          ),
        );
  }

  static RuleMetadata _metadata(String id) {
    if (id == 'mvvm-model-imports-ui') {
      return const RuleMetadata(
        id: 'mvvm-model-imports-ui',
        defaultSeverity: RuleSeverity.error,
        group: 'architecture',
        title: 'Keep Models independent of Flutter UI',
        why:
            'Models should remain independent of Flutter presentation concerns.',
        suggestion: 'Move UI conversion into the View or ViewModel.',
        languages: <String>['dart'],
      );
    }
    if (id.startsWith('mvvm-')) {
      return RuleMetadata(
        id: id,
        defaultSeverity: RuleSeverity.warn,
        group: 'architecture',
        semanticMaturity: RuleSemanticMaturity.ast,
        title: 'Review ${id.substring(5).replaceAll('-', ' ')}',
        why:
            'ViewModels should remain independent of Flutter presentation context.',
        suggestion:
            'Expose typed state or events and let the View handle presentation.',
        languages: const <String>['dart'],
      );
    }
    if (id == 'dart-overlapping-data-model') {
      return const RuleMetadata(
        id: 'dart-overlapping-data-model',
        defaultSeverity: RuleSeverity.info,
        group: 'maintainability',
        title: 'Consolidate overlapping data models',
        why:
            'Separate cross-file data models have strongly overlapping fields.',
        suggestion:
            'Confirm distinct contracts or share a common value object.',
        semanticMaturity: RuleSemanticMaturity.project,
        requirements: <RuleAnalysisRequirement>{
          RuleAnalysisRequirement.ast,
          RuleAnalysisRequirement.declarations,
        },
        taxonomy: <FindingTaxonomy>{FindingTaxonomy.maintainability},
        languages: <String>['dart'],
      );
    }
    final bool warning = _warningIds.contains(id);
    return RuleMetadata(
      id: id,
      defaultSeverity: warning ? RuleSeverity.warn : RuleSeverity.info,
      group: id == 'dart-unreachable-statement'
          ? 'core'
          : _securityIds.contains(id)
          ? 'security'
          : 'nim-style',
      title: 'Review ${id.substring(5).replaceAll('-', ' ')}',
      why:
          'This Dart construct can weaken static safety, reliability, or security.',
      suggestion:
          'Use the safer typed asynchronous Dart pattern described by the rule.',
      version: id == 'dart-hardcoded-secret'
          ? 3
          : _versionTwoIds.contains(id)
          ? 2
          : 1,
      languages: const <String>['dart'],
    );
  }

  static const Set<String> _securityIds = <String>{
    'dart-hardcoded-secret',
    'dart-insecure-random',
    'dart-process-shell',
    'dart-bad-certificate-callback',
    'dart-path-traversal',
    'dart-process-untrusted-argument',
    'dart-sensitive-data-logging',
    'dart-sql-interpolation',
  };

  static const Set<String> _versionTwoIds = <String>{
    'dart-insecure-random',
    'dart-http-client-not-closed',
    'flutter-expanded-outside-flex',
    'flutter-gesture-semantic-gap',
    'flutter-listener-without-remove',
    'flutter-unbounded-scrollable',
  };

  static const Set<String> _warningIds = <String>{
    'dart-blocking-in-async',
    'dart-hardcoded-secret',
    'dart-insecure-random',
    'dart-process-shell',
    'dart-unreachable-statement',
    'dart-bad-certificate-callback',
    'dart-catch-return-null',
    'dart-catch-without-stack-trace',
    'dart-controller-not-disposed',
    'dart-copy-with-missing-field',
    'dart-json-cast-without-validation',
    'dart-json-serialization-asymmetry',
    'dart-enum-name-persistence',
    'dart-http-client-not-closed',
    'dart-iosink-not-closed',
    'dart-isolate-not-terminated',
    'dart-random-access-file-not-closed',
    'dart-receive-port-not-closed',
    'dart-regexp-created-in-loop',
    'dart-repeated-iterable-traversal',
    'dart-late-final-persistence',
    'dart-map-string-dynamic-boundary',
    'dart-path-traversal',
    'dart-quadratic-list-membership',
    'dart-process-untrusted-argument',
    'dart-recommended-lints-missing',
    'dart-sensitive-data-logging',
    'dart-sql-interpolation',
    'dart-string-concat-in-loop',
    'dart-synchronous-file-io-in-async',
    'dart-timer-not-cancelled',
    'dart-throw-string',
    'flutter-future-created-in-build',
    'flutter-global-key-created-in-build',
    'flutter-expanded-outside-flex',
    'flutter-image-network-no-error-builder',
    'flutter-set-state-after-await',
    'flutter-provider-watch-in-callback',
    'flutter-stream-created-in-build',
    'flutter-unbounded-scrollable',
  };
}

/// Stable IDs emitted by the shared Dart analysis.
const List<String> dartAggregatedRuleIds = <String>[
  'dart-analyzer-ignore',
  'dart-bad-certificate-callback',
  'dart-blocking-in-async',
  'dart-broad-catch',
  'dart-catch-return-null',
  'dart-catch-without-stack-trace',
  'dart-controller-not-disposed',
  'dart-copy-with-missing-field',
  'dart-http-client-not-closed',
  'dart-iosink-not-closed',
  'dart-isolate-not-terminated',
  'dart-dynamic',
  'dart-enum-name-persistence',
  'dart-hardcoded-secret',
  'dart-insecure-random',
  'dart-json-cast-without-validation',
  'dart-json-serialization-asymmetry',
  'dart-late-final-persistence',
  'dart-late-mutable',
  'dart-null-assertion',
  'dart-map-string-dynamic-boundary',
  'dart-random-access-file-not-closed',
  'dart-receive-port-not-closed',
  'dart-regexp-created-in-loop',
  'dart-repeated-iterable-traversal',
  'dart-path-traversal',
  'dart-quadratic-list-membership',
  'dart-print',
  'dart-process-shell',
  'dart-process-untrusted-argument',
  'dart-recommended-lints-missing',
  'dart-sensitive-data-logging',
  'dart-sql-interpolation',
  'dart-string-concat-in-loop',
  'dart-synchronous-file-io-in-async',
  'dart-timer-not-cancelled',
  'dart-throw-string',
  'dart-unreachable-statement',
  'flutter-future-created-in-build',
  'flutter-global-key-created-in-build',
  'flutter-expanded-outside-flex',
  'flutter-gesture-semantic-gap',
  'flutter-image-network-no-error-builder',
  'flutter-listener-without-remove',
  'flutter-set-state-after-await',
  'flutter-provider-watch-in-callback',
  'flutter-stream-created-in-build',
  'flutter-unbounded-scrollable',
  'dart-overlapping-data-model',
  'mvvm-model-imports-ui',
  'mvvm-viewmodel-ui-context',
  'mvvm-viewmodel-returns-widget',
  'mvvm-viewmodel-performs-navigation',
];
