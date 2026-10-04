// Derived Go contexts retain timers and parent references until canceled or expired.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../languages/go/go_adapter.dart';

/// Reports derived contexts whose cancel function is discarded or never used.
final class GoDerivedContextCancelRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const GoDerivedContextCancelRule()
    : super(
        const RuleMetadata(
          id: 'go-derived-context-cancel-not-called',
          defaultSeverity: RuleSeverity.warn,
          group: 'reliability',
          title: 'Cancel derived Go contexts',
          why:
              'A derived context retains timers and parent references until its cancel function runs or its deadline expires.',
          suggestion:
              'Call the returned cancel function, normally with defer immediately after creating the context.',
          semanticMaturity: RuleSemanticMaturity.token,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.functions,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.reliability},
          languages: <String>['go'],
          languageVersions: <String, String>{'go': '>=1.13'},
          version: 1,
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final GoAdapter adapter = GoAdapter();
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.go')) continue;
      for (final FunctionSource function in adapter.functions(<String, String>{
        source.key: source.value,
      })) {
        for (final RegExpMatch creation in _derivedContext.allMatches(
          function.source,
        )) {
          final String cancel = creation.requiredNamedGroup('cancel');
          final String tail = function.source.substring(creation.end);
          if (cancel != '_' &&
              cachedRegExp(
                '\\b${RegExp.escape(cancel)}\\s*\\(',
              ).hasMatch(tail)) {
            continue;
          }
          if (cancel != '_' &&
              cachedRegExp('\\b${RegExp.escape(cancel)}\\b').hasMatch(tail)) {
            // Returning, storing, or passing the cancel function transfers
            // ownership beyond what this local check can prove.
            continue;
          }
          yield report(
            context,
            path: source.key,
            line:
                function.line +
                '\n'
                    .allMatches(function.source.substring(0, creation.start))
                    .length,
            message: cancel == '_'
                ? 'derived context discards its cancel function'
                : 'derived context cancel function `$cancel` is never called',
            confidence: 'high',
          );
        }
      }
    }
  }

  static final RegExp _derivedContext = cachedRegExp(
    r'\b[A-Za-z_]\w*\s*,\s*(?<cancel>[A-Za-z_]\w*|_)\s*:=\s*context\.(?:WithCancel|WithCancelCause|WithTimeout|WithTimeoutCause|WithDeadline|WithDeadlineCause)\s*\(',
  );
}
