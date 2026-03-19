// HTTP response bodies hold resources in Go, so this check follows request results to evidence of a corresponding Close.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../languages/go/go_adapter.dart';

/// Reports Go HTTP response bodies not closed in their owning function.
final class GoResponseBodyNotClosedRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const GoResponseBodyNotClosedRule()
    : super(
        const RuleMetadata(
          id: 'go-response-body-not-closed',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Close Go HTTP response bodies',
          why:
              'An unclosed response body leaks connections and prevents transport reuse.',
          suggestion:
              'After checking the request error, defer response.Body.Close().',
          semanticMaturity: RuleSemanticMaturity.token,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.functions,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.reliability},
          languages: <String>['go'],
          languageVersions: <String, String>{'go': '>=1.13'},
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
        for (final RegExpMatch request in _httpResponse.allMatches(
          function.source,
        )) {
          final String response = request.group(1)!;
          if (RegExp(
            '\\b${RegExp.escape(response)}\\.Body\\.Close\\s*\\(',
          ).hasMatch(function.source)) {
            continue;
          }
          yield report(
            context,
            path: source.key,
            line:
                function.line +
                '\n'
                    .allMatches(function.source.substring(0, request.start))
                    .length,
            message: 'HTTP response body is not closed in this function',
            confidence: 'high',
          );
        }
      }
    }
  }

  static final RegExp _httpResponse = RegExp(
    r'\b([A-Za-z_]\w*)\s*,\s*(?:err|_)\s*:=\s*(?:http\.(?:Get|Post|PostForm)|[A-Za-z_]\w*\.Do)\s*\(',
  );
}
