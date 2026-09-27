// HTTP response bodies hold resources in Go, so this check follows request results to evidence of a corresponding Close.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
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
          version: 5,
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final GoAdapter adapter = GoAdapter();
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.go')) continue;
      final List<FunctionSource> functions = adapter.functions(<String, String>{
        source.key: source.value,
      });
      for (final FunctionSource function in functions) {
        for (final RegExpMatch request in _httpResponse.allMatches(
          function.source,
        )) {
          final String response = request.requiredNamedGroup('response');
          final String? receiver = request.namedGroup('receiver');
          if (receiver != null &&
              !_isHttpClientReceiver(receiver, function.source, source.value)) {
            continue;
          }
          if (RegExp(
                '\\b${RegExp.escape(response)}\\.Body\\.Close\\s*\\(',
              ).hasMatch(function.source) ||
              _closedByLocalHelper(response, function.source, functions)) {
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
    r'\b(?<response>[A-Za-z_]\w*)\s*,\s*(?:err|_)\s*:=\s*(?:http\.(?:Get|Post|PostForm)|(?<receiver>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.Do)\s*\(',
  );

  static bool _closedByLocalHelper(
    String response,
    String caller,
    List<FunctionSource> functions,
  ) {
    final RegExp call = RegExp(
      '\\b(?:[A-Za-z_]\\w*\\.)?(?<name>[A-Za-z_]\\w*)'
      '\\s*\\(\\s*${RegExp.escape(response)}\\s*\\)',
    );
    for (final RegExpMatch match in call.allMatches(caller)) {
      final String name = match.requiredNamedGroup('name');
      for (final FunctionSource helper in functions) {
        if (helper.name != name) continue;
        final RegExpMatch? parameter = RegExp(
          '\\b${RegExp.escape(name)}\\s*\\(\\s*'
          '(?<parameter>[A-Za-z_]\\w*)\\s+\\*http\\.Response\\b',
        ).firstMatch(helper.source);
        if (parameter == null) continue;
        final String escaped = RegExp.escape(
          parameter.requiredNamedGroup('parameter'),
        );
        if (RegExp(
          '\\b$escaped\\.Body\\.Close\\s*\\(',
        ).hasMatch(helper.source)) {
          return true;
        }
      }
    }
    return false;
  }

  static bool _isHttpClientReceiver(
    String receiver,
    String functionSource,
    String source,
  ) {
    if (receiver == 'http.DefaultClient') return true;
    final String name = receiver.split('.').last;
    final String escaped = RegExp.escape(name);
    final String evidence = receiver.contains('.') ? source : functionSource;
    return RegExp(
      '(?:\\b$escaped\\s+\\*http\\.Client\\b|'
      '\\b$escaped\\s*:?=\\s*(?:&\\s*)?http\\.Client\\s*\\{)',
    ).hasMatch(evidence);
  }
}
