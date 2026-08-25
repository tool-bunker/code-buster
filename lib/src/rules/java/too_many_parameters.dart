// Long parameter lists are easy to call incorrectly and often signal mixed responsibilities.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../languages/java/java_adapter.dart';

/// Reports Java methods with more than seven parameters.
final class JavaTooManyParametersRule extends SelfContainedRule {
  /// Creates the stateless parameter-count rule.
  const JavaTooManyParametersRule()
    : super(
        const RuleMetadata(
          id: 'java-too-many-parameters',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Reduce Java method parameters',
          why:
              'A wide signature is difficult to call correctly and often combines unrelated responsibilities.',
          suggestion:
              'Split the responsibility or introduce a cohesive parameter object.',
          semanticMaturity: RuleSemanticMaturity.token,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.functions,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['java'],
          limitations: <String>[
            'Only method declarations recognized by the Java callable extractor are checked.',
          ],
        ),
      );

  static const int _maximumParameters = 7;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final FunctionSource function in JavaAdapter().functions(
      context.sources,
    )) {
      final int open = function.source.indexOf('(');
      if (open == -1) continue;
      final int close = _matchingParenthesis(function.source, open);
      if (close == -1) continue;
      final int count = _parameterCount(
        function.source.substring(open + 1, close),
      );
      if (count <= _maximumParameters) continue;
      yield report(
        context,
        path: function.path,
        line: function.line,
        message: '`${function.name}` has $count parameters',
        confidence: 'high',
      );
    }
  }
}

int _matchingParenthesis(String source, int open) {
  var depth = 0;
  for (var index = open; index < source.length; index++) {
    if (source[index] == '(') depth++;
    if (source[index] == ')' && --depth == 0) return index;
  }
  return -1;
}

int _parameterCount(String parameters) {
  if (parameters.trim().isEmpty) return 0;
  var count = 1;
  var angleDepth = 0;
  var parenthesisDepth = 0;
  var bracketDepth = 0;
  for (final int character in parameters.codeUnits) {
    switch (character) {
      case 60: // <
        angleDepth++;
      case 62: // >
        if (angleDepth > 0) angleDepth--;
      case 40: // (
        parenthesisDepth++;
      case 41: // )
        if (parenthesisDepth > 0) parenthesisDepth--;
      case 91: // [
        bracketDepth++;
      case 93: // ]
        if (bracketDepth > 0) bracketDepth--;
      case 44: // ,
        if (angleDepth == 0 && parenthesisDepth == 0 && bracketDepth == 0) {
          count++;
        }
    }
  }
  return count;
}
