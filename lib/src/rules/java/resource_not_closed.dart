// Closeable Java resources need ownership evidence, and this check flags constructions with no visible close or managed scope.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../languages/java/java_adapter.dart';

/// Reports locally-created Java resources whose ownership is not transferred.
final class JavaResourceNotClosedRule extends SelfContainedRule {
  /// Creates the stateless Java resource rule.
  const JavaResourceNotClosedRule()
    : super(
        const RuleMetadata(
          id: 'java-resource-not-closed',
          version: 2,
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Close Java resources in their creating method',
          why:
              'Unclosed streams and database resources leak file descriptors or connections.',
          suggestion:
              'Use try-with-resources or close the resource in a finally block.',
          semanticMaturity: RuleSemanticMaturity.token,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.functions,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.reliability},
          languages: <String>['java'],
          languageVersions: <String, String>{'java': '>=7'},
          limitations: <String>[
            'Only direct local allocations of common closeable types are checked.',
          ],
        ),
      );

  static final RegExp _closeableAllocation = RegExp(
    r'\b(?:FileInputStream|FileOutputStream|FileReader|FileWriter|Connection|Statement|ResultSet)\s+([A-Za-z_]\w*)\s*=\s*new\s+',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    if (!context.config.ruleGroups.contains(metadata.group) &&
        !context.config.severityOverrides.containsKey(metadata.id)) {
      return;
    }
    for (final FunctionSource function in JavaAdapter().functions(
      context.sources,
    )) {
      for (final RegExpMatch allocation in _closeableAllocation.allMatches(
        function.source,
      )) {
        final String variable = allocation.group(1)!;
        if (RegExp(
              '\\b${RegExp.escape(variable)}\\.close\\s*\\(',
            ).hasMatch(function.source) ||
            RegExp(r'\btry\s*\(').hasMatch(function.source) ||
            RegExp(
              '\\breturn\\s+${RegExp.escape(variable)}\\s*;',
            ).hasMatch(function.source)) {
          continue;
        }
        yield report(
          context,
          path: function.path,
          line:
              function.line +
              '\n'
                  .allMatches(function.source.substring(0, allocation.start))
                  .length,
          message: 'locally-created resource `$variable` is not closed',
          confidence: 'high',
        );
      }
    }
  }
}
