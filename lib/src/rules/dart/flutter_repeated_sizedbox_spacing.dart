// Uniform Row and Column gaps belong to the parent layout rather than repeated spacer widgets.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports statically equivalent repeated SizedBox gaps in Row and Column.
final class FlutterRepeatedSizedBoxSpacingRule extends SelfContainedRule {
  /// Creates the stateless Flutter layout rule.
  const FlutterRepeatedSizedBoxSpacingRule()
    : super(
        const RuleMetadata(
          id: 'flutter-repeated-sizedbox-spacing',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Use parent layout spacing for uniform gaps',
          why:
              'Repeated spacer widgets obscure the layout spacing policy and make design-system changes harder.',
          suggestion:
              'Remove identical spacer children and set Row.spacing or Column.spacing, preferably with a shared spacing token.',
          semanticMaturity: RuleSemanticMaturity.ast,
          requirements: <RuleAnalysisRequirement>{RuleAnalysisRequirement.ast},
          taxonomy: <FindingTaxonomy>{
            FindingTaxonomy.maintainability,
            FindingTaxonomy.style,
          },
          languages: <String>['dart'],
          limitations: <String>[
            'Only explicit Row and Column list literals with a spacer in every gap are analyzed.',
            'Conditional, spread, loop-produced, leading, trailing, and mixed-size gaps are skipped.',
            'The spacing property requires a Flutter SDK version that provides Row.spacing and Column.spacing.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final Map<String, CompilationUnit> units = context
        .requireLanguageAnalysis<Map<String, CompilationUnit>>();
    final List<Finding> findings = <Finding>[];
    for (final MapEntry<String, CompilationUnit> unit in units.entries) {
      unit.value.accept(
        _RepeatedSpacingVisitor(
          path: unit.key,
          lineAt: (int offset) =>
              unit.value.lineInfo.getLocation(offset).lineNumber,
          onFinding: findings.add,
        ),
      );
    }
    return findings.map(
      (Finding finding) => context.report(
        metadata: metadata,
        path: finding.path,
        line: finding.line,
        endLine: finding.endLine,
        message: finding.message,
        confidence: finding.confidence,
      ),
    );
  }
}

final class _RepeatedSpacingVisitor extends RecursiveAstVisitor<void> {
  _RepeatedSpacingVisitor({
    required this.path,
    required this.lineAt,
    required this.onFinding,
  });

  final String path;
  final int Function(int offset) lineAt;
  final void Function(Finding finding) onFinding;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _checkLayout(node, node.constructorName.type.toSource(), node.argumentList);
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (node.target == null) {
      _checkLayout(node, node.methodName.name, node.argumentList);
    }
    super.visitMethodInvocation(node);
  }

  void _checkLayout(AstNode node, String layout, ArgumentList argumentList) {
    if (layout != 'Row' && layout != 'Column') return;
    final Map<String, Expression> arguments = <String, Expression>{};
    for (final Argument argument in argumentList.arguments) {
      if (argument is NamedArgument) {
        arguments[argument.name.lexeme] = argument.argumentExpression;
      }
    }
    if (arguments.containsKey('spacing')) return;
    final Expression? children = arguments['children'];
    if (children is! ListLiteral || children.elements.length < 5) return;

    final String dimension = layout == 'Column' ? 'height' : 'width';
    String? spacing;
    var spacerCount = 0;
    for (var index = 0; index < children.elements.length; index++) {
      final CollectionElement element = children.elements[index];
      if (element is! Expression) {
        spacing = null;
        break;
      }
      if (index.isEven) {
        if (_spacingExpression(element, dimension) != null) {
          spacing = null;
          break;
        }
        continue;
      }
      final String? current = _spacingExpression(element, dimension);
      if (current == null || (spacing != null && spacing != current)) {
        spacing = null;
        break;
      }
      spacing = current;
      spacerCount++;
    }

    if (spacing != null && spacerCount >= 2) {
      onFinding(
        Finding(
          code: 'flutter-repeated-sizedbox-spacing',
          severity: RuleSeverity.info,
          path: path,
          line: lineAt(node.offset),
          endLine: lineAt(node.end),
          message:
              '$spacerCount identical $spacing ${dimension == 'height' ? 'vertical' : 'horizontal'} spacers can use $layout.spacing',
          confidence: 'high',
        ),
      );
    }
  }

  static String? _spacingExpression(Expression expression, String dimension) {
    final ArgumentList argumentList;
    if (expression is InstanceCreationExpression &&
        expression.constructorName.type.toSource() == 'SizedBox' &&
        expression.constructorName.name == null) {
      argumentList = expression.argumentList;
    } else if (expression is MethodInvocation &&
        expression.target == null &&
        expression.methodName.name == 'SizedBox') {
      argumentList = expression.argumentList;
    } else {
      return null;
    }
    final NodeList<Argument> arguments = argumentList.arguments;
    if (arguments.length != 1 || arguments.single is! NamedArgument) {
      return null;
    }
    final NamedArgument argument = arguments.single as NamedArgument;
    if (argument.name.lexeme != dimension ||
        !_isStableSpacingValue(argument.argumentExpression)) {
      return null;
    }
    return argument.argumentExpression.toSource();
  }

  static bool _isStableSpacingValue(Expression expression) =>
      expression is IntegerLiteral ||
      expression is DoubleLiteral ||
      expression is SimpleIdentifier ||
      expression is PrefixedIdentifier;
}
