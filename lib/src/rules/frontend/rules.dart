// The frontend registry binds HTML and CSS findings to stable metadata and the common rule lifecycle.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'frontend_rule_analysis.dart';

/// One independently registered HTML or CSS source rule.
final class FrontendSourceRule extends SelfContainedRule {
  /// Creates a frontend rule with canonical metadata.
  FrontendSourceRule({
    required String id,
    required RuleSeverity severity,
    required String group,
    required String language,
    String? why,
    String? suggestion,
  }) : language = language,
       super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: group,
           title:
               'Review ${id.replaceFirst(RegExp(r'^(?:html|css)-'), '').replaceAll('-', ' ')}',
           why:
               why ??
               'This frontend construct can weaken accessibility, security, or maintainability.',
           suggestion:
               suggestion ??
               'Use the safer accessible frontend pattern described by the rule.',
           languages: <String>[language],
         ),
       );

  /// Source language scanned by this rule.
  final String language;

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final FrontendRuleAnalysis analysis = FrontendRuleAnalysis();
    final Iterable<Finding> findings = language == 'html'
        ? analysis.htmlFindings(context.sources, metadata.id)
        : analysis.cssFindings(context.sources, metadata.id);
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

FrontendSourceRule _html(
  String id, {
  RuleSeverity severity = RuleSeverity.info,
  String group = 'nim-style',
  String? why,
  String? suggestion,
}) => FrontendSourceRule(
  id: id,
  severity: severity,
  group: group,
  language: 'html',
  why: why,
  suggestion: suggestion,
);
FrontendSourceRule _css(String id, {String? why, String? suggestion}) =>
    FrontendSourceRule(
      id: id,
      severity: RuleSeverity.info,
      group: 'nim-style',
      language: 'css',
      why: why,
      suggestion: suggestion,
    );

/// Self-contained HTML rules in deterministic execution order.
final RuleRegistry htmlRuleRegistry = RuleRegistry(<CodeBusterRule>[
  _html('html-blank-no-rel', severity: RuleSeverity.warn, group: 'security'),
  _html('html-duplicate-id', severity: RuleSeverity.warn),
  _html('html-form-method'),
  _html('html-http-resource', severity: RuleSeverity.warn, group: 'security'),
  _html(
    'html-img-alt',
    why: 'Images without alt text are inaccessible to screen readers.',
    suggestion: 'Add meaningful alt text or alt="" for decorative images.',
  ),
  _html('html-inline-event', severity: RuleSeverity.warn, group: 'security'),
  _html('html-inline-script', severity: RuleSeverity.warn, group: 'security'),
  _html('html-input-label'),
  _html('html-missing-lang'),
  _html('html-missing-title'),
  _html('html-missing-viewport'),
]);

/// Self-contained CSS rules in deterministic execution order.
final RuleRegistry cssRuleRegistry = RuleRegistry(<CodeBusterRule>[
  _css('css-animation-no-reduced-motion'),
  _css('css-duplicate-property'),
  _css('css-fixed-font-px'),
  _css('css-high-z-index'),
  _css(
    'css-important',
    why: '!important makes cascade/specificity harder to reason about.',
    suggestion:
        'Fix selector structure or ordering instead of forcing priority.',
  ),
  _css('css-selector-depth'),
  _css('css-universal-selector'),
  _css('css-vendor-prefix-only'),
]);
