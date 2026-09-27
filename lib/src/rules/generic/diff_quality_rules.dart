import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';
import 'generic_rules.dart';
import 'semantic_diff.dart';

final Map<String, RuleMetadata>
diffQualityRuleMetadata = <String, RuleMetadata>{
  'broad-refactor-in-focused-change': _metadata(
    'broad-refactor-in-focused-change',
    'Keep focused changes surgical',
    'One behavior change accompanied by broad style-only edits increases review surface and hides the functional change.',
    'Revert unrelated edits or move an intentional mechanical cleanup into a separate change.',
    limitations: <String>[
      'Requires changed-base snapshots and reports only when one file mixes behavior changes with at least six style-equivalent edits.',
    ],
  ),
  'style-drift-in-diff': _metadata(
    'style-drift-in-diff',
    'Avoid unrelated style drift',
    'Quote, whitespace, typing, or local declaration-style churn obscures the behavior being reviewed.',
    'Match the surrounding style and retain only formatting required by the behavioral edit.',
    limitations: <String>[
      'Requires changed-base snapshots and reports only repeated style-equivalent line replacements alongside behavior changes.',
    ],
  ),
  'changed-behavior-without-test': _metadata(
    'changed-behavior-without-test',
    'Add regression evidence for changed behavior',
    'Changed control flow without a related changed test leaves the intended outcome unverifiable during review.',
    'Add or update a behavior-focused test sharing the changed production concept.',
    limitations: <String>[
      'Requires changed-base evidence; external tests and unchanged integration coverage cannot be resolved.',
    ],
  ),
  'optional-feature-bundle': _metadata(
    'optional-feature-bundle',
    'Remove speculative optional features',
    'Several newly introduced optional switches and collaborators often implement unrequested future behavior.',
    'Keep only the currently required behavior; add options when a concrete caller needs them.',
    limitations: <String>[
      'Reports changed files that add at least three optional feature controls and speculative cache, validation, notification, retry, or callback vocabulary.',
    ],
  ),
  'abstraction-cost-exceeds-use': _metadata(
    'abstraction-cost-exceeds-use',
    'Reduce abstraction scaffolding',
    'A change dominated by declarations and delegation can cost more to understand than the behavior it owns.',
    'Keep the behavior local until multiple real callers or implementations justify the abstraction.',
    limitations: <String>[
      'Reports changed files adding at least three type declarations but no more than two behavioral lines.',
    ],
  ),
  'new-unused-declaration': _metadata(
    'new-unused-declaration',
    'Remove a newly unused declaration',
    'A new private declaration with no reference adds code that cannot contribute to current behavior.',
    'Remove it or connect it to the behavior that required it.',
    limitations: <String>[
      'Requires a newly added private function or method whose name appears only at its declaration.',
    ],
  ),
  'single-caller-wrapper': _metadata(
    'single-caller-wrapper',
    'Inline a single-caller forwarding wrapper',
    'A new private wrapper used once and only forwarding arguments adds navigation without owning policy.',
    'Call the underlying operation directly until the wrapper owns behavior or has multiple callers.',
    limitations: <String>[
      'Requires a newly added expression-bodied or one-line private forwarding function with exactly one caller.',
    ],
  ),
  'unrelated-symbol-churn': _metadata(
    'unrelated-symbol-churn',
    'Separate unrelated symbol changes',
    'Changing several disconnected functions in one focused diff increases review scope and couples independent work.',
    'Keep independently changing symbols in separate changes unless their call relationships require one edit.',
    limitations: <String>[
      'Requires at least four changed named functions and reports only symbols disconnected from every other changed function.',
    ],
  ),
  'boolean-option-explosion': _metadata(
    'boolean-option-explosion',
    'Replace a cluster of Boolean options',
    'Several Boolean parameters make call sites opaque and permit combinations that may not represent valid behavior.',
    'Keep only the required mode or use one purpose-named value when callers genuinely need multiple modes.',
    limitations: <String>[
      'Reports newly added single-line function declarations containing at least three Boolean parameters.',
    ],
  ),
};

RuleMetadata _metadata(
  String id,
  String title,
  String why,
  String suggestion, {
  required List<String> limitations,
}) => RuleMetadata(
  id: id,
  version: 1,
  defaultSeverity: RuleSeverity.info,
  group: 'yagni',
  title: title,
  why: why,
  suggestion: suggestion,
  semanticMaturity: RuleSemanticMaturity.project,
  taxonomy: const <FindingTaxonomy>{FindingTaxonomy.maintainability},
  limitations: <String>[
    ...limitations,
    'Runs only for focused changes touching at most five production source files.',
  ],
);

abstract base class _DiffQualityRule extends SelfContainedRule {
  _DiffQualityRule(String id)
    : super(diffQualityRuleMetadata.requiredValue(id));

  SemanticDiff? diff(RuleContext context) {
    if (context.config.changedBase.isEmpty || context.baseSources.isEmpty) {
      return null;
    }
    final SemanticDiff diff = SemanticDiff.fromContext(context);
    return diff.isFocused ? diff : null;
  }
}

final class BroadRefactorInFocusedChangeRule extends _DiffQualityRule {
  BroadRefactorInFocusedChangeRule()
    : super('broad-refactor-in-focused-change');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    for (final SemanticFileDiff file in change.productionFiles) {
      if (file.behaviorAdditions >= 1 && file.styleOnlyEdits >= 6) {
        yield report(
          context,
          path: file.path,
          line: file.addedLines.first.number,
          message:
              'focused behavior change includes ${file.styleOnlyEdits} unrelated style-equivalent edits',
          confidence: 'high',
        );
      }
    }
  }
}

final class StyleDriftInDiffRule extends _DiffQualityRule {
  StyleDriftInDiffRule() : super('style-drift-in-diff');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    for (final SemanticFileDiff file in change.productionFiles) {
      if (file.behaviorAdditions >= 1 && file.styleOnlyEdits >= 3) {
        yield report(
          context,
          path: file.path,
          line: file.addedLines.first.number,
          message:
              '${file.styleOnlyEdits} style-equivalent lines changed beside behavioral edits',
          confidence: 'high',
        );
      }
    }
  }
}

final class ChangedBehaviorWithoutTestRule extends _DiffQualityRule {
  ChangedBehaviorWithoutTestRule() : super('changed-behavior-without-test');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    final List<SemanticFileDiff> tests = change.testFiles.toList();
    for (final SemanticFileDiff file in change.productionFiles) {
      if (file.behaviorAdditions < 2) continue;
      final bool related = tests.any(
        (test) => test.concepts.intersection(file.concepts).isNotEmpty,
      );
      if (!related) {
        final SemanticLine line = file.addedLines.firstWhere(
          (line) => cachedRegExp(
            r'\b(?:if|for|while|switch|return|throw|await)\b',
          ).hasMatch(line.text),
          orElse: () => file.addedLines.first,
        );
        yield report(
          context,
          path: file.path,
          line: line.number,
          message: 'changed behavior has no concept-related changed test',
          confidence: 'medium',
        );
      }
    }
  }
}

final class OptionalFeatureBundleRule extends _DiffQualityRule {
  OptionalFeatureBundleRule() : super('optional-feature-bundle');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    final RegExp option = cachedRegExp(
      r'\b(?:bool\??\s+\w+\s*=|\w+\s*:\s*(?:true|false)|\w+\s*=\s*(?:True|False))\b',
      caseSensitive: false,
    );
    final RegExp speculative = cachedRegExp(
      r'\b(?:cache|validator|validation|notify|notification|retry|callback|hook)\w*\b',
      caseSensitive: false,
    );
    for (final SemanticFileDiff file in change.productionFiles) {
      final int options = file.addedLines
          .where((line) => option.hasMatch(line.text))
          .length;
      if (options >= 3 &&
          file.addedLines.any((line) => speculative.hasMatch(line.text))) {
        yield report(
          context,
          path: file.path,

          line: file.addedLines.first.number,
          message:
              'change adds $options optional controls with speculative feature collaborators',
          confidence: 'medium',
        );
      }
    }
  }
}

final class BooleanOptionExplosionRule extends _DiffQualityRule {
  BooleanOptionExplosionRule() : super('boolean-option-explosion');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    final RegExp booleanParameter = cachedRegExp(
      r'\b(?:bool(?:ean)?\??\s+[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*:\s*(?:bool|boolean))\b',
      caseSensitive: false,
    );
    for (final SemanticFileDiff file in change.productionFiles) {
      for (final SemanticLine line in file.addedLines) {
        if (!line.text.contains('(') || !line.text.contains(')')) continue;
        final int count = booleanParameter.allMatches(line.text).length;
        if (count < 3) continue;
        yield report(
          context,
          path: file.path,
          line: line.number,
          message: 'new API declares $count Boolean options',
          confidence: 'high',
        );
      }
    }
  }
}

final class AbstractionCostExceedsUseRule extends _DiffQualityRule {
  AbstractionCostExceedsUseRule() : super('abstraction-cost-exceeds-use');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    for (final SemanticFileDiff file in change.productionFiles) {
      if (file.declarationAdditions >= 3 && file.behaviorAdditions <= 2) {
        yield report(
          context,
          path: file.path,
          line: file.addedLines.first.number,
          message:
              'change adds ${file.declarationAdditions} declarations for ${file.behaviorAdditions} behavioral lines',
          confidence: 'medium',
        );
      }
    }
  }
}

final class NewUnusedDeclarationRule extends _DiffQualityRule {
  NewUnusedDeclarationRule() : super('new-unused-declaration');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    final String projectSource = _referenceSource(context);
    for (final SemanticFileDiff file in change.productionFiles) {
      for (final _ChangedFunction function in _changedFunctions(file)) {
        if (!function.isPrivate ||
            _identifierOccurrences(projectSource, function.name) != 1) {
          continue;
        }
        yield report(
          context,
          path: file.path,
          line: function.line,
          message:
              'new private declaration `${function.name}` has no references',
          confidence: 'high',
        );
      }
    }
  }
}

final class SingleCallerWrapperRule extends _DiffQualityRule {
  SingleCallerWrapperRule() : super('single-caller-wrapper');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    final String projectSource = _referenceSource(context);
    for (final SemanticFileDiff file in change.productionFiles) {
      for (final _ChangedFunction function in _changedFunctions(file)) {
        if (!function.isPrivate ||
            !function.isForwarder ||
            _identifierOccurrences(projectSource, function.name) != 2) {
          continue;
        }
        yield report(
          context,
          path: file.path,
          line: function.line,
          message:
              'new private forwarding wrapper `${function.name}` has one caller',
          confidence: 'high',
        );
      }
    }
  }
}

final class UnrelatedSymbolChurnRule extends _DiffQualityRule {
  UnrelatedSymbolChurnRule() : super('unrelated-symbol-churn');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    for (final SemanticFileDiff file in change.productionFiles) {
      final List<_ChangedFunction> functions = _changedFunctions(file);
      if (functions.length < 4) continue;
      for (final _ChangedFunction function in functions) {
        final bool connected = functions.any(
          (other) =>
              other.name != function.name &&
              (function.source.contains(
                    cachedRegExp('\\b${RegExp.escape(other.name)}\\b'),
                  ) ||
                  other.source.contains(
                    cachedRegExp('\\b${RegExp.escape(function.name)}\\b'),
                  )),
        );
        if (!connected) {
          yield report(
            context,
            path: file.path,
            line: function.line,
            message:
                'changed symbol `${function.name}` is disconnected from ${functions.length - 1} other changed functions',
            confidence: 'medium',
          );
        }
      }
    }
  }
}

final class _ChangedFunction {
  const _ChangedFunction({
    required this.name,
    required this.line,
    required this.source,
    required this.isPrivate,
    required this.isForwarder,
  });

  final String name;
  final int line;
  final String source;
  final bool isPrivate;
  final bool isForwarder;
}

List<_ChangedFunction> _changedFunctions(SemanticFileDiff file) {
  final List<_ChangedFunction> result = <_ChangedFunction>[];
  final RegExp declaration = cachedRegExp(
    r'^\s*(?:(private)\s+)?(?:static\s+)?(?:[A-Za-z_$][\w$<>,?\[\].]*\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:=>\s*(.+);|\{\s*(?:return\s+)?(.+);\s*\})\s*$',
  );
  for (final SemanticLine line in file.addedLines) {
    final RegExpMatch? match = declaration.firstMatch(line.text);
    if (match == null) continue;
    final String? name = match.group(2);
    final String? body = match.group(3) ?? match.group(4);
    if (name == null || body == null) continue;
    final bool privateName = name.startsWith('_') || match.group(1) != null;
    final bool forwarder = cachedRegExp(
      r'^(?:await\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\s*\([^;]*\)$',
    ).hasMatch(body.trim());
    result.add(
      _ChangedFunction(
        name: name,
        line: line.number,
        source: line.text,
        isPrivate: privateName,
        isForwarder: forwarder,
      ),
    );
  }
  return result;
}

String _referenceSource(RuleContext context) => context.sources.entries
    .expand(
      (entry) => maskGenericRuleStrings(
        entry.value.split('\n'),
        sourcePath: entry.key,
      ),
    )
    .join('\n');

int _identifierOccurrences(String source, String identifier) => cachedRegExp(
  '\\b${RegExp.escape(identifier)}\\b',
).allMatches(source).length;
