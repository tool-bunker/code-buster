import 'dart:convert';

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
  'caller-side-guard-duplication': _metadata(
    'caller-side-guard-duplication',
    'Move repeated guards to the shared callee',
    'Equivalent precondition guards added around one project-owned callee in several callers duplicate an invariant and leave sibling callers exposed.',
    'Validate the shared precondition once in the callee when it belongs to that operation.',
    limitations: <String>[
      'Requires at least two newly added single-line conditional calls with the same null, empty, or length guard around a directly declared project function.',
      'Caller-specific authorization, feature policy, and intentionally different fallback behavior cannot be inferred.',
    ],
  ),
  'thin-dependency-for-trivial-capability': _metadata(
    'thin-dependency-for-trivial-capability',
    'Prefer the native trivial capability',
    'A new dependency used once for an operation already provided by the declared runtime adds supply-chain and maintenance cost without owning behavior.',
    'Use the named native operation unless the dependency supplies behavior the call site actually requires.',
    limitations: <String>[
      'Requires a newly added package.json production dependency, one import, one use, and an explicit semantics-preserving capability mapping.',
      'Currently recognizes left-pad via String.padStart and object-assign via Object.assign in JavaScript and TypeScript.',
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

final class CallerSideGuardDuplicationRule extends _DiffQualityRule {
  CallerSideGuardDuplicationRule() : super('caller-side-guard-duplication');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null) return;
    final Map<String, List<_GuardedCall>> groups =
        <String, List<_GuardedCall>>{};
    final RegExp guardedCall = cachedRegExp(
      r'\bif\s*\(\s*([^)]*?)\s*\)\s*(?:\{\s*)?(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)',
    );
    for (final SemanticFileDiff file in change.productionFiles) {
      final List<String> maskedLines = maskGenericRuleStrings(
        file.after.split('\n'),
        sourcePath: file.path,
      );
      for (final SemanticLine line in file.addedLines) {
        final RegExpMatch? match = guardedCall.firstMatch(
          maskedLines[line.number - 1],
        );
        if (match == null) continue;
        final String guard = match.requiredGroup(1);
        final String callee = match.requiredGroup(2);
        final String argument = match.requiredGroup(3);
        if (!cachedRegExp('\\b${RegExp.escape(argument)}\\b').hasMatch(guard) ||
            !cachedRegExp(
              r'\b(?:null|nil|None|isEmpty|isNotEmpty|length)\b',
              caseSensitive: false,
            ).hasMatch(guard) ||
            !_declaresProjectFunction(context, callee)) {
          continue;
        }
        final String shape = guard
            .replaceAll(
              cachedRegExp('\\b${RegExp.escape(argument)}\\b'),
              r'$argument',
            )
            .replaceAll(cachedRegExp(r'\s+'), '');
        groups
            .putIfAbsent('$callee|$shape', () => <_GuardedCall>[])
            .add(_GuardedCall(file.path, line.number, callee));
      }
    }
    for (final List<_GuardedCall> calls in groups.values) {
      if (calls.length < 2) continue;
      final _GuardedCall first = calls.first;
      yield report(
        context,
        path: first.path,
        line: first.line,
        message:
            '${calls.length} callers add the same guard around `${first.callee}`',
        confidence: 'medium',
      );
    }
  }
}

final class ThinDependencyForTrivialCapabilityRule extends _DiffQualityRule {
  ThinDependencyForTrivialCapabilityRule()
    : super('thin-dependency-for-trivial-capability');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final SemanticDiff? change = diff(context);
    if (change == null || !context.changedPaths.contains('package.json')) {
      return;
    }
    final Set<String> added = _addedProductionDependencies(context);
    for (final _NativeCapability capability in _nativeCapabilities) {
      if (!added.contains(capability.package)) continue;
      final List<_DependencyUse> uses = <_DependencyUse>[];
      for (final SemanticFileDiff file in change.productionFiles) {
        final RegExpMatch? import = capability.importPattern.firstMatch(
          file.after,
        );
        if (import == null) continue;
        final String binding = import.requiredGroup(1);
        final String masked = maskGenericRuleStrings(
          file.after.split('\n'),
          sourcePath: file.path,
        ).join('\n');
        if (_identifierOccurrences(masked, binding) == 2) {
          uses.add(_DependencyUse(file.path, import.start, binding));
        }
      }
      if (uses.length != 1) continue;
      final _DependencyUse use = uses.single;
      final String source = context.sources.requiredValue(use.path);
      yield report(
        context,
        path: use.path,
        line: '\n'.allMatches(source.substring(0, use.offset)).length + 1,
        message:
            'new `${capability.package}` dependency is used once for `${use.binding}`; ${capability.replacement} is native',
        confidence: 'high',
      );
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

final class _GuardedCall {
  const _GuardedCall(this.path, this.line, this.callee);

  final String path;
  final int line;
  final String callee;
}

final class _DependencyUse {
  const _DependencyUse(this.path, this.offset, this.binding);

  final String path;
  final int offset;
  final String binding;
}

final class _NativeCapability {
  const _NativeCapability({
    required this.package,
    required this.importPattern,
    required this.replacement,
  });

  final String package;
  final RegExp importPattern;
  final String replacement;
}

final List<_NativeCapability> _nativeCapabilities = <_NativeCapability>[
  _NativeCapability(
    package: 'left-pad',
    importPattern: cachedRegExp(
      r'''(?:import\s+|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)\s*(?:from\s+|=\s*require\(\s*)["']left-pad["']''',
    ),
    replacement: 'String.padStart',
  ),
  _NativeCapability(
    package: 'object-assign',
    importPattern: cachedRegExp(
      r'''(?:import\s+|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)\s*(?:from\s+|=\s*require\(\s*)["']object-assign["']''',
    ),
    replacement: 'Object.assign',
  ),
];

bool _declaresProjectFunction(RuleContext context, String name) {
  final RegExp declaration = cachedRegExp(
    '(?:^|\\n)\\s*(?:(?:export|async|public|private|protected|static)\\s+)*(?:(?:function|def|fun|fn)\\s+${RegExp.escape(name)}\\s*\\(|(?:[A-Za-z_][\\w<>,?\\[\\].]*\\s+)+${RegExp.escape(name)}\\s*\\([^;\\n]*\\)\\s*(?:\\{|=>|:))',
  );
  if (context.sources.entries.any(
    (MapEntry<String, String> entry) => declaration.hasMatch(
      maskGenericRuleStrings(
        entry.value.split('\n'),
        sourcePath: entry.key,
      ).join('\n'),
    ),
  )) {
    return true;
  }
  final RegExp localImport = cachedRegExp(
    '(?:^|\\n)\\s*(?:import\\s*\\{[^}]*\\b${RegExp.escape(name)}\\b[^}]*\\}\\s*from\\s*["\\\']\\.|from\\s+\\.+[\\w.]*\\s+import\\s+[^\\n]*\\b${RegExp.escape(name)}\\b)',
  );
  return context.sources.values.any(localImport.hasMatch);
}

Set<String> _addedProductionDependencies(RuleContext context) {
  final Map<String, Object?> current = _jsonObject(
    context.auxiliaryFiles['package.json'],
  );
  final Map<String, Object?> previous = _jsonObject(
    context.auxiliaryFiles['@base/package.json'],
  );
  return _dependencyNames(current).difference(_dependencyNames(previous));
}

Map<String, Object?> _jsonObject(String? source) {
  if (source == null) return const <String, Object?>{};
  try {
    final Object? decoded = jsonDecode(source);
    return decoded is Map<String, Object?>
        ? decoded
        : const <String, Object?>{};
  } on FormatException {
    return const <String, Object?>{};
  }
}

Set<String> _dependencyNames(Map<String, Object?> manifest) {
  final Object? dependencies = manifest['dependencies'];
  return dependencies is Map<String, Object?>
      ? dependencies.keys.toSet()
      : const <String>{};
}
