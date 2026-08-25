// Parallel UI implementations quietly diverge because each local copy evolves without the shared component or token.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports CSS selectors that independently declare the same substantial style.
final class CssDuplicateDeclarationSetRule extends SelfContainedRule {
  /// Creates the project-level CSS declaration comparison.
  const CssDuplicateDeclarationSetRule()
    : super(
        const RuleMetadata(
          id: 'css-duplicate-declaration-set',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Share repeated CSS declaration sets',
          why:
              'Independent selectors with the same substantial style can drift instead of evolving as one component.',
          suggestion:
              'Extract a shared component class, utility, or custom property set when the selectors represent one visual role.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['css'],
          limitations: <String>[
            'Nested CSS blocks and semantically equivalent shorthand declarations are not compared.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final List<_CssBlock> blocks = _cssBlocks(context.sources);
    final Map<String, List<_CssBlock>> bySignature =
        <String, List<_CssBlock>>{};
    for (final _CssBlock block in blocks) {
      if (block.declarations.length < 4) continue;
      final String signature = _declarationSignature(block.declarations);
      bySignature.putIfAbsent(signature, () => <_CssBlock>[]).add(block);
    }
    for (final List<_CssBlock> matches in bySignature.values) {
      if (matches.length < 2) continue;
      final _CssBlock first = matches.first;
      for (final _CssBlock duplicate in matches.skip(1)) {
        yield report(
          context,
          path: duplicate.path,
          line: duplicate.line,
          message:
              '`${duplicate.selector}` duplicates ${duplicate.declarations.length} declarations from `${first.selector}`',
          confidence: 'high',
          relatedFiles: <String>['${first.path}:${first.line}'],
        );
      }
    }
  }
}

/// Reports raw CSS values that bypass an existing custom property with the same value.
final class CssDesignTokenDriftRule extends SelfContainedRule {
  /// Creates the project-level CSS token comparison.
  const CssDesignTokenDriftRule()
    : super(
        const RuleMetadata(
          id: 'css-design-token-drift',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Use existing CSS design tokens',
          why:
              'Repeating a token value directly creates another place that must change when the design system evolves.',
          suggestion:
              'Use the existing CSS custom property when the raw value has the same visual meaning.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['css'],
          limitations: <String>[
            'Only exact normalized values with an existing CSS custom property are compared.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, ({String name, String path, int line})> tokens =
        <String, ({String name, String path, int line})>{};
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.css')) continue;
      for (final RegExpMatch match in _cssDeclaration.allMatches(
        _withoutCssComments(entry.value),
      )) {
        final String property = match.group(1)!.trim();
        if (!property.startsWith('--')) continue;
        final String value = _normalizeCssValue(match.group(2)!);
        if (_usefulTokenValue(value)) {
          tokens.putIfAbsent(
            value,
            () => (
              name: property,
              path: entry.key,
              line: _lineAt(entry.value, match.start),
            ),
          );
        }
      }
    }
    if (tokens.isEmpty) return;

    for (final _CssBlock block in _cssBlocks(context.sources)) {
      for (final MapEntry<String, String> declaration
          in block.declarations.entries) {
        if (declaration.key.startsWith('--') ||
            declaration.value.contains('var(')) {
          continue;
        }
        final ({String name, String path, int line})? token =
            tokens[declaration.value];
        if (token == null) continue;
        yield report(
          context,
          path: block.path,
          line: block.line,
          message:
              '`${declaration.key}` repeats `${declaration.value}` instead of `${token.name}`',
          confidence: 'high',
          relatedFiles: <String>['${token.path}:${token.line}'],
        );
      }
    }
  }
}

/// Reports repeated substantial Flutter style constructors across files.
final class FlutterRepeatedInlineStyleRule extends SelfContainedRule {
  /// Creates the Flutter inline-style comparison.
  const FlutterRepeatedInlineStyleRule()
    : super(
        const RuleMetadata(
          id: 'flutter-repeated-inline-style',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Share repeated Flutter styles',
          why:
              'Repeated inline visual definitions can drift instead of evolving through one theme or component.',
          suggestion:
              'Extract a shared style, theme entry, or widget when the repeated definitions represent one visual role.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['dart'],
          limitations: <String>[
            'Only exact normalized style constructors with at least three named arguments are compared.',
          ],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, List<_StyleOccurrence>> groups =
        <String, List<_StyleOccurrence>>{};
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.dart')) continue;
      for (final _StyleOccurrence style in _flutterStyles(
        entry.key,
        entry.value,
      )) {
        groups
            .putIfAbsent(style.signature, () => <_StyleOccurrence>[])
            .add(style);
      }
    }
    for (final List<_StyleOccurrence> matches in groups.values) {
      final Set<String> paths = matches
          .map((_StyleOccurrence item) => item.path)
          .toSet();
      if (paths.length < 2) continue;
      final _StyleOccurrence first = matches.first;
      for (final _StyleOccurrence duplicate in matches.skip(1)) {
        if (duplicate.path == first.path) continue;
        yield report(
          context,
          path: duplicate.path,
          line: duplicate.line,
          message:
              '`${duplicate.constructor}` repeats an inline style from `${first.path}`',
          confidence: 'high',
          relatedFiles: <String>['${first.path}:${first.line}'],
        );
      }
    }
  }
}

/// Reports direct Flutter color values that duplicate a project color token.
final class FlutterThemeBypassRule extends SelfContainedRule {
  /// Creates the Flutter theme-token comparison.
  const FlutterThemeBypassRule()
    : super(
        const RuleMetadata(
          id: 'flutter-theme-bypass',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Use existing Flutter theme tokens',
          why:
              'Repeating a raw visual value bypasses the project abstraction that keeps the interface consistent.',
          suggestion:
              'Use the existing project color token when it represents the same visual role.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['dart'],
          limitations: <String>[
            'Only exact Color or Colors expressions matching a declared project constant are compared.',
          ],
        ),
      );

  static final RegExp _tokenDeclaration = RegExp(
    r'\b(?:static\s+)?const\s+(?:Color\s+)?([A-Za-z_]\w*)\s*=\s*(Color\s*\(\s*0x[0-9A-Fa-f]+\s*\)|Colors\.[A-Za-z_]\w*)\s*;',
  );
  static final RegExp _colorExpression = RegExp(
    r'Color\s*\(\s*0x[0-9A-Fa-f]+\s*\)|Colors\.[A-Za-z_]\w*',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Map<String, _FlutterToken> tokens = <String, _FlutterToken>{};
    final Set<String> declarationLocations = <String>{};
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.dart')) continue;
      for (final RegExpMatch match in _tokenDeclaration.allMatches(
        entry.value,
      )) {
        final String expression = _normalizeDart(match.group(2)!);
        final int line = _lineAt(entry.value, match.start);
        tokens.putIfAbsent(
          expression,
          () => _FlutterToken(match.group(1)!, entry.key, line),
        );
        declarationLocations.add(
          '${entry.key}:${match.start + match.group(0)!.indexOf(match.group(2)!)}',
        );
      }
    }
    if (tokens.isEmpty) return;

    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.dart')) continue;
      for (final RegExpMatch match in _colorExpression.allMatches(
        entry.value,
      )) {
        if (declarationLocations.contains('${entry.key}:${match.start}')) {
          continue;
        }
        final _FlutterToken? token = tokens[_normalizeDart(match.group(0)!)];
        if (token == null) continue;
        yield report(
          context,
          path: entry.key,
          line: _lineAt(entry.value, match.start),
          message:
              'raw `${match.group(0)}` duplicates project color token `${token.name}`',
          confidence: 'high',
          relatedFiles: <String>['${token.path}:${token.line}'],
        );
      }
    }
  }
}

/// Reports button-like Flutter pointer trees alongside semantic button widgets.
final class FlutterParallelControlComponentRule extends SelfContainedRule {
  /// Creates the Flutter control-divergence comparison.
  const FlutterParallelControlComponentRule()
    : super(
        const RuleMetadata(
          id: 'flutter-parallel-control-component',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Consolidate parallel Flutter controls',
          why:
              'A custom pointer-driven control beside semantic buttons can create a second implementation of the same interaction role.',
          suggestion:
              'Confirm the variation is intentional; otherwise reuse a semantic button or shared project control.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['dart'],
          limitations: <String>[
            'Button-like pointer trees are inferred from GestureDetector or InkWell containing both Container and Text.',
          ],
        ),
      );

  static final RegExp _semanticButton = RegExp(
    r'\b(?:ElevatedButton|FilledButton|TextButton|OutlinedButton|IconButton)\s*\(',
  );
  static final RegExp _pointerControl = RegExp(
    r'\b(?:GestureDetector|InkWell)\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    _Location? semantic;
    final List<_Location> pointerControls = <_Location>[];
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.dart')) continue;
      semantic ??= _firstLocation(entry.key, entry.value, _semanticButton);
      for (final RegExpMatch match in _pointerControl.allMatches(entry.value)) {
        final int close = _matchingDelimiter(
          entry.value,
          match.end - 1,
          '(',
          ')',
        );
        if (close == -1) continue;
        final String tree = entry.value.substring(match.start, close + 1);
        if (RegExp(r'\bContainer\s*\(').hasMatch(tree) &&
            RegExp(r'\bText\s*\(').hasMatch(tree)) {
          pointerControls.add(
            _Location(entry.key, _lineAt(entry.value, match.start)),
          );
        }
      }
    }
    if (semantic == null) return;
    for (final _Location pointer in pointerControls) {
      yield report(
        context,
        path: pointer.path,
        line: pointer.line,
        message:
            'button-like pointer tree exists alongside semantic Flutter buttons',
        confidence: 'medium',
        relatedFiles: <String>['${semantic.path}:${semantic.line}'],
      );
    }
  }
}

/// Reports direct Flutter controls that bypass an established shared wrapper.
final class FlutterSharedComponentBypassRule extends SelfContainedRule {
  /// Creates the project-level shared-component convention check.
  const FlutterSharedComponentBypassRule()
    : super(
        const RuleMetadata(
          id: 'flutter-shared-component-bypass',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Reuse established Flutter components',
          why:
              'Direct framework controls can drift from a shared component already used as the project convention.',
          suggestion:
              'Confirm the direct control is an intentional variant; otherwise use the established shared component.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['dart'],
          limitations: <String>[
            'A convention requires at least three external uses across two production files.',
            'Shared widgets are inferred from StatelessWidget or StatefulWidget classes that contain a known Flutter control.',
          ],
        ),
      );

  static final RegExp _widgetClass = RegExp(
    r'\bclass\s+([A-Za-z_]\w*)\s+extends\s+(?:StatelessWidget|StatefulWidget)\b[^{]*\{',
  );
  static final RegExp _frameworkControl = RegExp(
    r'\b(ElevatedButton|FilledButton|TextButton|OutlinedButton|IconButton|TextField|AlertDialog|Card|Scaffold|Checkbox)\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final List<_SharedWidget> wrappers = <_SharedWidget>[];
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.dart') || _isUiAuxiliaryPath(entry.key)) {
        continue;
      }
      for (final RegExpMatch declaration in _widgetClass.allMatches(
        entry.value,
      )) {
        final int open = declaration.end - 1;
        final int close = _matchingDelimiter(entry.value, open, '{', '}');
        if (close == -1) continue;
        final RegExpMatch? control = _frameworkControl.firstMatch(
          entry.value.substring(open + 1, close),
        );
        if (control == null) continue;
        wrappers.add(
          _SharedWidget(
            name: declaration.group(1)!,
            frameworkControl: control.group(1)!,
            path: entry.key,
            line: _lineAt(entry.value, declaration.start),
            start: declaration.start,
            end: close,
          ),
        );
      }
    }

    final List<_EstablishedWidget> established = <_EstablishedWidget>[];
    for (final _SharedWidget wrapper in wrappers) {
      final List<_Location> usages = <_Location>[];
      final RegExp use = RegExp('\\b${RegExp.escape(wrapper.name)}\\s*\\(');
      for (final MapEntry<String, String> entry in context.sources.entries) {
        if (!entry.key.endsWith('.dart') || _isUiAuxiliaryPath(entry.key)) {
          continue;
        }
        for (final RegExpMatch match in use.allMatches(entry.value)) {
          if (entry.key == wrapper.path &&
              match.start >= wrapper.start &&
              match.start <= wrapper.end) {
            continue;
          }
          usages.add(_Location(entry.key, _lineAt(entry.value, match.start)));
        }
      }
      if (usages.length >= 3 &&
          usages.map((_Location usage) => usage.path).toSet().length >= 2) {
        established.add(_EstablishedWidget(wrapper, usages));
      }
    }

    final Map<String, List<_EstablishedWidget>> byControl =
        <String, List<_EstablishedWidget>>{};
    for (final _EstablishedWidget widget in established) {
      byControl
          .putIfAbsent(
            widget.wrapper.frameworkControl,
            () => <_EstablishedWidget>[],
          )
          .add(widget);
    }

    for (final MapEntry<String, List<_EstablishedWidget>> group
        in byControl.entries) {
      final List<_EstablishedWidget> conventions = group.value
        ..sort(
          (_EstablishedWidget left, _EstablishedWidget right) =>
              right.usages.length.compareTo(left.usages.length),
        );
      if (conventions.length > 1 &&
          conventions[0].usages.length == conventions[1].usages.length) {
        continue;
      }
      final _EstablishedWidget convention = conventions.first;
      final RegExp direct = RegExp('\\b${RegExp.escape(group.key)}\\s*\\(');
      for (final MapEntry<String, String> entry in context.sources.entries) {
        if (!entry.key.endsWith('.dart') || _isUiAuxiliaryPath(entry.key)) {
          continue;
        }
        for (final RegExpMatch match in direct.allMatches(entry.value)) {
          if (wrappers.any(
            (_SharedWidget wrapper) =>
                wrapper.path == entry.key &&
                match.start >= wrapper.start &&
                match.start <= wrapper.end,
          )) {
            continue;
          }
          yield report(
            context,
            path: entry.key,
            line: _lineAt(entry.value, match.start),
            message:
                'direct `${group.key}` bypasses established `${convention.wrapper.name}` used ${convention.usages.length} times',
            confidence: 'medium',
            relatedFiles: <String>[
              '${convention.wrapper.path}:${convention.wrapper.line}',
              ...convention.usages
                  .take(3)
                  .map((_Location usage) => '${usage.path}:${usage.line}'),
            ],
          );
        }
      }
    }
  }
}

/// Reports mixed semantic implementations of button-like HTML controls.
final class HtmlParallelControlPatternRule extends SelfContainedRule {
  /// Creates the HTML control-divergence comparison.
  const HtmlParallelControlPatternRule()
    : super(
        const RuleMetadata(
          id: 'html-parallel-control-pattern',
          defaultSeverity: RuleSeverity.info,
          group: 'maintainability',
          title: 'Consolidate parallel HTML controls',
          why:
              'Mixing native buttons with separately styled button-like elements creates competing interaction implementations.',
          suggestion:
              'Prefer the established native button or shared component unless the semantic variation is intentional.',
          semanticMaturity: RuleSemanticMaturity.project,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.design},
          languages: <String>['html'],
          limitations: <String>[
            'Button-like alternatives are inferred from role=button or click handlers on non-button elements.',
          ],
        ),
      );

  static final RegExp _nativeButton = RegExp(
    r'<button\b',
    caseSensitive: false,
  );
  static final RegExp _alternative = RegExp(
    r'''<(?:a|div|span)\b[^>]*(?:role\s*=\s*["']button["']|on(?:click|keydown)\s*=)[^>]*>''',
    caseSensitive: false,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    _Location? native;
    final List<_Location> alternatives = <_Location>[];
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!entry.key.endsWith('.html') && !entry.key.endsWith('.htm')) continue;
      native ??= _firstLocation(entry.key, entry.value, _nativeButton);
      for (final RegExpMatch match in _alternative.allMatches(entry.value)) {
        alternatives.add(
          _Location(entry.key, _lineAt(entry.value, match.start)),
        );
      }
    }
    if (native == null) return;
    for (final _Location alternative in alternatives) {
      yield report(
        context,
        path: alternative.path,
        line: alternative.line,
        message:
            'button-like non-button element exists alongside native buttons',
        confidence: 'high',
        relatedFiles: <String>['${native.path}:${native.line}'],
      );
    }
  }
}

final RegExp _cssBlock = RegExp(r'([^{}]+)\{([^{}]+)\}', multiLine: true);
final RegExp _cssDeclaration = RegExp(r'([\w-]+)\s*:\s*([^;{}]+)\s*;');

List<_CssBlock> _cssBlocks(Map<String, String> sources) {
  final List<_CssBlock> result = <_CssBlock>[];
  for (final MapEntry<String, String> entry in sources.entries) {
    if (!entry.key.endsWith('.css')) continue;
    final String source = _withoutCssComments(entry.value);
    for (final RegExpMatch block in _cssBlock.allMatches(source)) {
      final String selector = block.group(1)!.trim();
      if (selector.startsWith('@') || selector.isEmpty) continue;
      final Map<String, String> declarations = <String, String>{};
      for (final RegExpMatch declaration in _cssDeclaration.allMatches(
        block.group(2)!,
      )) {
        declarations[declaration.group(1)!.toLowerCase()] = _normalizeCssValue(
          declaration.group(2)!,
        );
      }
      if (declarations.isNotEmpty) {
        result.add(
          _CssBlock(
            entry.key,
            _lineAt(source, block.start + block.group(0)!.indexOf(selector)),
            selector,
            declarations,
          ),
        );
      }
    }
  }
  return result;
}

String _declarationSignature(Map<String, String> declarations) {
  final List<String> pairs =
      declarations.entries
          .map((MapEntry<String, String> item) => '${item.key}:${item.value}')
          .toList()
        ..sort();
  return pairs.join(';');
}

String _withoutCssComments(String source) => source.replaceAllMapped(
  RegExp(r'/\*.*?\*/', dotAll: true),
  (Match match) => ' ' * match.group(0)!.length,
);

String _normalizeCssValue(String value) => value
    .trim()
    .toLowerCase()
    .replaceAll(RegExp(r'\s+'), ' ')
    .replaceAll(RegExp(r'\s*([,()/])\s*'), r'$1')
    .replaceAll(RegExp(r'\b0(?:px|em|rem|%|s|ms)\b'), '0')
    .replaceAllMapped(
      RegExp(r'#([0-9a-f])\1([0-9a-f])\2([0-9a-f])\3\b'),
      (Match match) => '#${match.group(1)}${match.group(2)}${match.group(3)}',
    );

bool _usefulTokenValue(String value) =>
    value.length >= 3 &&
    !const <String>{
      '0',
      'none',
      'auto',
      'inherit',
      'initial',
      'unset',
      'transparent',
    }.contains(value);

final RegExp _styleConstructor = RegExp(
  r'\b(TextStyle|ButtonStyle|BoxDecoration|InputDecoration|ElevatedButton\.styleFrom)\s*\(',
);

Iterable<_StyleOccurrence> _flutterStyles(String path, String source) sync* {
  for (final RegExpMatch match in _styleConstructor.allMatches(source)) {
    final int open = match.end - 1;
    final int close = _matchingDelimiter(source, open, '(', ')');
    if (close == -1) continue;
    final String body = source.substring(open + 1, close);
    if (RegExp(r'\b[A-Za-z_]\w*\s*:').allMatches(body).length < 3) continue;
    yield _StyleOccurrence(
      path,
      _lineAt(source, match.start),
      match.group(1)!,
      '${match.group(1)}:${_normalizeDart(body)}',
    );
  }
}

int _matchingDelimiter(
  String source,
  int open,
  String opening,
  String closing,
) {
  var depth = 0;
  String? quote;
  for (var index = open; index < source.length; index++) {
    final String character = source[index];
    if (quote != null) {
      if (character == r'\' && index + 1 < source.length) {
        index++;
      } else if (character == quote) {
        quote = null;
      }
      continue;
    }
    if (character == '"' || character == "'") {
      quote = character;
    } else if (character == opening) {
      depth++;
    } else if (character == closing && --depth == 0) {
      return index;
    }
  }
  return -1;
}

String _normalizeDart(String source) => source
    .replaceAll(RegExp(r'//.*?$|/\*.*?\*/', multiLine: true, dotAll: true), '')
    .replaceAll(RegExp(r'\s+'), '');

int _lineAt(String source, int offset) =>
    1 + '\n'.allMatches(source.substring(0, offset)).length;

_Location? _firstLocation(String path, String source, RegExp pattern) {
  final RegExpMatch? match = pattern.firstMatch(source);
  return match == null ? null : _Location(path, _lineAt(source, match.start));
}

bool _isUiAuxiliaryPath(String path) {
  final String normalized = path.replaceAll(r'\', '/');
  return normalized.endsWith('.g.dart') ||
      RegExp(
        r'(^|/)(?:test|tests|example|examples|fixture|fixtures|generated)(?:/|$)',
      ).hasMatch(normalized);
}

final class _CssBlock {
  const _CssBlock(this.path, this.line, this.selector, this.declarations);

  final String path;
  final int line;
  final String selector;
  final Map<String, String> declarations;
}

final class _StyleOccurrence {
  const _StyleOccurrence(
    this.path,
    this.line,
    this.constructor,
    this.signature,
  );

  final String path;
  final int line;
  final String constructor;
  final String signature;
}

final class _FlutterToken {
  const _FlutterToken(this.name, this.path, this.line);

  final String name;
  final String path;
  final int line;
}

final class _SharedWidget {
  const _SharedWidget({
    required this.name,
    required this.frameworkControl,
    required this.path,
    required this.line,
    required this.start,
    required this.end,
  });

  final String name;
  final String frameworkControl;
  final String path;
  final int line;
  final int start;
  final int end;
}

final class _EstablishedWidget {
  const _EstablishedWidget(this.wrapper, this.usages);

  final _SharedWidget wrapper;
  final List<_Location> usages;
}

final class _Location {
  const _Location(this.path, this.line);

  final String path;
  final int line;
}
