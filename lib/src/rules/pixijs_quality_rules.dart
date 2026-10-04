// PixiJS checks focus on v8 migration hazards, frame-loop allocation, and explicit ticker lifecycle ownership.

import '../core/models.dart';
import '../core/regexp_cache.dart';
import '../core/rule.dart';

const List<String> pixiJsQualityRuleIds = <String>[
  'pixijs-v8-legacy-interactive',
  'pixijs-v8-cache-as-bitmap',
  'pixijs-v8-unawaited-application-init',
  'pixijs-v8-numeric-ticker-delta',
  'pixijs-ticker-listener-without-removal',
  'pixijs-frame-loop-allocation',
];

final Map<String, RuleMetadata>
pixiJsQualityRuleMetadata = <String, RuleMetadata>{
  for (final String id in pixiJsQualityRuleIds)
    id: RuleMetadata(
      id: id,
      version: 1,
      defaultSeverity: RuleSeverity.info,
      group: id == 'pixijs-frame-loop-allocation'
          ? 'performance'
          : id == 'pixijs-ticker-listener-without-removal'
          ? 'reliability'
          : 'correctness',
      title: _title(id),
      why: _why(id),
      suggestion: _suggestion(id),
      semanticMaturity: RuleSemanticMaturity.project,
      taxonomy: <FindingTaxonomy>{
        if (id == 'pixijs-frame-loop-allocation')
          FindingTaxonomy.performance
        else if (id == 'pixijs-ticker-listener-without-removal')
          FindingTaxonomy.reliability
        else
          FindingTaxonomy.correctness,
      },
      languages: const <String>['javascript', 'typescript'],
      frameworks: const <String>{'pixijs'},
      limitations: const <String>[
        'PixiJS v8 migration checks require an explicit version 8 pixi.js or @pixi dependency in package.json.',
        'Ticker ownership is resolved only for direct receiver.ticker.add/remove calls and inline frame callbacks.',
      ],
    ),
};

String _title(String id) => switch (id) {
  'pixijs-v8-legacy-interactive' => 'Use PixiJS v8 eventMode',
  'pixijs-v8-cache-as-bitmap' => 'Use PixiJS v8 cacheAsTexture',
  'pixijs-v8-unawaited-application-init' =>
    'Await PixiJS application initialization',
  'pixijs-v8-numeric-ticker-delta' => 'Use PixiJS v8 ticker timing',
  'pixijs-ticker-listener-without-removal' => 'Remove owned ticker listeners',
  'pixijs-frame-loop-allocation' => 'Avoid display-object allocation per frame',
  _ => 'Review PixiJS framework usage',
};

String _why(String id) => switch (id) {
  'pixijs-v8-legacy-interactive' =>
    'PixiJS v8 uses eventMode to control hit testing; the legacy interactive flag obscures the intended mode.',
  'pixijs-v8-cache-as-bitmap' =>
    'PixiJS v8 replaced cacheAsBitmap with the cacheAsTexture API.',
  'pixijs-v8-unawaited-application-init' =>
    'Application.init is asynchronous in PixiJS v8; using the application before completion can race renderer setup.',
  'pixijs-v8-numeric-ticker-delta' =>
    'PixiJS v8 ticker callbacks receive a Ticker object rather than a numeric delta value.',
  'pixijs-ticker-listener-without-removal' =>
    'An owned ticker callback that is never removed can retain objects and continue updating after its feature is disposed.',
  'pixijs-frame-loop-allocation' =>
    'Allocating display objects every frame creates avoidable garbage and GPU/resource churn.',
  _ =>
    'The explicit PixiJS pattern can weaken lifecycle or rendering behavior.',
};

String _suggestion(String id) => switch (id) {
  'pixijs-v8-legacy-interactive' =>
    "Set eventMode to 'static' or 'dynamic' according to whether the target moves.",
  'pixijs-v8-cache-as-bitmap' =>
    'Use cacheAsTexture() and update or disable the cache deliberately when content changes.',
  'pixijs-v8-unawaited-application-init' =>
    'Await app.init(options) before accessing the canvas, renderer, stage, or ticker.',
  'pixijs-v8-numeric-ticker-delta' =>
    'Use the callback Ticker object and read ticker.deltaTime or ticker.deltaMS.',
  'pixijs-ticker-listener-without-removal' =>
    'Remove the same callback during feature or component disposal, or stop/destroy the owning application.',
  'pixijs-frame-loop-allocation' =>
    'Create and attach display objects outside the ticker callback, then mutate or pool them per frame.',
  _ =>
    'Use the explicit PixiJS lifecycle or rendering API appropriate to this finding.',
};

final class PixiJsQualityRule extends SelfContainedRule {
  PixiJsQualityRule(String id)
    : super(pixiJsQualityRuleMetadata.requiredValue(id));

  @override
  Iterable<Finding> analyze(RuleContext context) => switch (metadata.id) {
    'pixijs-v8-legacy-interactive' => _legacyInteractive(context),
    'pixijs-v8-cache-as-bitmap' => _legacyCache(context),
    'pixijs-v8-unawaited-application-init' => _unawaitedInit(context),
    'pixijs-v8-numeric-ticker-delta' => _numericTickerDelta(context),
    'pixijs-ticker-listener-without-removal' => _tickerRemoval(context),
    'pixijs-frame-loop-allocation' => _frameAllocations(context),
    _ => const <Finding>[],
  };

  Finding _finding(
    RuleContext context,
    _PixiSource source,
    int offset,
    String message, {
    String confidence = 'high',
  }) => report(
    context,
    path: source.path,
    line: source.lineAt(offset),
    message: message,
    confidence: confidence,
  );

  Iterable<Finding> _legacyInteractive(RuleContext context) sync* {
    if (!_isPixiV8(context)) return;
    for (final _PixiSource source in _sources(context)) {
      for (final RegExpMatch match in cachedRegExp(
        r'\.[ \t]*interactive\s*=\s*true\b',
      ).allMatches(source.masked)) {
        yield _finding(
          context,
          source,
          match.start,
          'legacy interactive=true is used with PixiJS v8',
        );
      }
    }
  }

  Iterable<Finding> _legacyCache(RuleContext context) sync* {
    if (!_isPixiV8(context)) return;
    for (final _PixiSource source in _sources(context)) {
      for (final RegExpMatch match in cachedRegExp(
        r'\.cacheAsBitmap\b',
      ).allMatches(source.masked)) {
        yield _finding(
          context,
          source,
          match.start,
          'cacheAsBitmap is a legacy API in PixiJS v8',
        );
      }
    }
  }

  Iterable<Finding> _unawaitedInit(RuleContext context) sync* {
    if (!_isPixiV8(context)) return;
    final RegExp application = cachedRegExp(
      r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+Application\b',
    );
    for (final _PixiSource source in _sources(context)) {
      for (final RegExpMatch declaration in application.allMatches(
        source.masked,
      )) {
        final String? name = declaration.group(1);
        if (name == null) continue;
        final RegExp init = cachedRegExp(
          '\\b${RegExp.escape(name)}\\.init\\s*\\(',
        );
        for (final RegExpMatch call in init.allMatches(source.masked)) {
          final int lineStart = source.masked.lastIndexOf('\n', call.start) + 1;
          final String prefix = source.masked.substring(lineStart, call.start);
          if (cachedRegExp(r'\bawait\s*$').hasMatch(prefix)) continue;
          yield _finding(
            context,
            source,
            call.start,
            '$name.init is not awaited',
          );
        }
      }
    }
  }

  Iterable<Finding> _numericTickerDelta(RuleContext context) sync* {
    if (!_isPixiV8(context)) return;
    final RegExp callback = cachedRegExp(
      r'\.ticker\.add\s*\(\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>',
    );
    for (final _PixiSource source in _sources(context)) {
      for (final RegExpMatch match in callback.allMatches(source.masked)) {
        final String? parameter = match.group(1);
        if (parameter == null) continue;
        final String tail = source.masked.substring(
          match.end,
          (match.end + 600).clamp(0, source.masked.length),
        );
        if (cachedRegExp(
          '\\b${RegExp.escape(parameter)}\\.(?:deltaTime|deltaMS|elapsedMS)\\b',
        ).hasMatch(tail)) {
          continue;
        }
        if (!cachedRegExp(
          '(?:[+*\\-/]=\\s*${RegExp.escape(parameter)}\\b|\\b${RegExp.escape(parameter)}\\s*[*\\-/])',
        ).hasMatch(tail)) {
          continue;
        }
        yield _finding(
          context,
          source,
          match.start,
          'ticker callback parameter `$parameter` is used as a numeric delta',
        );
      }
    }
  }

  Iterable<Finding> _tickerRemoval(RuleContext context) sync* {
    final RegExp add = cachedRegExp(
      r'\b([A-Za-z_$][\w$]*)\.ticker\.add\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]',
    );
    for (final _PixiSource source in _sources(context)) {
      for (final RegExpMatch match in add.allMatches(source.masked)) {
        final String? receiver = match.group(1);
        final String? handler = match.group(2);
        if (receiver == null || handler == null) continue;
        if (cachedRegExp(
          '\\b${RegExp.escape(receiver)}\\.ticker\\.remove\\s*\\(\\s*${RegExp.escape(handler)}\\s*[,)]',
        ).hasMatch(source.masked)) {
          continue;
        }
        yield _finding(
          context,
          source,
          match.start,
          '$receiver.ticker.add($handler) has no matching removal',
          confidence: 'medium',
        );
      }
    }
  }

  Iterable<Finding> _frameAllocations(RuleContext context) sync* {
    final RegExp callback = cachedRegExp(r'\.ticker\.add\s*\([^=]*=>\s*\{');
    final RegExp allocation = cachedRegExp(
      r'\bnew\s+(Graphics|Text|Sprite|Container)\s*\(',
    );
    for (final _PixiSource source in _sources(context)) {
      for (final RegExpMatch match in callback.allMatches(source.masked)) {
        final int opening = source.masked.indexOf('{', match.start);
        final int close = _matchingBrace(source.masked, opening);
        if (opening < 0 || close < 0) continue;
        final RegExpMatch? created = allocation.firstMatch(
          source.masked.substring(opening + 1, close),
        );
        if (created == null) continue;
        final String? type = created.group(1);
        if (type == null) continue;
        yield _finding(
          context,
          source,
          opening + 1 + created.start,
          'ticker callback allocates a new $type every frame',
        );
      }
    }
  }
}

final class _PixiSource {
  _PixiSource(this.path, this.source) : masked = _mask(source);

  final String path;
  final String source;
  final String masked;

  int lineAt(int offset) =>
      '\n'.allMatches(source.substring(0, offset)).length + 1;
}

Iterable<_PixiSource> _sources(RuleContext context) sync* {
  final List<String> paths = context.sources.keys.where((String path) {
    final String lower = path.toLowerCase();
    return lower.endsWith('.js') ||
        lower.endsWith('.jsx') ||
        lower.endsWith('.mjs') ||
        lower.endsWith('.cjs') ||
        lower.endsWith('.ts') ||
        lower.endsWith('.tsx') ||
        lower.endsWith('.mts') ||
        lower.endsWith('.cts');
  }).toList()..sort();
  for (final String path in paths) {
    yield _PixiSource(path, context.sources.requiredValue(path));
  }
}

bool _isPixiV8(RuleContext context) {
  for (final MapEntry<String, String> entry in context.auxiliaryFiles.entries) {
    if (!entry.key.toLowerCase().endsWith('package.json')) continue;
    if (cachedRegExp(
      r'''["'](?:pixi\.js|@pixi/[^"']+)["']\s*:\s*["'][^"']*\b8(?:\.|["'])''',
    ).hasMatch(entry.value)) {
      return true;
    }
  }
  return false;
}

int _matchingBrace(String source, int opening) {
  if (opening < 0) return -1;
  var depth = 0;
  for (var index = opening; index < source.length; index++) {
    if (source.codeUnitAt(index) == 123) depth++;
    if (source.codeUnitAt(index) == 125 && --depth == 0) return index;
  }
  return -1;
}

String _mask(String source) {
  final List<int> result = source.codeUnits.toList();
  var index = 0;
  while (index < result.length) {
    if (index + 1 < result.length &&
        result[index] == 47 &&
        result[index + 1] == 47) {
      while (index < result.length && result[index] != 10) {
        result[index++] = 32;
      }
      continue;
    }
    if (index + 1 < result.length &&
        result[index] == 47 &&
        result[index + 1] == 42) {
      result[index++] = 32;
      result[index++] = 32;
      while (index + 1 < result.length &&
          !(result[index] == 42 && result[index + 1] == 47)) {
        if (result[index] != 10) result[index] = 32;
        index++;
      }
      if (index + 1 < result.length) {
        result[index++] = 32;
        result[index++] = 32;
      }
      continue;
    }
    if (result[index] == 34 || result[index] == 39 || result[index] == 96) {
      final int quote = result[index];
      result[index++] = 32;
      while (index < result.length) {
        if (result[index] == 92) {
          result[index++] = 32;
          if (index < result.length && result[index] != 10) {
            result[index++] = 32;
          }
          continue;
        }
        if (result[index] == quote) {
          result[index++] = 32;
          break;
        }
        if (result[index] != 10) result[index] = 32;
        index++;
      }
      continue;
    }
    index++;
  }
  return String.fromCharCodes(result);
}
