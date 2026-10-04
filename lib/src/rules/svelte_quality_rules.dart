// Conservative Svelte checks focus on lifecycle, SSR, keyed animation, and explicit HTML trust boundaries.

import '../core/models.dart';
import '../core/regexp_cache.dart';
import '../core/rule.dart';

const List<String> svelteQualityRuleIds = <String>[
  'svelte-async-onmount-cleanup',
  'svelte-global-listener-without-cleanup',
  'svelte-interval-without-cleanup',
  'svelte-dynamic-html',
  'svelte-animate-unkeyed-each',
  'svelte-module-browser-global',
];

final Map<String, RuleMetadata>
svelteQualityRuleMetadata = <String, RuleMetadata>{
  for (final String id in svelteQualityRuleIds)
    id: RuleMetadata(
      id: id,
      version: 1,
      defaultSeverity: RuleSeverity.info,
      group: id == 'svelte-dynamic-html'
          ? 'security'
          : id == 'svelte-animate-unkeyed-each'
          ? 'correctness'
          : 'reliability',
      title: _title(id),
      why: _why(id),
      suggestion: _suggestion(id),
      semanticMaturity: RuleSemanticMaturity.project,
      taxonomy: <FindingTaxonomy>{
        if (id == 'svelte-dynamic-html')
          FindingTaxonomy.security
        else if (id == 'svelte-animate-unkeyed-each')
          FindingTaxonomy.correctness
        else
          FindingTaxonomy.reliability,
      },
      securityKind: id == 'svelte-dynamic-html'
          ? SecurityFindingKind.hotspot
          : SecurityFindingKind.none,
      languages: const <String>['html', 'javascript', 'typescript'],
      frameworks: const <String>{'svelte'},
      limitations: const <String>[
        'Only explicit syntax inside discovered .svelte components is analyzed.',
        'Custom lifecycle wrappers, aliased browser globals, and behavior in generated components are not resolved.',
      ],
    ),
};

String _title(String id) => switch (id) {
  'svelte-async-onmount-cleanup' => 'Keep onMount cleanup synchronous',
  'svelte-global-listener-without-cleanup' =>
    'Remove manually registered global listeners',
  'svelte-interval-without-cleanup' => 'Clear component intervals',
  'svelte-dynamic-html' => 'Review dynamic Svelte HTML',
  'svelte-animate-unkeyed-each' => 'Key animated each blocks',
  'svelte-module-browser-global' =>
    'Keep browser globals out of module initialization',
  _ => 'Review Svelte framework usage',
};

String _why(String id) => switch (id) {
  'svelte-async-onmount-cleanup' =>
    'An async onMount callback returns a Promise, so Svelte cannot use its returned cleanup function.',
  'svelte-global-listener-without-cleanup' =>
    'A global listener that survives component destruction retains callbacks and can duplicate behavior after remounting.',
  'svelte-interval-without-cleanup' =>
    'An interval that survives component destruction continues work against stale component state.',
  'svelte-dynamic-html' =>
    'Svelte inserts {@html} content without escaping; data crossing an unverified trust boundary can execute markup or script.',
  'svelte-animate-unkeyed-each' =>
    'Svelte animation directives require stable keyed identity to match DOM nodes across list updates.',
  'svelte-module-browser-global' =>
    'Module scripts can execute during server rendering, where browser-only globals are unavailable.',
  _ =>
    'The explicit Svelte pattern can weaken lifecycle or rendering behavior.',
};

String _suggestion(String id) => switch (id) {
  'svelte-async-onmount-cleanup' =>
    'Keep the onMount callback synchronous, start async work inside it, and return cleanup directly.',
  'svelte-global-listener-without-cleanup' =>
    'Use <svelte:window>, or remove the same listener from returned onMount/\$effect cleanup.',
  'svelte-interval-without-cleanup' =>
    'Retain the interval handle and clear it from returned onMount/\$effect cleanup.',
  'svelte-dynamic-html' =>
    'Render structured Svelte markup or sanitize the value at a documented trust boundary before {@html}.',
  'svelte-animate-unkeyed-each' =>
    'Add a stable key expression to the each block.',
  'svelte-module-browser-global' =>
    'Move browser work to instance onMount/\$effect or guard it with the SvelteKit browser environment.',
  _ =>
    'Use the explicit lifecycle or rendering boundary appropriate to this finding.',
};

final class SvelteQualityRule extends SelfContainedRule {
  SvelteQualityRule(String id)
    : super(svelteQualityRuleMetadata.requiredValue(id));

  @override
  Iterable<Finding> analyze(RuleContext context) => switch (metadata.id) {
    'svelte-async-onmount-cleanup' => _asyncOnMount(context),
    'svelte-global-listener-without-cleanup' => _globalListeners(context),
    'svelte-interval-without-cleanup' => _intervals(context),
    'svelte-dynamic-html' => _dynamicHtml(context),
    'svelte-animate-unkeyed-each' => _unkeyedAnimation(context),
    'svelte-module-browser-global' => _moduleBrowserGlobals(context),
    _ => const <Finding>[],
  };

  Finding _finding(
    RuleContext context,
    _SvelteSource source,
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

  Iterable<Finding> _asyncOnMount(RuleContext context) sync* {
    for (final _SvelteSource source in _sources(context)) {
      for (final RegExpMatch match in cachedRegExp(
        r'\bonMount\s*\(\s*async\b',
      ).allMatches(source.masked)) {
        yield _finding(
          context,
          source,
          match.start,
          'onMount uses an async callback and cannot return cleanup synchronously',
        );
      }
    }
  }

  Iterable<Finding> _globalListeners(RuleContext context) sync* {
    for (final _SvelteSource source in _sources(context)) {
      final RegExp add = cachedRegExp(
        r'\b(window|document)\.addEventListener\s*\(',
      );
      for (final RegExpMatch match in add.allMatches(source.masked)) {
        final String target = match.requiredGroup(1);
        if (cachedRegExp(
          '\\b${RegExp.escape(target)}\\.removeEventListener\\s*\\(',
        ).hasMatch(source.masked)) {
          continue;
        }
        yield _finding(
          context,
          source,
          match.start,
          '$target.addEventListener has no matching removal in this component',
        );
        break;
      }
    }
  }

  Iterable<Finding> _intervals(RuleContext context) sync* {
    for (final _SvelteSource source in _sources(context)) {
      final RegExpMatch? interval = cachedRegExp(
        r'\bsetInterval\s*\(',
      ).firstMatch(source.masked);
      if (interval == null ||
          cachedRegExp(r'\bclearInterval\s*\(').hasMatch(source.masked)) {
        continue;
      }
      yield _finding(
        context,
        source,
        interval.start,
        'setInterval has no matching clearInterval in this component',
      );
    }
  }

  Iterable<Finding> _dynamicHtml(RuleContext context) sync* {
    for (final _SvelteSource source in _sources(context)) {
      for (final RegExpMatch match in cachedRegExp(
        r'\{@html\s+([^}]+)\}',
      ).allMatches(source.masked)) {
        final String expression = match.requiredGroup(1).trim();
        if (expression.isEmpty ||
            cachedRegExp(
              r'^(?:DOMPurify\.)?sanitize\s*\(|^trusted(?:Html|Markup)\b',
            ).hasMatch(expression)) {
          continue;
        }
        yield _finding(
          context,
          source,
          match.start,
          '{@html} renders dynamic content from `$expression`',
          confidence: 'medium',
        );
      }
    }
  }

  Iterable<Finding> _unkeyedAnimation(RuleContext context) sync* {
    final RegExp eachStart = cachedRegExp(r'\{#each\s+([^}\n]+)\}');
    for (final _SvelteSource source in _sources(context)) {
      for (final RegExpMatch match in eachStart.allMatches(source.masked)) {
        final String header = match.requiredGroup(1).trim();
        if (cachedRegExp(r'\([^()]+\)\s*$').hasMatch(header)) continue;
        final int close = source.masked.indexOf('{/each}', match.end);
        if (close < 0) continue;
        final String block = source.masked.substring(match.end, close);
        if (!cachedRegExp(r'\banimate:[A-Za-z_$]').hasMatch(block)) continue;
        yield _finding(
          context,
          source,
          match.start,
          'an animated each block has no stable key expression',
        );
      }
    }
  }

  Iterable<Finding> _moduleBrowserGlobals(RuleContext context) sync* {
    final RegExp script = cachedRegExp(
      r'''<script\b([^>]*(?:\bmodule\b|context\s*=\s*["']module["'])[^>]*)>''',
      caseSensitive: false,
    );
    final RegExp browserGlobal = cachedRegExp(
      r'\b(?:window|document|localStorage|sessionStorage)\b',
    );
    for (final _SvelteSource source in _sources(context)) {
      for (final RegExpMatch opening in script.allMatches(
        source.commentMasked,
      )) {
        final int close = source.commentMasked.indexOf(
          '</script>',
          opening.end,
        );
        if (close < 0) continue;
        final String body = source.masked.substring(opening.end, close);
        for (final RegExpMatch global in browserGlobal.allMatches(body)) {
          final int absolute = opening.end + global.start;
          final int lineStart = source.masked.lastIndexOf('\n', absolute) + 1;
          final String prefix = source.masked.substring(lineStart, absolute);
          if (cachedRegExp(
            r'\b(?:typeof|browser\s*(?:&&|\?))\s*$',
          ).hasMatch(prefix)) {
            continue;
          }
          yield _finding(
            context,
            source,
            absolute,
            'module script accesses a browser-only global during initialization',
          );
          break;
        }
      }
    }
  }
}

final class _SvelteSource {
  _SvelteSource(this.path, this.source)
    : commentMasked = _mask(source, strings: false),
      masked = _mask(source, strings: true);

  final String path;
  final String source;
  final String commentMasked;
  final String masked;

  int lineAt(int offset) =>
      '\n'.allMatches(source.substring(0, offset)).length + 1;
}

Iterable<_SvelteSource> _sources(RuleContext context) sync* {
  final List<String> paths =
      context.sources.keys
          .where((String path) => path.toLowerCase().endsWith('.svelte'))
          .toList()
        ..sort();
  for (final String path in paths) {
    yield _SvelteSource(path, context.sources.requiredValue(path));
  }
}

String _mask(String source, {required bool strings}) {
  final List<int> result = source.codeUnits.toList();
  var index = 0;
  while (index < result.length) {
    if (index + 3 < result.length && source.startsWith('<!--', index)) {
      final int end = source.indexOf('-->', index + 4);
      final int stop = end < 0 ? result.length : end + 3;
      while (index < stop) {
        if (result[index] != 10) result[index] = 32;
        index++;
      }
      continue;
    }
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
    if (strings &&
        (result[index] == 34 || result[index] == 39 || result[index] == 96)) {
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
