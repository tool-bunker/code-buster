// HTML and CSS checks share lightweight document and selector facts, collected once before their individual findings are reported.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';

/// Shared scans used by independently registered HTML and CSS rules.
final class FrontendRuleAnalysis {
  /// Emits HTML findings for [ruleId].
  List<Finding> htmlFindings(Map<String, String> sources, String ruleId) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final String markup = _maskHtmlComments(entry.value);
      final List<String> lines = entry.value.split('\n');
      final List<String> maskedLines = markup.split('\n');
      final String document = markup.toLowerCase();
      final bool isSvelte = entry.key.toLowerCase().endsWith('.svelte');
      final bool isDocument = cachedRegExp(
        r'<html\b',
        caseSensitive: false,
      ).hasMatch(markup);
      final Map<String, List<Set<String>>> ids = <String, List<Set<String>>>{};
      final Set<String> labels = _labelTargets(markup);
      final Set<String> boundLabels = _boundLabelTargets(markup);
      final Set<int> blankTargetsWithoutRel = _blankTargetsWithoutRel(markup);
      final Set<int> imagesWithoutAlt = _startTagsWithoutAttribute(
        markup,
        'img',
        'alt',
      );
      final Set<int> inputsWithoutLabel = _inputsWithoutLabel(
        markup,
        labels,
        boundLabels,
      );
      final Set<int> formsWithoutNativeMethod = _formsWithoutNativeMethod(
        markup,
      );
      final Set<int> executableInlineScripts = _executableInlineScriptLines(
        markup,
      );
      final bool hasTemplatedHead = _hasMarkupTemplateInHead(entry.value);
      final bool hasTemplatedTitle =
          hasTemplatedHead || _hasJekyllSeoTagInHead(entry.value);
      final List<Set<String>> templateConditions = _templateConditions(lines);
      final bool hasLang = cachedRegExp(
        r'<html\b[^>]*\blang\s*=',
        caseSensitive: false,
        dotAll: true,
      ).hasMatch(markup);
      final bool hasViewport = _hasStartTagWithAttributeValue(
        markup,
        'meta',
        'name',
        'viewport',
      );
      final bool hasTitle = cachedRegExp(
        r'<title(?:\s[^>]*)?>\s*[^<\s]',
      ).hasMatch(document);
      for (var index = 0; index < lines.length; index++) {
        final String raw = lines[index];
        final String line = raw.trim();
        final String lower = line.toLowerCase();
        final String activeLower = maskedLines[index].trim().toLowerCase();
        void add(String id, RuleSeverity severity, String message) {
          if (id != ruleId) return;
          result.add(_finding(id, severity, entry.key, index + 1, message));
        }

        if (!isSvelte && executableInlineScripts.contains(index + 1)) {
          add('html-inline-script', RuleSeverity.warn, 'inline script block');
        }
        if (!isSvelte &&
            cachedRegExp(
              r'\son(?:click|load|change|submit|error)\s*=',
            ).hasMatch(lower)) {
          add('html-inline-event', RuleSeverity.warn, 'inline event handler');
        }
        if (blankTargetsWithoutRel.contains(index + 1)) {
          add(
            'html-blank-no-rel',
            RuleSeverity.warn,
            'target blank link lacks rel',
          );
        }
        if (imagesWithoutAlt.contains(index + 1)) {
          add('html-img-alt', RuleSeverity.info, 'image missing alt text');
        }
        if (_hasInsecureHttpResource(activeLower)) {
          add(
            'html-http-resource',
            RuleSeverity.warn,
            'insecure HTTP resource',
          );
        }
        final String id = _attribute(maskedLines[index], 'id');
        if (id.isNotEmpty) {
          final List<Set<String>> previous = ids.putIfAbsent(
            id,
            () => <Set<String>>[],
          );
          if (previous.any(
            (Set<String> conditions) =>
                !_mutuallyExclusive(conditions, templateConditions[index]),
          )) {
            add(
              'html-duplicate-id',
              RuleSeverity.warn,
              'duplicate id attribute: $id',
            );
          }
          previous.add(templateConditions[index]);
        }
        if (inputsWithoutLabel.contains(index + 1)) {
          add(
            'html-input-label',
            RuleSeverity.info,
            'input lacks obvious label',
          );
        }
        if (formsWithoutNativeMethod.contains(index + 1)) {
          add(
            'html-form-method',
            RuleSeverity.info,
            'form has no explicit method',
          );
        }
      }
      if (isDocument && !hasLang && ruleId == 'html-missing-lang') {
        result.add(
          _finding(
            'html-missing-lang',
            RuleSeverity.info,
            entry.key,
            1,
            'html document missing lang',
          ),
        );
      }
      if (isDocument &&
          !hasViewport &&
          !hasTemplatedHead &&
          ruleId == 'html-missing-viewport') {
        result.add(
          _finding(
            'html-missing-viewport',
            RuleSeverity.info,
            entry.key,
            1,
            'missing viewport meta',
          ),
        );
      }
      if (isDocument &&
          !hasTitle &&
          !hasTemplatedTitle &&
          ruleId == 'html-missing-title') {
        result.add(
          _finding(
            'html-missing-title',
            RuleSeverity.info,
            entry.key,
            1,
            'document missing title',
          ),
        );
      }
    }
    return result;
  }

  /// Emits CSS findings for [ruleId].
  List<Finding> cssFindings(Map<String, String> sources, String ruleId) {
    final List<Finding> result = <Finding>[];
    for (final MapEntry<String, String> entry in sources.entries) {
      final String source = _maskCssComments(entry.value);
      final String lowerSource = source.toLowerCase();
      final List<String> lines = source.split('\n');
      var inBlock = false;
      final bool sawReducedMotion = lowerSource.contains(
        'prefers-reduced-motion',
      );
      final Map<String, String> properties = <String, String>{};
      String? previousProperty;
      var inTailwindUtility = false;
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index].trim();
        final String lower = line.toLowerCase();
        void add(String id, String message) {
          if (id != ruleId) return;
          result.add(
            _finding(id, RuleSeverity.info, entry.key, index + 1, message),
          );
        }

        if (line.contains('{')) {
          inBlock = true;
          properties.clear();
          previousProperty = null;
          inTailwindUtility = line.startsWith('@utility ');
          final String selector = line.split('{').first.trim();
          if (!selector.startsWith('@')) {
            if (_selectorList(
              selector,
            ).any((String part) => _selectorDepth(part) > 4)) {
              add('css-selector-depth', 'deep CSS selector');
            }
            if (_hasUniversalSelectorToken(selector) &&
                !_isUniversalBoxSizingReset(selector, lines, index)) {
              add('css-universal-selector', 'universal selector used');
            }
          }
        }
        if (lower.contains('!important')) {
          add('css-important', '!important used');
        }
        final RegExpMatch? zIndex = cachedRegExp(
          r'z-index\s*:\s*(\d+)',
        ).firstMatch(lower);
        if (zIndex != null && int.parse(zIndex.requiredGroup(1)) > 1000) {
          add('css-high-z-index', 'very high z-index');
        }
        if (cachedRegExp(r'font-size\s*:[^;]*\dpx').hasMatch(lower)) {
          add('css-fixed-font-px', 'font size uses px');
        }
        final RegExpMatch? prefixedProperty = cachedRegExp(
          r'^-(?:webkit|moz|ms|o)-([a-z-]+)\s*:',
        ).firstMatch(lower);
        if (prefixedProperty != null) {
          final String standard = prefixedProperty.requiredGroup(1);
          if (!_vendorOnlyProperties.contains(standard) &&
              !cachedRegExp(
                '(?:^|[;{])\\s*${RegExp.escape(standard)}\\s*:',
              ).hasMatch(lowerSource)) {
            add('css-vendor-prefix-only', 'vendor-prefixed property');
          }
        }
        final RegExpMatch? declaration = inBlock
            ? cachedRegExp(r'^([a-z-]+)\s*:\s*([^;}]+)').firstMatch(lower)
            : null;
        if (declaration != null) {
          final String property = declaration.requiredGroup(1);
          final String value = declaration.requiredGroup(2).trim();
          final String? previous = properties[property];
          if (previous != null &&
              !(previousProperty == property &&
                  (_isCompatibilityValueFallback(property, previous, value) ||
                      (inTailwindUtility &&
                          property.startsWith('--') &&
                          _areDisjointTailwindValueOverloads(
                            previous,
                            value,
                          ))))) {
            add('css-duplicate-property', 'duplicate CSS property: $property');
          }
          properties[property] = value;
          previousProperty = property;
        }
        if (_hasMotionDeclaration(lower) && !sawReducedMotion) {
          add(
            'css-animation-no-reduced-motion',
            'motion without reduced-motion guard',
          );
        }
        if (line.contains('}')) {
          inBlock = false;
          inTailwindUtility = false;
        }
      }
    }
    return result;
  }

  static String _maskCssComments(String source) {
    final StringBuffer masked = StringBuffer();
    var inComment = false;
    String? quote;
    for (var index = 0; index < source.length; index++) {
      final String character = source[index];
      final String? next = index + 1 < source.length ? source[index + 1] : null;
      if (inComment) {
        if (character == '*' && next == '/') {
          masked.write('  ');
          index++;
          inComment = false;
        } else {
          masked.write(character == '\n' ? '\n' : ' ');
        }
        continue;
      }
      if (quote != null) {
        masked.write(character);
        if (character == r'\' && next != null) {
          masked.write(next);
          index++;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'") {
        quote = character;
        masked.write(character);
      } else if (character == '/' && next == '*') {
        masked.write('  ');
        index++;
        inComment = true;
      } else {
        masked.write(character);
      }
    }
    return masked.toString();
  }

  static Finding _finding(
    String id,
    RuleSeverity severity,
    String path,
    int line,
    String message,
  ) => Finding(
    code: id,
    severity: severity,
    path: path,
    line: line,
    endLine: line,
    message: message,
    confidence: 'medium',
    why: switch (id) {
      'css-important' =>
        '!important makes cascade/specificity harder to reason about.',
      'html-img-alt' =>
        'Images without alt text are inaccessible to screen readers.',
      _ =>
        'This frontend construct can weaken accessibility, security, or maintainability.',
    },
    suggestion: switch (id) {
      'css-important' =>
        'Fix selector structure or ordering instead of forcing priority.',
      'html-img-alt' =>
        'Add meaningful alt text or alt="" for decorative images.',
      _ => 'Use the safer accessible frontend pattern described by the rule.',
    },
  );

  static String _attribute(String line, String name) {
    final RegExpMatch? match = cachedRegExp(
      '(?:^|\\s)$name\\s*=\\s*(["\\\'])(.*?)\\1',
      caseSensitive: false,
    ).firstMatch(line);
    return match?.group(2) ?? '';
  }

  static bool _hasInsecureHttpResource(String line) {
    if (cachedRegExp(
      r'''\s(?:src|srcset)\s*=\s*["']http://''',
    ).hasMatch(line)) {
      return true;
    }
    if (cachedRegExp(
      r'''<(?:base|use)\b[^>]*\shref\s*=\s*["']http://''',
    ).hasMatch(line)) {
      return true;
    }
    for (final RegExpMatch match in cachedRegExp(
      r'<link\b[^>]*>',
    ).allMatches(line)) {
      final String tag = match.group(0)!;
      if (!cachedRegExp(r'''\shref\s*=\s*["']http://''').hasMatch(tag)) {
        continue;
      }
      if (_attribute(tag, 'rel').trim() != 'profile') return true;
    }
    return false;
  }

  static List<Set<String>> _doxygenConditions(List<String> lines) {
    final List<String> active = <String>[];
    final List<Set<String>> result = <Set<String>>[];
    final RegExp marker = cachedRegExp(
      r'<!--\s*(BEGIN|END)\s+(!?[A-Z0-9_]+)\s*-->',
      caseSensitive: false,
    );
    for (final String line in lines) {
      final Set<String> conditions = active.toSet();
      for (final RegExpMatch match in marker.allMatches(line)) {
        final String condition = match.requiredGroup(2).toUpperCase();
        if (match.requiredGroup(1).toUpperCase() == 'BEGIN') {
          active.add(condition);
          conditions.add(condition);
        } else {
          final int index = active.lastIndexOf(condition);
          if (index >= 0) active.removeAt(index);
        }
      }
      result.add(Set<String>.unmodifiable(conditions));
    }
    return result;
  }

  static List<Set<String>> _templateConditions(List<String> lines) {
    final List<Set<String>> doxygen = _doxygenConditions(lines);
    final List<Set<String>> svelte = _svelteConditions(lines);
    return <Set<String>>[
      for (var index = 0; index < lines.length; index++)
        Set<String>.unmodifiable(<String>{...doxygen[index], ...svelte[index]}),
    ];
  }

  static List<Set<String>> _svelteConditions(List<String> lines) {
    final List<({int branch, int group})> active =
        <({int branch, int group})>[];
    final List<Set<String>> result = <Set<String>>[];
    final RegExp marker = cachedRegExp(r'\{(#if\b|:else if\b|:else\b|/if\b)');
    var nextGroup = 0;
    String condition(({int branch, int group}) value) =>
        '@svelte:${value.group}:${value.branch}';
    for (final String line in lines) {
      final Set<String> conditions = active.map(condition).toSet();
      for (final RegExpMatch match in marker.allMatches(line)) {
        final String kind = match.requiredGroup(1);
        if (kind == '#if') {
          final ({int branch, int group}) value = (
            branch: 0,
            group: nextGroup++,
          );
          active.add(value);
          conditions.add(condition(value));
        } else if (kind.startsWith(':else') && active.isNotEmpty) {
          final ({int branch, int group}) previous = active.removeLast();
          conditions.remove(condition(previous));
          final ({int branch, int group}) value = (
            branch: previous.branch + 1,
            group: previous.group,
          );
          active.add(value);
          conditions.add(condition(value));
        } else if (kind == '/if' && active.isNotEmpty) {
          active.removeLast();
        }
      }
      result.add(Set<String>.unmodifiable(conditions));
    }
    return result;
  }

  static bool _mutuallyExclusive(Set<String> left, Set<String> right) {
    for (final String condition in left) {
      final String opposite = condition.startsWith('!')
          ? condition.substring(1)
          : '!$condition';
      if (right.contains(opposite)) return true;
      if (!condition.startsWith('@svelte:')) continue;
      final int separator = condition.lastIndexOf(':');
      final String group = condition.substring(0, separator + 1);
      if (right.any(
        (String candidate) =>
            candidate.startsWith(group) && candidate != condition,
      )) {
        return true;
      }
    }
    return false;
  }

  static bool _isUniversalBoxSizingReset(
    String selector,
    List<String> lines,
    int start,
  ) {
    if (selector.trim() != '*') return false;
    final List<String> declarations = <String>[];
    for (var index = start + 1; index < lines.length; index++) {
      final String line = lines[index].trim();
      if (line.contains('}')) break;
      if (line.isNotEmpty) declarations.add(line);
    }
    return declarations.isNotEmpty &&
        declarations.every(
          (line) => cachedRegExp(
            r'^(?:-webkit-|-moz-)?box-sizing\s*:\s*border-box\s*;$',
            caseSensitive: false,
          ).hasMatch(line),
        );
  }

  static bool _hasUniversalSelectorToken(String selector) {
    var brackets = 0;
    String? quote;
    for (var index = 0; index < selector.length; index++) {
      final String character = selector[index];
      if (quote != null) {
        if (character == r'\' && index + 1 < selector.length) {
          index++;
        } else if (character == quote) {
          quote = null;
        }
        continue;
      }
      if (character == '"' || character == "'") {
        quote = character;
        continue;
      }
      if (character == '[') {
        brackets++;
        continue;
      }
      if (character == ']') {
        if (brackets > 0) brackets--;
        continue;
      }
      if (character != '*' || brackets > 0) continue;
      if (index == 0) return true;
      switch (selector[index - 1]) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case '>':
        case '+':
        case '~':
        case ',':
        case '(':
        case '|':
          return true;
      }
    }
    return false;
  }

  static Iterable<String> _selectorList(String selector) sync* {
    var parentheses = 0;
    var brackets = 0;
    var start = 0;
    for (var index = 0; index < selector.length; index++) {
      switch (selector[index]) {
        case '(':
          parentheses++;
        case ')':
          if (parentheses > 0) parentheses--;
        case '[':
          brackets++;
        case ']':
          if (brackets > 0) brackets--;
        case ',':
          if (parentheses == 0 && brackets == 0) {
            yield selector.substring(start, index).trim();
            start = index + 1;
          }
      }
    }
    yield selector.substring(start).trim();
  }

  static int _selectorDepth(String selector) {
    var index = 0;
    var depth = 0;
    var parentheses = 0;
    var brackets = 0;
    for (; index < selector.length; index++) {
      final int character = selector.codeUnitAt(index);
      if (brackets > 0) {
        if (character == 0x5d) brackets--;
        continue;
      }
      if (parentheses > 0) {
        if (character == 0x28) {
          parentheses++;
        } else if (character == 0x29) {
          parentheses--;
        } else if (character == 0x5b) {
          brackets++;
        }
        continue;
      }

      if (character == 0x28) {
        parentheses++;
      } else if (character == 0x5b) {
        brackets++;
      } else if (_isCssCombinator(character)) {
        depth++;
      } else if (_isCssWhitespace(character)) {
        var next = index + 1;
        while (next < selector.length &&
            _isCssWhitespace(selector.codeUnitAt(next))) {
          next++;
        }
        if (index > 0 &&
            next < selector.length &&
            !_isCssCombinator(selector.codeUnitAt(index - 1)) &&
            selector.codeUnitAt(index - 1) != 0x2c &&
            !_isCssCombinator(selector.codeUnitAt(next)) &&
            selector.codeUnitAt(next) != 0x2c) {
          depth++;
        }
        index = next - 1;
      }
    }
    return depth;
  }

  static bool _isCssWhitespace(int character) =>
      character == 0x09 ||
      character == 0x0a ||
      character == 0x0c ||
      character == 0x0d ||
      character == 0x20;

  static bool _isCssCombinator(int character) =>
      character == 0x2b || character == 0x3e || character == 0x7e;

  static const Set<String> _vendorOnlyProperties = <String>{
    'box-orient',
    'font-smoothing',
    'osx-font-smoothing',
    'overflow-scrolling',
    'overflow-style',
    'tap-highlight-color',
    'text-fill-color',
    'text-stroke',
    'touch-callout',
  };

  static final RegExp _hexColor = cachedRegExp(r'^#([0-9a-f]{3}|[0-9a-f]{6})$');
  static final RegExp _rgbaColor = cachedRegExp(
    r'^rgba\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,',
  );

  static bool _isCompatibilityValueFallback(
    String property,
    String previous,
    String current,
  ) =>
      previous != current &&
      (_isStandardToVendorValueFallback(previous, current) ||
          _isLogicalTextAlignFallback(property, previous, current) ||
          _isEquivalentAlphaColorFallback(previous, current) ||
          ((previous == "''" || previous == '""') && current == 'none'));

  static bool _areDisjointTailwindValueOverloads(
    String previous,
    String current,
  ) {
    Set<String>? signatures(String value) {
      final RegExpMatch? match = cachedRegExp(
        r'--value\(([^)]+)\)',
      ).firstMatch(value);
      if (match == null) return null;
      return match
          .requiredGroup(1)
          .split(',')
          .map((String signature) => signature.trim())
          .where((String signature) => signature.isNotEmpty)
          .toSet();
    }

    final Set<String>? previousSignatures = signatures(previous);
    final Set<String>? currentSignatures = signatures(current);
    return previousSignatures != null &&
        currentSignatures != null &&
        previousSignatures.intersection(currentSignatures).isEmpty;
  }

  static bool _isLogicalTextAlignFallback(
    String property,
    String previous,
    String current,
  ) =>
      property == 'text-align' &&
      const <String>{'left', 'right'}.contains(previous) &&
      const <String>{'start', 'end'}.contains(current);

  static bool _isStandardToVendorValueFallback(
    String previous,
    String current,
  ) =>
      _hasVendorCompatibilityValue(previous) !=
      _hasVendorCompatibilityValue(current);

  static bool _hasVendorCompatibilityValue(String value) =>
      cachedRegExp(r'-(?:webkit|moz|ms|o)-').hasMatch(value) ||
      cachedRegExp(
        r'progid\s*:\s*dximagetransform\.microsoft\.gradient\s*\(',
      ).hasMatch(value);

  static bool _isEquivalentAlphaColorFallback(String previous, String current) {
    final RegExpMatch? hex = _hexColor.firstMatch(previous);
    final RegExpMatch? rgba = _rgbaColor.firstMatch(current);
    if (hex == null || rgba == null) return false;
    final String digits = hex.requiredGroup(1);
    final int color = int.parse(digits, radix: 16);
    final int red;
    final int green;
    final int blue;
    if (digits.length == 3) {
      red = ((color >> 8) & 0xf) * 17;
      green = ((color >> 4) & 0xf) * 17;
      blue = (color & 0xf) * 17;
    } else {
      red = (color >> 16) & 0xff;
      green = (color >> 8) & 0xff;
      blue = color & 0xff;
    }
    return red == int.parse(rgba.requiredGroup(1)) &&
        green == int.parse(rgba.requiredGroup(2)) &&
        blue == int.parse(rgba.requiredGroup(3));
  }

  static bool _hasMotionDeclaration(String line) {
    final RegExpMatch? declaration = cachedRegExp(
      r'^(?:-(?:webkit|moz|ms|o)-)?(?:animation|transition)\s*:\s*([^;}]+)',
    ).firstMatch(line);
    if (declaration == null) return false;
    final String value = declaration.requiredGroup(1).trim();
    if (const <String>{
      'none',
      'initial',
      'inherit',
      'unset',
      'revert',
      'revert-layer',
    }.contains(value)) {
      return false;
    }
    if (value.contains('var(') || value.contains('calc(')) return true;
    return cachedRegExp(r'(\d*\.?\d+)(?:ms|s)\b')
        .allMatches(value)
        .any((RegExpMatch match) => double.parse(match.requiredGroup(1)) > 0);
  }

  static String _maskHtmlComments(String source) {
    final List<int> result = source.codeUnits.toList();
    for (final RegExpMatch comment in cachedRegExp(
      r'<!--.*?(?:-->|$)',
      dotAll: true,
    ).allMatches(source)) {
      for (var index = comment.start; index < comment.end; index++) {
        if (result[index] != 10) result[index] = 32;
      }
    }
    return String.fromCharCodes(result);
  }

  static Set<String> _labelTargets(String source) => <String>{
    for (final RegExpMatch match in cachedRegExp(
      r'<label\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source))
      if (_attribute(match.group(0)!, 'for').isNotEmpty)
        _attribute(match.group(0)!, 'for'),
  };

  static Set<String> _boundLabelTargets(String source) => <String>{
    for (final RegExpMatch match in cachedRegExp(
      r'<label\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source))
      if (_boundAttribute(match.group(0)!, 'for').isNotEmpty)
        _boundAttribute(match.group(0)!, 'for'),
  };

  static Set<int> _inputsWithoutLabel(
    String source,
    Set<String> labelTargets,
    Set<String> boundLabelTargets,
  ) {
    final Set<int> result = <int>{};
    for (final RegExpMatch inputMatch in cachedRegExp(
      r'<input\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source)) {
      final String tag = inputMatch.group(0)!;
      final String type = _attribute(tag, 'type').toLowerCase();
      final String id = _attribute(tag, 'id');
      final String boundId = _boundAttribute(tag, 'id');
      if (const <String>{
            'hidden',
            'submit',
            'button',
            'reset',
          }.contains(type) ||
          cachedRegExp(
            r'(?:^|\s)hidden(?:\s|/?>|=)',
            caseSensitive: false,
          ).hasMatch(tag) ||
          (type == 'image' && _attribute(tag, 'alt').isNotEmpty) ||
          cachedRegExp(
            r'\baria-label(?:ledby)?\s*=',
            caseSensitive: false,
          ).hasMatch(tag) ||
          (id.isNotEmpty && labelTargets.contains(id)) ||
          (boundId.isNotEmpty && boundLabelTargets.contains(boundId)) ||
          _isInsideLabel(source, inputMatch.start)) {
        continue;
      }
      result.add(
        '\n'.allMatches(source.substring(0, inputMatch.start)).length + 1,
      );
    }
    return result;
  }

  static String _boundAttribute(String tag, String name) {
    final RegExpMatch? match = cachedRegExp(
      '(?:^|\\s)(?::|v-bind:)$name\\s*=\\s*(["\\\'])(.*?)\\1',
      caseSensitive: false,
    ).firstMatch(tag);
    return match?.group(2)?.trim() ?? '';
  }

  static bool _isInsideLabel(String source, int offset) {
    final String prefix = source.substring(0, offset);
    final int opening = prefix.lastIndexOf(
      cachedRegExp(r'<label\b[^>]*>', caseSensitive: false, dotAll: true),
    );
    final int closing = prefix.lastIndexOf(
      cachedRegExp(r'</label\s*>', caseSensitive: false),
    );
    return opening > closing;
  }

  static Set<int> _startTagsWithoutAttribute(
    String source,
    String tagName,
    String attributeName,
  ) {
    final Set<int> result = <int>{};
    for (final RegExpMatch tagMatch in cachedRegExp(
      '<$tagName\\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source)) {
      if (cachedRegExp(
        '\\b$attributeName\\s*=',
        caseSensitive: false,
      ).hasMatch(tagMatch.group(0)!)) {
        continue;
      }
      result.add(
        '\n'.allMatches(source.substring(0, tagMatch.start)).length + 1,
      );
    }
    return result;
  }

  static bool _hasStartTagWithAttributeValue(
    String source,
    String tagName,
    String attributeName,
    String attributeValue,
  ) {
    for (final RegExpMatch tagMatch in cachedRegExp(
      '<$tagName\\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source)) {
      if (_attribute(tagMatch.group(0)!, attributeName).toLowerCase() ==
          attributeValue.toLowerCase()) {
        return true;
      }
    }
    return false;
  }

  static Set<int> _formsWithoutNativeMethod(String source) {
    final Set<int> result = <int>{};
    for (final RegExpMatch tagMatch in cachedRegExp(
      r'<form\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source)) {
      final String tag = tagMatch.group(0)!;
      if (cachedRegExp(r'\bmethod\s*=', caseSensitive: false).hasMatch(tag) ||
          _preventsNativeFormSubmission(tag)) {
        continue;
      }
      result.add(
        '\n'.allMatches(source.substring(0, tagMatch.start)).length + 1,
      );
    }
    return result;
  }

  static bool _preventsNativeFormSubmission(String tag) {
    if (cachedRegExp(
      r'(?:@|v-on:)submit(?:\.[\w-]+)*\.prevent(?:\.[\w-]+)*\s*=',
      caseSensitive: false,
    ).hasMatch(tag)) {
      return true;
    }
    return cachedRegExp(r'\bonsubmit\b', caseSensitive: false).hasMatch(tag) &&
        cachedRegExp(
          r'\bpreventdefault\s*\(|\breturn\s+false\b',
          caseSensitive: false,
        ).hasMatch(tag);
  }

  static bool _hasMarkupTemplateInHead(String source) {
    if (cachedRegExp(
      r'''{%\s*include\s+["']?(?:[^"'%\s]+[/\\])?head(?:\.[a-z0-9_-]+)?["']?\s*%}''',
      caseSensitive: false,
    ).hasMatch(source)) {
      return true;
    }
    final RegExpMatch? head = cachedRegExp(
      r'<head\b[^>]*>(.*?)</head>',
      caseSensitive: false,
      dotAll: true,
    ).firstMatch(source);
    if (head == null) return false;
    return cachedRegExp(
      r'''<%-|{{{\s*|{{\s*>|{%\s*include\b|<\?(?:php)?\s*(?:include|require)\b''',
      caseSensitive: false,
    ).hasMatch(head.requiredGroup(1));
  }

  static bool _hasJekyllSeoTagInHead(String source) {
    final RegExpMatch? head = cachedRegExp(
      r'<head\b[^>]*>(.*?)</head>',
      caseSensitive: false,
      dotAll: true,
    ).firstMatch(source);
    return head != null &&
        cachedRegExp(
          r'{%\s*seo\b[^%]*%}',
          caseSensitive: false,
        ).hasMatch(head.requiredGroup(1));
  }

  static Set<int> _blankTargetsWithoutRel(String source) {
    final Set<int> result = <int>{};
    for (final RegExpMatch tagMatch in cachedRegExp(
      r'<a\b[^>]*>',
      caseSensitive: false,
      dotAll: true,
    ).allMatches(source)) {
      final String tag = tagMatch.group(0)!;
      final RegExpMatch? targetMatch = cachedRegExp(
        r'''target\s*=\s*["']_blank["']''',
        caseSensitive: false,
      ).firstMatch(tag);
      if (targetMatch == null ||
          cachedRegExp(r'''\brel\s*=''', caseSensitive: false).hasMatch(tag)) {
        continue;
      }
      result.add(
        '\n'
                .allMatches(
                  source.substring(0, tagMatch.start + targetMatch.start),
                )
                .length +
            1,
      );
    }
    return result;
  }
}

Set<int> _executableInlineScriptLines(String source) {
  final Set<int> result = <int>{};
  final RegExp openingTag = cachedRegExp(
    r'<script\b[^>]*>',
    caseSensitive: false,
    dotAll: true,
  );
  final RegExp closingTag = cachedRegExp(r'</script\s*>', caseSensitive: false);
  var cursor = 0;
  while (cursor < source.length) {
    final Iterator<RegExpMatch> openings = openingTag
        .allMatches(source, cursor)
        .iterator;
    if (!openings.moveNext()) break;
    final RegExpMatch opening = openings.current;
    final String tag = opening.group(0)!;
    if (_isExecutableInlineScriptTag(tag)) {
      result.add(
        '\n'.allMatches(source.substring(0, opening.start)).length + 1,
      );
    }
    final RegExpMatch? closing = closingTag.firstMatch(
      source.substring(opening.end),
    );
    if (closing == null) break;
    cursor = opening.end + closing.end;
  }
  return result;
}

bool _isExecutableInlineScriptTag(String tag) {
  if (cachedRegExp(r'\bsrc\s*=', caseSensitive: false).hasMatch(tag)) {
    return false;
  }
  if (cachedRegExp(
    r'''(?:\bnonce\s*=|\{\{[^}]*\bnonce(?:_?attribute)?\b[^}]*\}\})''',
    caseSensitive: false,
  ).hasMatch(tag)) {
    return false;
  }
  final RegExpMatch? type = cachedRegExp(
    r'''\btype\s*=\s*["']([^"']+)["']''',
    caseSensitive: false,
  ).firstMatch(tag);
  if (type == null) return true;
  return const <String>{
    'module',
    'text/javascript',
    'application/javascript',
  }.contains(type.requiredGroup(1).toLowerCase());
}
