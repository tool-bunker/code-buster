// C and C++ hazards such as casts, unsafe strings, macros, and namespace misuse are detected together because they share lexical masking rules.

import '../../core/models.dart';
import '../../core/rule.dart';

RuleMetadata _metadata(String id, RuleSeverity severity, String title) =>
    RuleMetadata(
      id: id,
      defaultSeverity: severity,
      group: 'nim-style',
      title: title,
      why: 'This construct weakens C++ type, lifetime, or interface safety.',
      suggestion: 'Use the safer typed C++ alternative described by the rule.',
      languages: const <String>['cpp'],
    );

SourcePatternRule _pattern({
  required String id,
  required RuleSeverity severity,
  required String title,
  required RegExp pattern,
  required String message,
  RegExp? exclusion,
}) => SourcePatternRule(
  metadata: _metadata(id, severity, title),
  pattern: pattern,
  message: message,
  exclusion: exclusion,
  confidence: 'medium',
);

/// Reports broad `std` namespace imports.
final SourcePatternRule cppUsingNamespaceStdRule = _pattern(
  id: 'cpp-using-namespace-std',
  severity: RuleSeverity.info,
  title: 'Avoid broad namespace imports',
  pattern: RegExp(r'^\s*using namespace std;\s*$'),
  message: 'using namespace std used',
);

/// Reports raw owning allocation unless Qt ownership is explicit.
final CodeBusterRule cppRawOwningNewRule = const CppRawOwningNewRule();

/// Reports raw `new` expressions that are not visibly parent- or setter-owned.
final class CppRawOwningNewRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const CppRawOwningNewRule()
    : super(
        const RuleMetadata(
          id: 'cpp-raw-owning-new',
          version: 3,
          defaultSeverity: RuleSeverity.warn,
          group: 'nim-style',
          title: 'Represent ownership with RAII',
          why:
              'This construct weakens C++ type, lifetime, or interface safety.',
          suggestion:
              'Use the safer typed C++ alternative described by the rule.',
          languages: <String>['cpp'],
        ),
      );

  static final RegExp _allocation = RegExp(r'(?:=\s*new\s|^\s*new\s)');
  static final RegExp _construction = RegExp(
    r'\bnew\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)(?:\s*<[^;{}()]*>)?\s*\(([^;{}]*)\)',
  );
  static final RegExp _parentArgument = RegExp(
    r'(?:^|,)\s*(?:this|parent\w*)\s*(?:,|$)',
  );
  static final RegExp _assignedName = RegExp(
    r'\b([A-Za-z_]\w*)\s*=\s*new\s+Q[A-Z]\w*',
  );
  static const Set<String> _owningSetters = <String>{
    'setCentralWidget',
    'setCheckBox',
    'setLayout',
    'setMenuBar',
    'setStatusBar',
    'setViewport',
    'setWidget',
  };
  static final RegExp _emscriptenMacro = RegExp(
    r'\b(?:[A-Z_]*EM_ASM[A-Z_]*|EM_JS)\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Set<String> qtOwnedTypes = _qtOwnedTypes(context);
    for (final String path in context.sources.keys) {
      final List<String> lines = context.linesFor(path);
      var emscriptenBraceDepth = 0;
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        if (emscriptenBraceDepth > 0) {
          emscriptenBraceDepth += _braceDelta(line);
          if (emscriptenBraceDepth < 0) emscriptenBraceDepth = 0;
          continue;
        }
        final RegExpMatch? emscriptenMacro = _emscriptenMacro.firstMatch(line);
        if (emscriptenMacro != null) {
          emscriptenBraceDepth = _braceDelta(
            line.substring(emscriptenMacro.start),
          );
          continue;
        }
        if (!_allocation.hasMatch(line) ||
            _hasExplicitQtParent(line, qtOwnedTypes) ||
            _isImmediatelyTransferred(lines, index)) {
          continue;
        }
        yield report(
          context,
          path: path,
          line: index + 1,
          message: 'raw new expression used',
          confidence: 'medium',
        );
      }
    }
  }

  static bool _hasExplicitQtParent(String line, Set<String> qtOwnedTypes) {
    final RegExpMatch? construction = _construction.firstMatch(line);
    if (construction == null ||
        !_parentArgument.hasMatch(construction.group(2)!)) {
      return false;
    }
    final String type = construction.group(1)!.split('::').last;
    return RegExp(r'^Q[A-Z]').hasMatch(type) || qtOwnedTypes.contains(type);
  }

  static Set<String> _qtOwnedTypes(RuleContext context) {
    final Map<String, Set<String>> basesByClass = <String, Set<String>>{};
    final Set<String> result = <String>{};
    for (final String path in context.sources.keys) {
      final List<String> lines = context.linesFor(path);
      for (var index = 0; index < lines.length; index++) {
        final String first = lines[index].trimLeft();
        if (!first.startsWith('class ') && !first.startsWith('struct ')) {
          continue;
        }
        final StringBuffer declaration = StringBuffer();
        for (final String candidate in lines.skip(index).take(8)) {
          declaration.write(' ${candidate.trim()}');
          if (candidate.contains('{') || candidate.contains(';')) break;
        }
        final String text = declaration.toString().trim();
        final RegExpMatch? named = RegExp(
          r'^(?:class|struct)\s+([A-Za-z_]\w*)',
        ).firstMatch(text);
        if (named == null) continue;
        final String name = named.group(1)!;
        final int colon = text.indexOf(':');
        final int brace = text.indexOf('{');
        final Set<String> bases = colon < 0 || brace < colon
            ? <String>{}
            : text
                  .substring(colon + 1, brace)
                  .split(',')
                  .map(
                    (String base) => base
                        .replaceAll(
                          RegExp(r'\b(?:public|protected|private|virtual)\b'),
                          '',
                        )
                        .trim(),
                  )
                  .map((String base) => base.split('::').last)
                  .map(
                    (String base) =>
                        base.replaceFirst(RegExp(r'<.*$'), '').trim(),
                  )
                  .where((String base) => base.isNotEmpty)
                  .toSet();
        basesByClass[name] = bases;
        if (bases.any((String base) => RegExp(r'^Q[A-Z]').hasMatch(base)) ||
            _classContainsQObjectMacro(lines, index)) {
          result.add(name);
        }
      }
    }

    var changed = true;
    while (changed) {
      changed = false;
      for (final MapEntry<String, Set<String>> entry in basesByClass.entries) {
        if (!result.contains(entry.key) && entry.value.any(result.contains)) {
          result.add(entry.key);
          changed = true;
        }
      }
    }
    return result;
  }

  static bool _classContainsQObjectMacro(List<String> lines, int start) {
    var depth = 0;
    var opened = false;
    for (final String line in lines.skip(start)) {
      if (line.contains('Q_OBJECT')) return true;
      final int delta = _braceDelta(line);
      if (line.contains('{')) opened = true;
      depth += delta;
      if (opened && depth <= 0) break;
      if (!opened && line.contains(';')) break;
    }
    return false;
  }

  static bool _isImmediatelyTransferred(List<String> lines, int index) {
    final RegExpMatch? assignment = _assignedName.firstMatch(lines[index]);
    if (assignment == null) return false;
    final String name = RegExp.escape(assignment.group(1)!);
    final RegExp transfer = RegExp(
      '\\b(?:${_owningSetters.join('|')})\\s*\\(\\s*$name\\s*\\)',
    );
    for (
      var next = index + 1;
      next < lines.length && next <= index + 3;
      next++
    ) {
      final String candidate = lines[next].trim();
      if (candidate.isEmpty || candidate.startsWith('//')) continue;
      return transfer.hasMatch(candidate);
    }
    return false;
  }

  static int _braceDelta(String line) {
    var delta = 0;
    var quote = 0;
    var escaped = false;
    for (var index = 0; index < line.length; index++) {
      final int unit = line.codeUnitAt(index);
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quote != 0) {
        if (unit == 0x5C) {
          escaped = true;
        } else if (unit == quote) {
          quote = 0;
        }
        continue;
      }
      if (unit == 0x22 || unit == 0x27 || unit == 0x60) {
        quote = unit;
      } else if (unit == 0x2F &&
          index + 1 < line.length &&
          line.codeUnitAt(index + 1) == 0x2F) {
        break;
      } else if (unit == 0x7B) {
        delta++;
      } else if (unit == 0x7D) {
        delta--;
      }
    }
    return delta;
  }
}

/// Reports manual deletion.
final SourcePatternRule cppManualDeleteRule = _pattern(
  id: 'cpp-manual-delete',
  severity: RuleSeverity.warn,
  title: 'Avoid manual deletion',
  pattern: RegExp(r'\bdelete(?:\[\])?\s+'),
  message: 'manual delete used',
);

/// Reports C-style casts.
final SourcePatternRule cppCastRule = _pattern(
  id: 'cpp-cast',
  severity: RuleSeverity.info,
  title: 'Use explicit C++ casts',
  pattern: RegExp(
    r'\((?:int|float|double|char\s*\*|void\s*\*)\)\s*(?!(?:const|override|noexcept|final)\b)(?=[A-Za-z_0-9(])',
  ),
  exclusion: RegExp(
    r':\s*\((?:int|float|double|char\s*\*|void\s*\*)\)\s*[A-Za-z_]\w*\b',
  ),
  message: 'C-style cast used',
);

/// Reports legacy `NULL`.
final SourcePatternRule cppNullRule = _pattern(
  id: 'cpp-null',
  severity: RuleSeverity.info,
  title: 'Use nullptr',
  pattern: RegExp(r'\bNULL\b'),
  message: 'NULL used instead of nullptr',
);

/// Reports goto statements.
final SourcePatternRule cppGotoRule = _pattern(
  id: 'cpp-goto',
  severity: RuleSeverity.warn,
  title: 'Use structured control flow',
  pattern: RegExp(r'(^|\s)goto\s+'),
  message: 'goto statement used',
);

/// Reports mutable reference parameters.
final SourcePatternRule cppNonConstRefParamRule = SourcePatternRule(
  metadata: _metadata(
    'cpp-non-const-ref-param',
    RuleSeverity.info,
    'Make mutation explicit',
  ),
  pattern: RegExp(
    r'^\s*(?:void|int|bool|auto)\b[^=;{}]*\([^;{}]*&\s+[A-Za-z_]\w*',
  ),
  exclusion: RegExp(r'\bconst(?:\s|(?=&))|&&'),
  message: 'non-const reference parameter may hide mutation',
  confidence: 'medium',
);

/// Reports C allocation APIs.
final SourcePatternRule cppMallocFreeRule = _pattern(
  id: 'cpp-malloc-free',
  severity: RuleSeverity.warn,
  title: 'Use C++ lifetime management',
  pattern: RegExp(r'\b(?:malloc|calloc|realloc|free)\s*\('),
  message: 'C allocation API used in C++ code',
);

/// Reports unsafe C string APIs.
final SourcePatternRule cppUnsafeCStringRule = _pattern(
  id: 'cpp-unsafe-c-string',
  severity: RuleSeverity.warn,
  title: 'Use bounded string APIs',
  pattern: RegExp(
    r'(?:^|[^.\s>])\s*\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(|'
    r'^(?!.*(?:\.|->|::)\s*gets\s*\().*\bgets\s*\(\s*[^,)]*\)',
  ),
  message: 'unsafe C string/buffer API used',
);

/// Reports C random APIs.
final SourcePatternRule cppRandRule = _pattern(
  id: 'cpp-rand',
  severity: RuleSeverity.info,
  title: 'Use a suitable random engine',
  pattern: RegExp(r'\b(?:srand\s*\(|rand\s*\(\s*\))'),
  message: 'C rand/srand used',
);

/// Reports `const_cast`.
final SourcePatternRule cppConstCastRule = _pattern(
  id: 'cpp-const-cast',
  severity: RuleSeverity.warn,
  title: 'Preserve const correctness',
  pattern: RegExp(r'\bconst_cast\s*<'),
  message: 'const_cast used',
);

/// Reports `reinterpret_cast`.
final SourcePatternRule cppReinterpretCastRule = _pattern(
  id: 'cpp-reinterpret-cast',
  severity: RuleSeverity.warn,
  title: 'Preserve type safety',
  pattern: RegExp(r'\breinterpret_cast\s*<'),
  message: 'reinterpret_cast used',
);

/// Reports byte-based zero initialization.
final SourcePatternRule cppMemsetZeroRule = _pattern(
  id: 'cpp-memset-zero',
  severity: RuleSeverity.info,
  title: 'Use typed initialization',
  pattern: RegExp(r'\bmemset\s*\([^,]+,\s*0\s*,'),
  message: 'memset used for zero-initialization',
);

/// Reports untyped macro constants.
final class CppMacroConstantRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const CppMacroConstantRule()
    : super(
        const RuleMetadata(
          id: 'cpp-macro-constant',
          defaultSeverity: RuleSeverity.info,
          group: 'nim-style',
          title: 'Use typed constants',
          why:
              'This construct weakens C++ type, lifetime, or interface safety.',
          suggestion:
              'Use the safer typed C++ alternative described by the rule.',
          languages: <String>['cpp'],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      final Set<String> conditionalMacros =
          RegExp(r'^\s*#\s*if(?:n?def)?\s+([A-Za-z_]\w*)', multiLine: true)
              .allMatches(source.value)
              .map((RegExpMatch match) => match.group(1)!)
              .toSet();
      final List<String> lines = context.linesFor(source.key);
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? macro = _define.firstMatch(lines[index].trim());
        final String replacement = macro?.group(2)?.trimLeft() ?? '';
        if (macro == null ||
            replacement.isEmpty ||
            replacement.startsWith('//') ||
            replacement.startsWith('/*') ||
            !_constantReplacement.hasMatch(replacement) ||
            lines[index].contains('(') ||
            conditionalMacros.contains(macro.group(1))) {
          continue;
        }
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message: 'macro constant used',
          confidence: 'medium',
        );
      }
    }
  }

  static final RegExp _define = RegExp(r'^#define\s+([A-Za-z_]\w*)\s+(.*)$');

  static final RegExp _constantReplacement = RegExp(
    r'''^(?:[-+]?(?:0[xX][0-9A-Fa-f']+|0[bB][01']+|\d[\d']*(?:\.\d[\d']*)?)|true\b|false\b|nullptr\b|NULL\b|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')''',
  );
}

/// Reports polymorphic bases without safe destruction.
final class CppVirtualNoDestructorRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const CppVirtualNoDestructorRule()
    : super(
        const RuleMetadata(
          id: 'cpp-virtual-no-destructor',
          defaultSeverity: RuleSeverity.warn,
          group: 'nim-style',
          title: 'Make polymorphic destruction safe',
          why:
              'This construct weakens C++ type, lifetime, or interface safety.',
          suggestion:
              'Use the safer typed C++ alternative described by the rule.',
          languages: <String>['cpp'],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final Set<String> classesWithSafeOrUnknownDestructors =
        _classesWithSafeOrUnknownDestructors(context);
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index].trim();
        if (!line.startsWith('class ') && !line.startsWith('struct ')) continue;
        final List<String> body = _classBody(lines, index);
        final String? className = _className(lines, index);
        if (body.any((String value) => value.trim().startsWith('virtual ')) &&
            !body.any(_declaresVirtualDestructor) &&
            (className == null ||
                !classesWithSafeOrUnknownDestructors.contains(className))) {
          yield report(
            context,
            path: source.key,
            line: index + 1,
            message: 'class has virtual methods but no virtual destructor',
            confidence: 'medium',
          );
        }
      }
    }
  }

  static Set<String> _classesWithSafeOrUnknownDestructors(RuleContext context) {
    final Set<String> result = <String>{};
    final Map<String, Set<String>> basesByClass = <String, Set<String>>{};
    for (final String path in context.sources.keys) {
      final List<String> lines = context.linesFor(path);
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index].trim();
        if (!line.startsWith('class ') && !line.startsWith('struct ')) continue;
        final String? name = _className(lines, index);
        if (name == null) continue;
        final List<String> body = _classBody(lines, index);
        if (body.any(_declaresVirtualDestructor)) result.add(name);
        basesByClass[name] = _baseNames(lines, index);
      }
    }

    for (final MapEntry<String, Set<String>> classBases
        in basesByClass.entries) {
      if (classBases.value.any(
        (String base) => !basesByClass.containsKey(base),
      )) {
        result.add(classBases.key);
      }
    }

    var changed = true;
    while (changed) {
      changed = false;
      for (final MapEntry<String, Set<String>> classBases
          in basesByClass.entries) {
        if (!result.contains(classBases.key) &&
            classBases.value.any(result.contains)) {
          result.add(classBases.key);
          changed = true;
        }
      }
    }
    return result;
  }

  static bool _declaresVirtualDestructor(String line) =>
      line.contains('virtual ~') ||
      (line.contains('~') && line.contains('override'));

  static String? _className(List<String> lines, int start) {
    final String declaration = _classDeclaration(lines, start);
    final RegExpMatch? match = RegExp(
      r'^(?:class|struct)\s+(.+?)(?:\s*:\s*|\s*\{)',
    ).firstMatch(declaration);
    if (match == null) return null;
    final List<String> tokens = match.group(1)!.trim().split(RegExp(r'\s+'));
    if (tokens.isEmpty) return null;
    final int nameIndex = tokens.last == 'final'
        ? tokens.length - 2
        : tokens.length - 1;
    return nameIndex >= 0 ? tokens[nameIndex] : null;
  }

  static Set<String> _baseNames(List<String> lines, int start) {
    final String declaration = _classDeclaration(lines, start);
    final int colon = declaration.indexOf(':');
    final int brace = declaration.indexOf('{');
    if (colon < 0 || brace < colon) return const <String>{};
    return declaration
        .substring(colon + 1, brace)
        .split(',')
        .map(
          (String base) => base
              .replaceAll(
                RegExp(r'\b(?:public|protected|private|virtual)\b'),
                '',
              )
              .trim(),
        )
        .map((String base) => base.split('::').last)
        .map((String base) => base.replaceFirst(RegExp(r'<.*$'), '').trim())
        .where((String base) => base.isNotEmpty)
        .toSet();
  }

  static String _classDeclaration(List<String> lines, int start) {
    final StringBuffer declaration = StringBuffer();
    for (final String line in lines.skip(start).take(8)) {
      declaration.write(' ${line.trim()}');
      if (line.contains('{') || line.contains(';')) break;
    }
    return declaration.toString().trim();
  }

  static List<String> _classBody(List<String> lines, int start) {
    final List<String> body = <String>[];
    var depth = 0;
    var hasOpeningBrace = false;
    for (final String line in lines.skip(start)) {
      if (!hasOpeningBrace && line.contains(';') && !line.contains('{')) {
        return body;
      }
      for (final int character in line.codeUnits) {
        if (character == 0x7b) {
          hasOpeningBrace = true;
          depth++;
        } else if (character == 0x7d && hasOpeningBrace) {
          depth--;
        }
      }
      if (hasOpeningBrace) {
        body.add(line);
        if (depth == 0) break;
      }
    }
    return body;
  }
}
