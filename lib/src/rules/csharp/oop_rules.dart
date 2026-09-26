// Conservative C# object-design advisories use one project-wide lexical model.

import '../../core/models.dart';
import '../../core/rule.dart';
import '../oop/metadata.dart';
import 'oop_behavior_rules.dart';
import 'oop_boundary_rules.dart';

const List<String> csharpOopRuleIds = <String>[
  'oop-data-clump',
  'oop-interface-segregation-pressure',
  'oop-refused-bequest',
  'oop-middle-man-delegation',
  'oop-single-use-abstraction',
  ...csharpOopBehaviorRuleIds,
  ...ids,
];

final Expando<Map<String, List<Finding>>> _findingsByProject =
    Expando<Map<String, List<Finding>>>('csharp-oop-findings');

final class CSharpOopProject {
  const CSharpOopProject(this.classes, this.sources);

  final List<OopClass> classes;
  final Map<String, String> sources;

  static CSharpOopProject parse(Map<String, String> sources) {
    final List<OopClass> classes = <OopClass>[];
    for (final MapEntry<String, String> source in sources.entries) {
      if (!source.key.endsWith('.cs') &&
          !source.key.endsWith('.java') &&
          !source.key.endsWith('.ts') &&
          !source.key.endsWith('.tsx')) {
        continue;
      }
      final String code = _maskNonCode(source.value);
      for (final RegExpMatch declaration in _classDeclaration.allMatches(
        code,
      )) {
        final int open = declaration.end - 1;
        if (open < 0) continue;
        final int close = _matchingBrace(code, open);
        if (close < 0) continue;
        final String kind = declaration.group(1)!;
        final String name = declaration.group(2)!;
        final List<String> bases = _baseTypes(
          <String>[
            declaration.group(3) ?? '',
            declaration.group(4) ?? '',
            declaration.group(5) ?? '',
          ].where((value) => value.isNotEmpty).join(','),
        );
        final String body = code.substring(open + 1, close);
        classes.add(
          OopClass(
            path: source.key,
            line:
                1 +
                '\n'.allMatches(code.substring(0, declaration.start)).length,
            name: name,
            isInterface: kind == 'interface',
            parent: null,
            interfaces: kind == 'class' ? bases : const <String>[],
            methods: _methods(body, source.key),
            fields: _fields(body, source.key),
          ),
        );
      }
    }
    final Set<String> interfaceNames = classes
        .where((type) => type.isInterface)
        .map((type) => type.name)
        .toSet();
    final List<OopClass> resolved = classes
        .map((type) {
          if (type.isInterface) return type;
          final List<String> interfaces = type.interfaces
              .where(interfaceNames.contains)
              .toList(growable: false);
          final String? parent = type.interfaces
              .where((base) => !interfaceNames.contains(base))
              .firstOrNull;
          return OopClass(
            path: type.path,
            line: type.line,
            name: type.name,
            isInterface: false,
            parent: parent,
            interfaces: interfaces,
            methods: type.methods,
            fields: type.fields,
          );
        })
        .toList(growable: false);
    return CSharpOopProject(
      List<OopClass>.unmodifiable(resolved),
      Map<String, String>.unmodifiable({
        for (final entry in sources.entries)
          if (entry.key.endsWith('.cs') ||
              entry.key.endsWith('.java') ||
              entry.key.endsWith('.ts') ||
              entry.key.endsWith('.tsx'))
            entry.key: _maskNonCode(entry.value),
      }),
    );
  }
}

final class OopClass {
  const OopClass({
    required this.path,
    required this.line,
    required this.name,
    required this.isInterface,
    required this.parent,
    required this.interfaces,
    required this.methods,
    required this.fields,
  });

  final String path;
  final int line;
  final String name;
  final bool isInterface;
  final String? parent;
  final List<String> interfaces;
  final List<OopMethod> methods;
  final Set<String> fields;
}

final class OopMethod {
  const OopMethod({
    required this.name,
    required this.parameters,
    required this.body,
    required this.isPublic,
    required this.isStatic,
    required this.isOverride,
  });

  final String name;
  final List<({String type, String name})> parameters;
  final String body;
  final bool isPublic;
  final bool isStatic;
  final bool isOverride;
}

final class CSharpOopRule extends SelfContainedRule {
  CSharpOopRule(String id) : super(_metadata(id));

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final CSharpOopProject project = context
        .requireLanguageAnalysis<CSharpOopProject>();
    final Map<String, List<Finding>> findings = _findingsByProject[project] ??=
        _analyze(project);
    return findings[metadata.id]!.map(
      (Finding finding) => context.report(
        metadata: metadata,
        path: finding.path,
        line: finding.line,
        message: finding.message,
        confidence: finding.confidence,
        relatedFiles: finding.relatedFiles,
      ),
    );
  }
}

RuleMetadata _metadata(String id) => oopRuleMetadata(id);

Map<String, List<Finding>> _analyze(CSharpOopProject project) {
  return <String, List<Finding>>{
    'oop-data-clump': _dataClumps(project),
    'oop-interface-segregation-pressure': _interfacePressure(project),
    'oop-refused-bequest': _refusedBequests(project),
    'oop-single-use-abstraction': _singleUseAbstractions(project),
    'oop-middle-man-delegation': _middleMen(project),
    ...analyzeCSharpOopBehavior(project),
    ...analyzeBoundaries(project),
  };
}

List<Finding> _singleUseAbstractions(CSharpOopProject project) {
  final List<Finding> findings = <Finding>[];
  final String projectSource = project.sources.values.join('\n');
  for (final OopClass contract in project.classes.where(
    (type) => type.isInterface && type.methods.length == 1,
  )) {
    final List<OopClass> implementors = project.classes
        .where(
          (type) =>
              !type.isInterface &&
              type.parent == null &&
              type.interfaces.length == 1 &&
              type.interfaces.single == contract.name,
        )
        .toList(growable: false);
    if (implementors.length != 1) continue;
    final OopClass implementation = implementors.single;
    final List<OopMethod> behavior = implementation.methods
        .where(
          (method) =>
              !method.isStatic &&
              method.name != implementation.name &&
              method.name != 'constructor',
        )
        .toList(growable: false);
    if (behavior.length != 1 ||
        behavior.single.name != contract.methods.single.name ||
        implementation.fields.isNotEmpty ||
        !_isTrivialOwnedBehavior(behavior.single.body)) {
      continue;
    }
    final int constructions = RegExp(
      '\\bnew\\s+${RegExp.escape(implementation.name)}\\b',
    ).allMatches(projectSource).length;
    final int contractReferences = RegExp(
      '\\b${RegExp.escape(contract.name)}\\b',
    ).allMatches(projectSource).length;
    if (constructions != 1 || contractReferences > 2) continue;
    findings.add(
      Finding(
        code: 'oop-single-use-abstraction',
        severity: RuleSeverity.info,
        path: contract.path,
        line: contract.line,
        message:
            '${contract.name} has one stateless implementation, ${implementation.name}, constructed once for one small operation',
        confidence: 'medium',
        relatedFiles: <String>[
          if (implementation.path != contract.path) implementation.path,
        ],
      ),
    );
  }
  return findings;
}

bool _isTrivialOwnedBehavior(String body) {
  final String normalized = body.trim();
  if (normalized.isEmpty || normalized.length > 180) return false;
  if (RegExp(
    r'\b(?:if|for|while|switch|catch|await|yield|synchronized|lock|using|try)\b',
  ).hasMatch(normalized)) {
    return false;
  }
  if (RegExp(r'\bnew\s+[A-Za-z_$]').hasMatch(normalized)) return false;
  final int statements = ';'.allMatches(normalized).length;
  return statements <= 1;
}

List<Finding> _dataClumps(CSharpOopProject project) {
  final Map<String, List<({OopClass owner, OopMethod method})>> groups =
      <String, List<({OopClass owner, OopMethod method})>>{};
  for (final OopClass owner in project.classes) {
    for (final OopMethod method in owner.methods) {
      if (method.parameters.length < 3) continue;
      final String key = method.parameters
          .map((parameter) => '${parameter.type} ${parameter.name}')
          .join('|');
      groups.putIfAbsent(key, () => []).add((owner: owner, method: method));
    }
  }
  final List<Finding> findings = <Finding>[];
  for (final MapEntry<String, List<({OopClass owner, OopMethod method})>> entry
      in groups.entries) {
    final Set<String> paths = entry.value
        .map((item) => item.owner.path)
        .toSet();
    if (entry.value.length < 3 || paths.length < 2) continue;
    entry.value.sort(
      (left, right) => left.owner.path.compareTo(right.owner.path),
    );
    final OopClass first = entry.value.first.owner;
    findings.add(
      Finding(
        code: 'oop-data-clump',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            'Parameters ${entry.key.split('|').map((part) => part.split(' ').last).join(', ')} recur together in ${entry.value.length} declarations across ${paths.length} files',
        confidence: 'high',
        relatedFiles: paths.where((path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
  return findings;
}

List<Finding> _interfacePressure(CSharpOopProject project) {
  final List<Finding> findings = <Finding>[];
  for (final OopClass contract in project.classes.where(
    (type) => type.isInterface && type.methods.length >= 4,
  )) {
    final Set<String> contractMethods = contract.methods
        .map((method) => method.name)
        .toSet();
    final List<({OopClass owner, Set<String> rejected})> rejecting = [];
    for (final OopClass owner in project.classes.where(
      (type) => type.interfaces.contains(contract.name),
    )) {
      final Set<String> rejected = owner.methods
          .where(
            (method) =>
                contractMethods.contains(method.name) && _rejects(method.body),
          )
          .map((method) => method.name)
          .toSet();
      if (rejected.isNotEmpty) {
        rejecting.add((owner: owner, rejected: rejected));
      }
    }
    final Set<String> rejectedMethods = rejecting
        .expand((item) => item.rejected)
        .toSet();
    final int rejectedCount = rejecting.fold(
      0,
      (sum, item) => sum + item.rejected.length,
    );
    if (rejecting.length < 2 ||
        rejectedCount < 3 ||
        rejectedMethods.length < 2) {
      continue;
    }
    findings.add(
      Finding(
        code: 'oop-interface-segregation-pressure',
        severity: RuleSeverity.info,
        path: contract.path,
        line: contract.line,
        message:
            '${contract.name} has ${contract.methods.length} operations; ${rejecting.length} implementors contain $rejectedCount rejected implementations across ${rejectedMethods.length} operations',
        confidence: 'high',
        relatedFiles:
            rejecting
                .map((item) => item.owner.path)
                .where((path) => path != contract.path)
                .toSet()
                .toList()
              ..sort(),
      ),
    );
  }
  return findings;
}

List<Finding> _refusedBequests(CSharpOopProject project) {
  final List<Finding> findings = <Finding>[];
  for (final OopClass base in project.classes.where(
    (type) =>
        !type.isInterface &&
        type.methods.where((method) => !method.isStatic).length >= 4,
  )) {
    final Set<String> inherited = base.methods
        .map((method) => method.name)
        .toSet();
    final List<({OopClass owner, Set<String> rejected})> rejecting = [];
    for (final OopClass owner in project.classes.where(
      (type) => type.parent == base.name,
    )) {
      final bool implicitOverride =
          owner.path.endsWith('.java') ||
          owner.path.endsWith('.ts') ||
          owner.path.endsWith('.tsx');
      final Set<String> rejected = owner.methods
          .where(
            (method) =>
                (method.isOverride || implicitOverride) &&
                inherited.contains(method.name) &&
                _rejects(method.body),
          )
          .map((method) => method.name)
          .toSet();
      if (rejected.length >= 2) {
        rejecting.add((owner: owner, rejected: rejected));
      }
    }
    final Set<String> rejectedMethods = rejecting
        .expand((item) => item.rejected)
        .toSet();
    if (rejecting.length < 2 || rejectedMethods.length < 3) continue;
    findings.add(
      Finding(
        code: 'oop-refused-bequest',
        severity: RuleSeverity.info,
        path: base.path,
        line: base.line,
        message:
            '${base.name} has ${rejectedMethods.length} inherited operations rejected by ${rejecting.length} direct subclasses',
        confidence: 'high',
        relatedFiles:
            rejecting
                .map((item) => item.owner.path)
                .where((path) => path != base.path)
                .toSet()
                .toList()
              ..sort(),
      ),
    );
  }
  return findings;
}

List<Finding> _middleMen(CSharpOopProject project) {
  final List<Finding> findings = <Finding>[];
  for (final OopClass owner in project.classes.where(
    (type) =>
        !type.isInterface &&
        type.parent == null &&
        type.interfaces.isEmpty &&
        type.fields.isNotEmpty,
  )) {
    final List<OopMethod> publicMethods = owner.methods
        .where((method) => method.isPublic && !method.isStatic)
        .toList();
    if (publicMethods.length < 5) continue;
    final Map<String, int> counts = <String, int>{};
    for (final OopMethod method in publicMethods) {
      final String? field = _forwardedField(method, owner.fields);
      if (field != null) {
        counts.update(field, (count) => count + 1, ifAbsent: () => 1);
      }
    }
    if (counts.isEmpty) continue;
    final MapEntry<String, int> dominant = counts.entries.reduce(
      (left, right) => left.value >= right.value ? left : right,
    );
    if (dominant.value < 4 || dominant.value * 5 < publicMethods.length * 4) {
      continue;
    }
    findings.add(
      Finding(
        code: 'oop-middle-man-delegation',
        severity: RuleSeverity.info,
        path: owner.path,
        line: owner.line,
        message:
            '${owner.name} forwards ${dominant.value} of ${publicMethods.length} public methods unchanged to ${dominant.key}',
        confidence: 'high',
      ),
    );
  }
  return findings;
}

bool _rejects(String body) => RegExp(
  r'\bthrow\s+new\s+(?:NotSupportedException|NotImplementedException|UnsupportedOperationException|Error)\b',
).hasMatch(body);

String? _forwardedField(OopMethod method, Set<String> fields) {
  final RegExpMatch? call = RegExp(
    r'^\s*(?:return\s+)?(?:this\.)?([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(([^)]*)\)\s*;?\s*$',
  ).firstMatch(method.body);
  if (call == null ||
      call.group(2) != method.name ||
      !fields.contains(call.group(1))) {
    return null;
  }
  final List<String> arguments = call.group(3)!.trim().isEmpty
      ? <String>[]
      : call.group(3)!.split(',').map((value) => value.trim()).toList();
  final List<String> parameters = method.parameters
      .map((parameter) => parameter.name)
      .toList();
  return _sameStrings(arguments, parameters) ? call.group(1) : null;
}

bool _sameStrings(List<String> left, List<String> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

List<OopMethod> _methods(String body, String path) {
  final List<OopMethod> methods = <OopMethod>[];
  final bool isTypeScript = path.endsWith('.ts') || path.endsWith('.tsx');
  final declarations = isTypeScript
      ? <({RegExp pattern, bool arrow})>[
          (pattern: _typescriptMethodDeclaration, arrow: false),
          (pattern: _typescriptArrowMethodDeclaration, arrow: true),
        ]
      : <({RegExp pattern, bool arrow})>[
          (pattern: _methodDeclaration, arrow: false),
        ];
  for (final declaration in declarations) {
    for (final RegExpMatch match in declaration.pattern.allMatches(body)) {
      if (_braceDepth(body, match.start) != 0) continue;
      final String modifiers = match.group(1) ?? '';
      final String name = match.group(2)!;
      final List<({String type, String name})>? parameters = _parameters(
        match.group(3)!,
        isTypeScript: isTypeScript,
      );
      if (parameters == null) continue;
      final String terminator = match.group(4)!;
      String methodBody = '';
      if (declaration.arrow) {
        final int next = _nextNonWhitespace(body, match.end);
        if (next < body.length && body[next] == '{') {
          final int close = _matchingBrace(body, next);
          if (close < 0) continue;
          methodBody = body.substring(next + 1, close).trim();
        } else {
          final int end = body.indexOf(';', match.end);
          if (end < 0) continue;
          methodBody = body.substring(match.end, end).trim();
        }
      } else if (terminator == '=>') {
        final int end = body.indexOf(';', match.end);
        if (end < 0) continue;
        methodBody = body.substring(match.end, end).trim();
      } else if (terminator == '{') {
        final int open = match.end - 1;
        final int close = _matchingBrace(body, open);
        if (close < 0) continue;
        methodBody = body.substring(open + 1, close).trim();
      }
      methods.add(
        OopMethod(
          name: name,
          parameters: parameters,
          body: methodBody,
          isPublic: isTypeScript
              ? !RegExp(r'\b(?:private|protected)\b').hasMatch(modifiers)
              : RegExp(r'\bpublic\b').hasMatch(modifiers),
          isStatic: RegExp(r'\bstatic\b').hasMatch(modifiers),
          isOverride:
              RegExp(r'\boverride\b').hasMatch(modifiers) ||
              RegExp(
                r'@Override\s*$',
              ).hasMatch(body.substring(0, match.start).split('\n').last),
        ),
      );
    }
  }
  return methods;
}

int _nextNonWhitespace(String source, int start) {
  var index = start;
  while (index < source.length && source.codeUnitAt(index) <= 0x20) {
    index++;
  }
  return index;
}

Set<String> _fields(String body, String path) {
  final Set<String> fields = <String>{};
  final bool isTypeScript = path.endsWith('.ts') || path.endsWith('.tsx');
  final RegExp declaration = isTypeScript
      ? _typescriptFieldDeclaration
      : _fieldDeclaration;
  for (final RegExpMatch match in declaration.allMatches(body)) {
    if (_braceDepth(body, match.start) == 0) fields.add(match.group(1)!);
  }
  if (isTypeScript) {
    for (final RegExpMatch constructor in RegExp(
      r'\bconstructor\s*\(([^)]*)\)',
      dotAll: true,
    ).allMatches(body)) {
      for (final RegExpMatch parameter in RegExp(
        r'\b(?:private|protected)\s+(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*:',
      ).allMatches(constructor.group(1)!)) {
        fields.add(parameter.group(1)!);
      }
    }
  }
  return fields;
}

List<({String type, String name})>? _parameters(
  String source, {
  bool isTypeScript = false,
}) {
  if (source.trim().isEmpty) return <({String type, String name})>[];
  final List<({String type, String name})> result = [];
  for (final String raw in source.split(',')) {
    final String parameter = raw.split('=').first.trim();
    if (isTypeScript &&
        (parameter.startsWith('[') || parameter.startsWith('{'))) {
      return null;
    }
    if (!isTypeScript && (parameter.contains('[') || parameter.contains(']'))) {
      return null;
    }
    final RegExpMatch? match = isTypeScript
        ? RegExp(
            r'^(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)\??\s*:\s*(.+)$',
          ).firstMatch(parameter)
        : RegExp(
            r'^(?:(?:ref|out|in|params|this)\s+)?([A-Za-z_]\w*(?:[.<>?\[\],]\w*)*)\s+([A-Za-z_]\w*)$',
          ).firstMatch(parameter);
    if (match == null) return null;
    result.add(
      isTypeScript
          ? (
              type: match.group(2)!.replaceAll(RegExp(r'\s+'), ''),
              name: match.group(1)!,
            )
          : (type: match.group(1)!, name: match.group(2)!),
    );
  }
  return result;
}

List<String> _baseTypes(String source) => source
    .split(',')
    .map((value) => value.trim().replaceAll(RegExp(r'<.*>'), ''))
    .where((value) => value.isNotEmpty)
    .toList(growable: false);

int _braceDepth(String source, int end) {
  var depth = 0;
  for (var index = 0; index < end; index++) {
    if (source[index] == '{') depth++;
    if (source[index] == '}') depth--;
  }
  return depth;
}

int _matchingBrace(String source, int open) {
  var depth = 0;
  for (var index = open; index < source.length; index++) {
    if (source[index] == '{') depth++;
    if (source[index] == '}' && --depth == 0) return index;
  }
  return -1;
}

String _maskNonCode(String source) {
  final List<int> result = source.codeUnits.toList();
  String? quote;
  var rawQuoteCount = 0;
  var escaped = false;
  var lineComment = false;
  var blockComment = false;
  for (var index = 0; index < source.length; index++) {
    final String character = source[index];
    final String next = index + 1 < source.length ? source[index + 1] : '';
    if (lineComment) {
      if (character == '\n') {
        lineComment = false;
      } else {
        result[index] = 0x20;
      }
    } else if (blockComment) {
      if (character == '*' && next == '/') {
        result[index] = result[index + 1] = 0x20;
        index++;
        blockComment = false;
      } else if (character != '\n' && character != '\r') {
        result[index] = 0x20;
      }
    } else if (rawQuoteCount > 0) {
      if (character != '\n' && character != '\r') result[index] = 0x20;
      var count = 0;
      while (index + count < source.length && source[index + count] == '"') {
        count++;
      }
      if (count >= rawQuoteCount) {
        for (var offset = 1; offset < rawQuoteCount; offset++) {
          result[index + offset] = 0x20;
        }
        index += rawQuoteCount - 1;
        rawQuoteCount = 0;
      }
    } else if (quote != null) {
      if (character != '\n' && character != '\r') result[index] = 0x20;
      if (quote == '"' && character == '"' && next == '"') {
        result[index + 1] = 0x20;
        index++;
        escaped = false;
      } else {
        if (!escaped && character == quote) quote = null;
        escaped = !escaped && character == r'\';
        if (character != r'\') escaped = false;
      }
    } else if (character == '/' && next == '/') {
      result[index] = result[index + 1] = 0x20;
      index++;
      lineComment = true;
    } else if (character == '/' && next == '*') {
      result[index] = result[index + 1] = 0x20;
      index++;
      blockComment = true;
    } else if (character == '"') {
      var count = 1;
      while (index + count < source.length && source[index + count] == '"') {
        count++;
      }
      if (count >= 3) {
        rawQuoteCount = count;
        for (var offset = 0; offset < count; offset++) {
          result[index + offset] = 0x20;
        }
        index += count - 1;
      } else {
        result[index] = 0x20;
        quote = character;
      }
    } else if (character == "'") {
      result[index] = 0x20;
      quote = character;
    }
  }
  return String.fromCharCodes(result);
}

final RegExp _classDeclaration = RegExp(
  r'\b(?:public|internal|private|protected|abstract|sealed|static|partial|final|strictfp|new|\s)*\b(class|interface)\s+([A-Za-z_]\w*)(?:\s*<[^>{}]+>)?\s*(?:(?::\s*([^\n{]+))|(?:extends\s+([A-Za-z_]\w*)\s*)?(?:implements\s+([^\n{]+))?)?\s*\{',
  multiLine: true,
);
final RegExp _methodDeclaration = RegExp(
  r'^\s*((?:(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|extern|unsafe|new|partial)\s+)*)[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|<[^(){};]+>|\[\]|\?)*\s+([A-Za-z_]\w*)\s*(?:<[^>{}]+>)?\s*\(([^)]*)\)\s*(?:where[^\n{;=]+\s*)?(=>|\{|;)',
  multiLine: true,
);
final RegExp _typescriptMethodDeclaration = RegExp(
  r'^\s*((?:(?:public|private|protected|static|abstract|async|override|readonly|declare|get|set)\s+)*)([A-Za-z_$][\w$]*|constructor)\s*(?:<[^>{}]+>)?\s*\(([^)]*)\)\s*(?::\s*[^={;\n]+)?\s*(=>|\{|;)',
  multiLine: true,
);
final RegExp _typescriptArrowMethodDeclaration = RegExp(
  r'^\s*((?:(?:public|private|protected|static|readonly|declare|override)\s+)*)([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*(?::\s*[^=;\n]+)?\s*(=>)',
  multiLine: true,
);
final RegExp _fieldDeclaration = RegExp(
  r'^\s*(?:private|protected|internal)\s+(?:readonly\s+)?(?:static\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|<[^(){};]+>|\[\]|\?)*\s+([A-Za-z_]\w*)\s*(?:=[^;]+)?;',
  multiLine: true,
);
final RegExp _typescriptFieldDeclaration = RegExp(
  r'^\s*(?:(?:public|private|protected|static|readonly|declare|abstract)\s+)*([A-Za-z_$][\w$]*)[!?]?\s*:\s*[^;=]+(?:=[^;]+)?;',
  multiLine: true,
);
