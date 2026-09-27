import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import 'oop_rules.dart';

const ids = <String>[
  'oop-factory-bypass',
  'oop-facade-bypass',
  'oop-repository-bypass',
  'oop-proxy-bypass',
  'oop-repeated-adapter-mapping',
  'oop-template-workflow-candidate',
];

List<Finding> _bucket(Map<String, List<Finding>> findings, String id) {
  final List<Finding>? result = findings[id];
  if (result == null) throw StateError('Missing finding bucket for $id');
  return result;
}

// code-buster-ignore complex-function: one coordinated project pass shares class-role, mapping, and inheritance evidence across boundary rules.
Map<String, List<Finding>> analyzeBoundaries(CSharpOopProject p) {
  final r = {for (final id in ids) id: <Finding>[]};
  for (final role in ['Factory', 'Facade', 'Repository', 'Proxy']) {
    for (final a in p.classes.where((c) => c.name.endsWith(role))) {
      final covered = <String>{};
      final String? src = p.sources[a.path];
      if (src == null) continue;
      if (role == 'Factory') {
        covered.addAll(
          cachedRegExp(
            r'\bnew\s+([A-Z]\w*)\s*\(',
          ).allMatches(src).map((m) => m.requiredGroup(1)),
        );
      } else {
        covered.addAll(
          cachedRegExp(
            r'\b(?:private|protected)\s+(?:(?:readonly|final)\s+)?([A-Z]\w*(?:Client|Dao|Database|DataSource|Store|Service|Gateway))\s+_?\w+\s*[;=]',
          ).allMatches(src).map((m) => m.requiredGroup(1)),
        );
        if (a.path.endsWith('.ts') || a.path.endsWith('.tsx')) {
          covered.addAll(
            cachedRegExp(
              r'\b(?:private|protected)\s+(?:readonly\s+)?[A-Za-z_$][\w$]*\s*:\s*([A-Z]\w*(?:Client|Dao|Database|DataSource|Store|Service|Gateway))\b',
            ).allMatches(src).map((m) => m.requiredGroup(1)),
          );
        }
      }
      if (covered.length < (role == 'Facade' ? 3 : 1)) continue;
      final uses = <String>{};
      final bypass = <String>[];
      for (final e in p.sources.entries) {
        if (e.key == a.path) continue;
        if (cachedRegExp('\\b${a.name}\\b').hasMatch(e.value)) uses.add(e.key);
        final direct = covered
            .where(
              (t) => cachedRegExp('\\b(?:new\\s+)?$t\\b').hasMatch(e.value),
            )
            .length;
        if (direct >= (role == 'Facade' ? 2 : 1)) bypass.add(e.key);
      }
      if (uses.length >= 3 && uses.length > bypass.length) {
        for (final path in bypass) {
          _bucket(r, 'oop-${role.toLowerCase()}-bypass').add(
            Finding(
              code: 'oop-${role.toLowerCase()}-bypass',
              severity: RuleSeverity.info,
              path: path,
              line: 1,
              message:
                  '$path accesses an implementation directly although ${a.name} is the dominant boundary',
              confidence: 'high',
            ),
          );
        }
      }
    }
  }
  final maps = <String, List<OopClass>>{};
  final init = cachedRegExp(r'\bnew\s+([A-Z]\w*)\s*\{([^{}]+)\}', dotAll: true);
  for (final c in p.classes) {
    for (final m in c.methods) {
      for (final x in init.allMatches(m.body)) {
        final pairs =
            cachedRegExp(r'([A-Z]\w*)\s*=\s*([a-z_]\w*)\.([A-Z]\w*)')
                .allMatches(x.requiredGroup(2))
                .map((v) => '${v.group(1)}=${v.group(3)}')
                .toList()
              ..sort();
        if (pairs.length >= 3) {
          maps.putIfAbsent('${x.group(1)}|${pairs.join(',')}', () => []).add(c);
        }
      }
      if (!c.path.endsWith('.java')) continue;
      final RegExp constructor = cachedRegExp(
        r'\bnew\s+([A-Z]\w*)\s*\(\s*((?:[a-z_]\w*\s*\.\s*get[A-Z]\w*\s*\(\s*\)\s*,?\s*){3,})\)',
        dotAll: true,
      );
      for (final RegExpMatch x in constructor.allMatches(m.body)) {
        final List<String> members =
            cachedRegExp(r'\b[a-z_]\w*\s*\.\s*get([A-Z]\w*)\s*\(\s*\)')
                .allMatches(x.requiredGroup(2))
                .map((v) => v.requiredGroup(1))
                .toList();
        if (members.length >= 3) {
          maps
              .putIfAbsent(
                '${x.group(1)}|${members.map((v) => '$v=$v').join(',')}',
                () => [],
              )
              .add(c);
        }
      }
    }
  }
  final Map<String, List<OopClass>> objectMaps = <String, List<OopClass>>{};
  final RegExp objectLiteral = cachedRegExp(
    r'\breturn\s*\{([^{}]+)\}',
    dotAll: true,
  );
  for (final OopClass owner in p.classes.where(
    (type) => type.path.endsWith('.ts') || type.path.endsWith('.tsx'),
  )) {
    for (final OopMethod method in owner.methods) {
      for (final RegExpMatch object in objectLiteral.allMatches(method.body)) {
        final List<String> pairs =
            cachedRegExp(
                  r'\b([a-z_$][\w$]*)\s*:\s*([a-z_$][\w$]*)\.([a-z_$][\w$]*)',
                )
                .allMatches(object.requiredGroup(1))
                .map((match) => '${match.group(1)}=${match.group(3)}')
                .toList()
              ..sort();
        if (pairs.length >= 3) {
          objectMaps.putIfAbsent(pairs.join(','), () => []).add(owner);
        }
      }
    }
  }
  for (final entry in objectMaps.entries) {
    final Set<String> paths = entry.value.map((owner) => owner.path).toSet();
    if (entry.value.length < 3 || paths.length < 2) continue;
    final OopClass first = entry.value.first;
    _bucket(r, 'oop-repeated-adapter-mapping').add(
      Finding(
        code: 'oop-repeated-adapter-mapping',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            'Object mapping is repeated ${entry.value.length} times across ${paths.length} files',
        confidence: 'high',
        relatedFiles: paths.where((path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
  for (final e in maps.entries) {
    final paths = e.value.map((c) => c.path).toSet();
    if (e.value.length >= 3 && paths.length >= 2) {
      final c = e.value.first;
      _bucket(r, 'oop-repeated-adapter-mapping').add(
        Finding(
          code: 'oop-repeated-adapter-mapping',
          severity: RuleSeverity.info,
          path: c.path,
          line: c.line,
          message:
              'Object mapping is repeated ${e.value.length} times across ${paths.length} files',
          confidence: 'high',
          relatedFiles: paths.where((x) => x != c.path).toList()..sort(),
        ),
      );
    }
  }
  final inherited = p.classes.where((c) => c.parent != null).toList();
  for (var i = 0; i < inherited.length; i++) {
    for (var j = i + 1; j < inherited.length; j++) {
      final a = inherited[i], b = inherited[j];
      final bool implicitOverrideLanguage =
          a.path.endsWith('.java') ||
          a.path.endsWith('.ts') ||
          a.path.endsWith('.tsx');
      if (a.parent != b.parent ||
          a.path == b.path ||
          (implicitOverrideLanguage &&
              (a.name == b.name ||
                  a.path.split('/').last == b.path.split('/').last))) {
        continue;
      }
      for (final am in a.methods.where(
        (m) => m.isOverride || implicitOverrideLanguage,
      )) {
        for (final bm in b.methods.where(
          (m) =>
              (m.isOverride ||
                  b.path.endsWith('.java') ||
                  b.path.endsWith('.ts') ||
                  b.path.endsWith('.tsx')) &&
              m.name == am.name,
        )) {
          final ac = cachedRegExp(
                r'\b([A-Za-z_]\w*)\s*\(',
              ).allMatches(am.body).map((x) => x.requiredGroup(1)).toList(),
              bc = cachedRegExp(
                r'\b([A-Za-z_]\w*)\s*\(',
              ).allMatches(bm.body).map((x) => x.requiredGroup(1)).toList();
          if (ac.length >= 4 &&
              ac.length == bc.length &&
              [
                    for (var k = 0; k < ac.length; k++)
                      if (ac[k] != bc[k]) k,
                  ].length ==
                  1) {
            _bucket(r, 'oop-template-workflow-candidate').add(
              Finding(
                code: 'oop-template-workflow-candidate',
                severity: RuleSeverity.info,
                path: a.path,
                line: a.line,
                message:
                    '${a.name}.${am.name} and ${b.name}.${bm.name} repeat a stable workflow',
                confidence: 'high',
                relatedFiles: [b.path],
              ),
            );
          }
        }
      }
    }
  }
  return r;
}
