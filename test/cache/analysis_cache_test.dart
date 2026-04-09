import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test(
    'persists findings and invalidates on content config kind and version',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-cache-',
      );
      addTearDown(() => root.delete(recursive: true));
      const PersistentAnalysisCache cache = PersistentAnalysisCache(
        version: 'test-v1',
      );
      final AnalysisConfig config = AnalysisConfig(root: root.path);
      final Map<String, String> sources = <String, String>{
        'a.dart': 'void a() {}',
      };
      final String key = cache.key(
        config: config,
        sources: sources,
        kind: 'summary',
      );
      final Finding finding = Finding(
        code: 'todo-comment',
        severity: RuleSeverity.info,
        path: 'a.dart',
        line: 1,
        message: 'todo',
      );

      expect(cache.loadFindings(config: config, key: key), isNull);
      cache.storeFindings(
        config: config,
        key: key,
        findings: <Finding>[finding],
      );
      expect(
        cache.loadFindings(config: config, key: key)?.single.code,
        'todo-comment',
      );
      final Map<String, Object?> findingEnvelope =
          jsonDecode(
                File(
                  '${root.path}/.code-buster-cache/findings-$key.json',
                ).readAsStringSync(),
              )
              as Map<String, Object?>;
      expect(findingEnvelope['schemaVersion'], cacheSchemaVersion);
      expect(findingEnvelope['kind'], 'findings');
      final DependencyGraph graph = DependencyGraph(<String, Iterable<String>>{
        'a.dart': <String>['b.dart'],
        'b.dart': const <String>[],
      });
      cache.storeGraph(config: config, key: key, graph: graph);
      expect(
        cache.loadGraph(config: config, key: key)?.dependenciesOf('a.dart'),
        <String>['b.dart'],
      );
      final Map<String, Object?> graphEnvelope =
          jsonDecode(
                File(
                  '${root.path}/.code-buster-cache/graph-$key.json',
                ).readAsStringSync(),
              )
              as Map<String, Object?>;
      expect(graphEnvelope['schemaVersion'], cacheSchemaVersion);
      expect(graphEnvelope['kind'], 'graph');
      expect(
        cache.key(
          config: config,
          sources: <String, String>{'a.dart': 'void changed() {}'},
          kind: 'summary',
        ),
        isNot(key),
      );
      expect(
        cache.key(config: config, sources: sources, kind: 'graph'),
        isNot(key),
      );
      expect(
        const PersistentAnalysisCache(
          version: 'test-v2',
        ).key(config: config, sources: sources, kind: 'summary'),
        isNot(key),
      );
      const RuleMetadata ruleV1 = RuleMetadata(
        id: 'sample-rule',
        version: 1,
        defaultSeverity: RuleSeverity.info,
        group: 'core',
        title: 'Sample',
        why: 'Sample.',
        suggestion: 'Sample.',
      );
      const RuleMetadata ruleV2 = RuleMetadata(
        id: 'sample-rule',
        version: 2,
        defaultSeverity: RuleSeverity.info,
        group: 'core',
        title: 'Sample',
        why: 'Sample.',
        suggestion: 'Sample.',
      );
      expect(
        cache.key(
          config: config,
          sources: sources,
          kind: 'summary',
          rules: const <RuleMetadata>[ruleV1],
        ),
        isNot(
          cache.key(
            config: config,
            sources: sources,
            kind: 'summary',
            rules: const <RuleMetadata>[ruleV2],
          ),
        ),
      );
    },
  );

  test('ignores corrupt cache entries', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-cache-',
    );
    addTearDown(() => root.delete(recursive: true));
    final Directory directory = Directory('${root.path}/.code-buster-cache')
      ..createSync();
    File('${directory.path}/findings-bad.json').writeAsStringSync('{broken');
    expect(
      const PersistentAnalysisCache().loadFindings(
        config: AnalysisConfig(root: root.path),
        key: 'bad',
      ),
      isNull,
    );
  });
}
