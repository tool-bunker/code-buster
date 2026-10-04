import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/svelte_quality_rules.dart';
import 'package:test/test.dart';

void main() {
  Iterable<Finding> run(String id, String source) =>
      SvelteQualityRule(id).analyze(
        RuleContext(
          config: const AnalysisConfig(
            root: '.',
            frameworks: <String>{'svelte'},
          ),
          sources: <String, String>{'src/Panel.svelte': source},
          language: 'repository',
        ),
      );

  test('every Svelte rule has executable framework metadata', () {
    expect(svelteQualityRuleIds, hasLength(6));
    expect(svelteQualityRuleMetadata.keys, containsAll(svelteQualityRuleIds));
    for (final String id in svelteQualityRuleIds) {
      final RuleMetadata metadata = svelteQualityRuleMetadata.requiredValue(id);
      expect(metadata.frameworks, contains('svelte'));
      expect(metadata.languages, containsAll(<String>['html', 'typescript']));
    }
  });

  test('reports explicit lifecycle SSR HTML and animation hazards', () {
    const String source = r'''
<script module>
  const width = window.innerWidth;
</script>
<script lang="ts">
  import { onMount } from 'svelte';
  import { flip } from 'svelte/animate';
  let content = $state('');
  onMount(async () => {
    window.addEventListener('resize', resize);
    setInterval(refresh, 1000);
    await refresh();
    return () => refresh();
  });
</script>
{#each rows as row}
  <div animate:flip>{row.name}</div>
{/each}
<section>{@html content}</section>
''';

    for (final String id in svelteQualityRuleIds) {
      expect(run(id, source), isNotEmpty, reason: id);
    }
  });

  test('accepts explicit cleanup keyed animation and trusted HTML', () {
    const String source = r'''
<script module>
  export const prerender = true;
</script>
<script>
  import { onMount } from 'svelte';
  onMount(() => {
    window.addEventListener('resize', resize);
    const timer = setInterval(refresh, 1000);
    refreshAsync();
    return () => {
      window.removeEventListener('resize', resize);
      clearInterval(timer);
    };
  });
</script>
{#each rows as row (row.id)}
  <div animate:flip>{row.name}</div>
{/each}
<section>{@html sanitize(content)}</section>
''';

    for (final String id in svelteQualityRuleIds) {
      expect(run(id, source), isEmpty, reason: id);
    }
  });

  test('ignores Svelte-looking syntax in comments and strings', () {
    const String source = r'''
<!-- {@html content} -->
<script>
  // onMount(async () => setInterval(work, 1));
  const example = "window.addEventListener('resize', resize)";
  const markup = '{#each rows as row}<div animate:flip />{/each}';
</script>
''';

    for (final String id in svelteQualityRuleIds) {
      expect(run(id, source), isEmpty, reason: id);
    }
  });
}
