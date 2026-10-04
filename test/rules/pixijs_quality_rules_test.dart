import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/pixijs_quality_rules.dart';
import 'package:test/test.dart';

void main() {
  Iterable<Finding> run(
    String id,
    String source, {
    String version = '^8.0.0',
  }) => PixiJsQualityRule(id).analyze(
    RuleContext(
      config: const AnalysisConfig(root: '.', frameworks: <String>{'pixijs'}),
      sources: <String, String>{'src/game.ts': source},
      language: 'repository',
      auxiliaryFiles: <String, String>{
        'package.json': '{"dependencies":{"pixi.js":"$version"}}',
      },
    ),
  );

  test('every PixiJS rule has executable framework metadata', () {
    expect(pixiJsQualityRuleIds, hasLength(6));
    expect(pixiJsQualityRuleMetadata.keys, containsAll(pixiJsQualityRuleIds));
    for (final String id in pixiJsQualityRuleIds) {
      final RuleMetadata metadata = pixiJsQualityRuleMetadata.requiredValue(id);
      expect(metadata.frameworks, contains('pixijs'));
      expect(metadata.languages, <String>['javascript', 'typescript']);
    }
  });

  test('reports explicit PixiJS v8 lifecycle and frame-loop hazards', () {
    const String source = r'''
import { Application, Graphics, Text } from 'pixi.js';
const app = new Application();
app.init({ background: '#000' });
button.interactive = true;
world.cacheAsBitmap = true;
function update() {}
app.ticker.add(update);
app.ticker.add((delta) => {
  player.x += delta;
  const graphics = new Graphics();
  const label = new Text({ text: 'score' });
  stage.addChild(graphics, label);
});
''';

    for (final String id in pixiJsQualityRuleIds) {
      expect(run(id, source), isNotEmpty, reason: id);
    }
  });

  test('accepts PixiJS v8 APIs explicit cleanup and retained objects', () {
    const String source = r'''
import { Application, Graphics } from 'pixi.js';
const app = new Application();
await app.init({ background: '#000' });
button.eventMode = 'static';
world.cacheAsTexture();
const graphics = new Graphics();
function update(ticker) {
  player.x += ticker.deltaTime;
  graphics.x = player.x;
}
app.ticker.add(update);
app.ticker.remove(update);
app.ticker.add((ticker) => {
  player.y += ticker.deltaTime;
});
''';

    for (final String id in pixiJsQualityRuleIds) {
      expect(run(id, source), isEmpty, reason: id);
    }
  });

  test('gates migration findings on an explicit PixiJS v8 dependency', () {
    const String source = '''
const app = new Application();
app.init({});
sprite.interactive = true;
world.cacheAsBitmap = true;
app.ticker.add((delta) => { sprite.x += delta; });
''';

    for (final String id in <String>[
      'pixijs-v8-legacy-interactive',
      'pixijs-v8-cache-as-bitmap',
      'pixijs-v8-unawaited-application-init',
      'pixijs-v8-numeric-ticker-delta',
    ]) {
      expect(run(id, source, version: '^7.4.0'), isEmpty, reason: id);
    }
  });

  test('ignores PixiJS-looking syntax in comments and strings', () {
    const String source = r'''
// sprite.interactive = true;
const note = 'world.cacheAsBitmap = true';
const setup = 'app.init({})';
const ticker = 'app.ticker.add(update)';
''';

    for (final String id in pixiJsQualityRuleIds) {
      expect(run(id, source), isEmpty, reason: id);
    }
  });
}
