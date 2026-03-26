// Nim has a large compatibility inventory, and this file maps every supported ID to executable metadata without hiding gaps.

import '../../core/models.dart';

/// Metadata for the current generated Nim rule inventory.
final Map<String, RuleMetadata> nimRuleCatalog = <String, RuleMetadata>{
  'nim-asset-loaded-not-freed': const RuleMetadata(
    id: 'nim-asset-loaded-not-freed',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim asset loaded not freed',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-average-openarray-risk': const RuleMetadata(
    id: 'nim-average-openarray-risk',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim average openarray risk',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-broad-except': const RuleMetadata(
    id: 'nim-broad-except',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Narrow except',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-broad-import': const RuleMetadata(
    id: 'nim-broad-import',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Narrow imports',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-camera-transform-leak': const RuleMetadata(
    id: 'nim-camera-transform-leak',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim camera transform leak',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-case-on-string': const RuleMetadata(
    id: 'nim-case-on-string',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim case on string',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-cast-usage': const RuleMetadata(
    id: 'nim-cast-usage',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim cast usage',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-constructor-name': const RuleMetadata(
    id: 'nim-constructor-name',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Fix constructor name',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-could-be-const': const RuleMetadata(
    id: 'nim-could-be-const',
    defaultSeverity: RuleSeverity.warn,
    group: 'zerocost',
    title: 'Review Nim could be const',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-cstring-public-api': const RuleMetadata(
    id: 'nim-cstring-public-api',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Use string',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-debug-draw-not-gated': const RuleMetadata(
    id: 'nim-debug-draw-not-gated',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim debug draw not gated',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-default-overwrites-context': const RuleMetadata(
    id: 'nim-default-overwrites-context',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim default overwrites context',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-distinct-serialization-asymmetry': const RuleMetadata(
    id: 'nim-distinct-serialization-asymmetry',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim distinct serialization asymmetry',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-divide-by-len-without-empty-check': const RuleMetadata(
    id: 'nim-divide-by-len-without-empty-check',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim divide by len without empty check',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-double-negation': const RuleMetadata(
    id: 'nim-double-negation',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim double negation',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-draw-call-in-update': const RuleMetadata(
    id: 'nim-draw-call-in-update',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim draw call in update',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-draw-loads-asset': const RuleMetadata(
    id: 'nim-draw-loads-asset',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim draw loads asset',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-dt-not-used': const RuleMetadata(
    id: 'nim-dt-not-used',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim dt not used',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-dynlib-lifetime': const RuleMetadata(
    id: 'nim-dynlib-lifetime',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim dynlib lifetime',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-dynlib-unchecked-symbol': const RuleMetadata(
    id: 'nim-dynlib-unchecked-symbol',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim dynlib unchecked symbol',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-empty-except-body': const RuleMetadata(
    id: 'nim-empty-except-body',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Handle or document',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-entity-access-after-destroy': const RuleMetadata(
    id: 'nim-entity-access-after-destroy',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim entity access after destroy',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-exec-dynamic-command': const RuleMetadata(
    id: 'nim-exec-dynamic-command',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review Nim exec dynamic command',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-exported-object-without-doc': const RuleMetadata(
    id: 'nim-exported-object-without-doc',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Document exported type',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-exported-template-missing-doc': const RuleMetadata(
    id: 'nim-exported-template-missing-doc',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim exported template missing doc',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-float-equality-physics': const RuleMetadata(
    id: 'nim-float-equality-physics',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim float equality physics',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-float-test-exact-equality': const RuleMetadata(
    id: 'nim-float-test-exact-equality',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim float test exact equality',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-float-tests-missing-edge-cases': const RuleMetadata(
    id: 'nim-float-tests-missing-edge-cases',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim float tests missing edge cases',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-forced-decimal-comma-output': const RuleMetadata(
    id: 'nim-forced-decimal-comma-output',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review Nim forced decimal comma output',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-functional-alloc-chain': const RuleMetadata(
    id: 'nim-functional-alloc-chain',
    defaultSeverity: RuleSeverity.warn,
    group: 'zerocost',
    title: 'Review Nim functional alloc chain',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-game-loop-allocation': const RuleMetadata(
    id: 'nim-game-loop-allocation',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim game loop allocation',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-generic-exception-raise': const RuleMetadata(
    id: 'nim-generic-exception-raise',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Raise specific error',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-generic-hook-cross-module-call': const RuleMetadata(
    id: 'nim-generic-hook-cross-module-call',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim generic hook cross module call',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-generic-hook-missing-doc': const RuleMetadata(
    id: 'nim-generic-hook-missing-doc',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim generic hook missing doc',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-generic-hook-same-signature': const RuleMetadata(
    id: 'nim-generic-hook-same-signature',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim generic hook same signature',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-global-tab-replace': const RuleMetadata(
    id: 'nim-global-tab-replace',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review Nim global tab replace',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-god-module': const RuleMetadata(
    id: 'nim-god-module',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Split module',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-hardcoded-screen-size': const RuleMetadata(
    id: 'nim-hardcoded-screen-size',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim hardcoded screen size',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-home-dir-strip': const RuleMetadata(
    id: 'nim-home-dir-strip',
    defaultSeverity: RuleSeverity.warn,
    group: 'strings',
    title: 'Review Nim home dir strip',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-hook-overwrites-accumulator': const RuleMetadata(
    id: 'nim-hook-overwrites-accumulator',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim hook overwrites accumulator',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-hook-too-generic': const RuleMetadata(
    id: 'nim-hook-too-generic',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim hook too generic',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-hot-loop-allocation': const RuleMetadata(
    id: 'nim-hot-loop-allocation',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim hot loop allocation',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-http-case-sensitive-header-compare': const RuleMetadata(
    id: 'nim-http-case-sensitive-header-compare',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim http case sensitive header compare',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-http-header-contains': const RuleMetadata(
    id: 'nim-http-header-contains',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim http header contains',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-imported-hook-ambiguity-risk': const RuleMetadata(
    id: 'nim-imported-hook-ambiguity-risk',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim imported hook ambiguity risk',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-input-in-draw': const RuleMetadata(
    id: 'nim-input-in-draw',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim input in draw',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-json-heavy-api': const RuleMetadata(
    id: 'nim-json-heavy-api',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim json heavy api',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-large-number-ungrouped': const RuleMetadata(
    id: 'nim-large-number-ungrouped',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim large number ungrouped',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-large-template': const RuleMetadata(
    id: 'nim-large-template',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Split template',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-layout-assumption-undocumented': const RuleMetadata(
    id: 'nim-layout-assumption-undocumented',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim layout assumption undocumented',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-many-exports': const RuleMetadata(
    id: 'nim-many-exports',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Reduce exports',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-method-dispatch': const RuleMetadata(
    id: 'nim-method-dispatch',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Review dispatch',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-missing-doc': const RuleMetadata(
    id: 'nim-missing-doc',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Add doc comment',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-missing-epsilon-distance': const RuleMetadata(
    id: 'nim-missing-epsilon-distance',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim missing epsilon distance',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-missing-raises': const RuleMetadata(
    id: 'nim-missing-raises',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Add raises contract',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-missing-test-for-module': const RuleMetadata(
    id: 'nim-missing-test-for-module',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Add test file',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-mutate-while-iterating': const RuleMetadata(
    id: 'nim-mutate-while-iterating',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim mutate while iterating',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-negated-isnil': const RuleMetadata(
    id: 'nim-negated-isnil',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim negated isnil',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-nested-stdout-capture': const RuleMetadata(
    id: 'nim-nested-stdout-capture',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim nested stdout capture',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-nil-component-access': const RuleMetadata(
    id: 'nim-nil-component-access',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim nil component access',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-no-test-suite': const RuleMetadata(
    id: 'nim-no-test-suite',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Add test suite',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-nonref-inheritance': const RuleMetadata(
    id: 'nim-nonref-inheritance',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Use ref or composition',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-o-n-squared-collision': const RuleMetadata(
    id: 'nim-o-n-squared-collision',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim o n squared collision',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-openarray-missing-empty-test': const RuleMetadata(
    id: 'nim-openarray-missing-empty-test',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim openarray missing empty test',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-parameter-cluster-spread': const RuleMetadata(
    id: 'nim-parameter-cluster-spread',
    defaultSeverity: RuleSeverity.warn,
    group: 'design',
    title: 'Review Nim parameter cluster spread',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-per-frame-string-format': const RuleMetadata(
    id: 'nim-per-frame-string-format',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim per frame string format',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-physics-variable-timestep': const RuleMetadata(
    id: 'nim-physics-variable-timestep',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim physics variable timestep',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-plugin-hook-without-kind': const RuleMetadata(
    id: 'nim-plugin-hook-without-kind',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim plugin hook without kind',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-pointer-public-api': const RuleMetadata(
    id: 'nim-pointer-public-api',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Wrap pointer',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-pointer-with-separate-size': const RuleMetadata(
    id: 'nim-pointer-with-separate-size',
    defaultSeverity: RuleSeverity.warn,
    group: 'zerocost',
    title: 'Review Nim pointer with separate size',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-prefer-let': const RuleMetadata(
    id: 'nim-prefer-let',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Use let',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-proc-only-plugin-api': const RuleMetadata(
    id: 'nim-proc-only-plugin-api',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim proc only plugin api',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-protocol-split-without-strip': const RuleMetadata(
    id: 'nim-protocol-split-without-strip',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim protocol split without strip',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-public-mutable-container-field': const RuleMetadata(
    id: 'nim-public-mutable-container-field',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim public mutable container field',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-public-var-scalar-accessor': const RuleMetadata(
    id: 'nim-public-var-scalar-accessor',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Encapsulate state',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-raises-catchableerror': const RuleMetadata(
    id: 'nim-raises-catchableerror',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Narrow raises',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-random-in-render': const RuleMetadata(
    id: 'nim-random-in-render',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim random in render',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-random-in-simulation': const RuleMetadata(
    id: 'nim-random-in-simulation',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim random in simulation',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-readfile-concat-temp': const RuleMetadata(
    id: 'nim-readfile-concat-temp',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim readfile concat temp',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-readline-without-strip': const RuleMetadata(
    id: 'nim-readline-without-strip',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim readline without strip',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-redundant-type-init': const RuleMetadata(
    id: 'nim-redundant-type-init',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim redundant type init',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-ref-object-inheritance': const RuleMetadata(
    id: 'nim-ref-object-inheritance',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Consider composition',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-render-state-not-restored': const RuleMetadata(
    id: 'nim-render-state-not-restored',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim render state not restored',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-return-instead-of-result': const RuleMetadata(
    id: 'nim-return-instead-of-result',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim return instead of result',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-save-in-update': const RuleMetadata(
    id: 'nim-save-in-update',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim save in update',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-save-missing-version': const RuleMetadata(
    id: 'nim-save-missing-version',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim save missing version',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-skip-test-without-comment': const RuleMetadata(
    id: 'nim-skip-test-without-comment',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim skip test without comment',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-sleep-in-game-loop': const RuleMetadata(
    id: 'nim-sleep-in-game-loop',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim sleep in game loop',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-sound-every-frame': const RuleMetadata(
    id: 'nim-sound-every-frame',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim sound every frame',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-split-recursive-types': const RuleMetadata(
    id: 'nim-split-recursive-types',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Merge type sections',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-state-restore-without-finally': const RuleMetadata(
    id: 'nim-state-restore-without-finally',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim state restore without finally',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-std-import': const RuleMetadata(
    id: 'nim-std-import',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Use std/ prefix',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-string-serializer-missing-quote': const RuleMetadata(
    id: 'nim-string-serializer-missing-quote',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim string serializer missing quote',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-strip-chars-string-set': const RuleMetadata(
    id: 'nim-strip-chars-string-set',
    defaultSeverity: RuleSeverity.warn,
    group: 'strings',
    title: 'Review Nim strip chars string set',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-strip-one-sided-wrapper': const RuleMetadata(
    id: 'nim-strip-one-sided-wrapper',
    defaultSeverity: RuleSeverity.warn,
    group: 'strings',
    title: 'Review Nim strip one sided wrapper',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-tainted-exec': const RuleMetadata(
    id: 'nim-tainted-exec',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review Nim tainted exec',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-template-body-state-mutation': const RuleMetadata(
    id: 'nim-template-body-state-mutation',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim template body state mutation',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-test-naming': const RuleMetadata(
    id: 'nim-test-naming',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Rename test file',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-too-many-parameters': const RuleMetadata(
    id: 'nim-too-many-parameters',
    defaultSeverity: RuleSeverity.warn,
    group: 'design',
    title: 'Review Nim too many parameters',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-tuple-used-as-domain-type': const RuleMetadata(
    id: 'nim-tuple-used-as-domain-type',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review Review tuple modeling',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-type-prefix-proc-naming': const RuleMetadata(
    id: 'nim-type-prefix-proc-naming',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Use overloaded proc naming',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-unbounded-entity-growth': const RuleMetadata(
    id: 'nim-unbounded-entity-growth',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim unbounded entity growth',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-unordered-table-output': const RuleMetadata(
    id: 'nim-unordered-table-output',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review Nim unordered table output',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-update-blocking-io': const RuleMetadata(
    id: 'nim-update-blocking-io',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim update blocking io',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-wall-clock-in-update': const RuleMetadata(
    id: 'nim-wall-clock-in-update',
    defaultSeverity: RuleSeverity.warn,
    group: 'game-engine',
    title: 'Review Nim wall clock in update',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-websocket-tests-missing-header-variants': const RuleMetadata(
    id: 'nim-websocket-tests-missing-header-variants',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim websocket tests missing header variants',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-websocket-upgrade-fragile': const RuleMetadata(
    id: 'nim-websocket-upgrade-fragile',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-advanced',
    title: 'Review Nim websocket upgrade fragile',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-while-index-loop': const RuleMetadata(
    id: 'nim-while-index-loop',
    defaultSeverity: RuleSeverity.warn,
    group: 'idiomatic',
    title: 'Review Nim while index loop',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
  'nim-xml-output-unescaped': const RuleMetadata(
    id: 'nim-xml-output-unescaped',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review Nim xml output unescaped',
    why:
        'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
    suggestion: 'Use the safer explicit Nim pattern documented by this rule.',
  ),
};
