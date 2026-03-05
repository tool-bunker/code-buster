// Some rule descriptions outlive individual implementations; this table keeps their historical names and wording stable.

/// Canonical display metadata captured at the Dart runtime cutover.
const Map<String, ({String language, String group, String title})>
canonicalRuleDescriptors =
    <String, ({String language, String group, String title})>{
      'architecture-forbidden-dependency': (
        language: 'all',
        group: 'architecture',
        title: 'Architecture forbidden dependency',
      ),
      'architecture-layer-cycle': (
        language: 'all',
        group: 'architecture',
        title: 'Architecture layer cycle',
      ),
      'complex-function': (
        language: 'all',
        group: 'core',
        title: 'Reduce complexity',
      ),
      'constant-argument-parameter': (
        language: 'all',
        group: 'yagni',
        title: 'Constant argument parameter',
      ),
      'cpp-cast': (language: 'cpp', group: 'nim-style', title: 'Cpp cast'),
      'cpp-const-cast': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp const cast',
      ),
      'cpp-goto': (language: 'cpp', group: 'nim-style', title: 'Cpp goto'),
      'cpp-macro-constant': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp macro constant',
      ),
      'cpp-malloc-free': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp malloc free',
      ),
      'cpp-manual-delete': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp manual delete',
      ),
      'cpp-memset-zero': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp memset zero',
      ),
      'cpp-non-const-ref-param': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp non const ref param',
      ),
      'cpp-null': (language: 'cpp', group: 'nim-style', title: 'Cpp null'),
      'cpp-rand': (language: 'cpp', group: 'nim-style', title: 'Cpp rand'),
      'cpp-raw-owning-new': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp raw owning new',
      ),
      'cpp-reinterpret-cast': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp reinterpret cast',
      ),
      'cpp-unsafe-c-string': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp unsafe c string',
      ),
      'cpp-using-namespace-std': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp using namespace std',
      ),
      'cpp-virtual-no-destructor': (
        language: 'cpp',
        group: 'nim-style',
        title: 'Cpp virtual no destructor',
      ),
      'cs-aptca-attribute': (
        language: 'csharp',
        group: 'security',
        title: 'Cs aptca attribute',
      ),
      'cs-async-void': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs async void',
      ),
      'cs-binaryformatter': (
        language: 'csharp',
        group: 'security',
        title: 'Cs binaryformatter',
      ),
      'cs-cas-api': (
        language: 'csharp',
        group: 'security',
        title: 'Cs cas api',
      ),
      'cs-catch-system-exception': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs catch system exception',
      ),
      'cs-datetime-now': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs datetime now',
      ),
      'cs-dcom-api': (
        language: 'csharp',
        group: 'security',
        title: 'Cs dcom api',
      ),
      'cs-empty-catch': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs empty catch',
      ),
      'cs-explicit-delegate-new': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs explicit delegate new',
      ),
      'cs-file-scoped-namespace': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs file scoped namespace',
      ),
      'cs-hardcoded-secret': (
        language: 'csharp',
        group: 'security',
        title: 'Cs hardcoded secret',
      ),
      'cs-new-httpclient': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs new httpclient',
      ),
      'cs-non-short-circuit-bool': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs non short circuit bool',
      ),
      'cs-process-start-input': (
        language: 'csharp',
        group: 'security',
        title: 'Cs process start input',
      ),
      'cs-public-pinvoke': (
        language: 'csharp',
        group: 'security',
        title: 'Cs public pinvoke',
      ),
      'cs-random-security': (
        language: 'csharp',
        group: 'security',
        title: 'Cs random security',
      ),
      'cs-remoting-api': (
        language: 'csharp',
        group: 'security',
        title: 'Cs remoting api',
      ),
      'cs-runtime-type-alias': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs runtime type alias',
      ),
      'cs-sql-string-build': (
        language: 'csharp',
        group: 'security',
        title: 'Cs sql string build',
      ),
      'cs-string-concat-loop': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs string concat loop',
      ),
      'cs-sync-over-async': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs sync over async',
      ),
      'cs-thread-sleep': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs thread sleep',
      ),
      'cs-using-inside-namespace': (
        language: 'csharp',
        group: 'nim-style',
        title: 'Cs using inside namespace',
      ),
      'cs-weak-crypto': (
        language: 'csharp',
        group: 'security',
        title: 'Cs weak crypto',
      ),
      'css-animation-no-reduced-motion': (
        language: 'css',
        group: 'nim-style',
        title: 'Css animation no reduced motion',
      ),
      'css-duplicate-property': (
        language: 'css',
        group: 'nim-style',
        title: 'Css duplicate property',
      ),
      'css-fixed-font-px': (
        language: 'css',
        group: 'nim-style',
        title: 'Css fixed font px',
      ),
      'css-high-z-index': (
        language: 'css',
        group: 'nim-style',
        title: 'Css high z index',
      ),
      'css-important': (
        language: 'css',
        group: 'nim-style',
        title: 'Css important',
      ),
      'css-selector-depth': (
        language: 'css',
        group: 'nim-style',
        title: 'Css selector depth',
      ),
      'css-universal-selector': (
        language: 'css',
        group: 'nim-style',
        title: 'Css universal selector',
      ),
      'css-vendor-prefix-only': (
        language: 'css',
        group: 'nim-style',
        title: 'Css vendor prefix only',
      ),
      'cycle': (language: 'all', group: 'core', title: 'Break cycle'),
      'dart-analyzer-ignore': (
        language: 'dart',
        group: 'core',
        title: 'Dart analyzer ignore',
      ),
      'dart-blocking-in-async': (
        language: 'dart',
        group: 'core',
        title: 'Dart blocking in async',
      ),
      'dart-broad-catch': (
        language: 'dart',
        group: 'core',
        title: 'Dart broad catch',
      ),
      'dart-dynamic': (language: 'dart', group: 'core', title: 'Dart dynamic'),
      'dart-hardcoded-secret': (
        language: 'dart',
        group: 'core',
        title: 'Dart hardcoded secret',
      ),
      'dart-insecure-random': (
        language: 'dart',
        group: 'core',
        title: 'Dart insecure random',
      ),
      'dart-late-mutable': (
        language: 'dart',
        group: 'core',
        title: 'Dart late mutable',
      ),
      'dart-null-assertion': (
        language: 'dart',
        group: 'core',
        title: 'Dart null assertion',
      ),
      'dart-print': (language: 'dart', group: 'core', title: 'Dart print'),
      'dart-process-shell': (
        language: 'dart',
        group: 'core',
        title: 'Dart process shell',
      ),
      'dead-export': (
        language: 'all',
        group: 'core',
        title: 'Remove dead export',
      ),
      'dead-file': (
        language: 'all',
        group: 'core',
        title: 'Remove or connect file',
      ),
      'duplicate-block': (
        language: 'all',
        group: 'core',
        title: 'Extract shared logic',
      ),
      'feature-flag': (language: 'all', group: 'core', title: 'Review flag'),
      'fixme-comment': (
        language: 'all',
        group: 'suspicious',
        title: 'Fixme comment',
      ),
      'go-defer-in-loop': (
        language: 'go',
        group: 'core',
        title: 'Go defer in loop',
      ),
      'go-http-client-no-timeout': (
        language: 'go',
        group: 'reliability',
        title: 'Go http client no timeout',
      ),
      'go-insecure-tls': (
        language: 'go',
        group: 'security',
        title: 'Go insecure tls',
      ),
      'go-shell-command': (
        language: 'go',
        group: 'security',
        title: 'Go shell command',
      ),
      'go-world-writable': (
        language: 'go',
        group: 'security',
        title: 'Go world writable',
      ),
      'goto-statement': (
        language: 'all',
        group: 'core',
        title: 'Goto statement',
      ),
      'html-blank-no-rel': (
        language: 'html',
        group: 'security',
        title: 'Html blank no rel',
      ),
      'html-duplicate-id': (
        language: 'html',
        group: 'nim-style',
        title: 'Html duplicate id',
      ),
      'html-form-method': (
        language: 'html',
        group: 'nim-style',
        title: 'Html form method',
      ),
      'html-http-resource': (
        language: 'html',
        group: 'security',
        title: 'Html http resource',
      ),
      'html-img-alt': (
        language: 'html',
        group: 'nim-style',
        title: 'Html img alt',
      ),
      'html-inline-event': (
        language: 'html',
        group: 'security',
        title: 'Html inline event',
      ),
      'html-inline-script': (
        language: 'html',
        group: 'security',
        title: 'Html inline script',
      ),
      'html-input-label': (
        language: 'html',
        group: 'nim-style',
        title: 'Html input label',
      ),
      'html-missing-lang': (
        language: 'html',
        group: 'nim-style',
        title: 'Html missing lang',
      ),
      'html-missing-title': (
        language: 'html',
        group: 'nim-style',
        title: 'Html missing title',
      ),
      'html-missing-viewport': (
        language: 'html',
        group: 'nim-style',
        title: 'Html missing viewport',
      ),
      'java-catch-exception': (
        language: 'java',
        group: 'nim-style',
        title: 'Java catch exception',
      ),
      'java-hardcoded-secret': (
        language: 'java',
        group: 'security',
        title: 'Java hardcoded secret',
      ),
      'java-objectinputstream': (
        language: 'java',
        group: 'security',
        title: 'Java objectinputstream',
      ),
      'java-print-stacktrace': (
        language: 'java',
        group: 'nim-style',
        title: 'Java print stacktrace',
      ),
      'java-random-security': (
        language: 'java',
        group: 'security',
        title: 'Java random security',
      ),
      'java-sql-string-build': (
        language: 'java',
        group: 'security',
        title: 'Java sql string build',
      ),
      'java-string-equals': (
        language: 'java',
        group: 'nim-style',
        title: 'Java string equals',
      ),
      'java-system-out': (
        language: 'java',
        group: 'nim-style',
        title: 'Java system out',
      ),
      'java-thread-sleep': (
        language: 'java',
        group: 'nim-style',
        title: 'Java thread sleep',
      ),
      'java-weak-crypto': (
        language: 'java',
        group: 'security',
        title: 'Java weak crypto',
      ),
      'js-node-fs-constant-import': (
        language: 'javascript',
        group: 'core',
        title: 'Js node fs constant import',
      ),
      'large-file': (language: 'all', group: 'core', title: 'Split file'),
      'large-inline-list': (
        language: 'all',
        group: 'suspicious',
        title: 'Large inline list',
      ),
      'large-number-ungrouped': (
        language: 'all',
        group: 'suspicious',
        title: 'Large number ungrouped',
      ),
      'long-function': (language: 'all', group: 'core', title: 'Long function'),
      'long-line': (language: 'all', group: 'core', title: 'Wrap line'),
      'lua-global-assignment': (
        language: 'lua',
        group: 'nim-style',
        title: 'Lua global assignment',
      ),
      'lua-loadstring': (
        language: 'lua',
        group: 'security',
        title: 'Lua loadstring',
      ),
      'lua-mutate-pairs': (
        language: 'lua',
        group: 'nim-style',
        title: 'Lua mutate pairs',
      ),
      'lua-os-execute': (
        language: 'lua',
        group: 'security',
        title: 'Lua os execute',
      ),
      'lua-pcall-swallow': (
        language: 'lua',
        group: 'nim-style',
        title: 'Lua pcall swallow',
      ),
      'lua-print-in-loop': (
        language: 'lua',
        group: 'nim-style',
        title: 'Lua print in loop',
      ),
      'lua-table-alloc-in-loop': (
        language: 'lua',
        group: 'nim-style',
        title: 'Lua table alloc in loop',
      ),
      'near-duplicate-function': (
        language: 'all',
        group: 'core',
        title: 'Near duplicate function',
      ),
      'needless-bool-branch': (
        language: 'all',
        group: 'suspicious',
        title: 'Needless bool branch',
      ),
      'nim-asset-loaded-not-freed': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim asset loaded not freed',
      ),
      'nim-average-openarray-risk': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim average openarray risk',
      ),
      'nim-broad-except': (
        language: 'nim',
        group: 'nim-style',
        title: 'Narrow except',
      ),
      'nim-broad-import': (
        language: 'nim',
        group: 'nim-style',
        title: 'Narrow imports',
      ),
      'nim-camera-transform-leak': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim camera transform leak',
      ),
      'nim-case-on-string': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim case on string',
      ),
      'nim-cast-usage': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim cast usage',
      ),
      'nim-constructor-name': (
        language: 'nim',
        group: 'nim-style',
        title: 'Fix constructor name',
      ),
      'nim-could-be-const': (
        language: 'nim',
        group: 'zerocost',
        title: 'Nim could be const',
      ),
      'nim-cstring-public-api': (
        language: 'nim',
        group: 'nim-style',
        title: 'Use string',
      ),
      'nim-debug-draw-not-gated': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim debug draw not gated',
      ),
      'nim-default-overwrites-context': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim default overwrites context',
      ),
      'nim-distinct-serialization-asymmetry': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim distinct serialization asymmetry',
      ),
      'nim-divide-by-len-without-empty-check': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim divide by len without empty check',
      ),
      'nim-double-negation': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim double negation',
      ),
      'nim-draw-call-in-update': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim draw call in update',
      ),
      'nim-draw-loads-asset': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim draw loads asset',
      ),
      'nim-dt-not-used': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim dt not used',
      ),
      'nim-dynlib-lifetime': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim dynlib lifetime',
      ),
      'nim-dynlib-unchecked-symbol': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim dynlib unchecked symbol',
      ),
      'nim-empty-except-body': (
        language: 'nim',
        group: 'nim-style',
        title: 'Handle or document',
      ),
      'nim-entity-access-after-destroy': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim entity access after destroy',
      ),
      'nim-exec-dynamic-command': (
        language: 'nim',
        group: 'security',
        title: 'Nim exec dynamic command',
      ),
      'nim-exported-object-without-doc': (
        language: 'nim',
        group: 'nim-style',
        title: 'Document exported type',
      ),
      'nim-exported-template-missing-doc': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim exported template missing doc',
      ),
      'nim-float-equality-physics': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim float equality physics',
      ),
      'nim-float-test-exact-equality': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim float test exact equality',
      ),
      'nim-float-tests-missing-edge-cases': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim float tests missing edge cases',
      ),
      'nim-forced-decimal-comma-output': (
        language: 'nim',
        group: 'security',
        title: 'Nim forced decimal comma output',
      ),
      'nim-functional-alloc-chain': (
        language: 'nim',
        group: 'zerocost',
        title: 'Nim functional alloc chain',
      ),
      'nim-game-loop-allocation': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim game loop allocation',
      ),
      'nim-generic-exception-raise': (
        language: 'nim',
        group: 'nim-style',
        title: 'Raise specific error',
      ),
      'nim-generic-hook-cross-module-call': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim generic hook cross module call',
      ),
      'nim-generic-hook-missing-doc': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim generic hook missing doc',
      ),
      'nim-generic-hook-same-signature': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim generic hook same signature',
      ),
      'nim-global-tab-replace': (
        language: 'nim',
        group: 'security',
        title: 'Nim global tab replace',
      ),
      'nim-god-module': (
        language: 'nim',
        group: 'nim-style',
        title: 'Split module',
      ),
      'nim-hardcoded-screen-size': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim hardcoded screen size',
      ),
      'nim-home-dir-strip': (
        language: 'nim',
        group: 'strings',
        title: 'Nim home dir strip',
      ),
      'nim-hook-overwrites-accumulator': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim hook overwrites accumulator',
      ),
      'nim-hook-too-generic': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim hook too generic',
      ),
      'nim-hot-loop-allocation': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim hot loop allocation',
      ),
      'nim-http-case-sensitive-header-compare': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim http case sensitive header compare',
      ),
      'nim-http-header-contains': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim http header contains',
      ),
      'nim-imported-hook-ambiguity-risk': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim imported hook ambiguity risk',
      ),
      'nim-input-in-draw': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim input in draw',
      ),
      'nim-json-heavy-api': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim json heavy api',
      ),
      'nim-large-number-ungrouped': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim large number ungrouped',
      ),
      'nim-large-template': (
        language: 'nim',
        group: 'nim-style',
        title: 'Split template',
      ),
      'nim-layout-assumption-undocumented': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim layout assumption undocumented',
      ),
      'nim-many-exports': (
        language: 'nim',
        group: 'nim-style',
        title: 'Reduce exports',
      ),
      'nim-method-dispatch': (
        language: 'nim',
        group: 'nim-style',
        title: 'Review dispatch',
      ),
      'nim-missing-doc': (
        language: 'nim',
        group: 'nim-style',
        title: 'Add doc comment',
      ),
      'nim-missing-epsilon-distance': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim missing epsilon distance',
      ),
      'nim-missing-raises': (
        language: 'nim',
        group: 'nim-style',
        title: 'Add raises contract',
      ),
      'nim-missing-test-for-module': (
        language: 'nim',
        group: 'nim-style',
        title: 'Add test file',
      ),
      'nim-mutate-while-iterating': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim mutate while iterating',
      ),
      'nim-negated-isnil': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim negated isnil',
      ),
      'nim-nested-stdout-capture': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim nested stdout capture',
      ),
      'nim-nil-component-access': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim nil component access',
      ),
      'nim-no-test-suite': (
        language: 'nim',
        group: 'nim-style',
        title: 'Add test suite',
      ),
      'nim-nonref-inheritance': (
        language: 'nim',
        group: 'nim-style',
        title: 'Use ref or composition',
      ),
      'nim-o-n-squared-collision': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim o n squared collision',
      ),
      'nim-openarray-missing-empty-test': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim openarray missing empty test',
      ),
      'nim-parameter-cluster-spread': (
        language: 'nim',
        group: 'design',
        title: 'Nim parameter cluster spread',
      ),
      'nim-per-frame-string-format': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim per frame string format',
      ),
      'nim-physics-variable-timestep': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim physics variable timestep',
      ),
      'nim-plugin-hook-without-kind': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim plugin hook without kind',
      ),
      'nim-pointer-public-api': (
        language: 'nim',
        group: 'nim-style',
        title: 'Wrap pointer',
      ),
      'nim-pointer-with-separate-size': (
        language: 'nim',
        group: 'zerocost',
        title: 'Nim pointer with separate size',
      ),
      'nim-prefer-let': (language: 'nim', group: 'nim-style', title: 'Use let'),
      'nim-proc-only-plugin-api': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim proc only plugin api',
      ),
      'nim-protocol-split-without-strip': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim protocol split without strip',
      ),
      'nim-public-mutable-container-field': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim public mutable container field',
      ),
      'nim-public-var-scalar-accessor': (
        language: 'nim',
        group: 'nim-style',
        title: 'Encapsulate state',
      ),
      'nim-raises-catchableerror': (
        language: 'nim',
        group: 'nim-style',
        title: 'Narrow raises',
      ),
      'nim-random-in-render': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim random in render',
      ),
      'nim-random-in-simulation': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim random in simulation',
      ),
      'nim-readfile-concat-temp': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim readfile concat temp',
      ),
      'nim-readline-without-strip': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim readline without strip',
      ),
      'nim-redundant-type-init': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim redundant type init',
      ),
      'nim-ref-object-inheritance': (
        language: 'nim',
        group: 'nim-style',
        title: 'Consider composition',
      ),
      'nim-render-state-not-restored': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim render state not restored',
      ),
      'nim-return-instead-of-result': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim return instead of result',
      ),
      'nim-save-in-update': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim save in update',
      ),
      'nim-save-missing-version': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim save missing version',
      ),
      'nim-skip-test-without-comment': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim skip test without comment',
      ),
      'nim-sleep-in-game-loop': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim sleep in game loop',
      ),
      'nim-sound-every-frame': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim sound every frame',
      ),
      'nim-split-recursive-types': (
        language: 'nim',
        group: 'nim-style',
        title: 'Merge type sections',
      ),
      'nim-state-restore-without-finally': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim state restore without finally',
      ),
      'nim-std-import': (
        language: 'nim',
        group: 'nim-style',
        title: 'Use std/ prefix',
      ),
      'nim-string-serializer-missing-quote': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim string serializer missing quote',
      ),
      'nim-strip-chars-string-set': (
        language: 'nim',
        group: 'strings',
        title: 'Nim strip chars string set',
      ),
      'nim-strip-one-sided-wrapper': (
        language: 'nim',
        group: 'strings',
        title: 'Nim strip one sided wrapper',
      ),
      'nim-tainted-exec': (
        language: 'nim',
        group: 'security',
        title: 'Nim tainted exec',
      ),
      'nim-template-body-state-mutation': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim template body state mutation',
      ),
      'nim-test-naming': (
        language: 'nim',
        group: 'nim-style',
        title: 'Rename test file',
      ),
      'nim-too-many-parameters': (
        language: 'nim',
        group: 'design',
        title: 'Nim too many parameters',
      ),
      'nim-tuple-used-as-domain-type': (
        language: 'nim',
        group: 'nim-style',
        title: 'Review tuple modeling',
      ),
      'nim-type-prefix-proc-naming': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Use overloaded proc naming',
      ),
      'nim-unbounded-entity-growth': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim unbounded entity growth',
      ),
      'nim-unordered-table-output': (
        language: 'nim',
        group: 'security',
        title: 'Nim unordered table output',
      ),
      'nim-update-blocking-io': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim update blocking io',
      ),
      'nim-wall-clock-in-update': (
        language: 'nim',
        group: 'game-engine',
        title: 'Nim wall clock in update',
      ),
      'nim-websocket-tests-missing-header-variants': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim websocket tests missing header variants',
      ),
      'nim-websocket-upgrade-fragile': (
        language: 'nim',
        group: 'nim-advanced',
        title: 'Nim websocket upgrade fragile',
      ),
      'nim-while-index-loop': (
        language: 'nim',
        group: 'idiomatic',
        title: 'Nim while index loop',
      ),
      'nim-xml-output-unescaped': (
        language: 'nim',
        group: 'security',
        title: 'Nim xml output unescaped',
      ),
      'operation-on-same-value': (
        language: 'all',
        group: 'suspicious',
        title: 'Operation on same value',
      ),
      'py-assert-runtime': (
        language: 'python',
        group: 'nim-style',
        title: 'Py assert runtime',
      ),
      'py-async-blocking-call': (
        language: 'python',
        group: 'security',
        title: 'Py async blocking call',
      ),
      'py-backslash-continuation': (
        language: 'python',
        group: 'nim-style',
        title: 'Py backslash continuation',
      ),
      'py-bare-except': (
        language: 'python',
        group: 'nim-style',
        title: 'Py bare except',
      ),
      'py-broad-except': (
        language: 'python',
        group: 'nim-style',
        title: 'Py broad except',
      ),
      'py-compound-statement': (
        language: 'python',
        group: 'nim-style',
        title: 'Py compound statement',
      ),
      'py-debug-enabled': (
        language: 'python',
        group: 'security',
        title: 'Py debug enabled',
      ),
      'py-eval-exec': (
        language: 'python',
        group: 'security',
        title: 'Py eval exec',
      ),
      'py-extraneous-whitespace': (
        language: 'python',
        group: 'nim-style',
        title: 'Py extraneous whitespace',
      ),
      'py-function-naming': (
        language: 'python',
        group: 'nim-style',
        title: 'Py function naming',
      ),
      'py-hardcoded-secret': (
        language: 'python',
        group: 'security',
        title: 'Py hardcoded secret',
      ),
      'py-import-not-top': (
        language: 'python',
        group: 'nim-style',
        title: 'Py import not top',
      ),
      'py-logging-exception': (
        language: 'python',
        group: 'nim-style',
        title: 'Py logging exception',
      ),
      'py-multiple-imports': (
        language: 'python',
        group: 'nim-style',
        title: 'Py multiple imports',
      ),
      'py-mutable-default': (
        language: 'python',
        group: 'nim-style',
        title: 'Py mutable default',
      ),
      'py-open-no-encoding': (
        language: 'python',
        group: 'security',
        title: 'Py open no encoding',
      ),
      'py-pickle': (language: 'python', group: 'security', title: 'Py pickle'),
      'py-requests-timeout': (
        language: 'python',
        group: 'security',
        title: 'Py requests timeout',
      ),
      'py-sql-string-build': (
        language: 'python',
        group: 'security',
        title: 'Py sql string build',
      ),
      'py-subprocess-shell': (
        language: 'python',
        group: 'security',
        title: 'Py subprocess shell',
      ),
      'py-tempfile-mktemp': (
        language: 'python',
        group: 'security',
        title: 'Py tempfile mktemp',
      ),
      'py-weak-hash': (
        language: 'python',
        group: 'security',
        title: 'Py weak hash',
      ),
      'py-wildcard-import': (
        language: 'python',
        group: 'nim-style',
        title: 'Py wildcard import',
      ),
      'py-yaml-load': (
        language: 'python',
        group: 'security',
        title: 'Py yaml load',
      ),
      're-export': (language: 'all', group: 'core', title: 'Review re-export'),
      'regex-a-z-range': (
        language: 'all',
        group: 'regex',
        title: 'Regex a z range',
      ),
      'regex-catastrophic-backtracking-risk': (
        language: 'all',
        group: 'regex',
        title: 'Regex catastrophic backtracking risk',
      ),
      'regex-empty-alternative': (
        language: 'all',
        group: 'regex',
        title: 'Regex empty alternative',
      ),
      'regex-invalid': (
        language: 'all',
        group: 'regex',
        title: 'Regex invalid',
      ),
      'regex-leading-dot-star': (
        language: 'all',
        group: 'regex',
        title: 'Regex leading dot star',
      ),
      'regex-repeated-compile': (
        language: 'all',
        group: 'regex',
        title: 'Regex repeated compile',
      ),
      'regex-single-literal': (
        language: 'all',
        group: 'regex',
        title: 'Regex single literal',
      ),
      'regex-unanchored-validation': (
        language: 'all',
        group: 'regex',
        title: 'Regex unanchored validation',
      ),
      'repeated-condition': (
        language: 'all',
        group: 'design',
        title: 'Repeated condition',
      ),
      'single-use-trivial-wrapper': (
        language: 'all',
        group: 'yagni',
        title: 'Single use trivial wrapper',
      ),
      'sql-case-sensitive-like': (
        language: 'sql',
        group: 'sql',
        title: 'Sql case sensitive like',
      ),
      'sql-add-not-null-default': (
        language: 'sql',
        group: 'core',
        title: 'Sql add not null default',
      ),
      'sql-create-index-nonconcurrent': (
        language: 'sql',
        group: 'core',
        title: 'Sql create index nonconcurrent',
      ),
      'sql-leading-wildcard-like': (
        language: 'sql',
        group: 'core',
        title: 'Sql leading wildcard like',
      ),
      'sql-delete-without-where': (
        language: 'sql',
        group: 'sql',
        title: 'Sql delete without where',
      ),
      'sql-drop-table-without-if-exists': (
        language: 'sql',
        group: 'sql',
        title: 'Sql drop table without if exists',
      ),
      'sql-inline-string-concat': (
        language: 'sql',
        group: 'sql',
        title: 'Sql inline string concat',
      ),
      'sql-not-in-subquery-null-risk': (
        language: 'sql',
        group: 'sql',
        title: 'Sql not in subquery null risk',
      ),
      'sql-select-star': (
        language: 'sql',
        group: 'sql',
        title: 'Sql select star',
      ),
      'sql-update-without-where': (
        language: 'sql',
        group: 'sql',
        title: 'Sql update without where',
      ),
      'structure-missing-required-dir': (
        language: 'all',
        group: 'core',
        title: 'Structure missing required dir',
      ),
      'structure-missing-source-root': (
        language: 'all',
        group: 'core',
        title: 'Structure missing source root',
      ),
      'structure-top-level-file': (
        language: 'all',
        group: 'core',
        title: 'Structure top level file',
      ),
      'suspicious-command-arg-space': (
        language: 'all',
        group: 'suspicious',
        title: 'Suspicious command arg space',
      ),
      'tab-indent': (language: 'all', group: 'core', title: 'Replace tabs'),
      'todo-comment': (
        language: 'all',
        group: 'suspicious',
        title: 'Todo comment',
      ),
      'trailing-whitespace': (
        language: 'all',
        group: 'core',
        title: 'Trim whitespace',
      ),
      'ts-any': (language: 'typescript', group: 'nim-style', title: 'Ts any'),
      'ts-await-in-loop': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts await in loop',
      ),
      'ts-console': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts console',
      ),
      'ts-debugger': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts debugger',
      ),
      'ts-eval': (language: 'typescript', group: 'security', title: 'Ts eval'),
      'ts-floating-promise': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts floating promise',
      ),
      'ts-hardcoded-secret': (
        language: 'typescript',
        group: 'security',
        title: 'Ts hardcoded secret',
      ),
      'ts-inner-html': (
        language: 'typescript',
        group: 'security',
        title: 'Ts inner html',
      ),
      'ts-json-parse-unsafe': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts json parse unsafe',
      ),
      'ts-localstorage-json': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts localstorage json',
      ),
      'ts-non-null-assertion': (
        language: 'typescript',
        group: 'nim-style',
        title: 'Ts non null assertion',
      ),
      'unused-customization-hook': (
        language: 'all',
        group: 'yagni',
        title: 'Unused customization hook',
      ),
      'unused-generic-parameter': (
        language: 'all',
        group: 'yagni',
        title: 'Remove speculative generic parameter',
      ),
      'wren-broad-import': (
        language: 'wren',
        group: 'nim-style',
        title: 'Wren broad import',
      ),
      'wren-fiber-abort': (
        language: 'wren',
        group: 'security',
        title: 'Wren fiber abort',
      ),
      'wren-fiber-call': (
        language: 'wren',
        group: 'nim-style',
        title: 'Wren fiber call',
      ),
      'wren-foreign-boundary': (
        language: 'wren',
        group: 'security',
        title: 'Wren foreign boundary',
      ),
      'wren-inheritance': (
        language: 'wren',
        group: 'nim-style',
        title: 'Wren inheritance',
      ),
      'wren-number-parse-unchecked': (
        language: 'wren',
        group: 'nim-style',
        title: 'Wren number parse unchecked',
      ),
      'wren-print-in-loop': (
        language: 'wren',
        group: 'nim-style',
        title: 'Wren print in loop',
      ),
      'wren-system-print': (
        language: 'wren',
        group: 'nim-style',
        title: 'Wren system print',
      ),
    };
