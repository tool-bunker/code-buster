// Some Nim rules inherited carefully reviewed rationale and remediation text that must remain stable across implementation refactors.

/// Canonical fixed rationale and suggestion text for exercised Nim rules.
const Map<String, ({String why, String suggestion})>
canonicalNimEvidence = <String, ({String why, String suggestion})>{
  'nim-asset-loaded-not-freed': (
    why:
        'Assets loaded without unloading can leak GPU/memory resources over time.',
    suggestion:
        'Add unload/free/release calls for loaded assets, or document the lifecycle.',
  ),
  'nim-average-openarray-risk': (
    why:
        'Average over openArray is deceptively tricky: empty input, integer division, accumulator overflow, and result type all matter.',
    suggestion:
        'Guard empty input, use a suitable accumulator/result type, and add tests for empty/large/negative inputs.',
  ),
  'nim-broad-except': (
    why: 'Broad handlers can hide IO, parsing, and programmer errors.',
    suggestion:
        'Catch specific exceptions such as IOError, ValueError, or OSError.',
  ),
  'nim-broad-import': (
    why: 'Very broad import groups make dependencies harder to scan.',
    suggestion: 'Split imports by concern or remove unused modules.',
  ),
  'nim-camera-transform-leak': (
    why:
        'Camera transforms left modified can corrupt the next frame\'s rendering.',
    suggestion: 'Reset/restore the camera transform before the draw proc ends.',
  ),
  'nim-cast-usage': (
    why:
        'cast bypasses the type system and can cause undefined behavior if the types don\'t actually match. C programmers use it from habit, but Nim usually has safer alternatives.',
    suggestion:
        'Use type conversion procs, `typeof`, or design types to avoid needing cast.',
  ),
  'nim-could-be-const': (
    why:
        'Const values are evaluated at compile time and never enter runtime memory, which matters for constrained targets and avoids unnecessary runtime allocation.',
    suggestion:
        'Use `const` instead of `let` for compile-time-known literal values.',
  ),
  'nim-debug-draw-not-gated': (
    why:
        'Debug overlays left ungated can ship accidentally and waste frame time.',
    suggestion: 'Gate debug drawing behind a debug/showDebug/profiler flag.',
  ),
  'nim-distinct-serialization-asymmetry': (
    why:
        'One-way serialization hooks can surprise callers when round-tripping data from JSON or other formats.',
    suggestion:
        'Add the matching parse/decode hook or document that the conversion is intentionally one-way.',
  ),
  'nim-divide-by-len-without-empty-check': (
    why:
        'Dividing by len can fail or produce invalid numeric results when the input is empty.',
    suggestion:
        'Check len == 0 first, raise a specific error, or return Option/Result for empty input.',
  ),
  'nim-draw-call-in-update': (
    why:
        'Drawing in update mixes simulation and rendering; some engines ignore draw calls outside the draw phase.',
    suggestion: 'Move rendering to the draw proc and pass state from update.',
  ),
  'nim-draw-loads-asset': (
    why:
        'Loading textures/images/sounds/fonts during rendering can stall frames and leak resources if repeated.',
    suggestion:
        'Load assets during initialization and reuse handles in draw/render.',
  ),
  'nim-entity-access-after-destroy': (
    why:
        'Accessing fields of a destroyed entity can read stale or invalid data.',
    suggestion:
        'Check alive/dead status before accessing, or remove the entity first.',
  ),
  'nim-exec-dynamic-command': (
    why:
        'Dynamically concatenated shell/process commands are harder to quote safely and easier to misuse.',
    suggestion:
        'Prefer execProcess/startProcess with an args sequence and quoteShell for unavoidable shell fragments.',
  ),
  'nim-exported-object-without-doc': (
    why:
        'Public model types should have doc comments so callers understand the semantic role of the type and its fields.',
    suggestion: 'Add a ## doc comment above the exported type declaration.',
  ),
  'nim-exported-template-missing-doc': (
    why:
        'Public templates often define DSL/control-flow behavior that is harder to infer than ordinary procs.',
    suggestion:
        'Add a ## doc comment describing body execution, side effects, and expected usage.',
  ),
  'nim-float-test-exact-equality': (
    why:
        'Floating-point operations often require tolerance-based assertions due to rounding and platform differences.',
    suggestion:
        'Use an epsilon/tolerance comparison, except for deliberate NaN/Inf/sign-bit checks.',
  ),
  'nim-float-tests-missing-edge-cases': (
    why:
        'Numeric APIs should document or test NaN, infinity, signed zero, overflow/underflow, and tolerance behavior where relevant.',
    suggestion:
        'Add tests/docs for NaN, ±Inf, ±0.0, extremes, and precision tolerance.',
  ),
  'nim-hardcoded-screen-size': (
    why: 'Hardcoded screen sizes make resolution scaling and porting harder.',
    suggestion: 'Use config/settings values for screen dimensions.',
  ),
  'nim-hook-overwrites-accumulator': (
    why:
        'Mutable string hook parameters often contain already-serialized output; assigning replaces prior content.',
    suggestion:
        'Append with add or a quoting/escaping helper instead of assigning to the accumulator.',
  ),
  'nim-input-in-draw': (
    why:
        'Input should be processed in update, not draw; mixing them couples rendering to input timing.',
    suggestion:
        'Move input handling to the update proc and pass results to draw.',
  ),
  'nim-missing-doc': (
    why:
        'Exported symbols should have ## doc comments for nim doc and API discoverability.',
    suggestion:
        'Add a ## doc comment above or inline with the proc declaration.',
  ),
  'nim-missing-raises': (
    why:
        '{.raises.} contracts help document and enforce exception safety for exported procs.',
    suggestion:
        'Add {.raises: [SpecificError].} or {.raises: [].} if the proc cannot raise.',
  ),
  'nim-missing-test-for-module': (
    why:
        'A matching test file is a simple convention that improves module-level coverage discoverability.',
    suggestion:
        'Add tests/test_models.nim or include this module in an existing focused test suite.',
  ),
  'nim-nil-component-access': (
    why:
        'Component lookups can return nil; using the result without checking can crash.',
    suggestion: 'Check the result for nil before accessing fields.',
  ),
  'nim-openarray-missing-empty-test': (
    why: 'openArray APIs should define behavior for empty input explicitly.',
    suggestion:
        'Add tests/docs for empty input and either reject it or return an explicit empty result.',
  ),
  'nim-per-frame-string-format': (
    why:
        'Building strings every frame (e.g. debug HUD text) causes per-frame allocation.',
    suggestion: 'Cache formatted strings and update them at a lower frequency.',
  ),
  'nim-physics-variable-timestep': (
    why:
        'Variable timestep physics can be unstable and non-deterministic at different frame rates.',
    suggestion: 'Use a fixed timestep accumulator for physics integration.',
  ),
  'nim-prefer-let': (
    why: 'Nim style prefers let for values that do not change within scope.',
    suggestion: 'Use let unless the variable is reassigned or mutated.',
  ),
  'nim-ref-object-inheritance': (
    why:
        'Nim inheritance is optional; composition is often simpler and just as efficient for reuse.',
    suggestion:
        'Keep inheritance for true polymorphism/type hierarchies; otherwise compose fields.',
  ),
  'nim-render-state-not-restored': (
    why:
        'Begin scissor/clip/canvas/blend calls without matching end/restore can corrupt subsequent rendering.',
    suggestion:
        'Ensure every begin* has a matching end*/restore in the same proc.',
  ),
  'nim-return-instead-of-result': (
    why:
        'Using `result = value` instead of `return value` makes the return value trackable throughout the proc and is more idiomatic Nim. Save `return` for early exits.',
    suggestion:
        'Use `result = value` for the final return and `return` only for control flow.',
  ),
  'nim-save-missing-version': (
    why:
        'Save formats without a version field are hard to migrate when the format changes.',
    suggestion:
        'Add a "version" field to saved data for forward/backward compatibility.',
  ),
  'nim-sound-every-frame': (
    why: 'Playing sound every frame while a key is held creates audio spam.',
    suggestion: 'Gate playback with a key-pressed/trigger edge or a cooldown.',
  ),
  'nim-split-recursive-types': (
    why:
        'Nim mutually recursive object/ref types need to be declared in one type section.',
    suggestion:
        'Merge the mutually recursive declarations into a single type block.',
  ),
  'nim-state-restore-without-finally': (
    why: 'If the body raises, state restoration after the body may never run.',
    suggestion:
        'Wrap body execution with try/finally or use defer immediately after changing state.',
  ),
  'nim-std-import': (
    why:
        'Nim style prefers std/os or std/[os, strutils] for standard-library modules.',
    suggestion:
        'Use std/module for one stdlib import or std/[a, b] for grouped imports.',
  ),
  'nim-tainted-exec': (
    why:
        'Taint-style source/sink checks catch values from input/environment being used in command execution.',
    suggestion:
        'Pass values as argv entries where possible, validate them, and quote unavoidable shell fragments.',
  ),
  'nim-template-body-state-mutation': (
    why:
        'Templates that change context/global state around a user body need exception-safe restoration.',
    suggestion:
        'Use defer/try-finally to restore state and document nested behavior.',
  ),
  'nim-too-many-parameters': (
    why:
        'Functions with many parameters are hard to read, call, and maintain. Consider grouping related parameters into a single object/tuple type.',
    suggestion:
        'Introduce a parameter object for related parameter clusters, or split the proc\'s responsibilities.',
  ),
  'nim-tuple-used-as-domain-type': (
    why:
        'Named tuples are handy for transient grouping, but exported/domain data models are often clearer and safer as objects with distinct nominal types.',
    suggestion:
        'Use an object when the type represents a stable domain model or long-lived public API shape.',
  ),
  'nim-unordered-table-output': (
    why:
        'Hash-table iteration order is not a stable output contract and can make reports, manifests, or snapshots nondeterministic.',
    suggestion:
        'Sort `table.keys.toSeq()` before emitting output, or use OrderedTable when insertion order is the intended contract.',
  ),
  'nim-update-blocking-io': (
    why:
        'Blocking filesystem/network/process work inside frame loops can freeze rendering or input.',
    suggestion:
        'Move IO to load/save screens, background jobs, or explicit user-triggered actions.',
  ),
};
