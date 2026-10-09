// Rust boundary rules combine shared lexical facts with structural ownership instead of reporting isolated words.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';
import '../../languages/rust/rust_analysis.dart';

abstract base class RustStructuredRule extends SelfContainedRule {
  RustStructuredRule(
    String id,
    RuleSeverity severity,
    String group,
    String title,
    String why,
    String suggestion,
    FindingTaxonomy taxonomy, {
    RuleSemanticMaturity maturity = RuleSemanticMaturity.token,
    Set<RuleAnalysisRequirement> requirements = const <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.tokens,
    },
    int version = 2,
    SecurityFindingKind securityKind = SecurityFindingKind.none,
    List<String> limitations = const <String>[],
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: group,
           title: title,
           why: why,
           suggestion: suggestion,
           version: version,
           semanticMaturity: maturity,
           requirements: requirements,
           taxonomy: <FindingTaxonomy>{taxonomy},
           securityKind: securityKind,
           languages: const <String>['rust'],
           limitations: limitations,
         ),
       );

  RustAnalysis analysis(RuleContext context) =>
      context.languageAnalysis is RustAnalysis
      ? context.languageAnalysis! as RustAnalysis
      : RustAnalysis(context.sources);

  bool excluded(RustFileAnalysis file, int offset) =>
      file.testLines.contains(file.lineAt(offset) - 1);
}

final class RustUndocumentedUnsafeBlockRule extends RustStructuredRule {
  RustUndocumentedUnsafeBlockRule()
    : super(
        'rust-undocumented-unsafe-block',
        RuleSeverity.warn,
        'core',
        'Document Rust unsafe invariants',
        'Unsafe blocks transfer memory, aliasing, and lifetime obligations from the compiler to maintainers.',
        'Add an attached SAFETY comment that states the invariants making the block sound.',
        FindingTaxonomy.reliability,
        version: 3,
        limitations: const <String>[
          'The rule verifies that a nonempty SAFETY rationale is attached, not that the rationale proves soundness.',
          'Macro-generated unsafe blocks are not visible in source text.',
        ],
      );

  static final RegExp _unsafe = cachedRegExp(r'\bunsafe\s*\{');

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      for (final RegExpMatch match in _unsafe.allMatches(entry.value.masked)) {
        final int open = entry.value.masked.indexOf('{', match.start);
        if (excluded(entry.value, match.start) ||
            entry.value.hasSafetyRationale(match.start, open)) {
          continue;
        }
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(match.start),
          message: 'unsafe block has no attached SAFETY rationale',
          confidence: 'high',
        );
      }
    }
  }
}

final class RustStaticMutRule extends RustStructuredRule {
  RustStaticMutRule()
    : super(
        'rust-static-mut',
        RuleSeverity.warn,
        'core',
        'Avoid mutable Rust statics',
        'A mutable static permits aliased unsynchronized global mutation behind unsafe access.',
        'Use an atomic, Mutex, RwLock, OnceLock, or immutable initialization.',
        FindingTaxonomy.reliability,
        limitations: const <String>[
          'The declaration is reported as a review boundary; the rule does not prove an access is unsound.',
        ],
      );

  static final RegExp _declaration = cachedRegExp(
    r'\bstatic\s+mut\s+[A-Za-z_]\w*',
    multiLine: true,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      for (final RegExpMatch match in _declaration.allMatches(
        entry.value.masked,
      )) {
        if (excluded(entry.value, match.start)) continue;
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(match.start),
          message: 'mutable static requires unsafe synchronization discipline',
          confidence: 'high',
        );
      }
    }
  }
}

final class RustRawOwnershipReconstructionRule extends RustStructuredRule {
  RustRawOwnershipReconstructionRule()
    : super(
        'rust-raw-ownership-reconstruction',
        RuleSeverity.warn,
        'core',
        'Review Rust raw ownership reconstruction',
        'Reconstructing an owner from a raw pointer requires matching provenance, allocator, layout, and exactly-once ownership.',
        'Keep the transfer local and document the originating into_raw contract, allocator, layout, and unique ownership.',
        FindingTaxonomy.reliability,
        limitations: const <String>[
          'The rule cannot prove pointer provenance, allocator compatibility, uniqueness, or lifetime correctness.',
          'Aliases and wrapper functions around ownership reconstruction are not resolved.',
        ],
      );

  static final RegExp _reconstruction = cachedRegExp(
    r'\b(?:(?:std|alloc)::(?:boxed::Box|vec::Vec|string::String|ffi::CString|rc::Rc|sync::Arc)|Box|Vec|String|CString|Rc|Arc)::from_raw(?:_parts)?\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      for (final RegExpMatch match in _reconstruction.allMatches(
        entry.value.masked,
      )) {
        if (excluded(entry.value, match.start)) continue;
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(match.start),
          message: 'raw pointer is converted back into an owning Rust value',
          confidence: 'high',
        );
      }
    }
  }
}

final class RustManualSendSyncImplRule extends RustStructuredRule {
  RustManualSendSyncImplRule()
    : super(
        'rust-manual-send-sync-impl',
        RuleSeverity.warn,
        'core',
        'Document manual Rust Send and Sync contracts',
        'A manual Send or Sync implementation asserts thread-safety properties the compiler could not derive.',
        'Attach a SAFETY rationale covering every field, generic bound, aliasing invariant, and thread-affinity constraint.',
        FindingTaxonomy.reliability,
        limitations: const <String>[
          'The rule verifies documentation presence and cannot prove the implementation is sound.',
          'Send and Sync implementations separated by unrelated items are reported independently.',
        ],
      );

  static final RegExp _implementation = cachedRegExp(
    r'\bunsafe\s+impl(?:\s*<[^>{}]*>)?[^{};]*?\b(Send|Sync)\s+for\s+([A-Za-z_]\w*)',
    multiLine: true,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      final Set<String> reported = <String>{};
      for (final RegExpMatch match in _implementation.allMatches(
        entry.value.masked,
      )) {
        if (excluded(entry.value, match.start)) continue;
        final int open = entry.value.masked.indexOf('{', match.end);
        if (entry.value.hasSafetyRationale(match.start, open)) continue;
        final String key = match.requiredGroup(2);
        if (!reported.add(key)) continue;
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(match.start),
          message:
              'manual ${match.requiredGroup(1)} implementation has no attached SAFETY rationale',
          confidence: 'high',
        );
      }
    }
  }
}

final class RustCommandShellRule extends RustStructuredRule {
  RustCommandShellRule()
    : super(
        'rust-command-shell',
        RuleSeverity.warn,
        'security',
        'Review Rust command-string shell execution',
        'A shell command-string boundary interprets metacharacters and can turn untrusted data into commands.',
        'Invoke the target executable directly with separately supplied arguments.',
        FindingTaxonomy.security,
        version: 6,
        securityKind: SecurityFindingKind.hotspot,
        limitations: const <String>[
          'The rule recognizes literal shell executables and command-string switches in one builder expression.',
          'It does not resolve variables that contain a shell executable or follow a builder across statements.',
        ],
      );

  static final RegExp _shell = cachedRegExp(
    r'''\bCommand::new\s*\(\s*["'](?:/bin/|/usr/bin/)?(sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)["']\s*\)''',
    caseSensitive: false,
  );
  static final RegExp _posixSwitch = cachedRegExp(
    r'''\.arg\s*\(\s*["']-c["']\s*\)''',
  );
  static final RegExp _cmdSwitch = cachedRegExp(
    r'''\.arg\s*\(\s*["']/[cC]["']\s*\)''',
  );
  static final RegExp _powerShellSwitch = cachedRegExp(
    r'''\.arg\s*\(\s*["']-(?:Command|EncodedCommand)["']\s*\)''',
    caseSensitive: false,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      final String code = entry.value.commentsMasked;
      for (final RegExpMatch match in _shell.allMatches(code)) {
        if (excluded(entry.value, match.start)) continue;
        final int statementEnd = code.indexOf(';', match.end);
        final int stop = statementEnd == -1
            ? (match.end + 600).clamp(0, code.length)
            : statementEnd + 1;
        final String builder = code.substring(match.start, stop);
        final String shell = match.requiredGroup(1).toLowerCase();
        final bool hasSwitch = switch (shell) {
          'sh' || 'bash' || 'zsh' => _posixSwitch.hasMatch(builder),
          'cmd' || 'cmd.exe' => _cmdSwitch.hasMatch(builder),
          _ => _powerShellSwitch.hasMatch(builder),
        };
        if (!hasSwitch) continue;
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(match.start),
          message: 'shell interpreter executes a command string',
          confidence: 'high',
        );
      }
    }
  }
}

final class RustPanicAcrossFfiBoundaryRule extends RustStructuredRule {
  RustPanicAcrossFfiBoundaryRule()
    : super(
        'rust-panic-across-ffi-boundary',
        RuleSeverity.warn,
        'core',
        'Contain panics at exported Rust FFI boundaries',
        'A panic escaping a non-unwind foreign ABI can abort the process or violate the caller contract.',
        'Convert failures to an ABI-safe result and contain Rust panics with catch_unwind where unwinding is possible.',
        FindingTaxonomy.reliability,
        maturity: RuleSemanticMaturity.ast,
        requirements: const <RuleAnalysisRequirement>{
          RuleAnalysisRequirement.functions,
        },
        limitations: const <String>[
          'Only explicit panic-capable sites in the exported function body are detected; indirect panics through callees are not resolved.',
          'catch_unwind recognition is structural and does not prove that every panic path is contained.',
        ],
      );

  static final RegExp _function = cachedRegExp(
    r'''(?:(?:#\s*\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name)[^\]]*\]\s*)+)?(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?extern\s+"(C|system|cdecl|stdcall|fastcall)"\s+fn\s+([A-Za-z_]\w*)[^;{]*\{''',
    multiLine: true,
  );
  static final RegExp _exportAttribute = cachedRegExp(
    r'#\s*\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name)',
  );
  static final RegExp _publicExtern = cachedRegExp(
    r'\bpub(?:\([^)]*\))?\s+(?:unsafe\s+)?extern\b',
  );
  static final RegExp _panicSite = cachedRegExp(
    r'\b(?:panic|todo|unimplemented|unreachable|assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)!\s*\(|\.(?:unwrap|expect)\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      for (final RegExpMatch function in _function.allMatches(
        entry.value.commentsMasked,
      )) {
        if (excluded(entry.value, function.start)) continue;
        final String header = entry.value.commentsMasked.substring(
          function.start,
          function.end,
        );
        if (!_exportAttribute.hasMatch(header) &&
            !_publicExtern.hasMatch(header)) {
          continue;
        }
        final int open = entry.value.masked.indexOf('{', function.start);
        final int close = entry.value.matchingBrace(open);
        if (close == -1) continue;
        final String body = entry.value.masked.substring(open + 1, close);
        final RegExpMatch? panic = _panicSite
            .allMatches(body)
            .where(
              (RegExpMatch candidate) => !_insideCatchUnwind(
                entry.value,
                open + 1,
                open + 1 + candidate.start,
              ),
            )
            .firstOrNull;
        if (panic == null) continue;
        final int panicOffset = open + 1 + panic.start;
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(panicOffset),
          message:
              'exported ${function.requiredGroup(1)} ABI function ${function.requiredGroup(2)} contains an explicit panic path',
          confidence: 'high',
        );
      }
    }
  }

  bool _insideCatchUnwind(
    RustFileAnalysis file,
    int bodyStart,
    int panicOffset,
  ) {
    final RegExp catchUnwind = cachedRegExp(r'\bcatch_unwind\s*\(');
    for (final RegExpMatch match in catchUnwind.allMatches(
      file.masked,
      bodyStart,
    )) {
      if (match.start >= panicOffset) break;
      final int open = file.masked.indexOf('(', match.start);
      final int close = file.matchingParenthesis(open);
      if (open < panicOffset && close >= panicOffset) return true;
    }
    return false;
  }
}

final class RustBlockingCallInAsyncRule extends RustStructuredRule {
  RustBlockingCallInAsyncRule()
    : super(
        'rust-blocking-call-in-async',
        RuleSeverity.warn,
        'performance',
        'Keep blocking Rust APIs off async executors',
        'Blocking an executor thread delays unrelated tasks and can exhaust the runtime under load.',
        'Use the runtime-native async API or move blocking work to spawn_blocking, unblock, or a dedicated thread.',
        FindingTaxonomy.performance,
        maturity: RuleSemanticMaturity.ast,
        requirements: const <RuleAnalysisRequirement>{
          RuleAnalysisRequirement.functions,
        },
        limitations: const <String>[
          'Only fully qualified known-blocking APIs are recognized; aliases and wrappers require type resolution.',
          'Runtime scheduling and actual operation cost are not inferred.',
        ],
      );

  static final RegExp _asyncScope = cachedRegExp(
    r'\basync\s+(?:move\s+)?(?:fn\s+[A-Za-z_]\w*[^;{]*|)\{',
    multiLine: true,
  );
  static final RegExp _blocking = cachedRegExp(
    r'\b(?:std::thread::sleep|reqwest::blocking(?:::[A-Za-z_]\w*)?|std::fs::(?:read|read_to_string|write|copy|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename)|std::process::Command::new)\s*\(',
  );
  static final RegExp _offload = cachedRegExp(
    r'\b(?:tokio::task::spawn_blocking|async_std::task::spawn_blocking|smol::unblock)\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      for (final RegExpMatch scope in _asyncScope.allMatches(
        entry.value.masked,
      )) {
        if (excluded(entry.value, scope.start)) continue;
        final int open = entry.value.masked.indexOf('{', scope.start);
        final int close = entry.value.matchingBrace(open);
        if (close == -1) continue;
        final String body = entry.value.masked.substring(open + 1, close);
        for (final RegExpMatch call in _blocking.allMatches(body)) {
          final int absolute = open + 1 + call.start;
          if (_insideOffload(entry.value, open + 1, absolute)) continue;
          yield report(
            context,
            path: entry.key,
            line: entry.value.lineAt(absolute),
            message: 'known blocking API is called directly from async code',
            confidence: 'high',
          );
        }
      }
    }
  }

  bool _insideOffload(RustFileAnalysis file, int scopeStart, int callOffset) {
    for (final RegExpMatch match in _offload.allMatches(
      file.masked,
      scopeStart,
    )) {
      if (match.start >= callOffset) break;
      final int open = file.masked.indexOf('(', match.start);
      final int blockOpen = file.masked.indexOf('{', open);
      if (blockOpen == -1 || blockOpen > callOffset) continue;
      final int blockClose = file.matchingBrace(blockOpen);
      if (blockClose >= callOffset) return true;
    }
    return false;
  }
}

final class RustUnboundedChannelRule extends RustStructuredRule {
  RustUnboundedChannelRule()
    : super(
        'rust-unbounded-channel',
        RuleSeverity.info,
        'performance',
        'Bound Rust channel capacity',
        'An unbounded producer can grow queued messages until the process exhausts memory.',
        'Use a bounded channel with an explicit capacity or document the finite producer invariant.',
        FindingTaxonomy.reliability,
        limitations: const <String>[
          'The rule cannot infer producer rate, message size, consumer throughput, or process lifetime.',
        ],
      );

  static final RegExp _channel = cachedRegExp(
    r'\b(?:tokio::sync::mpsc::unbounded_channel|async_channel::unbounded|crossbeam_channel::unbounded|std::sync::mpsc::channel)\s*(?:::<[^;{}()]*>)?\s*\(',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, RustFileAnalysis> entry in analysis(
      context,
    ).files.entries) {
      for (final RegExpMatch match in _channel.allMatches(entry.value.masked)) {
        if (excluded(entry.value, match.start)) continue;
        yield report(
          context,
          path: entry.key,
          line: entry.value.lineAt(match.start),
          message: 'unbounded channel permits unlimited queued messages',
          confidence: 'high',
        );
      }
    }
  }
}
