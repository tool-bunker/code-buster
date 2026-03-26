// Nim APIs with runtime cost or lifecycle implications need stateful checks that follow calls beyond a single token pattern.

import '../../core/models.dart';
import 'canonical_nim_evidence.dart';
import 'nim_security_line_rule_pack.dart';

part 'nim_runtime_simulation_rules.dart';

/// Executes stateful runtime, performance, security, and game-engine rules.
final class NimRuntimeRulePack {
  static final RegExp _entityLifecycleMutation = RegExp(
    r'\.(?:alive\s*=\s*false|dead\s*=\s*true|destroyed\s*=\s*true|active\s*=\s*false)',
  );

  /// Creates runtime state for one file.
  NimRuntimeRulePack(String source) : fileLower = source.toLowerCase();

  /// Mutable state retained across lines in this file.
  final String fileLower;
  final NimSecurityLineRulePack _security = NimSecurityLineRulePack();

  /// Mutable state retained across lines in this file.
  final List<int> loopIndents = <int>[];

  /// Mutable state retained across lines in this file.
  final List<int> hotProcIndents = <int>[];

  /// Mutable state retained across lines in this file.
  final List<int> drawProcIndents = <int>[];

  /// Mutable state retained across lines in this file.
  final List<({String name, int indent})> loopCollections =
      <({String name, int indent})>[];

  /// Mutable state retained across lines in this file.
  int renderBeginCount = 0;

  /// Mutable state retained across lines in this file.
  int renderEndCount = 0;

  /// Mutable state retained across lines in this file.
  int renderProcLine = 1;

  /// Mutable state retained across lines in this file.
  final Set<String> destroyedEntities = <String>{};

  /// Mutable state retained across lines in this file.
  bool cameraModified = false;

  /// Mutable state retained across lines in this file.
  bool cameraRestored = false;

  /// Mutable state retained across lines in this file.
  int cameraProcLine = 1;

  /// Mutable state retained across lines in this file.
  int assetLoadCount = 0;

  /// Mutable state retained across lines in this file.
  int assetFreeCount = 0;

  /// Mutable state retained across lines in this file.
  bool floatEdgeFindingAdded = false;

  /// Mutable state retained across lines in this file.
  final List<({int line, Set<String> params})> procParameters =
      <({int line, Set<String> params})>[];

  /// Processes one line and returns findings emitted at that line.
  List<Finding> analyzeLine({
    required String path,
    required String source,
    required List<String> lines,
    required int index,
    required String raw,
    required String line,
    required String lower,
  }) {
    final context = _NimRuntimeLineContext(
      path: path,
      source: source,
      lines: lines,
      index: index,
      raw: raw,
      line: line,
      lower: lower,
    );
    _analyzeProcedureState(context);
    _analyzeLoopPerformance(context);
    _analyzeLifecycle(context);
    _analyzeRendering(context);
    _analyzeSimulation(context);
    _analyzeDrawAndParameters(context);
    return context.result;
  }

  void _analyzeProcedureState(_NimRuntimeLineContext context) {
    final List<Finding> result = context.result;
    final String path = context.path;
    final List<String> lines = context.lines;
    final int index = context.index;
    final String raw = context.raw;
    final String line = context.line;
    final String lower = context.lower;
    final int indent = raw.length - raw.trimLeft().length;
    result.addAll(
      _security.analyzeLine(
        path: path,
        lines: lines,
        index: index,
        line: line,
        indent: indent,
      ),
    );
    while (loopIndents.isNotEmpty && indent <= loopIndents.last) {
      loopIndents.removeLast();
    }
    while (hotProcIndents.isNotEmpty && indent <= hotProcIndents.last) {
      hotProcIndents.removeLast();
    }
    while (drawProcIndents.isNotEmpty && indent <= drawProcIndents.last) {
      drawProcIndents.removeLast();
    }
    while (loopCollections.isNotEmpty &&
        indent <= loopCollections.last.indent) {
      loopCollections.removeLast();
    }
    final bool procDeclaration =
        line.startsWith('proc ') || line.startsWith('func ');
    if (procDeclaration) {
      final String procBody = lines
          .skip(index + 1)
          .takeWhile(
            (String next) =>
                next.trim().isEmpty ||
                next.length - next.trimLeft().length > indent,
          )
          .join('\n')
          .toLowerCase();
      if (lower.contains('average') && lower.contains('openarray')) {
        context.add(
          'nim-average-openarray-risk',
          RuleSeverity.warn,
          'average-like openArray API needs edge-case handling',
        );
      }
      final bool hasDt =
          (lower.contains('dt:') || lower.contains('delta')) &&
          !lower.contains('_dt:') &&
          !lower.contains('_delta');
      if (hasDt &&
          RegExp(r'update|render|draw|tick|fixedupdate').hasMatch(lower) &&
          !RegExp(r'\bdt\b|delta').hasMatch(procBody)) {
        context.add(
          'nim-dt-not-used',
          RuleSeverity.info,
          'update-like proc accepts dt but does not appear to use it',
          confidence: 'low',
        );
      }
      if (!floatEdgeFindingAdded &&
          line.contains('*') &&
          RegExp(r'float|pow|sqrt|ln\(|exp\(').hasMatch(lower) &&
          !RegExp(
            r'nan|inf|epsilon|-0\.0|underflow|overflow',
          ).hasMatch(fileLower)) {
        result.add(
          Finding(
            code: 'nim-float-tests-missing-edge-cases',
            severity: RuleSeverity.info,
            path: path,
            line: 1,
            endLine: 1,
            message:
                'exported floating-point API has no obvious edge-case coverage nearby',
            confidence: 'low',
            why:
                'Numeric APIs should document or test NaN, infinity, signed zero, overflow/underflow, and tolerance behavior where relevant.',
            suggestion:
                'Add tests/docs for NaN, ±Inf, ±0.0, extremes, and precision tolerance.',
          ),
        );
        floatEdgeFindingAdded = true;
      }
    }
    final bool hotProc =
        procDeclaration &&
        RegExp(
          r'forward|backward|infer|predict|update|render|draw|tick|process',
        ).hasMatch(lower);
    if (hotProc) {
      hotProcIndents.add(indent);
      if (RegExp(r'draw|render').hasMatch(lower)) {
        drawProcIndents.add(indent);
        renderBeginCount = 0;
        renderEndCount = 0;
        renderProcLine = index + 1;
      }
      final bool layoutSensitive =
          RegExp(r'tensor|matrix|ndarray').hasMatch(lower) ||
          (RegExp(r'layout|stride|batch|channel|feature').hasMatch(lower) &&
              RegExp(r'shape|dims').hasMatch(lower));
      final String previous = index > 0
          ? lines[index - 1].trim().toLowerCase()
          : '';
      if (layoutSensitive &&
          !RegExp(r'shape|layout|stride|batch|channel').hasMatch(previous) &&
          !line.contains('##')) {
        context.add(
          'nim-layout-assumption-undocumented',
          RuleSeverity.info,
          'layout-sensitive public API lacks obvious shape/layout docs',
          confidence: 'low',
        );
      }
    }
  }

  void _analyzeLoopPerformance(_NimRuntimeLineContext context) {
    final int indent = context.indent;
    final List<String> lines = context.lines;
    final int index = context.index;
    final String line = context.line;
    final String lower = context.lower;
    if (line.startsWith('for ') || line.startsWith('while ')) {
      loopIndents.add(indent);
      final RegExpMatch? collection = RegExp(
        r'\bin\s+([A-Za-z_]\w*)',
      ).firstMatch(line);
      if (collection != null) {
        loopCollections.add((name: collection.group(1)!, indent: indent));
      }
    }
    if (loopIndents.isNotEmpty &&
        lower.contains('result') &&
        (lower.contains('&= readfile') ||
            (lower.contains('= result &') && lower.contains('readfile')))) {
      context.add(
        'nim-readfile-concat-temp',
        RuleSeverity.info,
        'readFile result is concatenated in a loop',
      );
    }
    if (loopIndents.isNotEmpty &&
        hotProcIndents.isNotEmpty &&
        RegExp(
          r'newseq|newstring|newtensor|zeros\(|ones\(|inittable|initorderedtable|=\s*@\[\]|\.clone',
        ).hasMatch(lower)) {
      context.add(
        'nim-hot-loop-allocation',
        RuleSeverity.info,
        'allocation-like operation inside loop',
        confidence: 'low',
      );
    }
    if (hotProcIndents.isNotEmpty &&
        RegExp(
          r'newseq|newstring|inittable|initorderedtable|parsejson|=\s*@\[\]',
        ).hasMatch(lower)) {
      context.add(
        'nim-game-loop-allocation',
        RuleSeverity.info,
        'allocation-like operation inside update/render loop',
        confidence: 'low',
      );
    }
    if (hotProcIndents.isNotEmpty &&
        RegExp(
          r'readfile|writefile|execprocess|execcmd|request\(|downloadfile',
        ).hasMatch(lower)) {
      context.add(
        'nim-update-blocking-io',
        RuleSeverity.warn,
        'blocking IO appears inside update/render loop',
      );
    }
    if (hotProcIndents.isNotEmpty &&
        RegExp(
          r'entity|entities|particle|projectile|sprite|object',
        ).hasMatch(lower) &&
        (lower.contains('.add(') || lower.contains('.add ')) &&
        !RegExp(r'setlen|delete|del\(|remove|max|limit|cap').hasMatch(
          lines
              .skip(index > 5 ? index - 5 : 0)
              .take(11)
              .join('\n')
              .toLowerCase(),
        )) {
      context.add(
        'nim-unbounded-entity-growth',
        RuleSeverity.info,
        'entity-like collection grows in hot loop without obvious cap/removal',
        confidence: 'low',
      );
    }
    if (drawProcIndents.isNotEmpty &&
        RegExp(
          r'loadtexture|loadimage|loadsound|loadmusic|loadfont|loadasset',
        ).hasMatch(lower)) {
      context.add(
        'nim-draw-loads-asset',
        RuleSeverity.warn,
        'asset loading appears inside draw/render proc',
      );
    }
    if (drawProcIndents.isNotEmpty &&
        RegExp(r'\brand(?:om)?\s*\(').hasMatch(lower)) {
      context.add(
        'nim-random-in-render',
        RuleSeverity.info,
        'random call appears inside draw/render proc',
        confidence: 'low',
      );
    }
  }

  void _analyzeLifecycle(_NimRuntimeLineContext context) {
    final List<Finding> result = context.result;
    final String path = context.path;
    final List<String> lines = context.lines;
    final int index = context.index;
    final String raw = context.raw;
    final String line = context.line;
    final String lower = context.lower;
    final bool procDeclaration = context.procDeclaration;
    final bool inUpdate = hotProcIndents.isNotEmpty && drawProcIndents.isEmpty;
    if (procDeclaration &&
        RegExp(
          r'save|serialize|persist|writestate|writedata',
        ).hasMatch(lower)) {
      final int procIndent = raw.length - raw.trimLeft().length;
      final String body = lines
          .skip(index + 1)
          .takeWhile(
            (String next) =>
                next.trim().isEmpty ||
                next.length - next.trimLeft().length > procIndent,
          )
          .join('\n')
          .toLowerCase();
      if (RegExp(
            r'writefile\(|encode\(|marshal\(|tojson|dump\(',
          ).hasMatch(body) &&
          !body.contains('version')) {
        result.add(
          Finding(
            code: 'nim-save-missing-version',
            severity: RuleSeverity.info,
            path: path,
            line: 1,
            endLine: 1,
            message: 'save proc writes data but has no version field',
            confidence: 'low',
            why:
                'Save formats without a version field are hard to migrate when the format changes.',
            suggestion:
                'Add a "version" field to saved data for forward/backward compatibility.',
          ),
        );
      }
    }
    if (inUpdate && _entityLifecycleMutation.hasMatch(lower)) {
      final RegExpMatch? entity = RegExp(r'([A-Za-z_]\w*)\.').firstMatch(line);
      if (entity != null && entity.group(1)!.length > 2) {
        destroyedEntities.add(entity.group(1)!.toLowerCase());
      }
    } else if (inUpdate) {
      for (final String entity in destroyedEntities) {
        if (lower.contains('$entity.') &&
            !RegExp('$entity\\.(?:alive|dead|destroyed)').hasMatch(lower)) {
          context.add(
            'nim-entity-access-after-destroy',
            RuleSeverity.warn,
            'entity field accessed after being marked dead/destroyed',
            confidence: 'low',
          );
          break;
        }
      }
    }
    if (inUpdate &&
        RegExp(
          r'obtain\(|getcomponent\(|findcomponent\(|lookup\(|getentity\(|findentity\(|getbyid\(|acquire\(',
        ).hasMatch(lower)) {
      final RegExpMatch? assigned = RegExp(
        r'(?:let|var)\s+([A-Za-z_]\w*)\s*=',
      ).firstMatch(line);
      if (assigned != null) {
        final String name = assigned.group(1)!.toLowerCase();
        final String nearby = lines
            .skip(index + 1)
            .take(5)
            .join('\n')
            .toLowerCase();
        if (!nearby.contains('$name != nil') &&
            !nearby.contains('$name == nil') &&
            !nearby.contains('$name.isnil') &&
            !nearby.contains('isnil($name')) {
          context.add(
            'nim-nil-component-access',
            RuleSeverity.info,
            'component obtained but not checked for nil before use',
            confidence: 'low',
          );
        }
      }
    }
    if (inUpdate &&
        loopIndents.length >= 2 &&
        RegExp(
          r'dist\(|distance\(|intersect\(|collide\(|overlap\(|aabb\(|hitbox\(',
        ).hasMatch(lower) &&
        !RegExp(
          r'grid|spatial|hash|quadtree|broad|bvh|partition|bucket',
        ).hasMatch(
          lines
              .skip(index > 10 ? index - 10 : 0)
              .take(11)
              .join('\n')
              .toLowerCase(),
        )) {
      context.add(
        'nim-o-n-squared-collision',
        RuleSeverity.warn,
        'nested-loop collision check without broad-phase hint',
      );
    }
  }

  void _analyzeRendering(_NimRuntimeLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String raw = context.raw;
    final String lower = context.lower;
    final bool inDraw = drawProcIndents.isNotEmpty;
    if (inDraw &&
        RegExp(
          r'(?:cam|camera)\.(?:x|y|zoom)\s*(?:\+?=)|(?:cam|camera)\.(?:translate|rotate|scale|setpos|move)\(',
        ).hasMatch(lower)) {
      cameraModified = true;
      cameraProcLine = renderProcLine;
    }
    if (inDraw &&
        RegExp(
          r'(?:cam|camera)\.(?:reset|restore|identity|pop)\(|resettransform',
        ).hasMatch(lower)) {
      cameraRestored = true;
    }
    final bool assetLoad =
        lower.contains('load') &&
        RegExp(
          r'texture|image|sound|audio|font|mesh|model|shader|sprite|music|asset',
        ).hasMatch(lower);
    final bool assetFree =
        RegExp(r'unload|free|release\(|destroy\(|dispose\(').hasMatch(lower) &&
        RegExp(
          r'texture|image|sound|audio|font|mesh|model|shader|sprite|music|asset|all',
        ).hasMatch(lower);
    if (assetLoad) assetLoadCount++;
    if (assetFree) assetFreeCount++;
    if (inDraw &&
        RegExp(
          r'drawtext\(|drawrect\(|drawcircle\(|drawline\(|drawtexture\(',
        ).hasMatch(lower) &&
        RegExp(
          r'fps|debug|trace|prof|memory|alloc',
        ).hasMatch(raw.toLowerCase()) &&
        !lines
            .skip(index > 5 ? index - 5 : 0)
            .take(6)
            .join('\n')
            .toLowerCase()
            .contains('if debug')) {
      context.add(
        'nim-debug-draw-not-gated',
        RuleSeverity.info,
        'debug-looking draw call not gated by a debug flag',
        confidence: 'low',
      );
    }
  }

  void _analyzeDrawAndParameters(_NimRuntimeLineContext context) {
    final int index = context.index;
    final String line = context.line;
    final String lower = context.lower;
    final bool procDeclaration = context.procDeclaration;
    final bool inDraw = drawProcIndents.isNotEmpty;
    if (inDraw) {
      if (RegExp(
        r'beginscissor|beginclip|begincanvas|beginblend',
      ).hasMatch(lower)) {
        renderBeginCount++;
      }
      if (RegExp(
        r'endscissor|endclip|endcanvas|finishcanvas',
      ).hasMatch(lower)) {
        renderEndCount++;
      }
    }
    if (loopCollections.isNotEmpty && !line.startsWith('for ')) {
      for (final collection in loopCollections) {
        if (RegExp(
          '${RegExp.escape(collection.name)}\\.(?:add|delete|del|remove|pop)\\(',
        ).hasMatch(lower)) {
          context.add(
            'nim-mutate-while-iterating',
            RuleSeverity.warn,
            'collection appears to be mutated while being iterated',
          );
          break;
        }
      }
    }
    if (procDeclaration) {
      final int open = line.indexOf('(');
      final int close = line.lastIndexOf(')');
      if (open >= 0 && close > open) {
        final Set<String> names = <String>{};
        for (final String segment
            in line.substring(open + 1, close).split(',')) {
          final String candidate = segment.split(':').first.trim();
          if (RegExp(r'^[A-Za-z_]\w*$').hasMatch(candidate)) {
            names.add(candidate.toLowerCase());
          }
        }
        procParameters.add((line: index + 1, params: names));
      }
    }
  }
}

final class _NimRuntimeLineContext {
  _NimRuntimeLineContext({
    required this.path,
    required this.source,
    required this.lines,
    required this.index,
    required this.raw,
    required this.line,
    required this.lower,
  });

  final String path;
  final String source;
  final List<String> lines;
  final int index;
  final String raw;
  final String line;
  final String lower;
  final List<Finding> result = <Finding>[];
  int get indent => raw.length - raw.trimLeft().length;
  bool get procDeclaration =>
      line.startsWith('proc ') || line.startsWith('func ');

  void add(
    String id,
    RuleSeverity severity,
    String message, {
    String confidence = 'medium',
  }) {
    result.add(
      Finding(
        code: id,
        severity: severity,
        path: path,
        line: index + 1,
        endLine: index + 1,
        message: message,
        confidence: confidence,
        why:
            canonicalNimEvidence[id]?.why ??
            'This Nim construct can weaken correctness, clarity, portability, or runtime performance.',
        suggestion:
            canonicalNimEvidence[id]?.suggestion ??
            'Use the safer explicit Nim pattern documented by this rule.',
      ),
    );
  }
}
