// Some runtime risks are best recognized by simulating small state transitions, keeping that machinery out of simpler packs.

part of 'nim_runtime_rule_pack.dart';

extension _NimRuntimeSimulationRules on NimRuntimeRulePack {
  void _analyzeSimulation(_NimRuntimeLineContext context) {
    _analyzeSimulationDimensions(context);
    _analyzeSimulationMath(context);
    _analyzeSimulationEffects(context);
  }

  void _analyzeSimulationDimensions(_NimRuntimeLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String lower = context.lower;
    final bool procDeclaration = context.procDeclaration;
    final bool inUpdate = hotProcIndents.isNotEmpty && drawProcIndents.isEmpty;
    final bool inDraw = drawProcIndents.isNotEmpty;
    if ((inUpdate || inDraw) &&
        RegExp(
          r'screenwidth|screenheight|windowwidth|windowheight',
        ).hasMatch(lower) &&
        RegExp(
          r'\b(?:320|360|480|540|640|720|768|1080|1280|1440|1920)\b',
        ).hasMatch(lower) &&
        !RegExp(r'config|cfg').hasMatch(lower)) {
      context.add(
        'nim-hardcoded-screen-size',
        RuleSeverity.info,
        'screen dimension appears hardcoded instead of using config',
        confidence: 'low',
      );
    }
    if (inUpdate &&
        lower.contains('* dt') &&
        RegExp(
          r'velocity|accel|force|gravity|physics|integrate|simulate',
        ).hasMatch(lower) &&
        !lines
            .skip(index > 10 ? index - 10 : 0)
            .take(21)
            .join('\n')
            .toLowerCase()
            .contains('fixed')) {
      context.add(
        'nim-physics-variable-timestep',
        RuleSeverity.info,
        'physics integration uses variable dt without fixed timestep',
        confidence: 'low',
      );
    }
    if (inUpdate &&
        !procDeclaration &&
        RegExp(
          r'drawtext\(|drawrect\(|drawcircle\(|drawline\(|drawtexture\(|render\(',
        ).hasMatch(lower) &&
        !lower.contains('debug')) {
      context.add(
        'nim-draw-call-in-update',
        RuleSeverity.warn,
        'draw/render call appears inside update proc',
      );
    }
  }

  void _analyzeSimulationMath(_NimRuntimeLineContext context) {
    final String line = context.line;
    final String lower = context.lower;
    final bool inUpdate = hotProcIndents.isNotEmpty && drawProcIndents.isEmpty;
    final bool inDraw = drawProcIndents.isNotEmpty;
    if (inUpdate &&
        line.contains(' == ') &&
        RegExp(
          r'\d\.\d|\.x\b|\.y\b|pos\.|vel\.|speed|gravity|\.mass|\.force',
        ).hasMatch(lower)) {
      context.add(
        'nim-float-equality-physics',
        RuleSeverity.info,
        'floating-point equality comparison in update/sim code',
        confidence: 'low',
      );
    }
    if ((inUpdate || inDraw) &&
        RegExp(r'\b(?:dist|distance)\(').hasMatch(lower) &&
        lower.contains(' == 0')) {
      context.add(
        'nim-missing-epsilon-distance',
        RuleSeverity.info,
        'distance compared exactly to zero',
        confidence: 'low',
      );
    }
    if (inUpdate &&
        RegExp(r'\b(?:rand|random)\(').hasMatch(lower) &&
        !lower.contains('rng') &&
        !lower.contains('seed')) {
      context.add(
        'nim-random-in-simulation',
        RuleSeverity.info,
        'unseeded random call in update/sim proc',
        confidence: 'low',
      );
    }
    if (inUpdate &&
        RegExp(r'gettime\(|\bnow\(|epochtime\(|getmonotonic').hasMatch(lower)) {
      context.add(
        'nim-wall-clock-in-update',
        RuleSeverity.warn,
        'wall-clock time used inside update/sim proc',
      );
    }
  }

  void _analyzeSimulationEffects(_NimRuntimeLineContext context) {
    final List<String> lines = context.lines;
    final int index = context.index;
    final String raw = context.raw;
    final String lower = context.lower;
    final bool procDeclaration = context.procDeclaration;
    final bool inUpdate = hotProcIndents.isNotEmpty && drawProcIndents.isEmpty;
    final bool inDraw = drawProcIndents.isNotEmpty;
    if ((inUpdate || inDraw) &&
        !procDeclaration &&
        (raw.contains(r'$"') ||
            raw.contains(r'$(') ||
            lower.contains('.format(') ||
            lower.contains('formatstring'))) {
      context.add(
        'nim-per-frame-string-format',
        RuleSeverity.info,
        'string formatting appears inside update/draw loop',
        confidence: 'low',
      );
    }
    if (inDraw &&
        !procDeclaration &&
        RegExp(r'keydown\(|keyup\(|keypressed\(').hasMatch(lower)) {
      context.add(
        'nim-input-in-draw',
        RuleSeverity.warn,
        'input polling appears inside draw/render proc',
      );
    }
    if ((inUpdate || inDraw) &&
        RegExp(r'playsound\(|playmusic\(|playsfx\(').hasMatch(lower) &&
        !lines
            .skip(index > 3 ? index - 3 : 0)
            .take(4)
            .join('\n')
            .toLowerCase()
            .contains('pressed')) {
      context.add(
        'nim-sound-every-frame',
        RuleSeverity.warn,
        'sound played in hot loop without an edge/trigger guard',
      );
    }
    if ((inUpdate || inDraw) &&
        RegExp(
          r'writefile\(|savefile\(|\.save\(|savestate\(',
        ).hasMatch(lower)) {
      context.add(
        'nim-save-in-update',
        RuleSeverity.warn,
        'save/write appears inside update/draw loop',
      );
    }
  }
}
