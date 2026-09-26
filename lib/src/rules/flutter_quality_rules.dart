// Conservative Flutter project checks infer local framework evidence instead of imposing one architecture.

import '../core/models.dart';
import '../core/rule.dart';
import 'generic/generic_rules.dart';

final Map<String, RuleMetadata>
flutterQualityRuleMetadata = <String, RuleMetadata>{
  'flutter-widget-missing-const-constructor': _metadata(
    'flutter-widget-missing-const-constructor',
    'Use a const widget constructor',
    'An immutable widget without a const constructor prevents canonicalization at const call sites.',
    'Make the constructor const when every instance field is final.',
  ),
  'flutter-listview-large-children': _metadata(
    'flutter-listview-large-children',
    'Build large lists lazily',
    'A large ListView children literal eagerly creates every child even when most are off screen.',
    'Use ListView.builder or ListView.separated for a dynamic or substantial list.',
  ),
  'flutter-image-cache-bypass': _metadata(
    'flutter-image-cache-bypass',
    'Reuse the established image cache',
    'Repeated direct network images bypass the project caching component and duplicate loading behavior.',
    'Use the project image-cache wrapper or CachedNetworkImage consistently.',
  ),
  'flutter-missing-widget-key': _metadata(
    'flutter-missing-widget-key',
    'Expose a widget key',
    'A reusable stateful widget without a key parameter cannot preserve identity when reordered by callers.',
    'Accept Key? key and forward it to super, or use a super.key parameter.',
  ),
  'flutter-setstate-in-build': _metadata(
    'flutter-setstate-in-build',
    'Do not call setState during build',
    'Mutating widget state while the framework is building can trigger build-phase exceptions or loops.',
    'Move the transition to an event, lifecycle callback, listener, or post-frame action with an explicit reason.',
  ),
  'flutter-context-after-await': _metadata(
    'flutter-context-after-await',
    'Guard BuildContext after await',
    'A widget can be unmounted while an asynchronous operation is suspended.',
    'Check mounted or context.mounted after the await before using BuildContext.',
  ),
  'flutter-controller-created-in-build': _metadata(
    'flutter-controller-created-in-build',
    'Retain controllers outside build',
    'Creating controllers or focus nodes during build loses state and repeatedly allocates resources.',
    'Own the object in State and dispose it, or use an appropriate hook.',
  ),
  'flutter-unlocalized-user-text': _metadata(
    'flutter-unlocalized-user-text',
    'Localize user-visible text',
    'A literal shown by an application with localization infrastructure cannot be translated consistently.',
    'Read the message from the established localization API.',
  ),
  'flutter-asset-reference-missing': _metadata(
    'flutter-asset-reference-missing',
    'Declare and provide the Flutter asset',
    'An asset reference that is undeclared or absent fails at runtime.',
    'Add the asset to pubspec.yaml and ensure the referenced file exists with matching case.',
  ),
  'flutter-form-without-validation': _metadata(
    'flutter-form-without-validation',
    'Validate submitted form input',
    'A submitted form containing editable fields has no visible validation path.',
    'Add validators and invoke FormState.validate before processing the submission.',
  ),
  'flutter-bloc-side-effect-in-builder': _metadata(
    'flutter-bloc-side-effect-in-builder',
    'Move BLoC side effects out of builders',
    'Builders may run repeatedly and should not navigate, show transient UI, persist data, or emit telemetry.',
    'Use BlocListener or BlocConsumer listener for the side effect.',
  ),
  'flutter-getit-lookup-in-widget': _metadata(
    'flutter-getit-lookup-in-widget',
    'Inject widget dependencies',
    'Service-locator calls inside widgets hide dependencies and couple rendering to global state.',
    'Resolve the dependency at the composition root and pass it through a constructor or provider.',
  ),
  'flutter-platform-branch-without-adaptation': _metadata(
    'flutter-platform-branch-without-adaptation',
    'Use Flutter adaptive controls',
    'A platform branch around a control duplicates selection logic while bypassing the adaptive widget API.',
    'Use the control’s adaptive constructor or a focused platform component.',
  ),
};

RuleMetadata _metadata(
  String id,
  String title,
  String why,
  String suggestion,
) => RuleMetadata(
  id: id,
  version: 1,
  defaultSeverity: RuleSeverity.info,
  group: 'maintainability',
  title: title,
  why: why,
  suggestion: suggestion,
  semanticMaturity: RuleSemanticMaturity.project,
  taxonomy: const <FindingTaxonomy>{FindingTaxonomy.maintainability},
  languages: const <String>['dart'],
  frameworks: const <String>{'flutter'},
  limitations: const <String>[
    'Generated, test, example, and vendored sources follow normal source classification controls.',
    'Framework wrappers and behavior outside the analyzed repository cannot be resolved.',
  ],
);

final class FlutterQualityRule extends SelfContainedRule {
  FlutterQualityRule(String id) : super(flutterQualityRuleMetadata[id]!);

  @override
  Iterable<Finding> analyze(RuleContext context) => switch (metadata.id) {
    'flutter-widget-missing-const-constructor' => _missingConst(context),
    'flutter-listview-large-children' => _largeLists(context),
    'flutter-image-cache-bypass' => _imageCache(context),
    'flutter-missing-widget-key' => _missingKeys(context),
    'flutter-setstate-in-build' => _setStateInBuild(context),
    'flutter-context-after-await' => _contextAfterAwait(context),
    'flutter-controller-created-in-build' => _controllersInBuild(context),
    'flutter-unlocalized-user-text' => _unlocalizedText(context),
    'flutter-asset-reference-missing' => _missingAssets(context),
    'flutter-form-without-validation' => _formsWithoutValidation(context),
    'flutter-bloc-side-effect-in-builder' => _blocBuilderEffects(context),
    'flutter-getit-lookup-in-widget' => _getItWidgets(context),
    'flutter-platform-branch-without-adaptation' => _platformBranches(context),
    _ => const <Finding>[],
  };

  Finding _finding(
    RuleContext context,
    String path,
    int line,
    String message,
  ) => report(
    context,
    path: path,
    line: line,
    message: message,
    confidence: 'high',
  );

  Iterable<Finding> _missingConst(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final _ClassBlock block in _classes(source)) {
        if (!block.header.contains('extends StatelessWidget')) continue;
        final RegExp constructor = RegExp(
          '(?:^|\\n)\\s*(const\\s+)?${RegExp.escape(block.name)}\\s*\\(',
        );
        final RegExpMatch? match = constructor.firstMatch(block.body);
        if (match == null || match.group(1) != null) continue;
        if (RegExp(
          r'^\s*(?!(?:static|final|const)\b)[A-Za-z_$][\w$<>?,.\[\]]*\s+\w+\s*(?:=|;)',
          multiLine: true,
        ).hasMatch(block.body)) {
          continue;
        }
        yield _finding(
          context,
          source.path,
          block.line,
          '${block.name} is immutable but its constructor is not const',
        );
      }
    }
  }

  Iterable<Finding> _largeLists(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final RegExpMatch start in RegExp(
        r'\bListView\s*\(',
      ).allMatches(source.masked)) {
        final String tail = source.masked.substring(
          start.start,
          (start.start + 3000).clamp(0, source.masked.length),
        );
        final RegExpMatch? children = RegExp(
          r'children\s*:\s*\[([\s\S]*?)\]',
        ).firstMatch(tail);
        if (children != null &&
            ','.allMatches(children.group(1)!).length >= 12) {
          yield _finding(
            context,
            source.path,
            source.lineAt(start.start),
            'ListView eagerly builds a large children literal',
          );
        }
      }
    }
  }

  Iterable<Finding> _imageCache(RuleContext context) sync* {
    final List<({String path, int line})> direct =
        <({String path, int line})>[];
    var establishedCache = (context.auxiliaryFiles['pubspec.yaml'] ?? '')
        .contains('cached_network_image:');
    for (final _Source source in _dartSources(context)) {
      if (source.masked.contains('CachedNetworkImage(') ||
          source.masked.contains('CachedNetworkImageProvider(')) {
        establishedCache = true;
      }
      for (final RegExpMatch match in RegExp(
        r'\bImage\.network\s*\(',
      ).allMatches(source.masked)) {
        direct.add((path: source.path, line: source.lineAt(match.start)));
      }
    }
    if (!establishedCache || direct.length < 3) return;
    final first = direct.first;
    yield _finding(
      context,
      first.path,
      first.line,
      '${direct.length} direct Image.network calls bypass the established cache',
    );
  }

  Iterable<Finding> _missingKeys(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final _ClassBlock block in _classes(source)) {
        if (!block.header.contains('extends StatefulWidget') ||
            block.name.startsWith('_')) {
          continue;
        }
        final RegExpMatch? constructor = RegExp(
          '${RegExp.escape(block.name)}\\s*\\(([^)]*)\\)',
        ).firstMatch(block.body);
        if (constructor != null &&
            !RegExp(
              r'\b(?:super\.key|Key\??\s+key)\b',
            ).hasMatch(constructor.group(1)!)) {
          yield _finding(
            context,
            source.path,
            block.line,
            '${block.name} does not expose a widget key',
          );
        }
      }
    }
  }

  Iterable<Finding> _setStateInBuild(RuleContext context) sync* {
    yield* _buildMatches(
      context,
      RegExp(r'\bsetState\s*\('),
      'build calls setState directly',
    );
  }

  Iterable<Finding> _contextAfterAwait(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final _FunctionBlock function in _functions(source)) {
        final int awaitOffset = function.body.indexOf(RegExp(r'\bawait\b'));
        if (awaitOffset < 0) continue;
        final String after = function.body.substring(awaitOffset);
        if (RegExp(r'\bcontext\b').hasMatch(after) &&
            !RegExp(r'\b(?:context\.)?mounted\b').hasMatch(after)) {
          yield _finding(
            context,
            source.path,
            function.line,
            '${function.name} uses BuildContext after await without a mounted guard',
          );
        }
      }
    }
  }

  Iterable<Finding> _controllersInBuild(RuleContext context) sync* {
    yield* _buildMatches(
      context,
      RegExp(
        r'\b(?:TextEditingController|AnimationController|ScrollController|PageController|TabController|FocusNode)\s*\(',
      ),
      'build creates a controller or focus node',
    );
  }

  Iterable<Finding> _unlocalizedText(RuleContext context) sync* {
    final bool localized =
        context.auxiliaryFiles.containsKey('l10n.yaml') ||
        (context.auxiliaryFiles['pubspec.yaml'] ?? '').contains(
          'generate: true',
        ) ||
        context.sources.values.any(
          (source) => source.contains('AppLocalizations'),
        );
    if (!localized) return;
    for (final _Source source in _dartSources(context)) {
      for (final RegExpMatch match in RegExp(
        r'''\b(?:Text|Tooltip)\s*\(\s*['"]([^'"$]{4,})['"]''',
      ).allMatches(source.raw)) {
        final String text = match.group(1)!.trim();
        if (RegExp(r'^[\d\W_]+$').hasMatch(text)) continue;
        yield _finding(
          context,
          source.path,
          source.lineAt(match.start),
          'user-visible literal `$text` bypasses localization',
        );
      }
    }
  }

  Iterable<Finding> _missingAssets(RuleContext context) sync* {
    final String pubspec = context.auxiliaryFiles['pubspec.yaml'] ?? '';
    for (final _Source source in _dartSources(context)) {
      for (final RegExpMatch match in RegExp(
        r'''\b(?:Image\.asset|AssetImage)\s*\(\s*['"](assets/[^'"]+)['"]''',
      ).allMatches(source.raw)) {
        final String asset = match.group(1)!;
        final bool declared =
            pubspec.contains(asset) || _declaredAssetDirectory(pubspec, asset);
        final bool exists = context.auxiliaryFiles['@exists/$asset'] == 'true';
        if (!declared || !exists) {
          yield _finding(
            context,
            source.path,
            source.lineAt(match.start),
            'asset `$asset` is ${!declared ? 'not declared' : 'missing on disk'}',
          );
        }
      }
    }
  }

  Iterable<Finding> _formsWithoutValidation(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      if (!source.masked.contains('Form(') ||
          !source.masked.contains('TextFormField(')) {
        continue;
      }
      final bool submits = RegExp(
        r'\bon(?:Pressed|FieldSubmitted|EditingComplete)\s*:',
      ).hasMatch(source.masked);
      final bool validates = RegExp(
        r'\bvalidator\s*:|\.validate\s*\(',
      ).hasMatch(source.masked);
      if (submits && !validates) {
        yield _finding(
          context,
          source.path,
          1,
          'submitted Form has editable fields but no validation path',
        );
      }
    }
  }

  Iterable<Finding> _blocBuilderEffects(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final RegExpMatch match in RegExp(
        r'\bBlocBuilder(?:<[^>]+>)?\s*\(',
      ).allMatches(source.masked)) {
        final String tail = source.masked.substring(
          match.start,
          (match.start + 3000).clamp(0, source.masked.length),
        );
        if (RegExp(
          r'\b(?:Navigator\.|showDialog\s*\(|ScaffoldMessenger\.|analytics\.|repository\.|\.save\s*\()',
        ).hasMatch(tail)) {
          yield _finding(
            context,
            source.path,
            source.lineAt(match.start),
            'BlocBuilder performs a navigation, UI, telemetry, or persistence side effect',
          );
        }
      }
    }
  }

  Iterable<Finding> _getItWidgets(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final _ClassBlock block in _classes(source)) {
        if (!RegExp(
          r'extends\s+(?:StatelessWidget|StatefulWidget|State<)',
        ).hasMatch(block.header)) {
          continue;
        }
        if (RegExp(
          r'\b(?:GetIt\.I|getIt)(?:\.get)?\s*(?:<|\()',
        ).hasMatch(block.body)) {
          yield _finding(
            context,
            source.path,
            block.line,
            '${block.name} resolves a dependency through GetIt',
          );
        }
      }
    }
  }

  Iterable<Finding> _platformBranches(RuleContext context) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final _FunctionBlock build in _functions(
        source,
      ).where((function) => function.name == 'build')) {
        final bool platformCheck = RegExp(
          r'\b(?:Platform\.is(?:IOS|Android|MacOS|Windows)|defaultTargetPlatform)\b',
        ).hasMatch(build.body);
        final bool adaptableControl = RegExp(
          r'\b(?:Switch|Slider|CircularProgressIndicator|RefreshIndicator)\s*\(',
        ).hasMatch(build.body);
        final bool adapted =
            build.body.contains('.adaptive(') ||
            build.body.contains('Cupertino');
        if (platformCheck && adaptableControl && !adapted) {
          yield _finding(
            context,
            source.path,
            build.line,
            'build branches by platform around a control without using an adaptive widget',
          );
        }
      }
    }
  }

  Iterable<Finding> _buildMatches(
    RuleContext context,
    RegExp pattern,
    String message,
  ) sync* {
    for (final _Source source in _dartSources(context)) {
      for (final _FunctionBlock build in _functions(
        source,
      ).where((function) => function.name == 'build')) {
        if (pattern.hasMatch(build.body)) {
          yield _finding(context, source.path, build.line, message);
        }
      }
    }
  }
}

bool _declaredAssetDirectory(String pubspec, String asset) {
  final List<String> segments = asset.split('/');
  for (var length = segments.length - 1; length >= 1; length--) {
    if (pubspec.contains('${segments.take(length).join('/')}/')) return true;
  }
  return false;
}

Iterable<_Source> _dartSources(RuleContext context) sync* {
  for (final MapEntry<String, String> entry in context.sources.entries) {
    if (!entry.key.endsWith('.dart')) continue;
    yield _Source(entry.key, entry.value);
  }
}

final class _Source {
  _Source(this.path, this.raw)
    : lines = raw.split('\n'),
      masked = maskGenericRuleStrings(
        raw.split('\n'),
        sourcePath: path,
      ).join('\n');
  final String path;
  final String raw;
  final List<String> lines;
  final String masked;
  int lineAt(int offset) =>
      '\n'.allMatches(masked.substring(0, offset)).length + 1;
}

final class _ClassBlock {
  const _ClassBlock(this.name, this.header, this.body, this.line);
  final String name;
  final String header;
  final String body;
  final int line;
}

final class _FunctionBlock {
  const _FunctionBlock(this.name, this.body, this.line);
  final String name;
  final String body;
  final int line;
}

List<_ClassBlock> _classes(_Source source) {
  final List<_ClassBlock> result = <_ClassBlock>[];
  for (final RegExpMatch match in RegExp(
    r'\bclass\s+([A-Za-z_$]\w*)[^\{]*\{',
  ).allMatches(source.masked)) {
    final int end = _blockEnd(source.masked, match.end - 1);
    if (end < 0) continue;
    result.add(
      _ClassBlock(
        match.group(1)!,
        match.group(0)!,
        source.masked.substring(match.start, end + 1),
        source.lineAt(match.start),
      ),
    );
  }
  return result;
}

List<_FunctionBlock> _functions(_Source source) {
  final List<_FunctionBlock> result = <_FunctionBlock>[];
  final RegExp declaration = RegExp(
    r'(?:^|\n)\s*(?:@[\w.()]+\s*)*(?:(?:Future<[^>]+>|Future|Widget|void|dynamic|[A-Za-z_$]\w*)\s+)([A-Za-z_$]\w*)\s*\([^;]*\)\s*(?:async\s*)?\{',
  );
  for (final RegExpMatch match in declaration.allMatches(source.masked)) {
    final int brace = source.masked.indexOf('{', match.start);
    final int end = _blockEnd(source.masked, brace);
    if (end < 0) continue;
    result.add(
      _FunctionBlock(
        match.group(1)!,
        source.masked.substring(match.start, end + 1),
        source.lineAt(match.start),
      ),
    );
  }
  return result;
}

int _blockEnd(String source, int openingBrace) {
  var depth = 0;
  for (var index = openingBrace; index < source.length; index++) {
    if (source[index] == '{') depth++;
    if (source[index] == '}' && --depth == 0) return index;
  }
  return -1;
}
