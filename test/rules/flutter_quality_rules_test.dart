import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/flutter_quality_rules.dart';
import 'package:test/test.dart';

void main() {
  RuleContext context(
    Map<String, String> sources, {
    Map<String, String> auxiliary = const <String, String>{},
  }) => RuleContext(
    config: const AnalysisConfig(root: '.', frameworks: <String>{'flutter'}),
    sources: sources,
    language: 'repository',
    auxiliaryFiles: auxiliary,
  );

  List<Finding> run(
    String id,
    String source, {
    Map<String, String> auxiliary = const <String, String>{},
  }) => FlutterQualityRule(id)
      .analyze(
        context(<String, String>{
          'lib/page.dart': source,
        }, auxiliary: auxiliary),
      )
      .toList();

  test('reports immutable widgets without const constructors', () {
    expect(
      run('flutter-widget-missing-const-constructor', '''
class UserCard extends StatelessWidget {
  final String name;
  UserCard({required this.name});
  Widget build(BuildContext context) { return Text(name); }
}
class GoodCard extends StatelessWidget {
  final String name;
  const GoodCard({required this.name});
  Widget build(BuildContext context) { return Text(name); }
}
'''),
      hasLength(1),
    );
  });

  test('reports substantial eager ListView children literals', () {
    final String children = List<String>.generate(
      13,
      (index) => 'Text("$index"),',
    ).join();
    expect(
      run(
        'flutter-listview-large-children',
        'Widget build(BuildContext context) { return ListView(children: [$children]); }',
      ),
      hasLength(1),
    );
  });

  test('reports repeated direct images when a cache is established', () {
    expect(
      run(
        'flutter-image-cache-bypass',
        'Widget build(BuildContext c) { return Column(children: [Image.network(a), Image.network(b), Image.network(c)]); }',
        auxiliary: const <String, String>{
          'pubspec.yaml': 'dependencies:\n  cached_network_image: ^3.0.0',
        },
      ),
      hasLength(1),
    );
  });

  test('reports public stateful widgets without key forwarding', () {
    expect(
      run('flutter-missing-widget-key', '''
class Editor extends StatefulWidget {
  const Editor();
}
class GoodEditor extends StatefulWidget {
  const GoodEditor({super.key});
}
'''),
      hasLength(1),
    );
  });

  test('reports setState directly inside build', () {
    expect(
      run(
        'flutter-setstate-in-build',
        'Widget build(BuildContext context) { setState(() {}); return const SizedBox(); }',
      ),
      hasLength(1),
    );
  });

  test('reports context after await without mounted guard', () {
    expect(
      run('flutter-context-after-await', '''
Future<void> submit(BuildContext context) async {
  await save();
  Navigator.of(context).pop();
}
Future<void> safe(BuildContext context) async {
  await save();
  if (!context.mounted) return;
  Navigator.of(context).pop();
}
'''),
      hasLength(1),
    );
  });

  test('reports controller creation inside build', () {
    expect(
      run(
        'flutter-controller-created-in-build',
        'Widget build(BuildContext context) { final c = TextEditingController(); return TextField(controller: c); }',
      ),
      hasLength(1),
    );
  });

  test('reports user text when localization is established', () {
    expect(
      run(
        'flutter-unlocalized-user-text',
        "Widget build(BuildContext context) { return const Text('Save changes'); }",
        auxiliary: const <String, String>{'l10n.yaml': 'arb-dir: lib/l10n'},
      ),
      hasLength(1),
    );
  });

  test('reports undeclared or absent assets', () {
    expect(
      run(
        'flutter-asset-reference-missing',
        "Widget build(BuildContext context) { return Image.asset('assets/logo.png'); }",
        auxiliary: const <String, String>{
          'pubspec.yaml': 'flutter:\n  assets:\n    - assets/logo.png',
          '@exists/assets/logo.png': 'false',
        },
      ),
      hasLength(1),
    );
  });

  test('reports submitted forms without validation', () {
    expect(
      run(
        'flutter-form-without-validation',
        'Widget build(BuildContext context) { return Form(child: Column(children: [TextFormField(), ElevatedButton(onPressed: submit, child: const Text("Save"))])); }',
      ),
      hasLength(1),
    );
  });

  test('reports side effects inside BlocBuilder', () {
    expect(
      run(
        'flutter-bloc-side-effect-in-builder',
        'Widget build(BuildContext context) { return BlocBuilder<AppBloc, AppState>(builder: (context, state) { Navigator.of(context).pop(); return const SizedBox(); }); }',
      ),
      hasLength(1),
    );
  });

  test('reports GetIt lookup inside widgets', () {
    expect(
      run('flutter-getit-lookup-in-widget', '''
class UserPage extends StatelessWidget {
  Widget build(BuildContext context) { return Text(GetIt.I.get<User>().name); }
}
'''),
      hasLength(1),
    );
  });

  test('reports manual platform branches around adaptive controls', () {
    expect(
      run('flutter-platform-branch-without-adaptation', '''
Widget build(BuildContext context) {
  if (Platform.isIOS) return Switch(value: value, onChanged: update);
  return Switch(value: value, onChanged: update);
}
'''),
      hasLength(1),
    );
  });
}
