import 'package:code_buster/src/cli/meta_commands.dart';
import 'package:test/test.dart';

void main() {
  test('selects Homebrew for a Cellar executable', () {
    const UpdateCommand command = UpdateCommand(
      executablePath: '/opt/homebrew/Cellar/code-buster/0.2.0/bin/cb',
      scriptPath: '/opt/homebrew/Cellar/code-buster/0.2.0/bin/cb',
      operatingSystem: 'macos',
    );

    final UpdatePlan plan = command.plan();

    expect(plan.channel, UpdateChannel.homebrew);
    expect(plan.executable, 'brew');
    expect(plan.arguments, <String>['upgrade', 'tool-bunker/tap/code-buster']);
  });

  test('selects pub global activation for a pub cache snapshot', () {
    const UpdateCommand command = UpdateCommand(
      executablePath: '/opt/dart/bin/dart',
      scriptPath:
          '/home/user/.pub-cache/global_packages/code_buster/bin/cb.dart.snapshot',
      operatingSystem: 'linux',
    );

    final UpdatePlan plan = command.plan();

    expect(plan.channel, UpdateChannel.pubGlobal);
    expect(plan.executable, 'dart');
    expect(plan.arguments, <String>[
      'pub',
      'global',
      'activate',
      'code_buster',
    ]);
  });

  test('updates a native executable through its installation prefix', () {
    const UpdateCommand command = UpdateCommand(
      executablePath: '/home/user/.local/bin/cb',
      scriptPath: '/home/user/.local/bin/cb',
      operatingSystem: 'linux',
    );

    final UpdatePlan plan = command.plan();

    expect(plan.channel, UpdateChannel.native);
    expect(plan.executable, '/bin/sh');
    expect(plan.downloadUrl, 'https://codebuster.toolbunker.dev/install');
    expect(plan.environment, <String, String>{'PREFIX': '/home/user/.local'});
  });

  test('refuses to overwrite the Dart runtime for a source checkout', () {
    const UpdateCommand command = UpdateCommand(
      executablePath: '/opt/dart/bin/dart',
      scriptPath: '/workspace/code-buster/bin/cb.dart',
      operatingSystem: 'linux',
    );

    final UpdatePlan plan = command.plan();

    expect(plan.channel, UpdateChannel.sourceCheckout);
    expect(plan.description, contains('running from source'));
  });

  test('refuses an unmanaged native build path', () {
    const UpdateCommand command = UpdateCommand(
      executablePath: '/workspace/code-buster/build/cb',
      scriptPath: '/workspace/code-buster/build/cb',
      operatingSystem: 'linux',
    );

    expect(command.plan().channel, UpdateChannel.sourceCheckout);
  });

  test('directs native Windows users to the safe installer', () {
    const UpdateCommand command = UpdateCommand(
      executablePath: r'C:\Users\user\.local\bin\cb.exe',
      scriptPath: r'C:\Users\user\.local\bin\cb.exe',
      operatingSystem: 'windows',
    );

    final UpdatePlan plan = command.plan();

    expect(plan.channel, UpdateChannel.unsupported);
    expect(plan.description, contains('install.ps1'));
  });
}
