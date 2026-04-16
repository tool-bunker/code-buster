// Users need to inspect the active rule inventory and metadata independently of running those rules.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Lists the stable rule catalog.
final class RulesCommand implements CliCommandHandler {
  /// Creates the rules command.
  const RulesCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.rules,
  };

  @override
  int execute(CodeBusterCliOptions options) => _rules(options);
}

int _rules(CodeBusterCliOptions options) {
  final AnalysisConfig config = CodeBusterConfigLoader.loadFromRoot(
    Directory(options.root).absolute.path,
  );
  final Set<String> languages = config.languages.isEmpty
      ? <String>{config.language}
      : config.languages.toSet();
  final Map<String, ({String language, String group, String title})>
  descriptors = <String, ({String language, String group, String title})>{
    ...canonicalRuleDescriptors,
    for (final RuleMetadata metadata in RuleCatalog.all.where(
      (RuleMetadata item) =>
          !canonicalRuleDescriptors.containsKey(item.id) &&
          (config.dartMvvmEnabled || !item.id.startsWith('mvvm-')),
    ))
      metadata.id: (
        language: metadata.languages.length == 1
            ? metadata.languages.single
            : 'all',
        group: metadata.group,
        title: metadata.title,
      ),
    if (config.dartMvvmEnabled)
      for (final RuleMetadata metadata in RuleCatalog.all.where(
        (RuleMetadata item) => item.id.startsWith('mvvm-'),
      ))
        metadata.id: (
          language: 'dart',
          group: metadata.group,
          title: metadata.title,
        ),
  };
  final RulePolicy policy = RulePolicy(config);
  final List<Map<String, Object>> rendered = <Map<String, Object>>[];
  final entries = descriptors.entries.toList()
    ..sort((left, right) => left.key.compareTo(right.key));
  for (final entry in entries) {
    final String id = entry.key;
    final descriptor = entry.value;
    if (!languages.contains('auto') &&
        descriptor.language != 'all' &&
        !languages.contains(descriptor.language)) {
      continue;
    }
    final RuleMode mode = policy.modeFor(id);
    if (options.inactiveRules && mode != RuleMode.off) continue;
    final String group = RulePolicy.taxonomyGroupFor(id);
    final String reason = mode != RuleMode.off
        ? ''
        : config.disabledRules.contains(id)
        ? 'explicitly disabled'
        : group == 'architecture'
        ? 'requires architecture configuration'
        : group == 'domain'
        ? 'requires a detected or configured domain profile'
        : 'disabled by group or rule mode';
    rendered.add(<String, Object>{
      'id': id,
      'language': descriptor.language,
      'group': group,
      'mode': mode.configValue,
      'title': descriptor.title,
      if (reason.isNotEmpty) 'inactiveReason': reason,
    });
  }
  if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'schemaVersion': reportSchemaVersion,
        'command': 'rules',
        'rules': rendered,
      }),
    );
    return 0;
  }
  stdout.writeln('Code Buster rules');
  for (final Map<String, Object> rule in rendered) {
    stdout.writeln(
      '${(rule['mode']! as String).padRight(7)} ${rule['id']} '
      '[${rule['language']}/${rule['group']}] — ${rule['title']}'
      '${rule.containsKey('inactiveReason') ? ' (${rule['inactiveReason']})' : ''}',
    );
  }
  return 0;
}
