// Suppression, baseline matching, severity overrides, changed-line filtering, and limits must run in a fixed order to be predictable.

import 'dart:convert';
import 'dart:io';

import '../catalog/rule_catalog.dart';
import '../core/models.dart';

/// Applies project severity, baselines, and source suppression directives.
final class FindingFilter {
  /// Filters [findings] using [config], optional [sources], and [baseline] entries.
  List<Finding> apply({
    required AnalysisConfig config,
    required Iterable<Finding> findings,
    Map<String, String> sources = const <String, String>{},
    Set<String> baseline = const <String>{},
    String? only,
  }) {
    final List<Finding> result = <Finding>[];
    for (final Finding finding in findings) {
      if (only != null && only.isNotEmpty && finding.code != only) {
        continue;
      }
      if (config.disabledRules.contains(finding.code) ||
          baseline.contains(finding.key) ||
          baseline.contains(finding.fingerprint) ||
          _isSuppressed(finding, sources[finding.path])) {
        continue;
      }
      result.add(
        config.severityOverrides.containsKey(finding.code)
            ? finding.withSeverity(config.severityOverrides[finding.code]!)
            : finding,
      );
    }
    return List<Finding>.unmodifiable(result);
  }

  bool _isSuppressed(Finding finding, String? source) {
    if (source == null) {
      return false;
    }
    final List<String> lines = source.split('\n');
    for (var index = 0; index < lines.length; index++) {
      final String? directive = _commentText(lines[index]);
      if (directive == null) {
        continue;
      }
      if (directive.startsWith('code-buster-ignore-file') &&
          _targetsRule(
            directive.substring('code-buster-ignore-file'.length),
            finding.code,
          )) {
        return true;
      }
      if ((index + 1 - finding.line).abs() <= 1 &&
          directive.startsWith('code-buster-ignore') &&
          !directive.startsWith('code-buster-ignore-file') &&
          _targetsRule(
            directive.substring('code-buster-ignore'.length),
            finding.code,
          )) {
        return true;
      }
    }
    return false;
  }

  bool _targetsRule(String rest, String code) {
    final String trimmed = rest.trim();
    if (trimmed.isEmpty || trimmed.startsWith(':')) {
      return true;
    }
    return trimmed
        .split(RegExp(r'\s+'))
        .map((String token) => token.replaceAll(RegExp(r'[:,]'), ''))
        .contains(code);
  }

  String? _commentText(String line) {
    final String masked = _maskStrings(line);
    const List<String> markers = <String>['//', '/*', '#', '--'];
    String? selected;
    var selectedIndex = masked.length;
    for (final String marker in markers) {
      final int index = masked.indexOf(marker);
      if (index >= 0 && index < selectedIndex) {
        selected = marker;
        selectedIndex = index;
      }
    }
    if (selected == null) return null;
    return masked
        .substring(selectedIndex + selected.length)
        .replaceAll(RegExp(r'^[/*#\-\s]+'), '');
  }
}

/// One reviewed triage decision retained in a baseline ledger.
final class BaselineEntry {
  /// Creates a triage entry from decoded machine data.
  const BaselineEntry({
    required this.fingerprint,
    required this.code,
    required this.path,
    required this.message,
    required this.status,
    required this.reason,
    required this.owner,
    required this.expiry,
    required this.ruleVersion,
    required this.sourceFingerprint,
    required this.history,
  });

  /// Stable finding fingerprint.
  final String fingerprint;

  /// Rule identifier.
  final String code;

  /// Project-relative source path.
  final String path;

  /// Finding message retained for compatibility matching.
  final String message;

  /// Triage state such as accepted, fixed, or false-positive.
  final String status;

  /// Human review rationale.
  final String reason;

  /// Optional responsible owner.
  final String owner;

  /// Optional ISO-8601 expiry date.
  final String expiry;

  /// Rule behavior version at review time.
  final int ruleVersion;

  /// Source identity at review time.
  final String sourceFingerprint;

  /// Ordered state-transition records.
  final List<Map<String, Object?>> history;
}

/// Reads and writes stable finding baselines and triage ledgers.
final class BaselineCodec {
  /// Reads a JSON baseline or legacy newline-delimited fingerprints from [file].
  static Set<String> read(File file) {
    if (!file.existsSync()) {
      return const <String>{};
    }
    final String content = file.readAsStringSync();
    try {
      final Object? decoded = jsonDecode(content);
      final Object? rawEntries = decoded is Map ? decoded['entries'] : decoded;
      if (rawEntries is! List) return const <String>{};
      final Set<String> result = <String>{};
      for (final Object? entry in rawEntries) {
        if (entry is! Map) {
          continue;
        }
        final Object? status = entry['status'];
        if (status is String &&
            !const <String>{
              'accepted',
              'false-positive',
              'wont-fix',
            }.contains(status)) {
          continue;
        }
        final Object? expiry = entry['expiry'];
        if (expiry is String && expiry.isNotEmpty) {
          final DateTime? date = DateTime.tryParse(expiry);
          if (date != null && date.isBefore(DateTime.now().toUtc())) continue;
        }
        final Object? code = entry['code'];
        final Object? path = entry['path'];
        final Object? message = entry['message'];
        final Object? fingerprint = entry['fingerprint'];
        if (code is String && path is String && message is String) {
          result.add('$code|$path|$message');
        }
        if (fingerprint is String && fingerprint.isNotEmpty) {
          result.add(fingerprint);
        }
      }
      return Set<String>.unmodifiable(result);
    } on FormatException {
      return Set<String>.unmodifiable(
        content
            .split('\n')
            .map((String line) => line.trim())
            .where((String line) => line.isNotEmpty && !line.startsWith('#'))
            .toSet(),
      );
    }
  }

  /// Writes a JSON baseline with stable keys and enriched finding locations.
  static void write(File file, Iterable<Finding> findings) {
    final Map<String, Map<String, Object>> existing = _metadata(file);
    final List<Map<String, Object>> entries = findings
        .map(
          (Finding finding) => <String, Object>{
            'status': 'accepted',
            'reason': 'baseline snapshot',
            'owner': '',
            'expiry': '',
            'rule_version': RuleCatalog.lookup(finding.code)?.version ?? 1,
            'source_fingerprint': finding.fingerprint,
            'history': <Map<String, Object?>>[
              <String, Object?>{
                'from': null,
                'to': 'accepted',
                'reason': 'baseline snapshot',
              },
            ],
            ...?existing[finding.fingerprint],
            'fingerprint': finding.fingerprint,
            'code': finding.code,
            'severity': finding.severity.configValue,
            'path': finding.path,
            'line': finding.line,
            'end_line': finding.endLine,
            'message': finding.message,
            'confidence': finding.confidence,
            'why': finding.why,
            'suggestion': finding.suggestion,
            'related_files': finding.relatedFiles,
            'snippet': finding.snippet,
            if (finding.codeFlow.isNotEmpty)
              'code_flow': finding.codeFlow
                  .map((CodeFlowStep step) => step.toJson())
                  .toList(growable: false),
          },
        )
        .toList(growable: false);
    file.writeAsStringSync(
      const JsonEncoder.withIndent('  ').convert(<String, Object>{
        'schemaVersion': 2,
        'kind': 'code-buster-triage-ledger',
        'entries': entries,
      }),
    );
  }

  static Map<String, Map<String, Object>> _metadata(File file) {
    if (!file.existsSync()) return const <String, Map<String, Object>>{};
    try {
      final Object? decoded = jsonDecode(file.readAsStringSync());
      final Object? rawEntries = decoded is Map ? decoded['entries'] : decoded;
      if (rawEntries is! List) return const <String, Map<String, Object>>{};
      final Map<String, Map<String, Object>> result =
          <String, Map<String, Object>>{};
      for (final Object? raw in rawEntries) {
        if (raw is! Map) continue;
        final Object? fingerprint = raw['fingerprint'];
        if (fingerprint is! String || fingerprint.isEmpty) continue;
        final Map<String, Object> copied = <String, Object>{};
        for (final MapEntry<Object?, Object?> field in raw.entries) {
          final Object? key = field.key;
          final Object? value = field.value;
          if (key is String && value != null) copied[key] = value;
        }
        result[fingerprint] = copied;
      }
      return result;
    } on FormatException {
      return const <String, Map<String, Object>>{};
    }
  }
}

/// Evaluates project-defined regex pattern rules against source code lines.
final class PatternRuleAnalysis {
  /// Finds configured rule matches without scanning comments or string literals.
  List<Finding> findings(
    Map<String, String> sources,
    Iterable<PatternRule> rules,
  ) {
    final List<Finding> result = <Finding>[];
    final List<String> paths = sources.keys.toList()..sort();
    for (final String path in paths) {
      final List<String> lines = sources[path]!.split('\n');
      for (var index = 0; index < lines.length; index++) {
        final String code = _codeText(lines[index]);
        for (final PatternRule rule in rules) {
          if (!_matchesAny(code, rule.pattern) ||
              (rule.patternNot.isNotEmpty &&
                  _matchesAny(code, rule.patternNot))) {
            continue;
          }
          result.add(
            Finding(
              code: rule.id,
              severity: rule.severity,
              path: path,
              line: index + 1,
              message: rule.message.isEmpty
                  ? 'custom pattern matched'
                  : rule.message,
              confidence: 'medium',
              why: rule.category.isEmpty
                  ? 'This finding was produced by a project-defined pattern rule.'
                  : 'This finding was produced by a project-defined pattern rule in category `${rule.category}`.',
              suggestion: _suggestion(rule),
            ),
          );
        }
      }
    }
    return List<Finding>.unmodifiable(result);
  }

  bool _matchesAny(String source, String pattern) {
    for (final String part in pattern.split(';;')) {
      final String expression = part.trim();
      if (expression.isNotEmpty && RegExp(expression).hasMatch(source)) {
        return true;
      }
    }
    return false;
  }

  String _suggestion(PatternRule rule) => rule.fix.isEmpty
      ? rule.suggestion
      : rule.suggestion.isEmpty
      ? 'Fix: ${rule.fix}'
      : '${rule.suggestion} Fix: ${rule.fix}';
}

String _codeText(String line) {
  final String masked = _maskStrings(line);
  final int slash = masked.indexOf('//');
  final int block = masked.indexOf('/*');
  final int marker = slash < 0
      ? block
      : (block < 0 ? slash : (slash < block ? slash : block));
  return marker < 0 ? masked : masked.substring(0, marker);
}

String _maskStrings(String source) => source.replaceAll(
  RegExp(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' '''.trim()),
  ' ',
);
