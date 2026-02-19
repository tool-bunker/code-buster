// Parser and pipeline failures are not source findings, so they need a separate structured channel with their own severity and stage.

/// Severity of an analyzer-processing problem, separate from source findings.
enum ProcessingDiagnosticSeverity {
  /// Analysis recovered and produced useful output.
  warning,

  /// An analysis stage could not produce trustworthy output.
  error,
}

extension on ProcessingDiagnosticSeverity {
  String get wireValue => switch (this) {
    ProcessingDiagnosticSeverity.warning => 'warning',
    ProcessingDiagnosticSeverity.error => 'error',
  };
}

/// A decoding, parsing, configuration, cache, or rule-execution problem.
final class ProcessingDiagnostic {
  const ProcessingDiagnostic({
    required this.code,
    required this.severity,
    required this.stage,
    required this.message,
    this.path = '',
  });

  final String code;

  final ProcessingDiagnosticSeverity severity;

  final String stage;

  final String message;

  final String path;

  Map<String, Object> toJson() => <String, Object>{
    'code': code,
    'severity': severity.wireValue,
    'stage': stage,
    'message': message,
    if (path.isNotEmpty) 'path': path,
  };
}
