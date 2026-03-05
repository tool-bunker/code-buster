// Source that embeds instructions for language models creates a distinct trust boundary and deserves focused evidence rather than a generic string warning.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Canonical metadata owned by AI security rules.
const Map<String, RuleMetadata> aiSecurityRuleMetadata = <String, RuleMetadata>{
  'ai-prompt-injection-instruction': RuleMetadata(
    id: 'ai-prompt-injection-instruction',
    version: 2,
    defaultSeverity: RuleSeverity.warn,
    group: 'core',
    title: 'Review a likely prompt-injection instruction',
    why:
        'Instructions that override trusted prompts can redirect an AI agent or disclose privileged context.',
    suggestion:
        'Treat the content as untrusted data, delimit it from instructions, and enforce the trusted policy outside the prompt.',
    securityKind: SecurityFindingKind.hotspot,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.security},
    limitations: <String>[
      'Requires AI-framework context and an explicit override-style instruction.',
    ],
  ),
  'ai-untrusted-prompt-construction': RuleMetadata(
    id: 'ai-untrusted-prompt-construction',
    defaultSeverity: RuleSeverity.warn,
    group: 'core',
    title: 'Separate untrusted data from AI instructions',
    why:
        'Interpolating request or retrieved content into privileged instructions creates a prompt-injection boundary.',
    suggestion:
        'Pass untrusted content in a clearly delimited data field and keep authorization and tool policy outside model-controlled text.',
    securityKind: SecurityFindingKind.hotspot,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.security},
    limitations: <String>[
      'Uses conservative prompt-target and untrusted-input naming evidence.',
    ],
  ),
  'ai-model-output-to-execution': RuleMetadata(
    id: 'ai-model-output-to-execution',
    defaultSeverity: RuleSeverity.error,
    group: 'core',
    title: 'Do not execute AI model output directly',
    why:
        'Prompt-injected model output reaching a command runner can turn text manipulation into arbitrary code execution.',
    suggestion:
        'Replace free-form execution with a typed allowlisted action schema and independently validate every argument.',
    securityKind: SecurityFindingKind.hotspot,
    taxonomy: <FindingTaxonomy>{FindingTaxonomy.security},
    limitations: <String>[
      'Tracks a named model-output variable to a nearby command-execution sink.',
    ],
  ),
};

/// Detects explicit prompt-injection instructions embedded in AI-facing source.
final class AiPromptInjectionInstructionRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const AiPromptInjectionInstructionRule();

  @override
  RuleMetadata get metadata =>
      aiSecurityRuleMetadata['ai-prompt-injection-instruction']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_hasAiContext(entry.value)) continue;
      final List<String> lines = context.linesFor(entry.key);
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        final String trimmed = line.trimLeft();
        if (trimmed.startsWith('//') ||
            trimmed.startsWith('/*') ||
            trimmed.startsWith('*') ||
            trimmed.startsWith('#') ||
            !_instruction.hasMatch(line) ||
            !_textLike.hasMatch(line) ||
            _defensiveInstruction.hasMatch(line)) {
          continue;
        }
        yield _finding(
          metadata,
          context,
          entry.key,
          index + 1,
          'prompt contains an instruction commonly used to override trusted directions',
          'high',
          line,
        );
      }
    }
  }
}

/// Detects likely untrusted data interpolated into privileged AI prompts.
final class AiUntrustedPromptConstructionRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const AiUntrustedPromptConstructionRule();

  @override
  RuleMetadata get metadata =>
      aiSecurityRuleMetadata['ai-untrusted-prompt-construction']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_hasAiContext(entry.value)) continue;
      final List<String> lines = context.linesFor(entry.key);
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        final String trimmed = line.trimLeft();
        if (trimmed.startsWith('//') ||
            trimmed.startsWith('/*') ||
            trimmed.startsWith('*') ||
            trimmed.startsWith('#') ||
            !_promptTarget.hasMatch(line) ||
            !_untrustedComposition.hasMatch(line) ||
            RegExp(
              r'\bsanitiz(?:e|ed|er|ing)',
              caseSensitive: false,
            ).hasMatch(line)) {
          continue;
        }
        yield _finding(
          metadata,
          context,
          entry.key,
          index + 1,
          'untrusted-looking data is composed into an AI instruction or prompt',
          'medium',
          line,
        );
      }
    }
  }
}

/// Detects model output passed to command execution without an evident boundary.
final class AiModelOutputExecutionRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const AiModelOutputExecutionRule();

  @override
  RuleMetadata get metadata =>
      aiSecurityRuleMetadata['ai-model-output-to-execution']!;

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      if (!_hasAiContext(entry.value)) continue;
      final List<String> lines = context.linesFor(entry.key);
      for (var index = 0; index < lines.length; index++) {
        final RegExpMatch? assignment = _modelOutputAssignment.firstMatch(
          lines[index],
        );
        if (assignment == null) continue;
        final String variable = assignment.group(1)!;
        final int limit = (index + 13).clamp(0, lines.length);
        for (var sinkIndex = index + 1; sinkIndex < limit; sinkIndex++) {
          final String sink = lines[sinkIndex];
          if (!_executionSink.hasMatch(sink) ||
              !RegExp('\\b${RegExp.escape(variable)}\\b').hasMatch(sink)) {
            continue;
          }
          yield Finding(
            code: metadata.id,
            severity:
                context.config.severityOverrides[metadata.id] ??
                metadata.defaultSeverity,
            path: entry.key,
            line: index + 1,
            endLine: sinkIndex + 1,
            message:
                'AI model output `$variable` reaches command execution without evident validation',
            confidence: 'high',
            why: metadata.why,
            suggestion: metadata.suggestion,
            snippet: lines[index].trim(),
            codeFlow: <CodeFlowStep>[
              CodeFlowStep(
                path: entry.key,
                line: index + 1,
                message: 'model output assigned to `$variable`',
              ),
              CodeFlowStep(
                path: entry.key,
                line: sinkIndex + 1,
                message: 'value passed to command execution',
              ),
            ],
          );
          break;
        }
      }
    }
  }
}

Finding _finding(
  RuleMetadata metadata,
  RuleContext context,
  String path,
  int line,
  String message,
  String confidence,
  String snippet,
) => Finding(
  code: metadata.id,
  severity:
      context.config.severityOverrides[metadata.id] ?? metadata.defaultSeverity,
  path: path,
  line: line,
  endLine: line,
  message: message,
  confidence: confidence,
  why: metadata.why,
  suggestion: metadata.suggestion,
  snippet: snippet.trim(),
);

bool _hasAiContext(String source) => _aiContext.hasMatch(source);

final RegExp _aiContext = RegExp(
  r'(?<![A-Za-z0-9])(?:openai|anthropic|claude|gemini|generativeai|langchain|semantic.?kernel|chatcompletion|chat.?completion|systemprompt|system_prompt|llm|language.?model)(?![A-Za-z0-9])',
  caseSensitive: false,
);
final RegExp _instruction = RegExp(
  r'ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)|disregard\s+(?:the\s+)?(?:previous|prior|system|developer)\s+(?:instructions?|prompts?|message)|override\s+(?:the\s+)?(?:system|developer)\s+(?:instructions?|prompt|message)|reveal\s+(?:the\s+)?system\s+prompt|you\s+are\s+now\s+(?:(?:an?\s+)[a-z][\w-]*(?:\s+[a-z][\w-]*){0,3}|dan\b|(?:in\s+)?(?:developer|jailbreak|god)\s+mode\b)|do\s+not\s+follow\s+(?:the\s+)?(?:previous|system|developer)',
  caseSensitive: false,
);
final RegExp _textLike = RegExp(r'''["'`]|//|/\*|<!--|#''');
final RegExp _defensiveInstruction = RegExp(
  r'treat\s+.*\s+as\s+(?:untrusted\s+)?data|never\s+(?:as\s+)?instructions|do\s+not\s+follow|disregard\s+it|defen[cs]e\s+against\s+prompt\s+injection|prompt.?injection|sanitiz',
  caseSensitive: false,
);
final RegExp _promptTarget = RegExp(
  r'''(?:system|user|developer)?_?prompt\s*(?:=|:)|(?:system|user|developer).?message|messages?\.(?:push|add)|["'](?:system|user|developer)["']\s*:''',
  caseSensitive: false,
);
final RegExp _untrustedComposition = RegExp(
  r'''(?:\$?\{[^}\n]*(?:user.?input|request\.(?:body|query)|req\.(?:body|query)|input\.(?:query|content|text)|retrieved|document|payload|currentHtml|evidence|headlines?|headlineText|feed.?content|story.?content)[^}\n]*\}|(?:\+|\.format\s*\()[^\n]*(?:user.?input|request\.(?:body|query)|req\.(?:body|query)|input\.(?:query|content|text)|retrieved|document|payload|currentHtml|evidence|headlines?|headlineText|feed.?content|story.?content))''',
  caseSensitive: false,
);
final RegExp _modelOutputAssignment = RegExp(
  r'\b((?:response|completion|modelOutput|model_output|assistantOutput|assistant_output|llmOutput|llm_output)\w*|[A-Za-z_]\w*(?:Response|Completion|ModelOutput|AssistantOutput|LlmOutput)\w*)\s*=',
  caseSensitive: false,
);
final RegExp _executionSink = RegExp(
  r'Process\.(?:run|start)|Runtime\.getRuntime\(\)\.exec|subprocess\.(?:run|Popen|call)|os\.system|child_process\.(?:exec|spawn)|(?:^|[^\w])(?:exec|execSync|spawn|spawnSync)\s*\(',
  caseSensitive: false,
);
