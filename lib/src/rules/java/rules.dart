// The Java registry is the single execution list for its correctness, resource, concurrency, and security checks.

import '../../core/rule.dart';
import 'catch_exception.dart';
import 'empty_catch.dart';
import 'hardcoded_secret.dart';
import 'object_input_stream.dart';
import 'package_cycle.dart';
import 'print_stacktrace.dart';
import 'random_security.dart';
import 'resource_not_closed.dart';
import 'sql_string_build.dart';
import 'string_concat_loop.dart';
import 'string_equals.dart';
import 'system_out.dart';
import 'thread_sleep.dart';
import 'too_many_parameters.dart';
import 'weak_crypto.dart';

/// Self-contained Java rules in deterministic execution order.
final RuleRegistry javaRuleRegistry = RuleRegistry(<CodeBusterRule>[
  javaCatchExceptionRule,
  const JavaEmptyCatchRule(),
  const JavaHardcodedSecretRule(),
  javaObjectInputStreamRule,
  const JavaPackageCycleRule(),
  javaPrintStacktraceRule,
  const JavaRandomSecurityRule(),
  const JavaResourceNotClosedRule(),
  javaSystemOutRule,
  javaSqlStringBuildRule,
  const JavaStringConcatLoopRule(),
  javaStringEqualsRule,
  javaThreadSleepRule,
  const JavaTooManyParametersRule(),
  javaWeakCryptoRule,
]);
