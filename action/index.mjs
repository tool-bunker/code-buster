import { appendFile } from 'node:fs/promises';
import { runAction, safeText } from './src/review.mjs';

function reportError(error) {
  const message = String(error.message || error).replaceAll('%', '%25')
    .replaceAll('\r', '%0D').replaceAll('\n', '%0A');
  process.stderr.write(`::error::${message}\n`);
  process.exitCode = 1;
}

try {
  const result = await runAction();
  console.log(`Code Buster ${result.version}: ${result.actionable} actionable, ${result.advisory} advisory; ${result.files} files.`);
  if (result.shouldFail) reportError(new Error(`Code Buster found ${result.actionable} actionable findings. Reports were retained.`));
} catch (error) {
  reportError(error);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY,
      `## Code Buster could not complete\n\n<code>${safeText(error.message || error)}</code>\n\nDo not interpret this as a clean scan.\n`)
      .catch(reportError);
  }
}
