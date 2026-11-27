import { spawn } from 'node:child_process';
import { appendFile, lstat, mkdir, mkdtemp, open, readFile, realpath, rm } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { executableVersion, installRelease, packageVersion } from './install.mjs';

function input(env, name, fallback = '') {
  return (env[`INPUT_${name.toUpperCase()}`] ?? fallback).trim();
}

function booleanInput(env, name, fallback) {
  const value = input(env, name, String(fallback)).toLowerCase();
  if (value !== 'true' && value !== 'false') throw new Error(`${name} must be true or false.`);
  return value === 'true';
}

export function readInputs(env) {
  return {
    version: input(env, 'version'),
    path: input(env, 'path', '.') || '.',
    executable: input(env, 'executable'),
    changedBase: input(env, 'changed-base'),
    advisory: booleanInput(env, 'advisory', true),
    failOnIssues: booleanInput(env, 'fail-on-issues', true),
  };
}

export async function scanRoot(workspace, path) {
  const root = await realpath(resolve(workspace, path));
  const offset = relative(workspace, root);
  if (isAbsolute(offset) || offset === '..' || offset.startsWith(`..${sep}`)) {
    throw new Error('path must resolve inside GITHUB_WORKSPACE.');
  }
  if (!(await lstat(root)).isDirectory()) throw new Error('path must be a directory.');
  return root;
}

export function reviewArguments(root, format, inputs) {
  const args = ['review', '--root', root, '--format', format, '--verbose', '--no-cache'];
  if (inputs.advisory) args.push('--advisory', '--all-findings');
  if (inputs.changedBase) args.push('--changed-base', inputs.changedBase);
  return args;
}

export function validateReport(report) {
  if (report.schemaVersion !== 3 || report.command !== 'review' || report.manifest?.status !== 'complete') {
    throw new Error('CB did not produce a complete supported review report (schema 3 required).');
  }
  const counts = {
    actionable: report.actionableFindingCount,
    advisory: report.advisorySummary?.total,
    files: report.files,
    codeLines: report.sourceMetrics?.codeLines,
  };
  for (const [name, count] of Object.entries(counts)) {
    if (!Number.isSafeInteger(count) || count < 0) throw new Error(`CB report has invalid ${name} measurement.`);
  }
  if (counts.files === 0) throw new Error('No supported source files were analyzed; this is not a clean scan.');
  return counts;
}

export async function setOutputs(file, values) {
  if (!file) return;
  const lines = [];
  for (const [name, value] of Object.entries(values)) {
    // Runner paths and validated measurements cannot introduce workflow records.
    if (/[\r\n]/.test(String(value))) throw new Error(`Output ${name} contains a line break.`);
    lines.push(`${name}=${value}\n`);
  }
  await appendFile(file, lines.join(''));
}

export function safeText(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('|', '&#124;').replaceAll('`', '&#96;')
    .replace(/[\r\n]/g, ' ');
}

async function runReview(executable, args, cwd, env, destination, diagnosticPath) {
  const output = await open(destination, 'wx', 0o600);
  let diagnostics;
  try {
    diagnostics = await open(diagnosticPath, 'wx', 0o600);
    const status = await new Promise((resolveStatus, reject) => {
      const child = spawn(executable, args, {
        cwd, env, shell: false, windowsHide: true,
        stdio: ['ignore', output.fd, diagnostics.fd],
      });
      child.once('error', reject);
      child.once('close', (code, signal) => resolveStatus({ code, signal }));
    });
    if (status.code !== 0) {
      throw new Error(`CB review failed (${status.signal || status.code}); diagnostics: ${diagnosticPath}`);
    }
  } finally {
    await output.close();
    await diagnostics?.close();
  }
}

export async function runAction(env = process.env) {
  const inputs = readInputs(env);
  const workspace = await realpath(env.GITHUB_WORKSPACE || process.cwd());
  const root = await scanRoot(workspace, inputs.path);
  const temporary = await mkdtemp(join(env.RUNNER_TEMP || tmpdir(), 'code-buster-action-'));
  const engineDirectory = join(temporary, 'engine');
  const reportDirectory = join(temporary, 'reports');
  await mkdir(reportDirectory);
  await setOutputs(env.GITHUB_OUTPUT, { 'report-directory': reportDirectory });
  try {
    const executable = inputs.executable
      ? await realpath(resolve(workspace, inputs.executable))
      : await installRelease(inputs.version || packageVersion(
        await readFile(new URL('../../Cargo.toml', import.meta.url), 'utf8')), engineDirectory);
    if (!(await lstat(executable)).isFile()) throw new Error('executable must be a regular file.');
    const version = await executableVersion(executable);
    const jsonPath = join(reportDirectory, 'code-buster.json');
    const sarifPath = join(reportDirectory, 'code-buster.sarif');
    // Capture the CLI's stable stdout contract. Do not require a newer CLI's
    // optional --output implementation merely to save the Action's artifacts.
    await runReview(executable, reviewArguments(root, 'json', inputs), workspace, env,
      jsonPath, join(reportDirectory, 'json.stderr.txt'));
    const report = JSON.parse(await readFile(jsonPath, 'utf8'));
    const counts = validateReport(report);
    await runReview(executable, reviewArguments(root, 'sarif', inputs), workspace, env,
      sarifPath, join(reportDirectory, 'sarif.stderr.txt'));
    const sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
    if (sarif.version !== '2.1.0' || !Array.isArray(sarif.runs) || sarif.runs.length !== 1
      || sarif.runs[0]?.tool?.driver?.version !== version) {
      throw new Error('CB did not produce a supported SARIF 2.1.0 report matching the executable version.');
    }
    await setOutputs(env.GITHUB_OUTPUT, {
      'json-path': jsonPath, 'sarif-path': sarifPath,
      'actionable-count': counts.actionable, 'advisory-count': counts.advisory,
      'files-scanned': counts.files, 'code-lines': counts.codeLines, 'cb-version': version,
    });
    const shouldFail = inputs.failOnIssues && counts.actionable > 0;
    if (env.GITHUB_STEP_SUMMARY) {
      await appendFile(env.GITHUB_STEP_SUMMARY,
        `## Code Buster\n\nRoot: <code>${safeText(relative(workspace, root) || '.')}</code> · Engine: <code>${safeText(version)}</code>\n\n`
        + '| Analyzed files | Code lines | Actionable | Advisory |\n| ---: | ---: | ---: | ---: |\n'
        + `| ${counts.files} | ${counts.codeLines} | ${counts.actionable} | ${counts.advisory} |\n\n`
        + `Policy: ${inputs.failOnIssues ? 'fail on actionable findings' : 'report only'}. Advisories remain review evidence, not proven defects.\n`
        + (inputs.executable ? '\nEngine source: explicitly supplied executable; no release checksum claim.\n' : '\nEngine source: checksum-verified published release.\n'));
    }
    return { ...counts, version, reportDirectory, jsonPath, sarifPath, shouldFail };
  } finally {
    // Keep reports and diagnostics for upload, including when analysis fails.
    await rm(engineDirectory, { recursive: true, force: true });
  }
}
