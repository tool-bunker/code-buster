import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { checksumFor, packageVersion, pinnedVersion, releaseFor, verifyArchive } from '../src/install.mjs';
import { readInputs, safeText, scanRoot, setOutputs, validateReport } from '../src/review.mjs';

async function scratch(t) {
  const directory = await mkdtemp(join(tmpdir(), 'cb-action-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function report() {
  return {
    schemaVersion: 3, command: 'review', manifest: { status: 'complete' },
    actionableFindingCount: 2, advisorySummary: { total: 5 }, files: 7,
    sourceMetrics: { codeLines: 100 },
  };
}

test('checksum selection accepts CRLF but rejects missing, ambiguous and lookalike entries', () => {
  const first = 'a'.repeat(64);
  const second = 'b'.repeat(64);
  assert.equal(checksumFor(`${second}  other.tar.gz\r\n${first} *engine.tar.gz\r\n`, 'engine.tar.gz'), first);
  for (const text of [
    `${first}  not-engine.tar.gz\n`,
    `${first}  engine.tar.gz.extra\n`,
    `${first}  engine.tar.gz\n${second}  engine.tar.gz\n`,
    `invalid  engine.tar.gz\n`,
  ]) assert.throws(() => checksumFor(text, 'engine.tar.gz'));
});

test('tampered archive bytes are rejected before installation', async t => {
  const directory = await scratch(t);
  const archive = join(directory, 'archive');
  const expected = createHash('sha256').update('original release bytes').digest('hex');
  await writeFile(archive, 'tampered release bytes');
  await assert.rejects(verifyArchive(archive, expected));
});

test('release selectors reject floating references, URL paths and unavailable architectures', () => {
  assert.equal(pinnedVersion('v0.14.5-rc.1+build'), '0.14.5-rc.1+build');
  for (const value of ['latest', 'main', '../0.14.5', '0.14.5?redirect=other', '01.2.3', '1.2']) {
    assert.throws(() => pinnedVersion(value));
  }
  assert.throws(() => releaseFor('linux', 'arm64'));
  assert.throws(() => releaseFor('darwin', 'x64'));
});

test('default release version comes from the package table, not dependencies or comments', () => {
  const manifest = '# version = "9.0.0"\r\n[package]\r\nname = "code-buster"\r\nversion = "0.14.6" # engine\r\n\r\n[dependencies]\r\nversion = "8.0.0"\r\n';
  assert.equal(packageVersion(manifest), '0.14.6');
  assert.throws(() => packageVersion('[dependencies]\nversion = "8.0.0"\n'));
  assert.throws(() => packageVersion('[package]\nversion.workspace = true\n'));
});

test('incomplete, unsupported, empty and malformed measurements never pass as clean reports', () => {
  assert.deepEqual(validateReport(report()), { actionable: 2, advisory: 5, files: 7, codeLines: 100 });
  for (const invalid of [
    { ...report(), schemaVersion: 4 },
    { ...report(), manifest: { status: 'failed' } },
    { ...report(), files: 0 },
    { ...report(), actionableFindingCount: -1 },
    { ...report(), advisorySummary: { total: '0' } },
    { ...report(), sourceMetrics: undefined },
  ]) assert.throws(() => validateReport(invalid));
});

test('realpath containment rejects sibling-prefix and symlink escapes', async t => {
  const directory = await scratch(t);
  const workspace = join(directory, 'project');
  const sibling = join(directory, 'project-other');
  await mkdir(join(workspace, 'src'), { recursive: true });
  await mkdir(sibling);
  await symlink(sibling, join(workspace, 'outside'), process.platform === 'win32' ? 'junction' : 'dir');
  const canonicalWorkspace = await realpath(workspace);
  assert.equal(await scanRoot(canonicalWorkspace, 'src'), await realpath(join(workspace, 'src')));
  await assert.rejects(scanRoot(canonicalWorkspace, '../project-other'));
  await assert.rejects(scanRoot(canonicalWorkspace, 'outside'));
  await assert.rejects(scanRoot(canonicalWorkspace, '../../'));
});

test('workflow output injection is rejected without partially appending records', async t => {
  const directory = await scratch(t);
  const outputs = join(directory, 'outputs');
  await writeFile(outputs, 'existing=value\n');
  await assert.rejects(setOutputs(outputs, { 'files-scanned': 5, 'json-path': 'report\ninjected=bad' }));
  assert.equal(await readFile(outputs, 'utf8'), 'existing=value\n');
});

test('invalid policy switches cannot silently become report-only', () => {
  assert.equal(readInputs({ 'INPUT_FAIL-ON-ISSUES': 'false', INPUT_ADVISORY: 'false' }).failOnIssues, false);
  assert.throws(() => readInputs({ 'INPUT_FAIL-ON-ISSUES': 'false; command' }));
  assert.throws(() => readInputs({ INPUT_ADVISORY: 'maybe' }));
});

test('summary root labels cannot inject HTML, table cells or inline-code delimiters', () => {
  assert.equal(safeText('</code>|`\n<img>'), '&lt;/code&gt;&#124;&#96; &lt;img&gt;');
});
