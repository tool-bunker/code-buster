import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, lstat, mkdir, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const releaseRoot = 'https://github.com/tool-bunker/code-buster/releases/download';

export function releaseFor(platform, arch) {
  const releases = {
    'linux-x64': { archive: 'code-buster-linux-x64.tar.gz', executable: 'cb' },
    'darwin-arm64': { archive: 'code-buster-macos-arm64.tar.gz', executable: 'cb' },
    'win32-x64': { archive: 'code-buster-windows-x64.zip', executable: 'cb.exe' },
  };
  const release = releases[`${platform}-${arch}`];
  if (!release) throw new Error(`Code Buster does not publish a binary for ${platform}/${arch}.`);
  return release;
}

export function pinnedVersion(value) {
  const version = value.trim().replace(/^v/, '');
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.test(version)) {
    throw new Error('version must be a pinned semantic version, not a branch or latest.');
  }
  return version;
}

export function packageVersion(manifest) {
  const table = /(?:^|\r?\n)\[package\][ \t]*\r?\n([\s\S]*?)(?=\r?\n\[|$)/.exec(manifest)?.[1];
  const version = /^[ \t]*version[ \t]*=[ \t]*"([^"]+)"[ \t]*(?:#.*)?\r?$/m.exec(table || '')?.[1];
  if (!version) throw new Error('The Action requires a literal [package].version in its Cargo.toml.');
  return pinnedVersion(version);
}

export function checksumFor(text, archive) {
  const matches = text.split(/\r?\n/)
    .map(line => /^([0-9a-f]{64})\s+\*?(\S+)\s*$/i.exec(line))
    .filter(match => match && match[2] === archive);
  if (matches.length !== 1) throw new Error(`SHA256SUMS must contain exactly one checksum for ${archive}.`);
  return matches[0][1].toLowerCase();
}

export async function verifyArchive(archive, expected) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(archive)) hash.update(chunk);
  if (hash.digest('hex') !== expected) throw new Error('Code Buster archive checksum mismatch; refusing to extract or execute it.');
}

async function download(url, destination) {
  const response = await fetch(url);
  if (!response.ok || !response.body) throw new Error(`Download failed (${response.status}): ${url}`);
  await pipeline(Readable.fromWeb(response.body), createWriteStream(destination, { flags: 'wx', mode: 0o600 }));
}

export async function executableVersion(executable) {
  const { stdout } = await execute(executable, ['version'], { windowsHide: true });
  const version = /^cb ([^\s]+)\r?$/m.exec(stdout)?.[1];
  if (!version) throw new Error('The executable did not identify itself as Code Buster.');
  return version;
}

export async function installRelease(versionInput, directory) {
  const version = pinnedVersion(versionInput);
  const release = releaseFor(process.platform, process.arch);
  await mkdir(directory, { recursive: true });
  const base = `${releaseRoot}/v${encodeURIComponent(version)}`;
  const archive = join(directory, release.archive);
  const checksums = join(directory, 'SHA256SUMS');
  await download(`${base}/SHA256SUMS`, checksums);
  const expected = checksumFor(await readFile(checksums, 'utf8'), release.archive);
  await download(`${base}/${release.archive}`, archive);
  await verifyArchive(archive, expected);
  // Extract only the executable, not arbitrary additional archive members.
  await execute('tar', ['-xf', archive, '-C', directory, release.executable], { windowsHide: true });
  const executable = join(directory, release.executable);
  if (!(await lstat(executable)).isFile()) throw new Error('Release executable is not a regular file.');
  if (process.platform !== 'win32') await chmod(executable, 0o755);
  if (await executableVersion(executable) !== version) throw new Error(`Downloaded executable does not report Code Buster ${version}.`);
  return executable;
}
