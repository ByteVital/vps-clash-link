import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { clashObject, exportArtifacts, shareUri, METHOD } from '../src/profiles.js';
import { target, deployment, redact } from '../src/validation.js';
import { fingerprint } from '../src/ssh.js';

const node = { host: '203.0.113.10', port: 18443, method: METHOD, password: Buffer.alloc(16, 0xff).toString('base64') };
test('SS2022 URI preserves the unencoded userinfo structure and percent-encodes the key', () => {
  const uri = shareUri(node), parsed = new URL(uri);
  assert.equal(parsed.username, METHOD);
  assert.equal(decodeURIComponent(parsed.password), node.password);
  assert.ok(uri.includes('%2F'));
  assert.equal(parsed.hostname, node.host);
});
test('generated profile routes local traffic directly and uses the requested server', () => {
  const config = clashObject(node);
  assert.equal(config.proxies[0].password, node.password);
  assert.equal(config['proxy-groups'][0].proxies[0], config.proxies[0].name);
  assert.equal(config.rules.at(-1), 'MATCH,Proxy');
  assert.equal(config.proxies[0].udp, true);
});
test('invalid keys and unexpected encryption methods are rejected', () => {
  for (const invalid of [{ password: 'not-a-key' }, { method: 'none' }, { host: 'example.test' }, { port: 0 }]) {
    assert.throws(() => shareUri({ ...node, ...invalid }));
  }
});
test('exports contain a valid YAML profile, matching link and PNG', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'vcl-artifacts-'));
  try {
    const result = await exportArtifacts(node, directory);
    assert.equal(YAML.parse(await readFile(result.profilePath, 'utf8')).proxies[0].server, node.host);
    assert.equal((await readFile(path.join(directory, 'node.txt'), 'utf8')).trim(), result.uri);
    assert.deepEqual((await readFile(path.join(directory, 'node.png'))).subarray(0, 8), Buffer.from([137,80,78,71,13,10,26,10]));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('input validation rejects shell fragments, invalid ports, non-root users and missing consent', () => {
  const input = { host: node.host, username: 'root', password: 'test-only', proxyPort: 18443,
    fingerprint: fingerprint(Buffer.from('test-host-key')), confirmChanges: true };
  assert.equal(deployment(input).sshPort, 22);
  for (const invalid of [{ host: '203.0.113.10; id' }, { sshPort: 65536 }, { proxyPort: 22 },
    { username: 'admin' }, { fingerprint: '' }, { confirmChanges: false }, { password: '' }]) {
    assert.throws(() => deployment({ ...input, ...invalid }));
  }
  assert.throws(() => target(null));
});
test('error redaction removes supplied secrets from repeated occurrences', () => {
  assert.equal(redact('failed test-only / test-only', ['test-only']), 'failed [已隐藏] / [已隐藏]');
});
