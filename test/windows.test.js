import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { appendProfile, importClash } from '../src/windows.js';

const original = '# Original comment\ncurrent: Old\nunknown: preserved\nitems:\n- uid: Old\n  type: local\n  name: Existing\n  file: old.yaml\n';
test('appending selects the new profile and retains existing entries and unknown fields', () => {
  const result = appendProfile(original, { name: 'VPS-203.0.113.10' }, 'new.yaml', 'New');
  const parsed = YAML.parse(result.text);
  assert.equal(parsed.current, 'New');
  assert.equal(parsed.items[0].uid, 'Old');
  assert.equal(parsed.items[1].selected[0].now, 'VPS-203.0.113.10');
  assert.equal(parsed.unknown, 'preserved');
  assert.ok(result.text.includes('# Original comment'));
});
test('malformed profile indices fail before any import', () => {
  assert.throws(() => appendProfile('items: nope', { name: 'test' }, 'test.yaml'));
  assert.throws(() => appendProfile('items: [', { name: 'test' }, 'test.yaml'));
});

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vcl-windows-'));
  const dataDir = path.join(root, 'clash'); await mkdir(path.join(dataDir, 'profiles'), { recursive: true });
  const settings = '# User preferences\nenable_system_proxy: false\nverge_mixed_port: 7897\n';
  await writeFile(path.join(dataDir, 'profiles.yaml'), original);
  await writeFile(path.join(dataDir, 'verge.yaml'), settings);
  const profilePath = path.join(root, 'export.yaml');
  const name = 'VPS-203.0.113.10';
  await writeFile(profilePath, YAML.stringify({ proxies: [{ name, type: 'ss', server: '203.0.113.10' }] }));
  return { root, dataDir, settings, artifact: { name, profilePath }, detection: { available: true, dataDir, executable: 'test.exe', mixedPort: 7897 } };
}

test('successful import backs up preferences and writes a separate local profile', async () => {
  const f = await fixture(), calls = [];
  try {
    const result = await importClash(f.artifact, path.join(f.root, 'backups'), { detection: f.detection,
      enableSystemProxy: true, controller: async action => calls.push(action) });
    assert.deepEqual(calls, ['Stop', 'Start']);
    assert.equal(await readFile(path.join(result.backup, 'profiles.yaml'), 'utf8'), original);
    assert.equal(YAML.parse(await readFile(path.join(f.dataDir, 'verge.yaml'), 'utf8')).enable_system_proxy, true);
    assert.equal((await readdir(path.join(f.dataDir, 'profiles'))).length, 1);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('app startup failure restores both index and preferences and removes the new profile', async () => {
  const f = await fixture(); let starts = 0;
  try {
    await assert.rejects(importClash(f.artifact, path.join(f.root, 'backups'), { detection: f.detection,
      enableSystemProxy: true, controller: async action => { if (action === 'Start' && starts++ === 0) throw new Error('simulated app error'); } }));
    assert.equal(await readFile(path.join(f.dataDir, 'profiles.yaml'), 'utf8'), original);
    assert.equal(await readFile(path.join(f.dataDir, 'verge.yaml'), 'utf8'), f.settings);
    assert.deepEqual(await readdir(path.join(f.dataDir, 'profiles')), []);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('concurrent configuration edits are preserved instead of overwritten', async () => {
  const f = await fixture();
  try {
    await assert.rejects(importClash(f.artifact, path.join(f.root, 'backups'), { detection: f.detection,
      controller: async action => { if (action === 'Stop') await writeFile(path.join(f.dataDir, 'profiles.yaml'), `${original}# External edit\n`); } }));
    assert.ok((await readFile(path.join(f.dataDir, 'profiles.yaml'), 'utf8')).includes('# External edit'));
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
