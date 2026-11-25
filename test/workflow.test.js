import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runWorkflow, newJob, rememberHost, loadKnownHosts } from '../src/workflow.js';
import { fingerprint } from '../src/ssh.js';

const options = () => ({ host: '203.0.113.10', sshPort: 22, proxyPort: 18443, password: 'test-only-ssh-password',
  fingerprint: fingerprint(Buffer.from('test-host-key')), autoImport: false, enableSystemProxy: false });
const remote = { success: true, port: 18443, method: '2022-blake3-aes-128-gcm', password: Buffer.alloc(16, 1).toString('base64'),
  service: 'vps-clash-link.service', backup: '/var/backups/vps-clash-link/test' };
function adapters(overrides = {}) {
  return { connect: async () => ({ end() {} }), runDeployment: async () => remote,
    detectClash: async () => ({ available: false }), verifyNode: async () => ({ verified: true, egress: '203.0.113.10', note: 'test' }), ...overrides };
}

test('workflow generates credentials locally without including SSH or node passwords in job status', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'vcl-workflow-'));
  try {
    const input = options(), job = newJob(input);
    await runWorkflow(job, input, dir, { adapters: adapters() });
    assert.equal(job.state, 'complete'); assert.equal(input.password, undefined);
    const status = JSON.stringify(job);
    assert.ok(!status.includes('test-only-ssh-password')); assert.ok(!status.includes(remote.password));
    assert.ok((await readFile(path.join(dir, 'jobs', job.id, 'node.txt'), 'utf8')).startsWith('ss://'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('failed verification never imports into the client', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'vcl-workflow-')); let imported = false;
  try {
    const input = { ...options(), autoImport: true }, job = newJob(input);
    await runWorkflow(job, input, dir, { adapters: adapters({ detectClash: async () => ({ available: true, core: 'test' }),
      verifyNode: async () => ({ verified: false, note: 'blocked' }), importClash: async () => { imported = true; } }) });
    assert.equal(job.state, 'attention'); assert.equal(imported, false); assert.ok(job.result.artifacts.clash);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('SSH failures clear the password and redact it from the status', async () => {
  const input = options(), job = newJob(input);
  await runWorkflow(job, input, 'unused', { adapters: adapters({ connect: async () => { throw new Error('failure test-only-ssh-password'); }, loadKnownHosts: async () => ({}) }) });
  assert.equal(job.state, 'failed'); assert.ok(!job.error.includes('test-only-ssh-password')); assert.equal(input.password, undefined);
});
test('changed remembered host keys stop before authentication', async () => {
  const input = options(), job = newJob(input); let connected = false;
  await runWorkflow(job, input, 'unused', { adapters: adapters({ connect: async () => { connected = true; },
    loadKnownHosts: async () => ({ '203.0.113.10:22': 'SHA256:other' }) }) });
  assert.equal(connected, false); assert.equal(job.state, 'failed');
});
test('host trust storage refuses replacement and reports corrupt files', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'vcl-trust-'));
  try {
    const input = options(); await rememberHost(dir, input);
    await assert.rejects(rememberHost(dir, { ...input, fingerprint: 'SHA256:replacement' }));
    assert.equal((await loadKnownHosts(dir))['203.0.113.10:22'], input.fingerprint);
    await writeFile(path.join(dir, 'known-hosts.json'), '{');
    await assert.rejects(loadKnownHosts(dir));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
