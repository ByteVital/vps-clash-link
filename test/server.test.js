import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { createApplication } from '../src/server.js';

async function app(options = {}) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'vcl-server-'));
  const server = createApplication({ dataDir, demo: true, ...options });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const page = await fetch(base), html = await page.text();
  const cookie = page.headers.get('set-cookie').split(';')[0];
  const token = html.match(/name="vps-link-token" content="([a-f0-9]+)"/)[1];
  return { server, base, headers: { Cookie: cookie, 'X-Vps-Link-Token': token, 'Content-Type': 'application/json' },
    close: async () => { await server.activeTask; await new Promise(resolve => server.close(resolve)); await rm(dataDir, { recursive: true, force: true }); } };
}
test('API requests require a session, mutation token and same-origin request', async () => {
  const f = await app();
  try {
    assert.equal((await fetch(`${f.base}/api/info`)).status, 403);
    assert.equal((await fetch(`${f.base}/api/info`, { headers: f.headers })).status, 200);
    assert.equal((await fetch(`${f.base}/api/inspect`, { method: 'POST', headers: { Cookie: f.headers.Cookie, 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
    assert.equal((await fetch(`${f.base}/api/inspect`, { method: 'POST', headers: { ...f.headers, Origin: 'https://attacker.invalid' }, body: '{}' })).status, 403);
  } finally { await f.close(); }
});
test('a demo task completes locally and its artifacts remain session-protected', async () => {
  const f = await app();
  try {
    const inspection = await (await fetch(`${f.base}/api/inspect`, { method: 'POST', headers: f.headers,
      body: JSON.stringify({ host: '203.0.113.10' }) })).json();
    const response = await fetch(`${f.base}/api/deploy`, { method: 'POST', headers: f.headers,
      body: JSON.stringify({ host: '203.0.113.10', password: 'demo-only', fingerprint: inspection.fingerprint, confirmChanges: true }) });
    assert.equal(response.status, 202);
    const { id } = await response.json(); await f.server.activeTask;
    const job = await (await fetch(`${f.base}/api/jobs/${id}`, { headers: f.headers })).json();
    assert.equal(job.state, 'complete'); assert.equal(job.result.demo, true);
    assert.equal((await fetch(`${f.base}${job.result.artifacts.qr}`)).status, 403);
    const png = await fetch(`${f.base}${job.result.artifacts.qr}`, { headers: f.headers });
    assert.equal(png.headers.get('content-type'), 'image/png'); assert.equal(png.status, 200);
    const yaml = await fetch(`${f.base}${job.result.artifacts.clash}`, { headers: f.headers });
    assert.ok(yaml.headers.get('content-disposition').includes('attachment'));
  } finally { await f.close(); }
});
test('rejects overlapping deployments without starting a second workflow', async () => {
  let finish, calls = 0;
  const f = await app({ workflow: async job => { calls++; await new Promise(resolve => { finish = resolve; }); job.state = 'complete'; } });
  try {
    const body = JSON.stringify({ host: '203.0.113.10', password: 'demo-only', fingerprint: `SHA256:${Buffer.alloc(32).toString('base64').replace(/=+$/, '')}`, confirmChanges: true });
    const request = () => fetch(`${f.base}/api/deploy`, { method: 'POST', headers: f.headers, body });
    assert.equal((await request()).status, 202); assert.equal((await request()).status, 409); assert.equal(calls, 1);
  } finally { finish?.(); await f.close(); }
});
test('host validation blocks DNS rebinding and malformed JSON never echoes credentials', async () => {
  const f = await app();
  try {
    const invalidHostStatus = await new Promise((resolve, reject) => {
      const request = http.get(`${f.base}/api/info`, { headers: { ...f.headers, Host: 'attacker.invalid' } }, response => {
        response.resume(); resolve(response.statusCode);
      });
      request.on('error', reject);
    });
    assert.equal(invalidHostStatus, 403);
    const response = await fetch(`${f.base}/api/deploy`, { method: 'POST', headers: f.headers, body: '{"password":"test-only-secret"' });
    assert.equal(response.status, 400); assert.ok(!(await response.text()).includes('test-only-secret'));
  } finally { await f.close(); }
});
