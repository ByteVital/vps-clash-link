import net from 'node:net';
import https from 'node:https';
import { spawn } from 'node:child_process';
import { writeFile, mkdtemp, rm } from 'node:fs/promises';
import { once } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { clashObject } from './profiles.js';

export async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function ready(port, timeout = 6000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const connected = await new Promise(resolve => {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      let settled = false;
      const finish = value => { if (settled) return; settled = true; socket.destroy(); resolve(value); };
      socket.setTimeout(400);
      socket.once('connect', () => finish(true));
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));
    });
    if (connected) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('本机代理端口启动超时。');
}

export function viaProxy(url, port, timeout = 12000) {
  const agent = new HttpsProxyAgent(`http://127.0.0.1:${port}`);
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const request = https.get(url, { agent, headers: { 'User-Agent': 'vps-clash-link/0.1' } }, response => {
      let body = '', size = 0;
      response.setEncoding('utf8');
      response.on('data', chunk => { size += chunk.length; if (size > 65536) request.destroy(new Error('响应过大。')); else body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body, milliseconds: Date.now() - started }));
      response.on('error', reject);
    });
    const timer = setTimeout(() => request.destroy(new Error('连接测试超时。')), timeout);
    request.on('error', reject);
    request.on('close', () => { clearTimeout(timer); agent.destroy(); });
  });
}

export async function verifyPort(proxyPort, expectedIp) {
  const [ip, google] = await Promise.allSettled([
    viaProxy('https://api.ipify.org', proxyPort),
    viaProxy('https://www.google.com/generate_204', proxyPort),
  ]);
  const egress = ip.status === 'fulfilled' && ip.value.status === 200 ? ip.value.body.trim() : null;
  const httpPassed = google.status === 'fulfilled' && google.value.status === 204;
  return { verified: egress === expectedIp && httpPassed, egress,
    googleStatus: google.status === 'fulfilled' ? google.value.status : null,
    milliseconds: google.status === 'fulfilled' ? google.value.milliseconds : null,
    note: egress === expectedIp && httpPassed ? '出口 IP 与 Google 连接验证通过。' : '未完成全部连接验证；请检查云防火墙端口、线路或出口 NAT。' };
}

export async function verifyNode(node, core) {
  if (!core) return { verified: false, unavailable: true, note: '未找到本机 Mihomo 内核；已生成配置，可导入客户端后验证。' };
  const directory = await mkdtemp(path.join(os.tmpdir(), 'vps-clash-link-'));
  let child;
  try {
    const proxyPort = await freePort();
    const config = { ...clashObject(node), 'mixed-port': proxyPort, 'bind-address': '127.0.0.1', 'allow-lan': false,
      'external-controller': '', 'log-level': 'silent' };
    const file = path.join(directory, 'config.yaml');
    await writeFile(file, YAML.stringify(config), { mode: 0o600 });
    child = spawn(core, ['-d', directory, '-f', file], { windowsHide: true, stdio: 'ignore' });
    let spawnError;
    child.on('error', error => { spawnError = error; });
    await ready(proxyPort);
    if (spawnError) throw spawnError;
    return await verifyPort(proxyPort, node.host);
  } catch { return { verified: false, note: '本机验证失败；配置仍可下载，自动导入已暂停。' }; }
  finally {
    if (child && child.exitCode === null && child.pid) {
      const closed = once(child, 'close').catch(() => {});
      child.kill();
      await Promise.race([closed, new Promise(resolve => setTimeout(resolve, 3000))]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
    await rm(directory, { recursive: true, force: true });
  }
}
