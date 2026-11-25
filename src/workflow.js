import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { connect, runDeployment } from './ssh.js';
import { exportArtifacts } from './profiles.js';
import { detectClash, importClash } from './windows.js';
import { verifyNode, verifyPort } from './verify.js';
import { redact } from './validation.js';

export const steps = {
  connect: '连接 SSH 并验证主机指纹', preflight: '检查系统与端口', binary: '准备并校验 sing-box',
  configure: '备份并写入独立配置', started: '启动代理服务', export: '生成 Clash 配置和手机二维码',
  verify: '验证代理出口', import: '导入并重启 Clash Verge', finished: '任务结束',
};

export async function loadKnownHosts(dataDir) {
  try {
    const value = JSON.parse(await readFile(path.join(dataDir, 'known-hosts.json'), 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid map');
    return value;
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw new Error('本地主机指纹记录损坏，请先检查 runtime/known-hosts.json。');
  }
}

export async function rememberHost(dataDir, destination) {
  const known = await loadKnownHosts(dataDir);
  const key = `${destination.host}:${destination.sshPort}`;
  if (known[key] && known[key] !== destination.fingerprint) throw new Error('已记录的主机指纹发生变化，已停止连接。');
  known[key] = destination.fingerprint;
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(dataDir, 'known-hosts.json');
  const temporary = `${file}.${randomBytes(4).toString('hex')}.pending`;
  await writeFile(temporary, JSON.stringify(known, null, 2), { mode: 0o600 });
  await rename(temporary, file);
}

export function newJob(input) {
  return { id: randomBytes(16).toString('hex'), state: 'running', host: input.host, proxyPort: input.proxyPort,
    createdAt: new Date().toISOString(), events: [], result: null };
}

export function addEvent(job, step) {
  if (!Object.hasOwn(steps, step)) return;
  job.step = step;
  job.events.push({ step, message: steps[step], at: new Date().toISOString() });
  job.events = job.events.slice(-32);
}

export async function runWorkflow(job, input, dataDir, { demo = false, adapters = {} } = {}) {
  const services = { connect, runDeployment, exportArtifacts, detectClash, importClash, verifyNode, verifyPort,
    rememberHost, loadKnownHosts, ...adapters };
  let client;
  const rootPassword = input.password;
  let nodePassword;
  try {
    addEvent(job, 'connect');
    const directory = path.join(dataDir, 'jobs', job.id);
    let remote;
    if (demo) {
      // Reserved documentation address, synthetic key; no SSH or local app changes.
      for (const step of ['preflight', 'binary', 'configure', 'started']) {
        await new Promise(resolve => setTimeout(resolve, 180)); addEvent(job, step);
      }
      remote = { success: true, port: 18443, method: '2022-blake3-aes-128-gcm',
        password: Buffer.alloc(16, 0x42).toString('base64'), service: 'vps-clash-link.service', backup: '(演示数据)' };
      input.host = '203.0.113.10'; job.host = input.host;
    } else {
      const known = await services.loadKnownHosts(dataDir);
      const prior = known[`${input.host}:${input.sshPort}`];
      if (prior && prior !== input.fingerprint) throw new Error('SSH 主机指纹与已记录内容不同，已停止连接。');
      client = await services.connect(input);
      await services.rememberHost(dataDir, input);
      delete input.password;
      remote = await services.runDeployment(client, input, step => addEvent(job, step));
      client.end(); client = null;
    }
    job.remote = { service: remote.service, backup: remote.backup };
    nodePassword = remote.password;
    const node = { host: input.host, port: remote.port, method: remote.method, password: remote.password };
    addEvent(job, 'export');
    const artifacts = await services.exportArtifacts(node, directory);
    addEvent(job, 'verify');
    const detection = demo ? { available: false } : await services.detectClash();
    const verification = demo ? { verified: true, egress: '203.0.113.10', googleStatus: 204,
      milliseconds: 86, note: '演示结果，未进行真实网络测试。' } : await services.verifyNode(node, detection.core);
    let imported = null;
    if (!demo && input.autoImport && verification.verified && detection.available) {
      addEvent(job, 'import');
      try {
        imported = await services.importClash(artifacts, path.join(dataDir, 'backups'), {
          enableSystemProxy: input.enableSystemProxy, detection,
        });
        // The app starts asynchronously. The verification timeout also bounds startup delay.
        let active;
        for (let attempt = 0; attempt < 3; attempt++) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          active = await services.verifyPort(imported.mixedPort, input.host);
          if (active.verified) break;
        }
        imported.verification = active;
      } catch (error) {
        imported = { imported: false, error: redact(error.message, [rootPassword, nodePassword]) };
      }
    }
    job.result = { name: artifacts.name, verification, imported, canImport: !demo && detection.available,
      artifacts: { clash: `/api/artifacts/${job.id}/clash.yaml`, qr: `/api/artifacts/${job.id}/node.png`,
        link: `/api/artifacts/${job.id}/node.txt` }, demo };
    job.state = verification.verified && (!input.autoImport || demo || imported?.verification?.verified) ? 'complete' : 'attention';
    addEvent(job, 'finished');
  } catch (error) {
    job.state = 'failed';
    job.error = redact(error.message, [rootPassword, nodePassword]);
  } finally {
    client?.end(); delete input.password;
    job.finishedAt = new Date().toISOString();
  }
}
