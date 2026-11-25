import ssh2 from 'ssh2';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { redact } from './validation.js';

export function fingerprint(key) {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
}

export function inspectHost(destination, Client = ssh2.Client) {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let observed;
    const timer = setTimeout(() => { client.destroy(); reject(new Error('SSH 握手超时，请检查 IP、端口和服务器状态。')); }, 20000);
    const finish = () => { clearTimeout(timer); client.end(); };
    client.on('error', error => {
      finish();
      if (observed) resolve(observed);
      else reject(new Error(`SSH 检测失败：${error.message}`));
    });
    client.connect({ host: destination.host, port: destination.sshPort, username: destination.username,
      readyTimeout: 18000, hostVerifier: key => { observed = { fingerprint: fingerprint(key) }; return false; } });
  });
}

export async function connect(destination, Client = ssh2.Client) {
  const password = destination.password;
  const client = new Client();
  await new Promise((resolve, reject) => {
    client.once('ready', resolve);
    client.once('error', error => {
      client.end();
      reject(new Error(`SSH 登录失败：${redact(error.message, [password])}`));
    });
    client.connect({ host: destination.host, port: destination.sshPort, username: destination.username,
      password, readyTimeout: 25000, keepaliveInterval: 10000, keepaliveCountMax: 3,
      hostVerifier: key => fingerprint(key) === destination.fingerprint });
  });
  // Keep subsequent transport errors handled after the authentication promise settles.
  client.on('error', () => {});
  return client;
}

export async function runDeployment(client, options, onProgress, { timeout = 240000 } = {}) {
  const script = await readFile(new URL('../remote/deploy.py', import.meta.url), 'utf8');
  const payload = Buffer.from(JSON.stringify({ port: options.proxyPort })).toString('base64');
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
    const timer = setTimeout(() => { client.destroy(); done(new Error('部署超时。服务器可能仍在处理，请重新检测后再操作。')); }, timeout);
    client.exec(`python3 - ${payload}`, (error, stream) => {
      if (error) return done(new Error('无法启动远端 Python 任务。'));
      let pending = '', result, parseError = false, bytes = 0;
      stream.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) { stream.close(); return done(new Error('远端响应超过限制。')); }
        pending += chunk.toString('utf8');
        const lines = pending.split('\n'); pending = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const event = JSON.parse(line);
            if (event.kind === 'progress' && typeof event.step === 'string') onProgress(event.step);
            if (event.kind === 'result') result = event;
          } catch { parseError = true; }
        }
      });
      // Never forward subprocess stderr: it may contain configuration values.
      stream.stderr.on('data', () => {});
      stream.on('error', () => done(new Error('SSH 执行通道中断。')));
      stream.on('close', code => {
        if (code !== 0 || parseError || !result) return done(new Error('服务器未返回有效部署结果；请确认已安装 Python 3。'));
        if (!result.success) return done(new Error(result.error || '远端部署失败，已尝试恢复原状态。'));
        done(null, result);
      });
      stream.end(script);
    });
  });
}
