import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { target, deployment } from './validation.js';
import { inspectHost } from './ssh.js';
import { detectClash } from './windows.js';
import { loadKnownHosts, newJob, runWorkflow } from './workflow.js';

const projectRoot = fileURLToPath(new URL('../', import.meta.url));
const staticFiles = { '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'] };
const artifactTypes = { 'clash.yaml': 'application/yaml; charset=utf-8', 'node.txt': 'text/plain; charset=utf-8', 'node.png': 'image/png' };

function equal(left, right) {
  const a = Buffer.from(String(left ?? '')), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function body(request) {
  if (!request.headers['content-type']?.startsWith('application/json')) throw new Error('需要 JSON 请求。');
  let size = 0, text = '';
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16384) throw new Error('请求内容过大。');
    text += chunk;
  }
  return JSON.parse(text);
}

export function createApplication({ dataDir = path.join(projectRoot, 'runtime'), demo = false,
  inspect = inspectHost, detect = detectClash, workflow = runWorkflow } = {}) {
  const csrf = randomBytes(32).toString('hex'), session = randomBytes(32).toString('hex');
  const jobs = new Map();
  let busy = false;
  const server = http.createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
    const json = (code, value) => { response.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); response.end(JSON.stringify(value)); };
    try {
      const port = server.address().port;
      const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
      if (!hosts.has(request.headers.host)) return json(403, { error: '只允许本机访问。' });
      if (request.headers.origin && !new Set([...hosts].map(host => `http://${host}`)).has(request.headers.origin)) return json(403, { error: '拒绝跨站请求。' });
      const url = new URL(request.url, `http://${request.headers.host}`);
      if (request.method === 'GET' && url.pathname === '/') {
        const html = (await readFile(path.join(projectRoot, 'public/index.html'), 'utf8')).replace('__CSRF_TOKEN__', csrf);
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': `vcl_session=${session}; HttpOnly; SameSite=Strict; Path=/` });
        return response.end(html);
      }
      if (request.method === 'GET' && Object.hasOwn(staticFiles, url.pathname)) {
        const [file, type] = staticFiles[url.pathname];
        response.writeHead(200, { 'Content-Type': type });
        return response.end(await readFile(path.join(projectRoot, 'public', file)));
      }
      const cookie = request.headers.cookie?.split(';').map(s => s.trim()).find(s => s.startsWith('vcl_session='))?.slice(12);
      if (!equal(cookie, session)) return json(403, { error: '请先打开本机操作页面。' });
      if (request.method === 'POST' && !equal(request.headers['x-vps-link-token'], csrf)) return json(403, { error: '请求校验失败，请刷新页面。' });
      if (request.method === 'GET' && url.pathname === '/api/info') {
        const clash = demo ? { available: false, reason: '演示模式不会操作你的客户端。' } : await detect();
        return json(200, { version: '0.1.0', demo, platform: process.platform, clash: { available: clash.available, reason: clash.reason } });
      }
      if (request.method === 'POST' && url.pathname === '/api/inspect') {
        const destination = target(await body(request));
        const result = demo ? { fingerprint: `SHA256:${Buffer.alloc(32, 0x42).toString('base64').replace(/=+$/, '')}` } : await inspect(destination);
        const known = demo ? {} : await loadKnownHosts(dataDir);
        const prior = known[`${destination.host}:${destination.sshPort}`];
        return json(200, { ...result, known: !!prior, changed: !!prior && prior !== result.fingerprint });
      }
      if (request.method === 'POST' && url.pathname === '/api/deploy') {
        if (busy) return json(409, { error: '已有部署任务正在执行。' });
        if (jobs.size >= 32) return json(429, { error: '本次会话任务数量已达上限，请重启工具。' });
        const input = deployment(await body(request));
        const job = newJob(input); jobs.set(job.id, job); busy = true;
        const done = workflow(job, input, dataDir, { demo }).catch(() => {
          job.state = 'failed'; job.error = '任务中断，请检查本机和服务器状态。';
        }).finally(() => { busy = false; });
        server.activeTask = done;
        return json(202, { id: job.id });
      }
      const status = url.pathname.match(/^\/api\/jobs\/([a-f0-9]{32})$/);
      if (request.method === 'GET' && status) return jobs.has(status[1]) ? json(200, jobs.get(status[1])) : json(404, { error: '任务不存在。' });
      const artifact = url.pathname.match(/^\/api\/artifacts\/([a-f0-9]{32})\/(clash\.yaml|node\.txt|node\.png)$/);
      if (request.method === 'GET' && artifact && jobs.get(artifact[1])?.result) {
        const content = await readFile(path.join(dataDir, 'jobs', artifact[1], artifact[2]));
        response.writeHead(200, { 'Content-Type': artifactTypes[artifact[2]], ...(artifact[2] === 'node.png' ? {} : { 'Content-Disposition': `attachment; filename="${artifact[2]}"` }) });
        return response.end(content);
      }
      json(404, { error: '未找到此资源。' });
    } catch (error) {
      const safeErrors = ['端口', '当前版本', '请输入 SSH', '请先检测', '请确认', '需要 JSON', '请求内容', 'SSH 检测失败', 'SSH 握手超时', '本地主机'];
      const message = safeErrors.some(prefix => error.message.startsWith(prefix)) ? error.message : '操作失败，请检查输入和连接状态。';
      if (!response.headersSent) json(400, { error: message }); else response.end();
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const port = Number(process.env.PORT || 3066);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT 无效。');
  const demo = process.argv.includes('--demo');
  const server = createApplication({ demo, dataDir: process.env.VPS_CLASH_DATA_DIR || path.join(projectRoot, 'runtime') });
  server.on('error', () => { console.error('本机服务无法启动，请检查 PORT 是否被占用。'); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => {
    console.log(`VPS Clash Link${demo ? ' [DEMO]' : ''} · http://127.0.0.1:${port}`);
    console.log('仅在本机运行。SSH 密码不会写入文件；导出节点凭据保存在被 Git 忽略的 runtime/。');
  });
}
