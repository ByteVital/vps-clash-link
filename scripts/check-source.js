import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const ignored = new Set(['.git', 'node_modules', 'runtime', '__pycache__']);
const files = [];
async function walk(directory) {
  for (const item of await readdir(directory, { withFileTypes: true })) {
    if (ignored.has(item.name)) continue;
    const file = path.join(directory, item.name);
    if (item.isDirectory()) await walk(file); else files.push(file);
  }
}
await walk(root);
let errors = 0;
for (const file of files) {
  if (!/\.(?:js|cjs|json|py|ps1|md|ya?ml|html|css|svg)$/.test(file)) continue;
  const content = await readFile(file, 'utf8');
  const issue = message => { console.error(`${path.relative(root, file)}: ${message}`); errors++; };
  if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(content)) issue('发现私钥材料。');
  if (/\b(?:ghp|github_pat)_[A-Za-z0-9_]{30,}\b/.test(content)) issue('发现可能的 GitHub 凭据。');
  if (/\b[\w.+-]+@(?:gmail|outlook|qq)\.com\b/i.test(content)) issue('发现可能的真实邮箱。');
  for (const value of content.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []) {
    const octets = value.split('.').map(Number);
    if (octets.some(n => n > 255)) continue;
    const safe = /^(?:0\.|127\.|10\.|192\.168\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(value)
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31);
    if (!safe) issue('发现非示例公网 IPv4，请确认没有提交真实服务器信息。');
  }
  if (file.endsWith('.js') || file.endsWith('.cjs')) {
    try { execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' }); }
    catch { issue('JavaScript 语法检查失败。'); }
  }
}
if (errors) process.exitCode = 1;
else console.log(`检查通过：${files.length} 个项目文件，无已识别的私钥、真实邮箱或非示例公网地址。此检查不能替代发布前人工审阅。`);
