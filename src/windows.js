import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, access, rename, copyFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import YAML from 'yaml';

const execute = promisify(execFile);
const helper = fileURLToPath(new URL('../scripts/clash-verge.ps1', import.meta.url));
const powershell = process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe') : 'powershell.exe';

async function control(action, executable = '') {
  const { stdout } = await execute(powershell, ['-NoProfile', '-NonInteractive', '-File', helper, '-Action', action,
    ...(executable ? ['-Executable', executable] : [])], { windowsHide: true, timeout: 20000 });
  return JSON.parse(stdout.trim() || '{}');
}

export async function detectClash() {
  if (process.platform !== 'win32' || !process.env.APPDATA) return { available: false, reason: '自动导入支持 Windows 标准安装版；其他系统可下载配置手动导入。' };
  try {
    const { executable } = await control('Detect');
    if (!executable) return { available: false, reason: '未找到 Clash Verge，可设置 CLASH_VERGE_EXE 或手动导入配置。' };
    const dataDir = path.join(process.env.APPDATA, 'io.github.clash-verge-rev.clash-verge-rev');
    await access(path.join(dataDir, 'profiles.yaml'));
    const core = path.join(path.dirname(executable), 'verge-mihomo.exe');
    await access(core);
    const settings = YAML.parse(await readFile(path.join(dataDir, 'verge.yaml'), 'utf8'));
    return { available: true, executable, dataDir, core, mixedPort: Number(settings.verge_mixed_port || 7897) };
  } catch { return { available: false, reason: '无法读取 Clash Verge，请先安装并至少启动一次，或手动导入。' }; }
}

export function appendProfile(source, node, file, uid = `LVcl${randomBytes(6).toString('hex')}`) {
  const doc = YAML.parseDocument(source);
  if (doc.errors.length || !YAML.isMap(doc.contents)) throw new Error('Clash Verge 订阅索引无法解析。');
  const items = doc.get('items');
  if (!YAML.isSeq(items)) throw new Error('Clash Verge 订阅索引缺少 items 数组。');
  items.add(doc.createNode({ uid, type: 'local', name: node.name, file, desc: 'Managed by VPS Clash Link',
    selected: [{ name: 'Proxy', now: node.name }], updated: Math.floor(Date.now() / 1000) }));
  doc.set('current', uid);
  return { text: doc.toString(), uid };
}

async function atomicWrite(filename, text) {
  const temporary = `${filename}.${randomBytes(4).toString('hex')}.pending`;
  try { await writeFile(temporary, text, { mode: 0o600 }); await rename(temporary, filename); }
  finally { await unlink(temporary).catch(() => {}); }
}

/** Import only after the temporary verification core has exited. */
export async function importClash(artifact, backupRoot, { enableSystemProxy = false, detection, controller = control } = {}) {
  const info = detection ?? await detectClash();
  if (!info.available) throw new Error(info.reason);
  const indexPath = path.join(info.dataDir, 'profiles.yaml');
  const settingsPath = path.join(info.dataDir, 'verge.yaml');
  const folder = path.join(backupRoot, `clash-${Date.now()}-${randomBytes(3).toString('hex')}`);
  await mkdir(folder, { recursive: true, mode: 0o700 });
  const originals = { 'profiles.yaml': await readFile(indexPath, 'utf8'), 'verge.yaml': await readFile(settingsPath, 'utf8') };
  for (const [name, text] of Object.entries(originals)) await writeFile(path.join(folder, name), text, { mode: 0o600 });
  const uid = `LVcl${randomBytes(6).toString('hex')}`;
  const filename = `${uid}.yaml`;
  const destination = path.join(info.dataDir, 'profiles', filename);
  const settings = YAML.parseDocument(originals['verge.yaml']);
  if (settings.errors.length || !YAML.isMap(settings.contents)) throw new Error('Clash Verge 设置无法解析，未修改。');
  if (enableSystemProxy) settings.set('enable_system_proxy', true);
  const updated = appendProfile(originals['profiles.yaml'], artifact, filename, uid);
  const profile = YAML.parse(await readFile(artifact.profilePath, 'utf8'));
  if (!Array.isArray(profile.proxies) || profile.proxies[0]?.name !== artifact.name) throw new Error('待导入配置验证失败。');
  let stopped = false, wrote = false;
  try {
    await controller('Stop', info.executable); stopped = true;
    // Avoid overwriting edits made while we were preparing the import.
    if (await readFile(indexPath, 'utf8') !== originals['profiles.yaml'] || await readFile(settingsPath, 'utf8') !== originals['verge.yaml']) throw new Error('Clash Verge 配置发生变化，请重新导入。');
    await copyFile(artifact.profilePath, destination);
    wrote = true;
    await atomicWrite(indexPath, updated.text);
    await atomicWrite(settingsPath, settings.toString());
    await controller('Start', info.executable); stopped = false;
    return { imported: true, backup: folder, profileId: uid, mixedPort: info.mixedPort, systemProxyRequested: enableSystemProxy };
  } catch (error) {
    if (wrote) {
      await atomicWrite(indexPath, originals['profiles.yaml']);
      await atomicWrite(settingsPath, originals['verge.yaml']);
      await unlink(destination).catch(() => {});
    }
    if (stopped) await controller('Start', info.executable).catch(() => {});
    throw error;
  }
}
