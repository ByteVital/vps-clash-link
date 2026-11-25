import { isIP } from 'node:net';

export function port(value, fallback) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number) || number < 1 || number > 65535) throw new Error('端口必须是 1～65535 的整数。');
  return number;
}

export function target(input) {
  if (!input || typeof input !== 'object') throw new Error('请求格式错误。');
  const host = String(input.host ?? '').trim();
  if (isIP(host) !== 4) throw new Error('当前版本需要填写 VPS 的 IPv4 地址。');
  const username = String(input.username ?? 'root').trim();
  if (username !== 'root') throw new Error('当前版本需要 root SSH 账号；不会修改 SSH 设置。');
  return { host, username, sshPort: port(input.sshPort, 22) };
}

export function deployment(input) {
  const destination = target(input);
  const proxyPort = port(input.proxyPort, 18443);
  if (proxyPort === destination.sshPort) throw new Error('代理端口不能与 SSH 端口相同。');
  if (typeof input.password !== 'string' || !input.password || input.password.length > 1024) throw new Error('请输入 SSH 密码。');
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(input.fingerprint ?? '')) throw new Error('请先检测并确认 SSH 主机指纹。');
  if (input.confirmChanges !== true) throw new Error('请确认允许部署独立代理服务。');
  return { ...destination, proxyPort, password: input.password, fingerprint: input.fingerprint,
    autoImport: input.autoImport === true, enableSystemProxy: input.enableSystemProxy === true };
}

export function redact(message, secrets = []) {
  let output = String(message);
  for (const secret of secrets.filter(Boolean)) output = output.split(secret).join('[已隐藏]');
  return output.replace(/((?:password|passwd|access_token|refresh_token|authorization)\s*[:=]\s*)\S+/gi, '$1[已隐藏]');
}
