import YAML from 'yaml';
import QRCode from 'qrcode';
import { mkdir, writeFile, chmod } from 'node:fs/promises';
import path from 'node:path';
import { isIP } from 'node:net';

export const METHOD = '2022-blake3-aes-128-gcm';

export function validateNode(node) {
  if (isIP(node?.host) !== 4 || !Number.isInteger(node.port) || node.port < 1 || node.port > 65535) throw new Error('节点地址或端口无效。');
  if (node.method !== METHOD || typeof node.password !== 'string' ||
      !/^[A-Za-z0-9+/]{22}==$/.test(node.password) || Buffer.from(node.password, 'base64').length !== 16) throw new Error('节点密钥格式无效。');
}

export function shareUri(node) {
  validateNode(node);
  return `ss://${encodeURIComponent(node.method)}:${encodeURIComponent(node.password)}@${node.host}:${node.port}#${encodeURIComponent(`VPS-${node.host}`)}`;
}

export function clashObject(node) {
  validateNode(node);
  const name = `VPS-${node.host}`;
  return {
    mode: 'rule', 'log-level': 'warn', ipv6: false,
    proxies: [{ name, type: 'ss', server: node.host, port: node.port, cipher: node.method, password: node.password, udp: true }],
    'proxy-groups': [{ name: 'Proxy', type: 'select', proxies: [name, 'DIRECT'] }],
    rules: ['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
      'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve', 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
      'DOMAIN-SUFFIX,cn,DIRECT', 'MATCH,Proxy'],
  };
}

export async function exportArtifacts(node, directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const profilePath = path.join(directory, 'clash.yaml');
  await writeFile(profilePath, YAML.stringify(clashObject(node)), { mode: 0o600 });
  const uri = shareUri(node);
  await writeFile(path.join(directory, 'node.txt'), `${uri}\n`, { mode: 0o600 });
  await QRCode.toFile(path.join(directory, 'node.png'), uri, { width: 512, margin: 4, errorCorrectionLevel: 'M' });
  await chmod(path.join(directory, 'node.png'), 0o600);
  return { profilePath, uri, name: `VPS-${node.host}` };
}
