const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name=vps-link-token]').content;
const panels = [...document.querySelectorAll('[data-panel]')];
const stepButtons = [...document.querySelectorAll('[data-go]')];
const editableIds = ['host', 'ssh-port', 'password', 'proxy-port', 'trust', 'auto-import', 'system-proxy', 'confirm', 'toggle-password'];
let currentStep = 0, unlockedStep = 0, currentFingerprint = null;
let inspecting = false, running = false, info = null, lastJob = null;

function connection() {
  return { host: $('host').value.trim(), sshPort: Number($('ssh-port').value), username: 'root' };
}

function storedJob(id) {
  try {
    if (id === undefined) return sessionStorage.getItem('vcl-active-job');
    if (id === null) sessionStorage.removeItem('vcl-active-job');
    else sessionStorage.setItem('vcl-active-job', id);
  } catch { /* Storage is optional; credentials are never persisted here. */ }
  return null;
}

function errorGuidance(message) {
  if (/授权/.test(message)) return '阅读上方的操作范围，确认是自己管理的服务器后，再勾选授权说明。';
  if (/指纹|身份/.test(message)) return '先检测服务器，并与服务商控制台提供的 SSH 指纹核对。指纹变化时先确认原因。';
  if (/超时|timeout|ECONN/i.test(message)) return '确认服务器已开机，IP 和 SSH 端口正确，服务商的防火墙允许 SSH 连接。';
  if (/认证|登录失败|authentication/i.test(message)) return '使用服务器的 root 密码，不是服务商网站的密码；复制时留意空格，并确认服务商允许密码登录。';
  if (/端口/.test(message)) return '在“连接服务器 → 高级设置”中核对端口。SSH 登录端口与节点端口用途不同。';
  if (/本地|会话|校验失败|工具重启/.test(message)) return '保持本机工具运行。刷新页面可尝试恢复当前会话；若工具已重启，请先确认服务器状态再重新部署。';
  return '可先查看下方的常见问题。不要连续重复部署或直接重装系统；先确认具体失败在哪一步。';
}

function showError(message, guidance) {
  $('error-message').textContent = message;
  $('error-guidance').textContent = message ? guidance ?? errorGuidance(message) : '';
  $('form-error').classList.toggle('hidden', !message);
}

async function api(url, input) {
  let response;
  try {
    response = await fetch(url, input ? { method: 'POST', headers: {
      'Content-Type': 'application/json', 'X-Vps-Link-Token': token,
    }, body: JSON.stringify(input) } : {});
  } catch { throw new Error('无法连接本地工具，请确认本机服务仍在运行。'); }
  let value;
  try { value = await response.json(); }
  catch { throw new Error('本地工具未返回有效结果，请检查服务是否仍在运行。'); }
  if (!response.ok) {
    const error = new Error(value.error || '操作失败。');
    error.status = response.status;
    throw error;
  }
  return value;
}

function updateNavigation() {
  stepButtons.forEach((button, index) => {
    button.disabled = running || index > unlockedStep;
    button.classList.toggle('active', index === currentStep);
    button.classList.toggle('done', index < unlockedStep);
    if (index === currentStep) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
  });
}

function goStep(step, { unlock = false, scroll = true } = {}) {
  if (running && step !== 2) return;
  if (unlock) unlockedStep = Math.max(unlockedStep, step);
  if (step > unlockedStep || step < 0 || step > 3) return;
  currentStep = step;
  panels.forEach((panel, index) => panel.classList.toggle('hidden', index !== step));
  updateNavigation();
  if (scroll) {
    const heading = panels[step].querySelector('.panel-title');
    heading.focus({ preventScroll: true });
    document.getElementById('builder').scrollIntoView({ block: 'start', behavior: 'smooth' });
  }
}

function setBusy(value) {
  running = value;
  for (const id of editableIds) $(id).disabled = value;
  $('inspect').disabled = value || inspecting;
  $('deploy').disabled = value;
  $('deploy-back').disabled = value;
  $('connection-next').disabled = value;
  if (!value) {
    $('auto-import').disabled = !info?.clash.available || !!info?.demo;
    $('system-proxy').disabled = !$('auto-import').checked;
  }
  updateNavigation();
}

function resetFingerprint() {
  currentFingerprint = null;
  $('trust').checked = false;
  $('trust').disabled = false;
  $('fingerprint-box').classList.add('hidden');
  resetDeployment();
}

function resetDeployment() {
  $('confirm').checked = false;
  unlockedStep = Math.min(unlockedStep, 1);
  lastJob = null;
  storedJob(null);
  updateNavigation();
}

function validateConnection({ password = true, trust = true } = {}) {
  const pieces = $('host').value.trim().split('.');
  if (pieces.length !== 4 || pieces.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255 || String(Number(p)) !== p)) {
    showError('请填写有效的服务器公网 IPv4 地址，例如示例框中的格式。');
    $('host').focus(); return false;
  }
  for (const id of ['ssh-port', 'proxy-port']) {
    if (!$(id).checkValidity()) {
      $('advanced-settings').open = true;
      $(id).reportValidity(); return false;
    }
  }
  if (Number($('ssh-port').value) === Number($('proxy-port').value)) {
    showError('SSH 登录端口和节点服务端口不能相同。');
    $('advanced-settings').open = true; $('proxy-port').focus(); return false;
  }
  if (password && !$('password').value) {
    showError('请填写服务商提供的 root 登录密码。'); $('password').focus(); return false;
  }
  if (trust && (!currentFingerprint || !$('trust').checked)) {
    showError('请先检测服务器，并核对、确认 SSH 主机指纹。');
    document.querySelector('.identity-section').scrollIntoView({ block: 'nearest' });
    $('inspect').focus(); return false;
  }
  showError(''); return true;
}

function updateReview(job = null) {
  $('review-host').textContent = job?.host || $('host').value.trim();
  $('review-ssh').textContent = job ? 'root · 当前任务的 SSH 连接' : `root · 端口 ${$('ssh-port').value}`;
  const port = job?.proxyPort || $('proxy-port').value;
  $('review-port').textContent = `${port} · TCP / UDP`;
  $('firewall-port').textContent = port;
}

function nextConnection() {
  if (!validateConnection()) return;
  lastJob = null; storedJob(null);
  updateReview();
  $('deployment-options').classList.remove('hidden');
  $('deployment-progress').classList.add('hidden');
  $('deploy').textContent = info?.demo ? '运行演示流程 →' : '开始部署节点 →';
  $('status-pill').textContent = '等待开始'; $('status-pill').className = 'status-pill';
  goStep(2, { unlock: true });
}

$('prepare-next').addEventListener('click', () => { showError(''); goStep(1, { unlock: true }); });
$('connection-next').addEventListener('click', nextConnection);
stepButtons.forEach(button => button.addEventListener('click', () => { showError(''); goStep(Number(button.dataset.go)); }));
document.querySelectorAll('[data-back]').forEach(button => button.addEventListener('click', () => { showError(''); goStep(Number(button.dataset.back)); }));
for (const id of ['host', 'ssh-port']) $(id).addEventListener('input', resetFingerprint);
for (const id of ['password', 'proxy-port']) $(id).addEventListener('input', resetDeployment);
$('auto-import').addEventListener('change', () => {
  $('system-proxy').disabled = !$('auto-import').checked;
  if (!$('auto-import').checked) $('system-proxy').checked = false;
});
$('toggle-password').addEventListener('click', () => {
  const visible = $('password').type === 'password';
  $('password').type = visible ? 'text' : 'password';
  $('toggle-password').setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
  $('toggle-password').setAttribute('aria-pressed', String(visible));
});

$('inspect').addEventListener('click', async () => {
  if (inspecting || running || !validateConnection({ password: false, trust: false })) return;
  showError(''); inspecting = true; currentFingerprint = null;
  $('trust').checked = false; $('trust').disabled = true;
  $('inspect').disabled = true; $('inspect').textContent = '正在检测服务器身份…';
  const destination = connection();
  try {
    const result = await api('/api/inspect', destination);
    if (JSON.stringify(destination) !== JSON.stringify(connection())) throw new Error('服务器信息已经变化，请重新检测主机指纹。');
    $('fingerprint').textContent = result.fingerprint;
    $('fingerprint-note').textContent = result.changed ? '此指纹与本机保存的记录不同。请先核对服务器是否重装或发生变化，本次不会继续部署。' :
      result.known ? '与本机保存的指纹一致。请确认这是你要管理的服务器。' :
      info?.demo ? '这是演示指纹。体验模式下可以勾选下方确认，继续查看后续流程。' : '首次连接，请与服务商控制台提供的 SSH 主机指纹核对。';
    $('trust').disabled = result.changed;
    currentFingerprint = result.changed ? null : result.fingerprint;
    $('fingerprint-box').classList.remove('hidden');
    $('fingerprint-box').scrollIntoView({ block: 'nearest' });
  } catch (error) { showError(error.message); }
  finally { inspecting = false; $('inspect').disabled = false; $('inspect').textContent = '重新检测服务器 ↗'; }
});

function selectDevice(device, focus = false) {
  for (const type of ['computer', 'phone']) {
    const active = type === device;
    $(`tab-${type}`).setAttribute('aria-selected', String(active));
    $(`tab-${type}`).tabIndex = active ? 0 : -1;
    $(`device-${type}`).hidden = !active;
    $(`device-${type}`).classList.toggle('hidden', !active);
  }
  if (focus) $(`tab-${device}`).focus();
}
for (const type of ['computer', 'phone']) {
  $(`tab-${type}`).addEventListener('click', () => selectDevice(type));
  $(`tab-${type}`).addEventListener('keydown', event => {
    if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      selectDevice(event.key === 'Home' ? 'computer' : event.key === 'End' ? 'phone' : type === 'computer' ? 'phone' : 'computer', true);
    }
  });
}
selectDevice('computer');

function instructions(lines) {
  const elements = lines.map(line => { const li = document.createElement('li'); li.textContent = line; return li; });
  $('computer-instructions').replaceChildren(...elements);
}

function renderResult(job) {
  const result = job.result;
  const resultIcon = document.querySelector('.success-icon');
  resultIcon.classList.toggle('needs-attention', job.state !== 'complete');
  resultIcon.querySelector('use').setAttribute('href', job.state === 'complete' ? '#i-check' : '#i-info');
  $('result-title').textContent = result.demo ? '演示完成，看看你的连接方式。' : job.state === 'complete' ? '你的节点已准备好。' : '配置已生成，连接还需要检查。';
  $('result-badge').textContent = result.demo ? '演示数据' : job.state === 'complete' ? '验证通过' : '需要检查';
  $('result-badge').className = `status-pill ${job.state === 'complete' ? 'complete' : 'attention'}`;
  const warning = result.imported?.error || (result.imported?.imported && !result.imported.verification?.verified ? '已写入 Clash 配置，但客户端连接验证尚未通过。' : '');
  $('result-note').textContent = `${result.verification.note}${warning ? ` ${warning}` : ''}`;
  $('egress').textContent = result.verification.egress || '尚未确认';
  $('latency').textContent = result.verification.milliseconds == null ? '尚未测得' : `${result.verification.milliseconds} ms`;
  $('import-state').textContent = result.demo ? '演示预览' : result.imported?.verification?.verified ? '已导入并验证' : result.imported?.imported ? '等待确认' : '需要手动导入';
  $('download-clash').href = result.artifacts.clash;
  $('download-link').href = result.artifacts.link;
  $('qr').src = result.artifacts.qr;
  $('download-qr').href = result.artifacts.qr;
  if (result.imported?.verification?.verified && !result.demo) {
    $('computer-title').textContent = 'Clash Verge 已导入，接下来确认使用';
    instructions(['打开 Clash Verge，确认选中刚生成的 VPS 节点。',
      result.imported.systemProxyRequested ? '确认客户端的“系统代理”开关处于开启状态。' : '在 Clash Verge 中开启“系统代理”，让支持它的应用使用节点。',
      '用浏览器打开网页，检查是否能够正常访问。']);
  } else {
    $('computer-title').textContent = result.demo ? '真实部署完成后，可以这样连接电脑' : '把配置导入 Clash Verge';
    instructions(['下载下方的 Clash 配置文件。', '打开 Clash Verge，在“订阅”页面导入这个本地文件。', '选中新节点，开启“系统代理”，再用浏览器测试连接。']);
  }
  $('deployment-info').textContent = [`节点名称：${result.name}`, `独立服务：${job.remote?.service || '—'}`,
    `服务器备份：${job.remote?.backup || '—'}`, `本机备份：${result.imported?.backup || '未修改本机配置'}`].join('\n');
}

function render(job) {
  lastJob = job;
  const stateLabels = { running: '正在部署', complete: '已完成', attention: '需要检查', failed: '任务失败' };
  $('status-pill').textContent = stateLabels[job.state] || job.state;
  $('status-pill').className = `status-pill ${job.state}`;
  const completed = new Set(job.events.map(event => event.step));
  const stages = [completed.has('connect'), completed.has('configure') || completed.has('binary'), completed.has('export'), completed.has('verify')];
  const latest = stages.lastIndexOf(true);
  document.querySelectorAll('#timeline li').forEach((element, index) => {
    const done = index < latest || (job.state === 'complete' && index <= latest);
    const active = index === latest && job.state !== 'complete';
    element.classList.toggle('done', done); element.classList.toggle('active', active);
    element.querySelector('.step-dot').textContent = done ? '✓' : index + 1;
    element.querySelector('.timeline-state').textContent = done ? '已完成' : active ? job.state === 'failed' ? '已停止' : '处理中' : '等待中';
  });
  $('event-log').textContent = job.error || job.events.at(-1)?.message || '正在准备…';
  const elapsed = Math.max(0, Math.floor(((job.finishedAt ? Date.parse(job.finishedAt) : Date.now()) - Date.parse(job.createdAt)) / 1000));
  $('elapsed-time').textContent = `已用时 ${String(Math.floor(elapsed / 60)).padStart(2, '0')}:${String(elapsed % 60).padStart(2, '0')}`;
  if (job.state === 'failed') showError(`${job.error}${job.remote ? ' 服务器上的节点已经部署，客户端步骤未完成；请保留服务器配置。' : ''}`);
  if (job.result) renderResult(job);
}

async function pollJob(id) {
  while (true) {
    const job = await api(`/api/jobs/${id}`); render(job);
    if (job.state !== 'running') {
      setBusy(false);
      if (job.result) { $('deploy').textContent = '查看连接结果 →'; goStep(3, { unlock: true }); }
      else $('deploy').textContent = info?.demo ? '重新运行演示 →' : '重新部署前请先检查信息';
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 1200));
  }
}

$('connect-form').addEventListener('submit', async event => {
  event.preventDefault(); if (running) return;
  if (currentStep === 1) return nextConnection();
  if (currentStep !== 2) return;
  if (lastJob?.result) return goStep(3, { unlock: true });
  showError('');
  if (!currentFingerprint || !$('password').value) {
    goStep(1); showError('请重新确认服务器信息和登录密码。'); return;
  }
  if (!$('confirm').checked) {
    showError('开始前，请阅读并勾选服务器操作授权说明。'); $('confirm').focus(); return;
  }
  const input = { ...connection(), proxyPort: Number($('proxy-port').value), password: $('password').value,
    fingerprint: currentFingerprint, confirmChanges: $('confirm').checked,
    autoImport: $('auto-import').checked, enableSystemProxy: $('system-proxy').checked };
  setBusy(true);
  $('deploy').textContent = '正在部署，请稍候…';
  $('deployment-options').classList.add('hidden');
  $('deployment-progress').classList.remove('hidden');
  try {
    const { id } = await api('/api/deploy', input);
    storedJob(id); $('password').value = ''; input.password = '';
    await pollJob(id);
  } catch (error) {
    showError(error.message); setBusy(false);
    $('deployment-options').classList.remove('hidden');
    $('deploy').textContent = info?.demo ? '重新运行演示 →' : '检查信息后重新开始';
  } finally { input.password = ''; $('password').value = ''; setBusy(false); }
});

$('start-another').addEventListener('click', () => {
  storedJob(null); lastJob = null; unlockedStep = 1; currentFingerprint = null;
  $('host').value = info?.demo ? '203.0.113.10' : '';
  $('password').value = info?.demo ? 'demo-only' : '';
  $('password').type = 'password'; $('toggle-password').setAttribute('aria-label', '显示密码');
  $('toggle-password').setAttribute('aria-pressed', 'false');
  $('trust').checked = false; $('confirm').checked = false;
  $('fingerprint-box').classList.add('hidden');
  $('deployment-options').classList.remove('hidden');
  $('deployment-progress').classList.add('hidden');
  selectDevice('computer'); showError(''); goStep(1);
});

// A FAQ anchor opens the relevant answer before scrolling to it.
document.querySelectorAll('a[href="#faq-firewall"]').forEach(link => link.addEventListener('click', () => { $('faq-firewall').open = true; }));

async function init() {
  try {
    info = await api('/api/info'); $('version').textContent = `v${info.version}`;
    const detected = info.clash.available;
    $('clash-note').textContent = detected ? '已检测到 Clash Verge；导入前会备份已有配置。' : info.clash.reason;
    $('clash-prep-note').textContent = info.demo ? '演示模式：不会检查或修改本机客户端。' : detected ? '已检测到 Clash Verge，可以自动导入。' : '暂未检测到客户端；仍可生成配置后手动导入。';
    $('client-detection').classList.toggle('detected', detected);
    $('auto-import').disabled = !detected; $('auto-import').checked = detected;
    $('system-proxy').disabled = !detected;
    if (info.demo) {
      $('demo-banner').classList.remove('hidden');
      $('host').value = '203.0.113.10'; $('password').value = 'demo-only';
    }
    const previous = storedJob();
    if (previous && /^[a-f0-9]{32}$/.test(previous)) {
      try {
        const job = await api(`/api/jobs/${previous}`);
        updateReview(job); $('host').value = job.host; $('proxy-port').value = job.proxyPort;
        $('deployment-progress').classList.remove('hidden');
        $('deployment-options').classList.add('hidden');
        goStep(2, { unlock: true, scroll: false }); render(job);
        if (job.state === 'running') { setBusy(true); await pollJob(previous); }
        else if (job.result) {
          $('deploy').textContent = '查看连接结果 →';
          goStep(3, { unlock: true, scroll: false });
        }
        else showError(job.error || '上一次部署未完成，请先检查服务器状态。');
      } catch (error) {
        if (error.status === 404) storedJob(null);
        setBusy(false); goStep(0, { scroll: false });
        showError('无法恢复上次本地任务，工具可能已重启。请先检查服务器状态，再决定是否重新部署。');
      }
    }
  } catch { showError('无法连接本地工具，请确认 npm start 正在运行并刷新页面。'); }
}
init();
