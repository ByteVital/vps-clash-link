"""Isolated sing-box deployment. JSONL stdout is the SSH protocol, never a log sink."""
import base64
import datetime
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

SERVICE = "vps-clash-link.service"
CONFIG_DIR = Path("/etc/vps-clash-link")
UNIT = Path("/etc/systemd/system") / SERVICE
BINARY = Path("/usr/local/lib/vps-clash-link/sing-box")
BACKUPS = Path("/var/backups/vps-clash-link")
METHOD = "2022-blake3-aes-128-gcm"


def emit(kind, **fields):
    print(json.dumps(dict(kind=kind, **fields)), flush=True)


def run(*args, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def checked(*args):
    if run(*args).returncode:
        raise RuntimeError("系统命令失败：" + args[0])


def fetch(url, limit=100 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "vps-clash-link/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("下载内容超过大小限制。")
    return data


def verified_binary(archive, expected_digest, member_name):
    """Only read one regular executable; never extract archive paths to disk."""
    if not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", expected_digest or ""):
        raise RuntimeError("官方发行文件缺少 SHA-256 摘要，已停止安装。")
    if hashlib.sha256(archive).hexdigest() != expected_digest.split(":", 1)[1].lower():
        raise RuntimeError("sing-box 下载文件校验失败。")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        member = package.getmember(member_name)
        if not member.isfile() or member.size > 150 * 1024 * 1024:
            raise RuntimeError("发行包中的可执行文件不符合要求。")
        with package.extractfile(member) as handle:
            return handle.read()


def choose_binary():
    for candidate in [BINARY, Path("/usr/bin/sing-box"), Path("/usr/local/bin/sing-box")]:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            with candidate.open("rb") as handle:
                if handle.read(4) == b"\x7fELF":
                    return str(candidate), "existing"
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise RuntimeError("当前版本仅支持 amd64 和 arm64。")
    release = json.loads(fetch("https://api.github.com/repos/SagerNet/sing-box/releases/latest", 2 * 1024 * 1024))
    version = release.get("tag_name", "").removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("无法确认 sing-box 稳定发行版本。")
    name = "sing-box-{}-linux-{}.tar.gz".format(version, arch)
    asset = next((a for a in release.get("assets", []) if a.get("name") == name), None)
    if not asset:
        raise RuntimeError("官方发行包不支持当前架构。")
    url = asset["browser_download_url"]
    if not url.startswith("https://github.com/SagerNet/sing-box/releases/download/"):
        raise RuntimeError("发行包下载地址不属于官方仓库。")
    data = verified_binary(fetch(url), asset.get("digest"), name.removesuffix(".tar.gz") + "/sing-box")
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    temporary = BINARY.with_suffix(".pending")
    temporary.write_bytes(data)
    temporary.chmod(0o755)
    os.replace(temporary, BINARY)
    return str(BINARY), version


def unit_text(binary):
    return """[Unit]
Description=VPS Clash Link managed proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={} run -c /etc/vps-clash-link/config.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077

[Install]
WantedBy=multi-user.target
""".format(binary)


def preflight(port):
    if os.geteuid() != 0:
        raise RuntimeError("需要 root SSH 账号。")
    os_release = Path("/etc/os-release").read_text()
    if not re.search(r"(?m)^ID=(?:\"?)(ubuntu|debian)(?:\"?)$", os_release):
        raise RuntimeError("当前版本支持 Ubuntu / Debian。")
    if not Path("/run/systemd/system").is_dir() or not shutil.which("systemctl") or not shutil.which("ss"):
        raise RuntimeError("需要 systemd 和 ss；不会自动修改服务器的软件源或防火墙。")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RuntimeError("代理端口无效。")


def deploy(options):
    port = options["port"]
    emit("progress", step="preflight")
    preflight(port)
    marker = CONFIG_DIR / "managed.json"
    config_path = CONFIG_DIR / "config.json"
    if (CONFIG_DIR.exists() or UNIT.exists()) and not marker.is_file():
        raise RuntimeError("目标目录或服务已存在且不由本项目管理，已停止以避免覆盖。")
    previous = None
    if marker.is_file():
        if json.loads(marker.read_text()).get("owner") != "vps-clash-link":
            raise RuntimeError("管理标记不匹配。")
        previous = json.loads(config_path.read_text())
    was_active = run("systemctl", "is-active", "--quiet", SERVICE).returncode == 0
    was_enabled = run("systemctl", "is-enabled", "--quiet", SERVICE).returncode == 0
    listeners = run("ss", "-H", "-lntu")
    if listeners.returncode:
        raise RuntimeError("无法确认代理端口是否被占用。")
    occupied = any(len(parts) > 4 and parts[4].rsplit(":", 1)[-1] == str(port)
                   for parts in (line.split() for line in listeners.stdout.splitlines()))
    own_port = previous and previous["inbounds"][0].get("listen_port") == port and was_active
    if occupied and not own_port:
        raise RuntimeError("代理端口已被占用，请换一个端口；现有服务未修改。")
    emit("progress", step="binary")
    binary, version = choose_binary()
    old_files = {p: p.read_bytes() if p.is_file() else None for p in [config_path, marker, UNIT]}
    old_modes = {p: stat.S_IMODE(p.stat().st_mode) for p, data in old_files.items() if data is not None}
    backup = BACKUPS / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-%f")
    backup.mkdir(parents=True, mode=0o700)
    backup.chmod(0o700)
    for index, (file_path, content) in enumerate(old_files.items()):
        if content is not None:
            saved = backup / (str(index) + "-" + file_path.name)
            saved.write_bytes(content)
            saved.chmod(0o600)
    (backup / "state.json").write_text(json.dumps({"active": was_active, "enabled": was_enabled,
        "files": {str(p): {"exists": old_files[p] is not None, "mode": old_modes.get(p)} for p in old_files}}))
    password = base64.b64encode(secrets.token_bytes(16)).decode()
    if previous:
        old_inbound = previous["inbounds"][0]
        if old_inbound.get("method") != METHOD or len(base64.b64decode(old_inbound.get("password", ""), validate=True)) != 16:
            raise RuntimeError("已有项目配置的协议或密钥异常，已停止。")
        password = old_inbound["password"]
    config = {"log": {"level": "warn"}, "inbounds": [{"type": "shadowsocks", "tag": "vps-clash-link",
        "listen": "0.0.0.0", "listen_port": port, "method": METHOD, "password": password}],
        "outbounds": [{"type": "direct"}]}
    changed = False
    try:
        emit("progress", step="configure")
        CONFIG_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
        CONFIG_DIR.chmod(0o700)
        candidate = CONFIG_DIR / "candidate.pending"
        candidate.write_text(json.dumps(config, indent=2) + "\n")
        candidate.chmod(0o600)
        if run(binary, "check", "-c", str(candidate)).returncode:
            raise RuntimeError("sing-box 配置检查失败，原配置未替换。")
        changed = True
        os.replace(candidate, config_path)
        marker.write_text(json.dumps({"owner": "vps-clash-link", "version": 1}))
        marker.chmod(0o600)
        UNIT.write_text(unit_text(binary))
        UNIT.chmod(0o644)
        checked("systemctl", "daemon-reload")
        checked("systemctl", "restart", SERVICE)
        time.sleep(2)
        checked("systemctl", "is-active", "--quiet", SERVICE)
        checked("systemctl", "enable", SERVICE)
        emit("progress", step="started")
        return {"success": True, "port": port, "method": METHOD, "password": password,
                "service": SERVICE, "backup": str(backup), "binaryVersion": version}
    except Exception:
        if changed:
            run("systemctl", "stop", SERVICE)
            for file_path, content in old_files.items():
                if content is None:
                    file_path.unlink(missing_ok=True)
                else:
                    file_path.write_bytes(content)
                    file_path.chmod(old_modes[file_path])
            checked("systemctl", "daemon-reload")
            if was_active:
                checked("systemctl", "start", SERVICE)
            run("systemctl", "enable" if was_enabled else "disable", SERVICE)
        raise
    finally:
        (CONFIG_DIR / "candidate.pending").unlink(missing_ok=True)
        if not marker.exists() and CONFIG_DIR.exists() and not any(CONFIG_DIR.iterdir()):
            CONFIG_DIR.rmdir()


def main():
    try:
        options = json.loads(base64.b64decode(sys.argv[1], validate=True))
        result = deploy(options)
    except Exception as error:
        # No subprocess output or key material is returned on failures.
        message = str(error) if isinstance(error, RuntimeError) else "部署失败（{}），请检查服务器状态。".format(type(error).__name__)
        result = {"success": False, "error": message}
    emit("result", **result)


if __name__ == "__main__":
    main()
