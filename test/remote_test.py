"""Remote transaction tests run against temporary files and a fake systemctl."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("deploy", Path(__file__).parents[1] / "remote" / "deploy.py")
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config_dir = root / "config"
        self.unit = root / "units" / deploy.SERVICE
        self.unit.parent.mkdir()
        self.backups = root / "backups"
        self.calls = []
        self.active = False
        self.enabled = False
        self.fail_start = False
        self.fail_check = False
        self.fail_enable = False
        self.occupied = False
        self.patches = [patch.object(deploy, "CONFIG_DIR", self.config_dir), patch.object(deploy, "UNIT", self.unit),
            patch.object(deploy, "BACKUPS", self.backups), patch.object(deploy, "preflight"),
            patch.object(deploy, "choose_binary", return_value=("/usr/bin/sing-box", "existing")),
            patch.object(deploy, "run", side_effect=self.fake_run), patch.object(deploy.time, "sleep"), patch.object(deploy, "emit")]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def fake_run(self, *args, **kwargs):
        self.calls.append(args)
        code, stdout = 0, ""
        if args[:3] == ("systemctl", "is-active", "--quiet"):
            code = 0 if self.active else 3
        elif args[:3] == ("systemctl", "is-enabled", "--quiet"):
            code = 0 if self.enabled else 1
        elif args[:2] == ("systemctl", "restart"):
            if self.fail_start:
                code = 1
                self.fail_start = False
            else:
                self.active = True
        elif args[:2] == ("systemctl", "start"):
            self.active = True
        elif args[:2] == ("systemctl", "stop"):
            self.active = False
        elif args[:2] == ("systemctl", "enable"):
            code = 1 if self.fail_enable else 0
            if not code:
                self.enabled = True
        elif args[:2] == ("systemctl", "disable"):
            self.enabled = False
        elif args[:2] == ("/usr/bin/sing-box", "check"):
            code = 1 if self.fail_check else 0
        elif args[0] == "ss" and self.occupied:
            stdout = "tcp LISTEN 0 4096 0.0.0.0:18443 0.0.0.0:*\n"
        return subprocess.CompletedProcess(args, code, stdout, "")

    def managed(self):
        self.config_dir.mkdir()
        old = {"inbounds": [{"type": "shadowsocks", "method": deploy.METHOD, "listen_port": 18443,
                            "password": "AQEBAQEBAQEBAQEBAQEBAQ=="}]}
        (self.config_dir / "config.json").write_text(json.dumps(old))
        (self.config_dir / "managed.json").write_text(json.dumps({"owner": "vps-clash-link"}))
        self.unit.write_text("previous-unit")
        return old

    def test_fresh_deploy_uses_isolated_paths(self):
        result = deploy.deploy({"port": 18443})
        self.assertTrue(result["success"])
        self.assertTrue(self.active and self.enabled)
        self.assertEqual(json.loads((self.config_dir / "config.json").read_text())["inbounds"][0]["listen_port"], 18443)
        self.assertIn("ProtectSystem=strict", self.unit.read_text())
        self.assertTrue(Path(result["backup"]).is_dir())
        self.assertFalse(any("sing-box.service" in call for call in self.calls))

    def test_redeployment_preserves_the_existing_node_key(self):
        old = self.managed()
        result = deploy.deploy({"port": 18444})
        self.assertEqual(result["password"], old["inbounds"][0]["password"])

    def test_unmanaged_config_is_never_overwritten(self):
        self.config_dir.mkdir()
        file = self.config_dir / "config.json"
        file.write_text("user data")
        with self.assertRaises(RuntimeError):
            deploy.deploy({"port": 18443})
        self.assertEqual(file.read_text(), "user data")

    def test_port_conflict_stops_before_changes(self):
        self.occupied = True
        with self.assertRaises(RuntimeError):
            deploy.deploy({"port": 18443})
        self.assertFalse(self.config_dir.exists())
        self.assertFalse(self.unit.exists())

    def test_failed_candidate_check_preserves_existing_config(self):
        self.managed()
        before = (self.config_dir / "config.json").read_bytes()
        self.fail_check = True
        with self.assertRaises(RuntimeError):
            deploy.deploy({"port": 18444})
        self.assertEqual((self.config_dir / "config.json").read_bytes(), before)
        self.assertFalse(any(call[:2] == ("systemctl", "stop") for call in self.calls))

    def test_failed_start_restores_an_existing_service(self):
        self.managed()
        before = (self.config_dir / "config.json").read_bytes()
        self.active = self.enabled = True
        self.fail_start = True
        with self.assertRaises(RuntimeError):
            deploy.deploy({"port": 18444})
        self.assertEqual((self.config_dir / "config.json").read_bytes(), before)
        self.assertEqual(self.unit.read_text(), "previous-unit")
        self.assertTrue(self.active and self.enabled)

    def test_failed_fresh_start_leaves_no_unmanaged_directory(self):
        self.fail_start = True
        with self.assertRaises(RuntimeError):
            deploy.deploy({"port": 18443})
        self.assertFalse(self.config_dir.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.active or self.enabled)

    def test_enable_failure_also_rolls_back_a_fresh_install(self):
        self.fail_enable = True
        with self.assertRaises(RuntimeError):
            deploy.deploy({"port": 18443})
        self.assertFalse(self.config_dir.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.active)


class ArchiveTest(unittest.TestCase):
    def archive(self, symbolic=False):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            member = tarfile.TarInfo("release/sing-box")
            if symbolic:
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                tar.addfile(member)
            else:
                member.size = 4
                tar.addfile(member, io.BytesIO(b"test"))
        data = buffer.getvalue()
        return data, "sha256:" + hashlib.sha256(data).hexdigest()

    def test_verifies_hash_and_extracts_only_the_expected_regular_file(self):
        data, digest = self.archive()
        self.assertEqual(deploy.verified_binary(data, digest, "release/sing-box"), b"test")

    def test_rejects_missing_or_incorrect_digests(self):
        data, _ = self.archive()
        for digest in [None, "sha256:" + "0" * 64]:
            with self.assertRaises(RuntimeError):
                deploy.verified_binary(data, digest, "release/sing-box")

    def test_rejects_a_symlink_in_place_of_the_binary(self):
        data, digest = self.archive(symbolic=True)
        with self.assertRaises(RuntimeError):
            deploy.verified_binary(data, digest, "release/sing-box")


if __name__ == "__main__":
    unittest.main()
