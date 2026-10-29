"""Integration tests for Oct29 kernel module packaging and verification (U149).

Runs the real tools/package_plugin.py and tools/verify_package.py on a
selective copy of the project source (no node_modules). These tests target
observable tool behavior only, not internal helper names.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COPY_ITEMS = (
    "plugin.json",
    "package.json",
    "main.py",
    "supervisor.py",
    "dist",
    "LICENSE",
    "README.md",
    "py_modules",
    "compat",
)
COMPAT_DIR_NAME = "armada-7.2.6"
OCT29_MODULE_DIR = "oct29"
OCT29_MODULES = (
    f"uu-accelerator/compat/{COMPAT_DIR_NAME}/oct29/xt_cgroup.ko",
    f"uu-accelerator/compat/{COMPAT_DIR_NAME}/oct29/xt_nat.ko",
)


class PackageOct29Test(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="u149-oct29-"))
        self.project = self.tmp / "project"
        self.project.mkdir()
        for item in COPY_ITEMS:
            src = PROJECT_ROOT / item
            dst = self.project / item
            if src.is_dir():
                shutil.copytree(
                    src, dst, ignore=shutil.ignore_patterns("node_modules")
                )
            else:
                shutil.copy2(src, dst)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _manifest_path(self):
        return self.project / "compat" / COMPAT_DIR_NAME / "manifest.json"

    def _write_manifest(self, data):
        self._manifest_path().write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _package(self):
        out_dir = self.tmp / "out"
        result = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "package_plugin.py"),
                "--root",
                str(self.project),
                "--output",
                str(out_dir),
            ],
            capture_output=True,
            text=True,
        )
        return result, out_dir

    def _verify(self, zip_path):
        return subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "verify_package.py"),
                str(zip_path),
            ],
            capture_output=True,
            text=True,
        )

    def _single_zip(self, out_dir):
        zips = sorted(out_dir.glob("*.zip"))
        self.assertEqual(len(zips), 1)
        return zips[0]

    def test_package_then_verify_oct29_ok(self):
        result, out_dir = self._package()
        self.assertEqual(result.returncode, 0, result.stderr)
        zip_path = self._single_zip(out_dir)
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()
        self.assertEqual(len(names), 25)
        for module in OCT29_MODULES:
            self.assertIn(module, names)
        verify = self._verify(zip_path)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        report = json.loads(verify.stdout)
        self.assertTrue(report["ok"])
        self.assertTrue(report["checks"].get("compat_oct29_profile_valid"))

    def test_packager_rejects_tampered_oct29_module_hash(self):
        data = json.loads(self._manifest_path().read_text(encoding="utf-8"))
        for profile in data["compatible_kernels"]:
            if profile.get("module_dir") == OCT29_MODULE_DIR:
                profile["module_sha256"] = "0" * 64
        self._write_manifest(data)
        result, _ = self._package()
        self.assertNotEqual(result.returncode, 0)

    def test_packager_rejects_missing_oct29_profile(self):
        data = json.loads(self._manifest_path().read_text(encoding="utf-8"))
        data["compatible_kernels"] = [
            profile
            for profile in data["compatible_kernels"]
            if profile.get("module_dir") != OCT29_MODULE_DIR
        ]
        self._write_manifest(data)
        result, _ = self._package()
        self.assertNotEqual(result.returncode, 0)

    def test_verifier_rejects_replaced_oct29_module(self):
        result, out_dir = self._package()
        self.assertEqual(result.returncode, 0, result.stderr)
        zip_path = self._single_zip(out_dir)
        tampered = self.tmp / "tampered.zip"
        with zipfile.ZipFile(zip_path) as src, zipfile.ZipFile(
            tampered, "w"
        ) as dst:
            for info in src.infolist():
                payload = src.read(info.filename)
                if info.filename == OCT29_MODULES[0]:
                    payload = b"\x7fELF" + b"\x00" * 64
                dst.writestr(info, payload)
        verify = self._verify(tampered)
        self.assertNotEqual(verify.returncode, 0)


if __name__ == "__main__":
    unittest.main()
