import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "pack_beta3", Path(__file__).resolve().parents[1] / "scripts" / "pack-beta3.py")
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


class PackageValidationTests(unittest.TestCase):
    def setUp(self):
        self.config = {"app-id": "test-app", "version": "0.1.1", "min-keyos-version": "1.4.0-beta3"}
        self.header = b"PRM1" + bytes(pack.HEADER_SIZE - 4)
        self.manifest = {
            "appId": "test-app", "version": "0.1.1", "minKeyosVersion": "1.4.0-beta3",
            "fileHashes": {"app.elf": hashlib.sha256(b"example-app").hexdigest()}}

    def files(self, manifest=None):
        return {"manifest.json": self.header + json.dumps(manifest or self.manifest).encode(),
                "app.elf": self.header + b"example-app"}

    def test_valid_metadata_and_hashes(self):
        pack.validate(self.files(), self.config)

    def test_missing_minimum_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        del manifest["minKeyosVersion"]
        with self.assertRaisesRegex(ValueError, "minKeyosVersion"):
            pack.validate(self.files(manifest), self.config)

    def test_legacy_input_can_be_read_for_repair(self):
        manifest = copy.deepcopy(self.manifest)
        del manifest["minKeyosVersion"]
        pack.validate(self.files(manifest), self.config, require_minimum=False)

    def test_wrong_minimum_is_not_silently_changed(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["minKeyosVersion"] = "2.0.0"
        with self.assertRaisesRegex(ValueError, "minKeyosVersion"):
            pack.validate(self.files(manifest), self.config, require_minimum=False)

    def test_changed_app_is_rejected(self):
        files = self.files()
        files["app.elf"] += b"corrupt"
        with self.assertRaisesRegex(ValueError, "Hash mismatch"):
            pack.validate(files, self.config)

    def test_extra_archive_file_is_rejected(self):
        files = self.files()
        files["unexpected"] = b"extra"
        with self.assertRaisesRegex(ValueError, "Archive files"):
            pack.validate(files, self.config)

    def test_wrong_version_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["version"] = "0.1.0"
        with self.assertRaisesRegex(ValueError, "app/version"):
            pack.validate(self.files(manifest), self.config)

    def test_version_comes_from_cargo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app-config.toml").write_text('app-id = "test-app"\n')
            (root / "Cargo.toml").write_text('[package]\nversion = "0.2.0"\n')
            self.assertEqual(pack.read_config(root)["version"], "0.2.0")

    def test_conflicting_legacy_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app-config.toml").write_text('version = "0.1.1"\n')
            (root / "Cargo.toml").write_text('[package]\nversion = "0.2.0"\n')
            with self.assertRaisesRegex(ValueError, "differs from Cargo.toml"):
                pack.read_config(root)

    def test_app_declares_no_security_permission(self):
        root = Path(__file__).resolve().parents[1]
        config = pack.read_config(root)
        self.assertNotIn("os/security", config["permissions"])
        self.assertEqual(config["min-keyos-version"], "1.4.0-beta3")


if __name__ == "__main__":
    unittest.main()
