import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

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


class SignatureVerificationTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256K1())
        self.pubkey = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        self.version = "0.1.2"

    def signed(self, payload):
        header = bytearray(pack.HEADER_SIZE)
        header[:4] = b"PRM1"
        header[22:22 + len(self.version)] = self.version.encode()
        header[42:46] = len(payload).to_bytes(4, "little")
        header[143:176] = self.pubkey
        fields = hashlib.sha256(bytes(header[:46]).ljust(128, b"\0")).digest()
        reserved = hashlib.sha256(bytes(header[240:])).digest()
        binary = hashlib.sha256(payload).digest()
        digest = hashlib.sha256(hashlib.sha256(
            (fields + reserved + binary).ljust(128, b"\0")).digest()).digest()
        der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        header[176:240] = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return bytes(header) + payload

    def test_valid_developer_signature(self):
        pack.verify_signature(self.signed(b"manifest"), self.pubkey, self.version)

    def test_changed_payload_is_rejected(self):
        data = self.signed(b"manifest")
        with self.assertRaisesRegex(ValueError, "Invalid publisher signature"):
            pack.verify_signature(data[:-1] + b"X", self.pubkey, self.version)

    def test_changed_header_is_rejected(self):
        data = bytearray(self.signed(b"manifest"))
        data[240] ^= 1
        with self.assertRaisesRegex(ValueError, "Invalid publisher signature"):
            pack.verify_signature(bytes(data), self.pubkey, self.version)

    def test_wrong_publisher_is_rejected(self):
        other = ec.generate_private_key(ec.SECP256K1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        with self.assertRaisesRegex(ValueError, "wrong publisher"):
            pack.verify_signature(self.signed(b"manifest"), other, self.version)

    def test_unsigned_header_is_rejected(self):
        data = bytearray(self.signed(b"manifest"))
        data[176:240] = bytes(64)
        with self.assertRaisesRegex(ValueError, "no developer signature"):
            pack.verify_signature(bytes(data), self.pubkey, self.version)

    @unittest.skipUnless(shutil.which("cosign2"), "cosign2 is not installed")
    def test_verifies_real_cosign2_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "payload.json"
            private = root / "test-private.pem"
            signed = root / "signed.json"
            source.write_bytes(b'{"test":true}')
            private.write_bytes(self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            subprocess.run([
                "cosign2", "sign", "--developer", "--input", str(source),
                "--output", str(signed), "--binary-version", self.version,
                "--secret", str(private), "--pubkey", self.pubkey.hex(),
                "--target", "atsama5d27-keyos",
            ], check=True, capture_output=True)
            pack.verify_signature(signed.read_bytes(), self.pubkey, self.version)


if __name__ == "__main__":
    unittest.main()
