#!/usr/bin/env python3
"""Validate an SDK archive and preserve its configured minimum KeyOS version."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

HEADER_SIZE = 2048
MAX_SIZE = 64 * 1024 * 1024


def read_config(root):
    config = tomllib.loads((root / "app-config.toml").read_text())
    cargo = tomllib.loads((root / "Cargo.toml").read_text())
    version = cargo["package"]["version"]
    if "version" in config and config["version"] != version:
        raise ValueError("App config version differs from Cargo.toml")
    config["version"] = version
    return config


def signed_payload(data):
    if len(data) <= HEADER_SIZE or data[:4] != b"PRM1":
        raise ValueError("Missing KeyOS signature header")
    return data[HEADER_SIZE:]


def read_bundle(path):
    files = {}
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            name = entry.name
            if not files and name != "manifest.json":
                raise ValueError("Manifest must be the first archive entry")
            if (not entry.isfile() or name in files or
                    PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts):
                raise ValueError(f"Invalid archive entry: {name}")
            total += entry.size
            if total > MAX_SIZE:
                raise ValueError("Archive exceeds the device size limit")
            files[name] = archive.extractfile(entry).read()
    return files


def validate(files, config, require_minimum=True):
    manifest = json.loads(signed_payload(files["manifest.json"]))
    if manifest["appId"] != config["app-id"] or manifest["version"] != config["version"]:
        raise ValueError("Archive does not match this app/version")
    minimum = manifest.get("minKeyosVersion")
    if (require_minimum or minimum is not None) and minimum != config["min-keyos-version"]:
        raise ValueError("Missing or incorrect minKeyosVersion; Beta 3 refuses this archive")
    hashes = manifest["fileHashes"]
    if "app.elf" not in hashes or set(files) != {"manifest.json", *hashes}:
        raise ValueError("Archive files do not match the signed manifest")
    for name, expected in hashes.items():
        data = signed_payload(files[name]) if name == "app.elf" else files[name]
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Hash mismatch: {name}")
    if files["manifest.json"][143:176] != files["app.elf"][143:176]:
        raise ValueError("Manifest and application have different developer signers")
    return manifest


def verify_signature(data, expected_pubkey, version):
    """Verify a cosign2 developer signature over the complete signed payload."""
    payload = signed_payload(data)
    header = data[:HEADER_SIZE]
    if int.from_bytes(header[42:46], "little") != len(payload):
        raise ValueError("Signed payload length differs from header")
    if header[22:42] != version.encode().ljust(20, b"\0"):
        raise ValueError("Signed payload version differs from app version")
    date, _, padding = header[8:22].partition(b"\0")
    try:
        date.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Signed payload has an invalid date") from exc
    if any(padding):
        raise ValueError("Signed payload has an invalid date")
    if header[46:143] != bytes(97):
        raise ValueError("Expected a developer signature without a trusted signature")
    if header[143:176] != expected_pubkey:
        raise ValueError("Signed payload has the wrong publisher key")
    signature = header[176:240]
    if signature == bytes(64):
        raise ValueError("Signed payload has no developer signature")

    fields = hashlib.sha256(header[:46].ljust(128, b"\0")).digest()
    reserved = hashlib.sha256(header[240:HEADER_SIZE]).digest()
    binary = hashlib.sha256(payload).digest()
    digest = hashlib.sha256(hashlib.sha256(
        (fields + reserved + binary).ljust(128, b"\0")).digest()).digest()
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), expected_pubkey)
        key.verify(utils.encode_dss_signature(r, s), digest,
                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Invalid publisher signature") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = read_config(root)
    identity = config["signing-identity"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", identity):
        raise ValueError("Invalid signing identity")
    public_key_path = Path.home() / ".foundation" / "signing" / identity / "public.pub"
    expected_pubkey = bytes.fromhex(public_key_path.read_text().strip())
    if len(expected_pubkey) != 33:
        raise ValueError("Publisher public key must be 33 bytes")
    if args.output.exists():
        raise ValueError("Output already exists; choose a new output path")
    files = read_bundle(args.input)
    manifest = validate(files, config, require_minimum=False)
    signer = files["manifest.json"][143:176]
    for name in ("manifest.json", "app.elf"):
        verify_signature(files[name], expected_pubkey, config["version"])

    with tempfile.TemporaryDirectory(prefix="beta3-pack-", dir=root / "target") as tmp:
        tmp = Path(tmp)
        for name in ("manifest.json", "app.elf"):
            path = tmp / name
            path.write_bytes(files[name])
        if "minKeyosVersion" not in manifest:
            # The older SDK CLI drops this field even when app-config.toml declares it.
            manifest["minKeyosVersion"] = config["min-keyos-version"]
            unsigned = tmp / "manifest-unsigned.json"
            signed = tmp / "manifest-corrected.json"
            unsigned.write_text(json.dumps(manifest, indent=2) + "\n")
            signing_config = Path.home() / ".foundation" / "signing" / identity / "cosign2.toml"
            subprocess.run(["cosign2", "sign", "--developer", "--input", str(unsigned),
                            "--output", str(signed), "--binary-version", config["version"],
                            "--config", str(signing_config)], check=True)
            files["manifest.json"] = signed.read_bytes()
        if files["manifest.json"][143:176] != signer:
            raise ValueError("Signing identity changed")
        validate(files, config)
        for name in ("manifest.json", "app.elf"):
            verify_signature(files[name], expected_pubkey, config["version"])

        with args.output.open("xb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    for name in ["manifest.json", *sorted(manifest["fileHashes"])]:
                        entry = tarfile.TarInfo(name)
                        entry.size = len(files[name])
                        entry.mode = 0o644
                        archive.addfile(entry, io.BytesIO(files[name]))
    installed = read_bundle(args.output)
    validate(installed, config)
    for name in ("manifest.json", "app.elf"):
        verify_signature(installed[name], expected_pubkey, config["version"])
    print(f"Verified {args.output}: version {manifest['version']}, "
          f"minimum KeyOS {manifest['minKeyosVersion']}, unchanged app and signer")


if __name__ == "__main__":
    main()
