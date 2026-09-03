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


def verify_signature(path):
    subprocess.run(["cosign2", "dump", "--input", str(path)],
                   check=True, stdout=subprocess.DEVNULL)


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
    if args.output.exists():
        raise ValueError("Output already exists; choose a new output path")
    files = read_bundle(args.input)
    manifest = validate(files, config, require_minimum=False)
    signer = files["manifest.json"][143:176]

    with tempfile.TemporaryDirectory(prefix="beta3-pack-", dir=root / "target") as tmp:
        tmp = Path(tmp)
        for name in ("manifest.json", "app.elf"):
            path = tmp / name
            path.write_bytes(files[name])
            verify_signature(path)
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
            verify_signature(signed)
            files["manifest.json"] = signed.read_bytes()
        if files["manifest.json"][143:176] != signer:
            raise ValueError("Signing identity changed")
        validate(files, config)

        with args.output.open("xb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    for name in ["manifest.json", *sorted(manifest["fileHashes"])]:
                        entry = tarfile.TarInfo(name)
                        entry.size = len(files[name])
                        entry.mode = 0o644
                        archive.addfile(entry, io.BytesIO(files[name]))
    validate(read_bundle(args.output), config)
    print(f"Verified {args.output}: version {manifest['version']}, "
          f"minimum KeyOS {manifest['minKeyosVersion']}, unchanged app and signer")


if __name__ == "__main__":
    main()
