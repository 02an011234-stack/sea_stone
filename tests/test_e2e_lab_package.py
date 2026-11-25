from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

from os_guard_agent.installer import UnixInstaller
from tools.build_e2e_lab_package import ARCHIVE_BASENAME, build


ROOT = Path(__file__).parents[1]


def test_e2e_lab_archive_is_check_only_complete_and_secret_free(tmp_path):
    archive_path, checksum_path = build(ROOT, tmp_path)
    assert archive_path.name == f"{ARCHIVE_BASENAME}.tar.gz"
    expected_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    assert checksum_path.read_text(encoding="ascii") == (
        f"{expected_digest}  {archive_path.name}\n"
    )

    with tarfile.open(archive_path, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        prefix = f"{ARCHIVE_BASENAME}/"
        check_modules = [
            name
            for name in members
            if name.startswith(f"{prefix}modules/unix/U-")
            and name.endswith(".sh")
            and "/harden/" not in name
        ]
        harden_modules = [
            name
            for name in members
            if name.startswith(f"{prefix}modules/unix/harden/U-")
            and name.endswith(".sh")
        ]
        assert len(check_modules) == 67
        assert len(harden_modules) == 42
        assert all(members[name].mode == 0o755 for name in check_modules)
        assert all(members[name].mode == 0o755 for name in harden_modules)
        assert f"{prefix}packaging/runtime-requirements.txt" in members
        assert f"{prefix}docs/unix_server_bundle_contract.md" in members
        manifest_file = archive.extractfile(f"{prefix}modules/manifest.json")
        assert manifest_file is not None
        manifest = json.load(manifest_file)
        assert len(manifest["items"]) == 67
        assert all(item["actions"] == ["CHECK"] for item in manifest["items"])
        assert not any(
            Path(name).name.lower()
            in {"agent.toml", "credentials.json", "token.json", ".env"}
            for name in members
        )
        assert f"{prefix}registration/registration.json" not in members


def test_e2e_lab_archive_is_reproducible(tmp_path):
    first_archive, _ = build(ROOT, tmp_path / "first")
    second_archive, _ = build(ROOT, tmp_path / "second")

    assert first_archive.read_bytes() == second_archive.read_bytes()


def test_e2e_lab_readme_keeps_harden_operationally_blocked(tmp_path):
    archive_path, _ = build(ROOT, tmp_path)
    with tarfile.open(archive_path, "r:gz") as archive:
        readme_file = archive.extractfile(f"{ARCHIVE_BASENAME}/README.md")
        assert readme_file is not None
        readme = readme_file.read().decode("utf-8")
    assert "operational_use_allowed=false" in readme
    assert "HARDEN`, `RECHECK`, and `ROLLBACK` task claims are rejected" in readme
    assert "isolated Agent virtual environment" in readme
    assert "--wheelhouse" in readme


def test_e2e_lab_archive_extracts_as_a_valid_importable_installer_source(tmp_path):
    archive_path, _ = build(ROOT, tmp_path)
    extraction_root = tmp_path / "extracted"
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extractall(extraction_root, filter="data")
    release_root = extraction_root / ARCHIVE_BASENAME
    fixture_root = tmp_path / "fixture-root"
    fixture_root.mkdir()
    UnixInstaller(release_root, root=fixture_root, test_mode=True)._validate_source()

    completed = subprocess.run(
        [sys.executable, "-c", "import os_guard_agent"],
        env={**os.environ, "PYTHONPATH": str(release_root / "src")},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
