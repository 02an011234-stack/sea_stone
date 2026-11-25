"""Build the explicit, secret-free OS Guard Unix E2E lab archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable, Sequence


ARCHIVE_BASENAME = "os-guard-unix-agent-e2e-lab-v0.1.0-dev"
CHECK_PATTERN = re.compile(r"U-[0-9]{2}\.sh$")
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
FORBIDDEN_NAMES = {
    ".env",
    "agent.toml",
    "credentials.json",
    "agent-credentials.json",
    "token.json",
    "tokens.json",
}
ROOT_FILES = (
    Path("install.sh"),
    Path("pyproject.toml"),
)
DOCUMENT_FILES = (
    Path("docs/unix_local_install.md"),
    Path("docs/unix_server_bundle_contract.md"),
    Path("docs/harden_policy_fixture_contract.md"),
    Path("docs/agent_api_v2_policy_security.md"),
)
PACKAGING_FILES = (
    Path("packaging/systemd/os-guard-agent.service"),
    Path("packaging/unix/os-guard-agent"),
    Path("packaging/unix/os-guard-preflight"),
    Path("packaging/runtime-requirements.txt"),
    Path("config/agent.toml.example"),
)


class PackageBuildError(RuntimeError):
    """Raised when the release allowlist or safety checks fail."""


def _tree_files(root: Path, relative: Path, suffix: str) -> tuple[Path, ...]:
    directory = root / relative
    return tuple(
        path.relative_to(root)
        for path in sorted(directory.rglob(f"*{suffix}"))
        if path.is_file() and "__pycache__" not in path.parts
    )


def release_files(root: Path) -> tuple[Path, ...]:
    files = [*ROOT_FILES, *DOCUMENT_FILES, *PACKAGING_FILES]
    files.extend(_tree_files(root, Path("src/os_guard_agent"), ".py"))
    files.extend(_tree_files(root, Path("modules/lib"), ".sh"))
    files.extend(
        path.relative_to(root)
        for path in sorted((root / "modules/unix").glob("U-??.sh"))
        if path.is_file()
    )
    files.extend(_tree_files(root, Path("modules/unix/harden"), ".sh"))
    wheelhouse = root / "wheelhouse"
    if wheelhouse.exists():
        if wheelhouse.is_symlink() or not wheelhouse.is_dir():
            raise PackageBuildError("wheelhouse must be a regular directory")
        files.extend(
            path.relative_to(root)
            for path in sorted(wheelhouse.glob("*.whl"))
            if path.is_file()
        )
    files.append(Path("modules/manifest.json"))
    files.append(Path("packaging/e2e/README.md"))
    return tuple(dict.fromkeys(files))


def _validate_manifest(root: Path) -> None:
    try:
        document = json.loads((root / "modules/manifest.json").read_text("utf-8"))
        items = document["items"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError):
        raise PackageBuildError("Manifest cannot be validated") from None
    expected = {f"U-{number:02d}" for number in range(1, 68)}
    if (
        not isinstance(items, list)
        or len(items) != 67
        or {item.get("item_id") for item in items} != expected
    ):
        raise PackageBuildError("Manifest does not contain the complete Unix CHECK set")
    for item in items:
        if item.get("implemented") is not True or item.get("actions") != ["CHECK"]:
            raise PackageBuildError("Manifest must remain implemented CHECK-only")
        module = item.get("module")
        if not isinstance(module, str) or not CHECK_PATTERN.search(module):
            raise PackageBuildError("Manifest CHECK module path is invalid")
        module_path = root / "modules" / module
        if not module_path.is_file() or module_path.is_symlink():
            raise PackageBuildError("Manifest references an unsafe CHECK module")


def _validate_files(root: Path, files: Iterable[Path]) -> None:
    for relative in files:
        source = root / relative
        if source.is_symlink() or not source.is_file():
            raise PackageBuildError(f"unsafe or missing release file: {relative.as_posix()}")
        if source.name.lower() in FORBIDDEN_NAMES:
            raise PackageBuildError(f"runtime secret file is forbidden: {relative.as_posix()}")
        if source.suffix.lower() in {".key", ".pem", ".p12", ".pfx", ".jks"}:
            raise PackageBuildError(f"private material is forbidden: {relative.as_posix()}")
        content = source.read_bytes()
        if PRIVATE_KEY_MARKER.search(content):
            raise PackageBuildError(f"private key content is forbidden: {relative.as_posix()}")


def _archive_mode(relative: Path) -> int:
    if relative == Path("install.sh") or relative.parent == Path("packaging/unix"):
        return 0o755
    if relative.suffix == ".sh":
        return 0o755
    return 0o644


def _tar_bytes(root: Path, files: Sequence[Path]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for relative in files:
            content = (root / relative).read_bytes()
            archive_path = Path(ARCHIVE_BASENAME) / (
                Path("README.md")
                if relative == Path("packaging/e2e/README.md")
                else relative
            )
            info = tarfile.TarInfo(archive_path.as_posix())
            info.size = len(content)
            info.mode = _archive_mode(relative)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _validate_archive(archive_path: Path) -> None:
    prefix = f"{ARCHIVE_BASENAME}/"
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        if any(
            not member.isfile()
            or not member.name.startswith(prefix)
            or ".." in Path(member.name).parts
            or member.issym()
            or member.islnk()
            for member in members
        ):
            raise PackageBuildError("archive contains an unsafe member")
        check_names = {
            name
            for name in names
            if name.startswith(f"{prefix}modules/unix/U-")
            and name.endswith(".sh")
            and "/harden/" not in name
        }
        if len(check_names) != 67:
            raise PackageBuildError("archive does not contain 67 CHECK modules")
        required = {
            f"{prefix}README.md",
            f"{prefix}install.sh",
            f"{prefix}modules/manifest.json",
            f"{prefix}src/os_guard_agent/__main__.py",
        }
        if not required.issubset(names):
            raise PackageBuildError("archive is missing required entry points")


def build(root: Path, output_directory: Path) -> tuple[Path, Path]:
    root = root.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    files = release_files(root)
    _validate_manifest(root)
    _validate_files(root, files)
    tar_payload = _tar_bytes(root, files)
    archive_path = output_directory / f"{ARCHIVE_BASENAME}.tar.gz"
    checksum_path = output_directory / f"{archive_path.name}.sha256"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_directory,
        prefix=f".{archive_path.name}.",
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with temporary_path.open("wb") as raw_output:
            # Do not leak the random atomic-write filename into the gzip header.
            # An empty header filename plus a fixed timestamp makes the artifact
            # byte-for-byte reproducible for the same allowlisted inputs.
            with gzip.GzipFile(
                filename="",
                fileobj=raw_output,
                mode="wb",
                mtime=0,
            ) as compressed:
                compressed.write(tar_payload)
        os.replace(temporary_path, archive_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
    _validate_archive(archive_path)
    return archive_path, checksum_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build-e2e-lab-package")
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--output", type=Path, default=Path("dist"))
    arguments = parser.parse_args(argv)
    archive, checksum = build(arguments.root, arguments.output)
    print(archive.resolve())
    print(checksum.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
