"""Bounded ZIP ingestion. Repository bytes are data; no repository scripts run."""

import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from uuid import uuid4

from sentinel.domain import Manifest, SourceFile

MAX_ARCHIVE = 8 * 1024 * 1024
MAX_SOURCE = 16 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_FILES = 500
ALLOWED = {".sol", ".json", ".toml", ".lock", ".md"}


class IngestionError(ValueError):
    pass


def safe_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or len(name) > 240
        or "\\" in name
        or ":" in name
        or any(ord(char) < 32 for char in name)
        or path.is_absolute()
        or any(part in {".", "..", ".git"} for part in name.split("/"))
    ):
        raise IngestionError("Unsafe archive path")
    return path


def ingest_zip(data: bytes, storage: Path) -> tuple[Manifest, Path]:
    if len(data) > MAX_ARCHIVE:
        raise IngestionError("Archive exceeds download limit")
    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise IngestionError("Too many archive entries")
            total = 0
            seen: set[str] = set()
            for entry in entries:
                path = safe_path(entry.filename.rstrip("/") if entry.is_dir() else entry.filename)
                name = str(path)
                if name.casefold() in seen:
                    raise IngestionError("Duplicate or case-colliding path")
                seen.add(name.casefold())
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                    raise IngestionError("Links and special files are forbidden")
                if entry.is_dir():
                    continue
                if path.suffix not in ALLOWED or path.name in {".gitmodules", "manifest.json"}:
                    raise IngestionError("Unsupported archive entry")
                if entry.flag_bits & 1:
                    raise IngestionError("Encrypted archives are forbidden")
                if entry.file_size > MAX_FILE:
                    raise IngestionError("File exceeds size limit")
                total += entry.file_size
                if total > MAX_SOURCE:
                    raise IngestionError("Source exceeds expanded size limit")
                with archive.open(entry) as stream:
                    value = stream.read(MAX_FILE + 1)
                if len(value) != entry.file_size or len(value) > MAX_FILE:
                    raise IngestionError("Invalid expanded file size")
                value.decode("utf-8")
                contents[name] = value
    except (zipfile.BadZipFile, UnicodeError, RuntimeError, NotImplementedError) as exc:
        raise IngestionError("Invalid UTF-8 ZIP archive") from exc
    if not any(name.endswith(".sol") for name in contents):
        raise IngestionError("No Solidity sources found")
    names = {name.casefold() for name in contents}
    for name in contents:
        if any(
            str(parent).casefold() in names
            for parent in PurePosixPath(name).parents
            if str(parent) != "."
        ):
            raise IngestionError("Archive file conflicts with a directory")
    files = [
        SourceFile(path=name, sha256=hashlib.sha256(value).hexdigest(), size=len(value))
        for name, value in sorted(contents.items())
    ]
    revision = hashlib.sha256(
        json.dumps([f.model_dump() for f in files], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    pragmas = sorted(
        {
            match
            for name, value in contents.items()
            if name.endswith(".sol")
            for match in re.findall(r"pragma\s+solidity\s+([^;]+);", value.decode())
        }
    )
    manifest = Manifest(
        revision=revision,
        files=files,
        compiler_pragmas=pragmas,
        configurations=[
            name
            for name in contents
            if PurePosixPath(name).name in {"foundry.toml", "package.json"}
        ],
    )
    # Fresh private directory; never merge into an existing or attacker-owned tree.
    storage.mkdir(parents=True, exist_ok=True, mode=0o700)
    snapshot = storage / str(uuid4())
    snapshot.mkdir(mode=0o700)
    for name, value in contents.items():
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        target.chmod(0o444)
    (snapshot / "manifest.json").write_text(manifest.model_dump_json(indent=2))
    return manifest, snapshot


def verify_snapshot(manifest: Manifest, snapshot: Path) -> None:
    for source in manifest.files:
        target = snapshot / source.path
        if target.is_symlink() or not target.is_file():
            raise IngestionError("Snapshot changed")
        if hashlib.sha256(target.read_bytes()).hexdigest() != source.sha256:
            raise IngestionError("Snapshot hash mismatch")
