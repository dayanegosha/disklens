from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
import time
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    mtime_ns: int
    ctime_ns: int
    device: int
    inode: int


class ChangedFileError(OSError):
    pass


def _matches(file: FileEntry, info: os.stat_result) -> bool:
    return (stat.S_ISREG(info.st_mode)
            and (file.device, file.inode, file.size, file.mtime_ns, file.ctime_ns)
            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))


def _read_exact(descriptor: int, count: int) -> bytes:
    chunks = []
    while count:
        chunk = os.read(descriptor, count)
        if not chunk:
            raise ChangedFileError("файл укоротился при чтении")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _hash_file(root: Path, file: FileEntry, *, sample: bool) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(root / file.path, flags)
    try:
        if not _matches(file, os.fstat(descriptor)):
            raise ChangedFileError("файл изменился после обхода")
        digest = hashlib.sha256()
        if sample and file.size > 131072:
            digest.update(_read_exact(descriptor, 65536))
            os.lseek(descriptor, file.size - 65536, os.SEEK_SET)
            digest.update(_read_exact(descriptor, 65536))
        else:
            remaining = file.size
            while remaining:
                chunk = os.read(descriptor, min(1048576, remaining))
                if not chunk:
                    raise ChangedFileError("файл укоротился при чтении")
                digest.update(chunk)
                remaining -= len(chunk)
        if (not _matches(file, os.fstat(descriptor))
                or not _matches(file, os.stat(root / file.path, follow_symlinks=False))):
            raise ChangedFileError("файл изменился при чтении")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _find_duplicates(root, files, minimum, summary, issues, progress):
    by_size = defaultdict(list)
    for file in files:
        if file.size >= max(1, minimum):
            by_size[file.size].append(file)
    invalid = set()
    checked = set()

    def issue(file, error):
        if file.path not in invalid:
            invalid.add(file.path)
            issues.append({"path": file.path, "message": str(error)})
            if isinstance(error, ChangedFileError):
                summary["changed_files"] += 1

    def fingerprint(file, sample):
        try:
            value = _hash_file(root, file, sample=sample)
            if not sample:
                checked.add(file.path)
                summary["hashed_files"] = len(checked)
            if progress:
                progress("hash", len(checked))
            return value
        except OSError as error:
            issue(file, error)
            return None

    confirmed = []
    for size, candidates in by_size.items():
        if len(candidates) < 2:
            continue
        by_sample = defaultdict(list)
        for file in candidates:
            value = fingerprint(file, True)
            if value is not None:
                by_sample[value].append(file)
        for sample_group in by_sample.values():
            if len(sample_group) < 2:
                continue
            by_hash = defaultdict(list)
            for file in sample_group:
                value = fingerprint(file, False)
                if value is not None:
                    by_hash[value].append(file)
            for digest, group in by_hash.items():
                if len(group) > 1:
                    confirmed.append((size, digest, group))
    duplicates = []
    # Перепроверяем все группы после чтения: поздний хэш мог занять несколько минут.
    for size, digest, group in confirmed:
        valid = []
        for file in group:
            try:
                if not _matches(file, os.stat(root / file.path, follow_symlinks=False)):
                    raise ChangedFileError("файл изменился до завершения проверки")
                valid.append(file.path)
            except OSError as error:
                issue(file, error)
        if len(valid) > 1:
            duplicates.append({"size": size, "sha256": digest,
                               "reclaimable_bytes": size * (len(valid) - 1),
                               "paths": sorted(valid)})
    return sorted(duplicates, key=lambda row: (-row["reclaimable_bytes"], row["paths"]))


def _utc(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        return ""


def _excluded(path: str, patterns: Iterable[str]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(name, pattern)
               for pattern in patterns)


def scan(
    root: str | Path,
    *,
    excludes: Iterable[str] = (),
    ignored_paths: Iterable[str | Path] = (),
    progress: Callable[[str, int], None] | None = None,
    min_duplicate_size: int = 1,
    find_duplicates: bool = True,
) -> dict:
    started = time.monotonic()
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"не папка: {root}")
    patterns = tuple(excludes)
    ignored = {str(Path(path).expanduser().resolve(strict=False)) for path in ignored_paths}
    files: list[FileEntry] = []
    issues: list[dict] = []
    hardlinks: list[dict] = []
    seen: dict[tuple[int, int], str] = {}
    folders = {"."}
    summary = dict(files=0, directories=0, total_bytes=0, duplicate_groups=0,
                   duplicate_files=0, duplicate_bytes=0, symlinks_skipped=0,
                   hardlinks_skipped=0, excluded=0, hashed_files=0, changed_files=0)
    pending = [root]
    while pending:
        folder = pending.pop()
        relative = folder.relative_to(root).as_posix()
        try:
            if folder.is_symlink():
                summary["symlinks_skipped"] += 1
                continue
            with os.scandir(folder) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError as error:
            issues.append({"path": relative, "message": str(error)})
            continue
        folders.add(relative)
        summary["directories"] += 1
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            if os.path.abspath(path) in ignored or _excluded(relative, patterns):
                summary["excluded"] += 1
                continue
            try:
                info = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    summary["symlinks_skipped"] += 1
                elif stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    folders.add(relative)
                elif stat.S_ISREG(info.st_mode):
                    # DirEntry.stat в Windows не заполняет идентификаторы файла.
                    if os.name == "nt":
                        info = os.stat(path, follow_symlinks=False)
                        if not stat.S_ISREG(info.st_mode):
                            raise ChangedFileError("тип файла изменился после обхода")
                    identity = (info.st_dev, info.st_ino)
                    if info.st_ino and identity in seen:
                        hardlinks.append({"path": relative, "target": seen[identity]})
                        summary["hardlinks_skipped"] += 1
                        continue
                    seen[identity] = relative
                    files.append(FileEntry(relative, info.st_size, info.st_mtime_ns,
                                           info.st_ctime_ns, info.st_dev, info.st_ino))
                    if progress and len(files) % 250 == 0:
                        progress("scan", len(files))
                else:
                    issues.append({"path": relative, "message": "необычный тип файла, пропущен"})
            except OSError as error:
                issues.append({"path": relative, "message": str(error)})
    sizes = {folder: {"path": folder, "size": 0, "files": 0} for folder in folders}
    for file in files:
        parent = Path(file.path).parent
        while True:
            row = sizes[parent.as_posix()]
            row["size"] += file.size
            row["files"] += 1
            if parent == Path("."):
                break
            parent = parent.parent
    summary["files"] = len(files)
    summary["total_bytes"] = sum(file.size for file in files)
    duplicates = (_find_duplicates(root, files, min_duplicate_size, summary, issues, progress)
                  if find_duplicates else [])
    summary["duplicate_groups"] = len(duplicates)
    summary["duplicate_files"] = sum(len(group["paths"]) for group in duplicates)
    summary["duplicate_bytes"] = sum(group["reclaimable_bytes"] for group in duplicates)
    return {
        "schema_version": 1,
        "root": str(root),
        "created_at": _utc(time.time()),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "summary": summary,
        "files": [{"path": file.path, "size": file.size, "modified": _utc(file.mtime_ns / 1e9)}
                  for file in sorted(files, key=lambda file: (-file.size, file.path))],
        "directories": sorted(sizes.values(), key=lambda row: (-row["size"], row["path"])),
        "duplicates": duplicates,
        "hardlinks": hardlinks,
        "issues": issues,
    }
