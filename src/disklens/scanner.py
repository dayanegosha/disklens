from __future__ import annotations

import fnmatch
import os
import stat
import time
from dataclasses import dataclass
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


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


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
) -> dict:
    started = time.monotonic()
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"не папка: {root}")
    patterns = tuple(excludes)
    ignored = {os.path.abspath(Path(path).expanduser()) for path in ignored_paths}
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
    return {
        "schema_version": 1,
        "root": str(root),
        "created_at": _utc(time.time()),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "summary": summary,
        "files": [{"path": file.path, "size": file.size, "modified": _utc(file.mtime_ns / 1e9)}
                  for file in sorted(files, key=lambda file: (-file.size, file.path))],
        "directories": sorted(sizes.values(), key=lambda row: (-row["size"], row["path"])),
        "duplicates": [],
        "hardlinks": hardlinks,
        "issues": issues,
    }
