import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from disklens.report import render_html
from disklens.scanner import scan


MIB = 1024 * 1024
MODIFIED = datetime(2026, 10, 12, 12, tzinfo=timezone.utc).timestamp()
FILES = (
    ("фото/карелия.jpg", 2 * MIB, "photo"),
    ("резерв/карелия — копия.jpg", 2 * MIB, "photo"),
    ("видео/поездка.mp4", 3 * MIB, "video"),
    ("документы/инструкция.pdf", MIB // 2, "manual"),
    ("резерв/инструкция.pdf", MIB // 2, "manual"),
    ("архив/проект.zip", MIB, "archive"),
    ("заметки/планы.txt", 32 * 1024, "notes"),
    ("музыка/эскиз.wav", MIB // 2, "music"),
    ("черновик.txt", 0, "empty"),
)


def write_file(root: Path, name: str, size: int, seed: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    block = hashlib.sha256(seed.encode("utf-8")).digest() * 2048
    with path.open("wb") as stream:
        while size:
            part = block[:size]
            stream.write(part)
            size -= len(part)
    os.utime(path, (MODIFIED, MODIFIED))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="disklens-demo-") as temporary:
        root = Path(temporary)
        for name, size, seed in FILES:
            write_file(root, name, size, seed)
        (root / "пустая папка").mkdir()
        report = scan(root)
    report["root"] = "/demo/домашний-архив"
    report["options"] = {"find_duplicates": True, "min_duplicate_size": 1, "excludes": []}
    output = Path(__file__).resolve().parent
    html_path = output / "report.html"
    json_path = output / "report.json"
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(html_path)
    print(json_path)


if __name__ == "__main__":
    main()
