import argparse
import sys

from . import __version__
from .scanner import scan


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ"):
        if value < 1024 or unit == "ПиБ":
            return f"{value:.1f} {unit}"
        value /= 1024
    return str(size)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="локальный анализ диска")
    parser.add_argument("path", help="папка для анализа")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    parser.add_argument("--version", action="version", version=f"disklens {__version__}")
    args = parser.parse_args(argv)
    try:
        report = scan(args.path, excludes=args.exclude)
    except (OSError, ValueError) as error:
        print(f"disklens: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(f"{summary['files']} файлов · {format_size(summary['total_bytes'])}")
    for file in report["files"][:10]:
        print(f"{format_size(file['size']):>12}  {file['path']}")
    if report["issues"]:
        print(f"пропущено с ошибками: {len(report['issues'])}", file=sys.stderr)
    return 0
