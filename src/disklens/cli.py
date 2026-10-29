from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

from . import __version__
from .report import render_html
from .scanner import scan


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ"):
        if value < 1024 or unit == "ПиБ":
            return f"{value:.1f} {unit}"
        value /= 1024
    return str(size)


def parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*", value)
    units = {"": 1, "b": 1, "kb": 1000, "mb": 1000**2, "gb": 1000**3,
             "tb": 1000**4, "kib": 1024, "mib": 1024**2,
             "gib": 1024**3, "tib": 1024**4}
    if not match or match[2].lower() not in units:
        raise argparse.ArgumentTypeError("размер: например, 512, 1MiB или 2GB")
    result = float(match[1]) * units[match[2].lower()]
    if not result < 2**63:
        raise argparse.ArgumentTypeError("слишком большой размер")
    return int(result)


def display_path(value: str) -> str:
    return "".join(character if character.isprintable() else ascii(character)[1:-1]
                   for character in value)


def _output_path(value: str | Path) -> Path:
    path = Path(value).expanduser().absolute()
    return path.parent.resolve() / path.name


def _check_output(path: Path, force: bool) -> None:
    if path.is_symlink():
        raise ValueError(f"выходной файл — символическая ссылка: {display_path(str(path))}")
    if path.exists() and (not force or not path.is_file()):
        raise FileExistsError(f"файл уже существует: {display_path(str(path))}; используй --force для перезаписи отчёта")


def _write_report(path: Path, content: str, *, force: bool) -> None:
    _check_output(path, force)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".disklens-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        if force:
            os.replace(temporary, path)
        else:
            # Создание ссылки не перезапишет файл, появившийся после предварительной проверки.
            try:
                os.link(temporary, path)
            except FileExistsError:
                raise
            except OSError:
                # FAT/exFAT не поддерживают жёсткие ссылки. Режим x сохраняет защиту от перезаписи.
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | getattr(os, "O_BINARY", 0), 0o600)
                identity = os.fstat(descriptor)
                try:
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        stream.write(content)
                except BaseException:
                    try:
                        if os.path.samestat(identity, path.stat(follow_symlinks=False)):
                            path.unlink()
                    except OSError:
                        pass
                    raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="крупные файлы, точные дубликаты и локальный HTML-отчёт")
    parser.add_argument("path", help="папка для анализа")
    parser.add_argument("--html", default="disklens-report.html", metavar="FILE",
                        help="HTML-отчёт (по умолчанию: disklens-report.html)")
    parser.add_argument("--json", metavar="FILE", help="дополнительно сохранить JSON")
    parser.add_argument("--no-html", action="store_true", help="только терминал и выбранный JSON")
    parser.add_argument("--open", action="store_true", help="открыть HTML-отчёт в браузере")
    parser.add_argument("--force", action="store_true", help="перезаписать выбранные отчёты")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                        help="пропустить имя или относительный путь по glob-шаблону; можно повторять")
    parser.add_argument("--min-size", type=parse_size, default=1, metavar="SIZE",
                        help="искать дубликаты от этого размера; список файлов остаётся полным")
    parser.add_argument("--no-duplicates", action="store_true", help="быстрый обзор без чтения содержимого")
    parser.add_argument("--quiet", action="store_true", help="скрыть прогресс и сводку")
    parser.add_argument("--version", action="version", version=f"disklens {__version__}")
    args = parser.parse_args(argv)
    if args.open and args.no_html:
        parser.error("--open нельзя использовать с --no-html")
    html_path = None if args.no_html else _output_path(args.html)
    json_path = _output_path(args.json) if args.json else None
    if html_path and html_path == json_path:
        parser.error("HTML и JSON нужно сохранять в разные файлы")
    outputs = [path for path in (html_path, json_path) if path is not None]
    last_progress = 0.0

    def progress(stage, count):
        nonlocal last_progress
        now = time.monotonic()
        if not args.quiet and sys.stderr.isatty() and now - last_progress >= 0.3:
            text = "найдено файлов" if stage == "scan" else "полностью проверено файлов"
            print(f"\r\033[K{text}: {count}", end="", file=sys.stderr, flush=True)
            last_progress = now

    try:
        for path in outputs:
            _check_output(path, args.force)
        report = scan(args.path, excludes=args.exclude, ignored_paths=outputs,
                      min_duplicate_size=args.min_size,
                      find_duplicates=not args.no_duplicates, progress=progress)
        report["options"] = {"find_duplicates": not args.no_duplicates,
                             "min_duplicate_size": args.min_size, "excludes": args.exclude}
        if last_progress:
            print("\r\033[K", end="", file=sys.stderr)
        if html_path:
            _write_report(html_path, render_html(report), force=args.force)
        if json_path:
            _write_report(json_path, json.dumps(report, ensure_ascii=True, indent=2) + "\n",
                          force=args.force)
    except KeyboardInterrupt:
        print("\nсканирование прервано", file=sys.stderr)
        return 130
    except (OSError, ValueError) as error:
        print(f"disklens: {display_path(str(error))}", file=sys.stderr)
        return 1
    summary = report["summary"]
    if not args.quiet:
        print(f"{summary['files']} файлов · {format_size(summary['total_bytes'])}")
        if args.no_duplicates:
            print("поиск дубликатов отключён")
        else:
            print(f"повторяющиеся данные: {format_size(summary['duplicate_bytes'])} "
                  f"в {summary['duplicate_groups']} группах")
        for file in report["files"][:10]:
            print(f"{format_size(file['size']):>12}  {display_path(file['path'])}")
        for path in outputs:
            print(f"отчёт: {display_path(str(path))}")
    if report["issues"]:
        detail = "; подробности в отчёте" if outputs else ""
        print(f"замечаний: {len(report['issues'])}{detail}", file=sys.stderr)
        if not outputs:
            for issue in report["issues"][:10]:
                print(f"  {display_path(issue['path'])}: {display_path(issue['message'])}", file=sys.stderr)
    if args.open and html_path:
        if not webbrowser.open(html_path.as_uri()):
            print(f"открой отчёт вручную: {display_path(str(html_path))}", file=sys.stderr)
    return 0
