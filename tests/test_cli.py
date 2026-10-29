import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from disklens import cli


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "input"
        self.source.mkdir()
        self.previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous)

    def invoke(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main([str(argument) for argument in arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def write(self, name, content=b"content"):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_default_command_creates_a_standalone_html_report(self):
        self.write("document.txt")

        code, _, stderr = self.invoke(self.source, "--quiet")

        self.assertEqual(code, 0, stderr)
        report = self.root / "disklens-report.html"
        self.assertTrue(report.is_file())
        self.assertIn('id="report-data"', report.read_text(encoding="utf-8"))
        self.assertEqual((self.source / "document.txt").read_bytes(), b"content")

    def test_json_export_has_real_inventory_and_duplicate_totals(self):
        self.write("first.txt", b"same")
        self.write("nested/second.txt", b"same")
        output = self.root / "отчёт.json"

        code, _, stderr = self.invoke(self.source, "--json", output, "--no-html", "--quiet")

        self.assertEqual(code, 0, stderr)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["files"], 2)
        self.assertEqual(report["summary"]["total_bytes"], 8)
        self.assertEqual(report["summary"]["duplicate_bytes"], 4)
        self.assertEqual(set(report["duplicates"][0]["paths"]),
                         {"first.txt", "nested/second.txt"})
        self.assertFalse((self.root / "disklens-report.html").exists())

    def test_terminal_only_mode_does_not_write_a_report(self):
        self.write("only.txt", b"123")

        code, stdout, stderr = self.invoke(self.source, "--no-html")

        self.assertEqual(code, 0, stderr)
        self.assertIn("only.txt", stdout)
        self.assertFalse((self.root / "disklens-report.html").exists())

    def test_existing_output_is_refused_before_reading_the_source(self):
        output = self.root / "report.html"
        output.write_text("keep this report", encoding="utf-8")

        with patch.object(cli, "scan") as scan:
            code, _, stderr = self.invoke(self.source, "--html", output)

        self.assertEqual(code, 1)
        self.assertTrue(stderr)
        scan.assert_not_called()
        self.assertEqual(output.read_text(encoding="utf-8"), "keep this report")

    def test_force_rescan_does_not_analyze_its_own_outputs(self):
        self.write("keep.txt", b"12345")
        html = self.source / "report.html"
        json_path = self.source / "report.json"
        html.write_text("previous report", encoding="utf-8")
        json_path.write_text("previous data", encoding="utf-8")

        for _ in range(2):
            code, _, stderr = self.invoke(self.source, "--html", html, "--json", json_path,
                                          "--force", "--quiet")
            self.assertEqual(code, 0, stderr)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual([item["path"] for item in report["files"]], ["keep.txt"])
            self.assertEqual(report["summary"]["total_bytes"], 5)

    def test_symlink_output_is_refused_even_with_force(self):
        target = self.root / "private.txt"
        target.write_text("do not overwrite", encoding="utf-8")
        output = self.root / "report.html"
        try:
            output.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")

        with patch.object(cli, "scan") as scan:
            code, _, _ = self.invoke(self.source, "--html", output, "--force")

        self.assertEqual(code, 1)
        scan.assert_not_called()
        self.assertTrue(output.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "do not overwrite")

    def test_same_html_and_json_output_is_an_argument_error(self):
        with self.assertRaises(SystemExit) as error:
            self.invoke(self.source, "--html", "report", "--json", "./report")
        self.assertEqual(error.exception.code, 2)

    def test_open_requires_an_html_report(self):
        with self.assertRaises(SystemExit) as error:
            self.invoke(self.source, "--no-html", "--open")
        self.assertEqual(error.exception.code, 2)

    def test_open_uses_the_written_report_file_uri(self):
        self.write("file.txt")
        output = self.root / "отчёт с пробелом.html"

        with patch("webbrowser.open", return_value=True) as browser:
            code, _, stderr = self.invoke(self.source, "--html", output, "--open", "--quiet")

        self.assertEqual(code, 0, stderr)
        browser.assert_called_once()
        self.assertEqual(browser.call_args.args[0], output.as_uri())
        self.assertTrue(output.exists())

    def test_size_units_are_passed_to_duplicate_detection(self):
        values = {"12": 12, "12B": 12, "2KiB": 2048, "1MiB": 1048576,
                  "2GiB": 2147483648, "1TiB": 1099511627776,
                  "2KB": 2000, "3MB": 3000000, "1GB": 1000000000}
        for value, expected in values.items():
            with self.subTest(value=value):
                with patch.object(cli, "scan", wraps=cli.scan) as scan:
                    code, _, stderr = self.invoke(self.source, "--no-html", "--min-size", value,
                                                  "--quiet")
                self.assertEqual(code, 0, stderr)
                self.assertEqual(scan.call_args.kwargs["min_duplicate_size"], expected)

    def test_invalid_size_is_an_argument_error(self):
        for value in ("nonsense", "-1", "1XB"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit) as error:
                    self.invoke(self.source, "--no-html", "--min-size", value)
                self.assertEqual(error.exception.code, 2)

    def test_terminal_paths_cannot_inject_ansi_control_sequences(self):
        if os.name == "nt":
            self.skipTest("Windows file names reject control characters")
        self.write("unsafe\x1b[31m.txt")

        code, stdout, stderr = self.invoke(self.source, "--no-html")

        self.assertEqual(code, 0, stderr)
        self.assertNotIn("\x1b", stdout)
        self.assertIn("unsafe", stdout)

    def test_writer_preserves_an_existing_file_without_force(self):
        output = self.root / "report.txt"
        output.write_text("old", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            cli._write_report(output, "new", force=False)

        self.assertEqual(output.read_text(encoding="utf-8"), "old")

    def test_writer_uses_utf8_and_supports_explicit_replacement(self):
        output = self.root / "отчёт.txt"
        cli._write_report(output, "первый отчёт", force=False)
        self.assertEqual(output.read_bytes(), "первый отчёт".encode("utf-8"))

        cli._write_report(output, "второй отчёт", force=True)

        self.assertEqual(output.read_bytes(), "второй отчёт".encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
