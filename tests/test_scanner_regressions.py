import hashlib
import os
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from disklens import scanner


class ScannerRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        self.root = self.parent / "files"
        self.root.mkdir()

    def test_path_and_open_file_metadata_agree_for_unchanged_files(self):
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        for index in range(30):
            path = self.root / f"file-{index}.txt"
            path.write_bytes(b"unchanged content")
            before = os.stat(path, follow_symlinks=False)
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
            self.assertEqual({name: getattr(before, name) for name in fields},
                             {name: getattr(opened, name) for name in fields})
            self.assertEqual(scanner._metadata_time(before), scanner._metadata_time(opened))

    def test_windows_birthtime_keeps_unchanged_files_valid_when_ctime_semantics_differ(self):
        entry = scanner.FileEntry("file.txt", 100, 1000, 500, 1, 2)
        descriptor_info = SimpleNamespace(st_mode=0o100644, st_dev=1, st_ino=2,
                                          st_size=100, st_mtime_ns=1000,
                                          st_ctime_ns=900, st_birthtime_ns=500)
        with patch.object(scanner.os, "name", "nt"):
            matches = scanner._matches(entry, descriptor_info)
        self.assertTrue(matches)

    def test_later_hashing_cannot_leave_an_earlier_changed_duplicate_confirmed(self):
        for name, content in (("a", b"a"), ("b", b"a"), ("c", b"cc"), ("d", b"cc")):
            (self.root / name).write_bytes(content)
        hash_file = scanner._hash_file

        def mutate_earlier_group(root, entry, *, sample):
            if entry.path == "c" and sample:
                (root / "a").write_bytes(b"changed")
            return hash_file(root, entry, sample=sample)

        with patch.object(scanner, "_hash_file", side_effect=mutate_earlier_group):
            report = scanner.scan(self.root)

        self.assertEqual([group["paths"] for group in report["duplicates"]], [["c", "d"]])
        self.assertEqual(report["summary"]["duplicate_bytes"], 2)
        self.assertEqual(report["summary"]["changed_files"], 1)
        self.assertTrue(any(issue["path"] == "a" for issue in report["issues"]))

    def test_ignored_reports_are_resolved_with_a_symlinked_scan_root(self):
        (self.root / "source.txt").write_bytes(b"source")
        (self.root / "report.json").write_bytes(b"old report")
        alias = self.parent / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")

        report = scanner.scan(alias, ignored_paths=(alias / "report.json",))

        self.assertEqual([file["path"] for file in report["files"]], ["source.txt"])
        self.assertEqual(report["summary"]["total_bytes"], 6)
        self.assertEqual(report["summary"]["excluded"], 1)

    def test_short_sample_reads_do_not_hide_identical_large_files(self):
        content = bytes(range(256)) * 1025
        first = self.root / "first.bin"
        first.write_bytes(content)
        (self.root / "second.bin").write_bytes(content)
        short_read_identity = (first.stat().st_dev, first.stat().st_ino)
        read = os.read

        def different_read_lengths(descriptor, count):
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == short_read_identity:
                count = min(count, 8192)
            return read(descriptor, count)

        with patch.object(scanner.os, "read", side_effect=different_read_lengths):
            report = scanner.scan(self.root)

        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(report["duplicates"][0]["paths"], ["first.bin", "second.bin"])
        self.assertEqual(report["duplicates"][0]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(report["issues"], [])


if __name__ == "__main__":
    unittest.main()
