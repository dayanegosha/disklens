import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from disklens import scanner


class ScannerRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        self.root = self.parent / "files"
        self.root.mkdir()

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


if __name__ == "__main__":
    unittest.main()
