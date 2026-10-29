import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from disklens import scanner


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_exact_copies_are_grouped_without_touching_files(self):
        content = b"a useful document\n" * 17
        paths = ["original.txt", "backup/copy.txt", "copies/another.txt"]
        for path in paths:
            self.write(path, content)
        self.write("unrelated.txt", b"different")

        report = scanner.scan(self.root)

        self.assertEqual(len(report["duplicates"]), 1)
        group = report["duplicates"][0]
        self.assertEqual(set(group["paths"]), set(paths))
        self.assertEqual(group["size"], len(content))
        self.assertEqual(group["reclaimable_bytes"], len(content) * 2)
        self.assertEqual(group["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(report["summary"]["duplicate_bytes"], len(content) * 2)
        for path in paths:
            self.assertEqual((self.root / path).read_bytes(), content)

    def test_equal_size_and_equal_samples_do_not_prove_a_duplicate(self):
        prefix = b"a" * 65536
        suffix = b"z" * 65536
        self.write("first.bin", prefix + b"b" * 65536 + suffix)
        self.write("second.bin", prefix + b"c" * 65536 + suffix)
        self.write("short-first.txt", b"abc")
        self.write("short-second.txt", b"xyz")

        report = scanner.scan(self.root)

        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["summary"]["duplicate_bytes"], 0)

    def test_unique_sizes_and_empty_files_do_not_need_hashing(self):
        self.write("one", b"a")
        self.write("two", b"ab")
        self.write("empty-one", b"")
        self.write("empty-two", b"")

        with patch.object(scanner, "_hash_file", side_effect=AssertionError("unneeded read")):
            report = scanner.scan(self.root)

        self.assertEqual(report["summary"]["files"], 4)
        self.assertEqual(report["summary"]["total_bytes"], 3)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["summary"]["hashed_files"], 0)

    def test_minimum_size_only_filters_duplicate_detection(self):
        self.write("small-a", b"abc")
        self.write("small-b", b"abc")
        self.write("large-a", b"abcdefgh")
        self.write("large-b", b"abcdefgh")

        report = scanner.scan(self.root, min_duplicate_size=8)

        self.assertEqual(report["summary"]["files"], 4)
        self.assertEqual(report["summary"]["total_bytes"], 22)
        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(set(report["duplicates"][0]["paths"]), {"large-a", "large-b"})

    def test_duplicate_detection_can_be_disabled_without_losing_inventory(self):
        self.write("first", b"same content")
        self.write("second", b"same content")

        with patch.object(scanner, "_hash_file", side_effect=AssertionError("unneeded read")):
            report = scanner.scan(self.root, find_duplicates=False)

        self.assertEqual(report["summary"]["files"], 2)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["summary"]["hashed_files"], 0)

    def test_duplicate_groups_are_ordered_by_repeated_bytes(self):
        self.write("large-a", b"x" * 100)
        self.write("large-b", b"x" * 100)
        for name in ("small-a", "small-b", "small-c", "small-d"):
            self.write(name, b"y" * 40)

        report = scanner.scan(self.root)

        self.assertEqual([group["reclaimable_bytes"] for group in report["duplicates"]],
                         [120, 100])
        self.assertEqual(report["summary"]["duplicate_bytes"], 220)

    def test_unicode_and_markup_are_preserved_as_file_names(self):
        paths = ["архив/отпуск & <лето>.txt", "копия/фото '2026'.txt"]
        for path in paths:
            self.write(path, b"same")

        report = scanner.scan(self.root)

        self.assertEqual({file["path"] for file in report["files"]}, set(paths))
        self.assertEqual(set(report["duplicates"][0]["paths"]), set(paths))

    def test_symlink_files_and_directory_cycles_are_skipped(self):
        self.write("folder/original.txt", b"content")
        try:
            (self.root / "linked.txt").symlink_to("folder/original.txt")
            (self.root / "folder" / "cycle").symlink_to(self.root, target_is_directory=True)
            (self.root / "broken").symlink_to("missing.txt")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")

        report = scanner.scan(self.root)

        self.assertEqual(report["summary"]["files"], 1)
        self.assertEqual(report["summary"]["symlinks_skipped"], 3)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["issues"], [])

    def test_hardlinks_are_one_file_and_the_alias_remains_visible(self):
        original = self.write("original.bin", b"content")
        try:
            os.link(original, self.root / "alias.bin")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"hardlinks unavailable: {error}")
        self.write("independent-copy.bin", b"content")

        report = scanner.scan(self.root)

        self.assertEqual(report["summary"]["files"], 2)
        self.assertEqual(report["summary"]["total_bytes"], 14)
        self.assertEqual(report["summary"]["hardlinks_skipped"], 1)
        self.assertEqual(len(report["hardlinks"]), 1)
        alias = report["hardlinks"][0]
        self.assertEqual({alias["path"], alias["target"]}, {"original.bin", "alias.bin"})
        self.assertEqual(report["duplicates"][0]["reclaimable_bytes"], 7)
        self.assertEqual(len(report["duplicates"][0]["paths"]), 2)

    def test_name_patterns_prune_directories_and_match_nested_files(self):
        self.write("keep.txt", b"keep")
        self.write(".cache/large.bin", b"hidden")
        self.write("nested/temporary.tmp", b"temporary")
        self.write("nested/keep.txt", b"other")

        report = scanner.scan(self.root, excludes=(".cache", "*.tmp"))

        self.assertEqual({file["path"] for file in report["files"]},
                         {"keep.txt", "nested/keep.txt"})
        self.assertEqual(report["summary"]["excluded"], 2)
        self.assertFalse(any(row["path"].startswith(".cache") for row in report["directories"]))

    def test_relative_path_patterns_do_not_hide_same_name_elsewhere(self):
        self.write("first/result.bin", b"first")
        self.write("second/result.bin", b"second")

        report = scanner.scan(self.root, excludes=("first/*.bin",))

        self.assertEqual([file["path"] for file in report["files"]], ["second/result.bin"])

    def test_reports_inside_the_root_can_be_ignored_on_repeated_scans(self):
        self.write("source.txt", b"content")
        html = self.write("reports/disk.html", b"old report")
        json = self.write("reports/disk.json", b"old json")

        for _ in range(2):
            report = scanner.scan(self.root, ignored_paths=(html, json))
            self.assertEqual([file["path"] for file in report["files"]], ["source.txt"])
            self.assertEqual(report["summary"]["total_bytes"], 7)
            html.write_text("new report", encoding="utf-8")

    def test_directory_sizes_include_descendants_and_empty_folders(self):
        self.write("root.txt", b"1")
        self.write("folder/child.txt", b"22")
        self.write("folder/deeper/leaf.txt", b"333")
        (self.root / "empty").mkdir()

        report = scanner.scan(self.root)
        rows = {row["path"]: row for row in report["directories"]}

        self.assertEqual(rows["."], {"path": ".", "size": 6, "files": 3})
        self.assertEqual(rows["folder"], {"path": "folder", "size": 5, "files": 2})
        self.assertEqual(rows["folder/deeper"],
                         {"path": "folder/deeper", "size": 3, "files": 1})
        self.assertEqual(rows["empty"], {"path": "empty", "size": 0, "files": 0})

    def test_permission_errors_are_reported_while_other_folders_are_scanned(self):
        self.write("blocked/file.txt", b"hidden")
        self.write("readable/file.txt", b"readable")
        scandir = os.scandir

        def guarded(path):
            if Path(path).name == "blocked":
                raise PermissionError("access denied")
            return scandir(path)

        with patch.object(scanner.os, "scandir", side_effect=guarded):
            report = scanner.scan(self.root)

        self.assertEqual([file["path"] for file in report["files"]], ["readable/file.txt"])
        self.assertEqual(len(report["issues"]), 1)
        self.assertEqual(report["issues"][0]["path"], "blocked")
        self.assertIn("access denied", report["issues"][0]["message"])

    def test_changed_files_are_excluded_from_confirmed_duplicates(self):
        for path in ("first.txt", "second.txt", "changed.txt"):
            self.write(path, b"same content")
        hash_file = scanner._hash_file

        def guarded(root, entry, *, sample):
            if entry.path == "changed.txt":
                raise scanner.ChangedFileError("file changed while reading")
            return hash_file(root, entry, sample=sample)

        with patch.object(scanner, "_hash_file", side_effect=guarded):
            report = scanner.scan(self.root)

        self.assertEqual(report["summary"]["changed_files"], 1)
        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(set(report["duplicates"][0]["paths"]), {"first.txt", "second.txt"})
        self.assertTrue(any(issue["path"] == "changed.txt" for issue in report["issues"]))

    def test_real_content_change_during_read_is_detected(self):
        changed = self.write("changed.txt", b"same content")
        self.write("copy.txt", b"same content")
        read = os.read
        modified = False

        def mutate_after_read(descriptor, size):
            nonlocal modified
            chunk = read(descriptor, size)
            if not modified:
                modified = True
                with changed.open("ab") as stream:
                    stream.write(b"!")
            return chunk

        with patch.object(scanner.os, "read", side_effect=mutate_after_read):
            report = scanner.scan(self.root)

        self.assertTrue(modified)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["summary"]["changed_files"], 1)
        self.assertTrue(any(issue["path"] == "changed.txt" for issue in report["issues"]))

    def test_replacing_path_during_read_invalidates_the_old_file(self):
        replaced = self.write("changed.txt", b"same content")
        self.write("copy.txt", b"same content")
        read = os.read
        modified = False

        def replace_after_read(descriptor, size):
            nonlocal modified
            chunk = read(descriptor, size)
            if not modified:
                modified = True
                replacement = self.root / "replacement.tmp"
                replacement.write_bytes(b"same content")
                replacement.replace(replaced)
            return chunk

        with patch.object(scanner.os, "read", side_effect=replace_after_read):
            report = scanner.scan(self.root)

        self.assertTrue(modified)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["summary"]["changed_files"], 1)
        self.assertTrue(any(issue["path"] == "changed.txt" for issue in report["issues"]))

    def test_empty_directory_is_a_valid_report(self):
        report = scanner.scan(self.root)

        self.assertEqual(report["files"], [])
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["summary"]["total_bytes"], 0)
        self.assertEqual(report["directories"], [{"path": ".", "size": 0, "files": 0}])

    def test_missing_root_and_plain_file_are_rejected(self):
        with self.assertRaises(FileNotFoundError):
            scanner.scan(self.root / "missing")
        path = self.write("file.txt", b"content")
        with self.assertRaises(NotADirectoryError):
            scanner.scan(path)


if __name__ == "__main__":
    unittest.main()
