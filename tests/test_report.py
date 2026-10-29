import json
import re
import unittest
from copy import deepcopy

from disklens.report import render_html


def sample_report():
    return {
        "schema_version": 1,
        "root": "/example/documents",
        "created_at": "2026-10-29T12:00:00+00:00",
        "elapsed_seconds": 0.5,
        "summary": {
            "files": 2, "directories": 1, "total_bytes": 8,
            "duplicate_groups": 1, "duplicate_files": 2, "duplicate_bytes": 4,
            "symlinks_skipped": 0, "hardlinks_skipped": 0, "excluded": 0,
            "hashed_files": 2, "changed_files": 0,
        },
        "files": [
            {"path": "first.txt", "size": 4, "modified": "2026-10-29T12:00:00+00:00"},
            {"path": "second.txt", "size": 4, "modified": "2026-10-29T12:00:00+00:00"},
        ],
        "directories": [{"path": ".", "size": 8, "files": 2}],
        "duplicates": [{"size": 4, "reclaimable_bytes": 4, "sha256": "abc",
                        "paths": ["first.txt", "second.txt"]}],
        "issues": [],
        "hardlinks": [],
        "options": {"find_duplicates": True, "min_duplicate_size": 1, "excludes": []},
    }


class ReportTests(unittest.TestCase):
    def embedded_data(self, html):
        match = re.search(r'<script\b(?=[^>]*\bid="report-data")[^>]*>(.*?)</script>',
                          html, re.DOTALL | re.IGNORECASE)
        self.assertIsNotNone(match, "standalone report must contain its own data")
        return match.group(1)

    def test_report_embeds_a_complete_json_snapshot(self):
        report = sample_report()
        original = deepcopy(report)

        html = render_html(report)

        self.assertEqual(json.loads(self.embedded_data(html)), report)
        self.assertEqual(report, original)
        self.assertNotIn("__DISKLENS_DATA__", html)

    def test_hostile_paths_cannot_close_the_data_script(self):
        report = sample_report()
        hostile = '</script><script>alert("injected")</script>&\u2028\u2029\udcff'
        report["root"] = hostile
        report["files"][0]["path"] = hostile
        report["duplicates"][0]["paths"][0] = hostile
        report["issues"] = [{"path": hostile, "message": hostile}]
        report["hardlinks"] = [{"path": hostile, "target": hostile}]
        report["options"]["excludes"] = [hostile]

        html = render_html(report)
        payload = self.embedded_data(html)

        self.assertEqual(json.loads(payload), report)
        self.assertNotIn("<", payload)
        self.assertNotIn(">", payload)
        self.assertNotIn("&", payload)
        self.assertNotIn("\u2028", payload)
        self.assertNotIn("\u2029", payload)
        self.assertNotIn("\udcff", payload)
        self.assertNotIn('<script>alert("injected")</script>', html)
        html.encode("utf-8")

    def test_empty_reports_still_have_valid_embedded_data(self):
        report = sample_report()
        report["files"] = []
        report["duplicates"] = []
        report["directories"] = []
        report["summary"] = dict.fromkeys(report["summary"], 0)

        html = render_html(report)

        self.assertEqual(json.loads(self.embedded_data(html)), report)

    def test_scan_options_and_hardlink_targets_survive_serialization(self):
        report = sample_report()
        report["options"] = {
            "find_duplicates": False,
            "min_duplicate_size": 1024 * 1024,
            "excludes": ["*.tmp", "архив/копии/*"],
        }
        report["duplicates"] = []
        report["hardlinks"] = [{"path": "копии/файл.txt", "target": "first.txt"}]

        data = json.loads(self.embedded_data(render_html(report)))

        self.assertEqual(data["options"], report["options"])
        self.assertEqual(data["hardlinks"], report["hardlinks"])

    def test_report_has_no_external_asset_dependencies(self):
        html = render_html(sample_report())

        self.assertNotRegex(html, r'<script\b[^>]*\bsrc\s*=')
        self.assertNotRegex(html, r'<link\b[^>]*\bhref\s*=')
        self.assertNotRegex(html, r'url\(\s*[\'\"]?https?://')


if __name__ == "__main__":
    unittest.main()
