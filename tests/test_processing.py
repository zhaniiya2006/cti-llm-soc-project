"""Meaningful boundaries: do not silently accept or alter unsafe/invalid data."""

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("processor", REPO / "week3/process_iocs.py")
processor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(processor)


class ProcessingTests(unittest.TestCase):
    def test_domain_equivalence_and_malformed_domains(self):
        self.assertEqual(processor.normalize_value("domain", " Example.COM. "), "example.com")
        self.assertEqual(processor.normalize_value("domain", "\t Example.COM. \n"), "example.com")
        for value in ["bad..domain", "example.com..", "-bad.example", "example", "x" * 64 + ".example"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                processor.normalize_value("domain", value)

    def test_ipv4_and_hash_validation(self):
        self.assertEqual(processor.normalize_value("ip-dst", "198.51.100.42"), "198.51.100.42")
        for kind, value in [("ip-dst", "999.10.10.5"), ("ip-dst", "::1"), ("sha256", "abc"), ("sha256", "z" * 64)]:
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                processor.normalize_value(kind, value)

    def test_url_keeps_case_sensitive_path_and_query(self):
        self.assertEqual(processor.normalize_value("url", "HTTPS://Example.COM:443/Case?Token=AbC#top"), "https://example.com/Case?Token=AbC")
        self.assertEqual(processor.normalize_value("url", "http://example.com:8080/"), "http://example.com:8080/")

    def test_url_rejects_unsupported_and_ambiguous_input(self):
        for value in ["ftp://example.com/", "https://user:password@example.com/", "https://example.com:99999/", "https://example.com../", "https://example.com/a b", "https://exam\nple.com/"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                processor.normalize_value("url", value)

    def test_sample_totals_provenance_and_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            summary = processor.process(output_dir=out)
            self.assertEqual([summary[k] for k in ["input_records", "valid_unique_indicators", "duplicates_removed", "invalid_records_filtered"]], [8, 4, 2, 2])
            self.assertEqual({d["record_id"] for d in summary["duplicate_records"]}, {"LAB-002", "LAB-006"})
            event = json.loads((out / "misp-event.json").read_text())["Event"]
            self.assertEqual(event["date"], "2026-10-08")
            self.assertFalse(event["published"])
            self.assertTrue(all(a["to_ids"] is False for a in event["Attribute"]))
            self.assertEqual(len({a["uuid"] for a in event["Attribute"]}), 4)

    def test_empty_and_invalid_only_csv_has_headers(self):
        for row in [None, ["BAD", "domain", "example.com", "source", "2026-10-08T09:00:00Z", "101", "test"]]:
            with self.subTest(row=row), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = root / "raw.csv"
                with raw.open("w", newline="", encoding="utf-8") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(["record_id", "type", "value", "source", "first_seen", "confidence", "note"])
                    if row:
                        writer.writerow(row)
                summary = processor.process(raw, root / "out")
                self.assertEqual(summary["valid_unique_indicators"], 0)
                self.assertIn("record_id", (root / "out/normalized_iocs.csv").read_text())
                if row:
                    self.assertEqual(summary["invalid_records_filtered"], 1)

    def test_unknown_confidence_and_timezone_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "observations.csv"
            with raw.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(["record_id", "type", "value", "source", "first_seen", "confidence", "note"])
                writer.writerow(["A", "domain", "example.com", "screenshot", "2026-10-08T12:00:00Z", "", "recorded in dataset"])
                writer.writerow(["B", "domain", "example.org", "screenshot", "2026-10-08T12:00:00", "", "timezone missing"])
            result = processor.process(raw, root / "out")
            self.assertEqual(result["valid_unique_indicators"], 1)
            self.assertEqual(result["invalid_records_filtered"], 1)
            event = json.loads((root / "out/misp-event.json").read_text())["Event"]
            self.assertIn("not assessed", event["Attribute"][0]["comment"])
            self.assertNotEqual(event["uuid"], processor.process(output_dir=root / "sample")["misp_event_uuid"])


if __name__ == "__main__":
    unittest.main()
