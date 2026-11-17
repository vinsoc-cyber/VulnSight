"""The per-record guard the three source clients share.

GHSA, NVD and OSV each used to normalize a page with a list comprehension,
so one malformed advisory raised an AttributeError that was not the module's
own error type, slipped past the per-source degradation in
`search_service.run_search`, and came out of `app.py` as a 500 -- discarding
the results the other sources had already paid for.

These tests pin the contract the clients rely on: a bad record costs one
record, the count is reported rather than silently swallowed, and nothing in
the guard itself can raise -- including the identifier callback it uses only
to write a log line.
"""

import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import records


def _double(item):
    return {"value": item * 2}


class TestNormalizeAll(unittest.TestCase):
    def test_a_clean_page_is_unchanged_and_reports_nothing_skipped(self):
        got, skipped = records.normalize_all([1, 2, 3], _double, source="test")
        self.assertEqual(got, [{"value": 2}, {"value": 4}, {"value": 6}])
        self.assertEqual(skipped, 0)

    def test_one_bad_record_costs_exactly_one_record(self):
        def normalize(item):
            if item == 2:
                raise AttributeError("'NoneType' object has no attribute 'get'")
            return _double(item)

        got, skipped = records.normalize_all([1, 2, 3], normalize, source="test")
        self.assertEqual(got, [{"value": 2}, {"value": 6}])
        self.assertEqual(skipped, 1)

    def test_every_record_failing_is_an_empty_list_not_an_exception(self):
        def normalize(_item):
            raise TypeError("unsupported")

        got, skipped = records.normalize_all([1, 2], normalize, source="test")
        self.assertEqual(got, [])
        self.assertEqual(skipped, 2)

    def test_the_skipped_count_is_logged_against_the_page_total(self):
        """The caller surfaces this as a warning. Returning a short list and
        saying nothing is the exact failure this module exists to prevent."""
        def normalize(item):
            if item % 2:
                raise ValueError("odd")
            return _double(item)

        with self.assertLogs(records.logger, logging.WARNING) as logs:
            _, skipped = records.normalize_all(range(4), normalize, source="osv")
        self.assertEqual(skipped, 2)
        self.assertTrue(
            any("Skipped 2 unusable osv record(s) of 4" in line
                for line in logs.output), logs.output)

    def test_a_clean_page_logs_no_warning(self):
        with self.assertNoLogs(records.logger, logging.WARNING):
            records.normalize_all([1], _double, source="ghsa")

    def test_an_identify_callback_that_raises_cannot_sink_the_page(self):
        """identify() exists only to put a name in a DEBUG line. A guard that
        crashes while reporting the thing it guarded against is worse than no
        guard, and the records it is asked about are malformed by definition."""
        def normalize(_item):
            raise KeyError("id")

        def identify(_item):
            raise RuntimeError("this record is too broken to even name")

        with self.assertLogs(records.logger, logging.DEBUG) as logs:
            got, skipped = records.normalize_all(
                [{"bad": True}], normalize, source="nvd", identify=identify)
        self.assertEqual((got, skipped), ([], 1))
        self.assertTrue(any("<unidentified>" in line for line in logs.output),
                        logs.output)

    def test_a_working_identify_names_the_record_in_the_log(self):
        def normalize(_item):
            raise KeyError("boom")

        with self.assertLogs(records.logger, logging.DEBUG) as logs:
            records.normalize_all(
                [{"ghsa_id": "GHSA-xxxx"}], normalize, source="ghsa",
                identify=lambda item: records.identify(item, "ghsa_id"))
        self.assertTrue(any("GHSA-xxxx" in line for line in logs.output),
                        logs.output)

    def test_it_accepts_any_iterable_not_just_a_list(self):
        got, skipped = records.normalize_all(
            (n for n in range(3)), _double, source="test")
        self.assertEqual(len(got), 3)
        self.assertEqual(skipped, 0)


class TestIdentify(unittest.TestCase):
    """Best-effort id for a log line, over records of unverified shape."""

    def test_the_first_key_that_holds_a_non_empty_string_wins(self):
        item = {"cve_id": "", "ghsa_id": "GHSA-1", "id": "OSV-1"}
        self.assertEqual(records.identify(item, "cve_id", "ghsa_id", "id"),
                         "GHSA-1")

    def test_a_non_string_value_is_skipped_rather_than_coerced(self):
        self.assertEqual(records.identify({"id": 7, "alt": "A-1"}, "id", "alt"),
                         "A-1")

    def test_no_match_is_the_empty_string(self):
        self.assertEqual(records.identify({"other": "x"}, "id"), "")

    def test_a_record_that_is_not_a_dict_does_not_raise(self):
        for item in (None, "a string", 42, ["a", "list"], object()):
            with self.subTest(item=type(item).__name__):
                self.assertEqual(records.identify(item, "id"), "")

    def test_no_keys_asked_for_is_the_empty_string(self):
        self.assertEqual(records.identify({"id": "x"}), "")


if __name__ == "__main__":
    unittest.main()
