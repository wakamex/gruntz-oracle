"""The real-source benchmark rejects drift instead of measuring unintended edits."""

import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "benchmarks/mutations.py"
SPEC = importlib.util.spec_from_file_location("mutations", SOURCE)
MUTATIONS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MUTATIONS)


class MutationTests(unittest.TestCase):
    def test_changed_source_is_rejected(self):
        for source in (b"", b"old old"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                MUTATIONS.replace(source, "old", "new", "constant")

    def test_missing_local_is_rejected(self):
        with self.assertRaises(ValueError):
            MUTATIONS.replace(b"body;", "b", "record", "renamed-local")

    def test_only_first_forwarder_is_mutated(self):
        self.assertEqual(
            MUTATIONS.replace(b"call call", "call", "swapped", "swapped-arguments"),
            b"swapped call",
        )

    def test_local_rename_preserves_identifier_boundaries(self):
        self.assertEqual(
            MUTATIONS.replace(
                b"b->field; body; b;" * 4, "b", "record", "renamed-local"
            ),
            b"record->field; body; record;" * 4,
        )


if __name__ == "__main__":
    unittest.main()
