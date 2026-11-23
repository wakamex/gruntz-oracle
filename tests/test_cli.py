"""Command-line exit statuses."""

import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from gruntz_oracle.cli import main


class ExitStatusTests(unittest.TestCase):
    def test_truncated_object_is_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.obj"
            # an i386 header whose symbol table lies past the end of the file
            path.write_bytes(struct.pack("<HHIIIHH", 0x14C, 0, 0, 1000, 1, 0, 0))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = main(["check", str(path), str(path), "--symbol", "_f", "--cases", "1"])
        self.assertEqual(status, 2)
        self.assertIn("error", json.loads(out.getvalue()))


if __name__ == "__main__":
    unittest.main()
