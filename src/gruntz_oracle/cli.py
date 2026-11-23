"""Command-line behaviour comparison: exits 0 when the builds agree, 1 when they differ, 2 on an error and 3
when no case ran the code that differs to completion (under-exercised)."""

import argparse
import json
import struct
import sys
from pathlib import Path

from .engine import Limits, check


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("check", help="compare two builds of one function")
    command.add_argument("before", type=Path)
    command.add_argument("after", type=Path)
    command.add_argument("--symbol", required=True)
    command.add_argument("--unit")
    command.add_argument("--cases", type=int, default=5000)
    command.add_argument("--seed", type=int, default=0)
    command.add_argument("--instructions", type=int, default=20000)
    command.add_argument("--pages", type=int, default=128)
    command.add_argument("--retail", type=Path, metavar="CHECKOUT",
                         help="gruntz-decomp checkout whose original executable supplies data retail objects reference")
    command.add_argument("--unguided", action="store_true", help="seeds only, without comparison-guided cases")
    command.add_argument("--layouts", type=Path, help="JSON record layouts of the unit, to lay out memory by type")
    args = parser.parse_args(argv)
    try:
        if args.instructions < 1 or args.pages < 1:
            raise ValueError("execution limits must be positive")
        report = check(
            args.before,
            args.after,
            args.symbol,
            args.unit,
            args.cases,
            seed=args.seed,
            limits=Limits(args.instructions, args.pages),
            layouts=json.loads(args.layouts.read_text()) if args.layouts else None,
            guided=not args.unguided,
            retail=args.retail,
        )
    except (ValueError, OSError, KeyError, struct.error) as error:  # struct.error: a malformed or truncated object
        print(json.dumps({"error": str(error)}))
        return 2
    print(json.dumps(report, separators=(",", ":")))
    return {"agree": 0, "differ": 1, "under-exercised": 3}[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
