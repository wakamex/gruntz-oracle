"""Command-line behaviour comparison."""

import argparse
import json
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
        )
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps({"error": str(error)}))
        return 2
    print(json.dumps(report, separators=(",", ":")))
    return int(report["verdict"] == "differ")


if __name__ == "__main__":
    sys.exit(main())
