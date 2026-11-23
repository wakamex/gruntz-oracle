"""Check functions whose code differs between two correct builds of the same unit.

Each unit's intermediate language is captured once and replayed through the code generator with the
checkout's -G5 and with -G6, which schedules for another processor. The two objects come from one front-end
output, so every function behaves the same in both, up to floating-point rounding; any reported difference
is the oracle's.
"""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from mutations import layouts, sha

from gruntz_oracle.coff import Object
from gruntz_oracle.engine import check


def build(target, root, unit, output):
    """The unit's -G5 and -G6 objects, replayed from one captured intermediate language."""
    il, evaluation = target.capture_il(unit, target.source_path(unit).read_bytes())
    if il is None:
        raise RuntimeError(f"{unit}: capture failed: {evaluation.error}")
    objects = {}
    for flag in ("-G5", "-G6"):
        work = Path(tempfile.mkdtemp(dir=root / "build" / "concord")) / "il"
        shutil.copytree(il, work)
        flags = (work / "flags.txt").read_text()
        if "-G5" not in flags:
            raise RuntimeError(f"{unit}: captured flags lack -G5: {flags}")
        (work / "flags.txt").write_text(flags.replace("-G5", flag))
        replay = target.replay_il(unit, work)
        if replay.object is None:
            raise RuntimeError(f"{unit} {flag}: replay failed: {replay.error}")
        objects[flag] = output / unit / f"{flag[1:]}.obj"
        objects[flag].parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(replay.object, objects[flag])
    return objects["-G5"], objects["-G6"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gruntz", type=Path, required=True)
    parser.add_argument("--concord", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--units", nargs="+", required=True)
    parser.add_argument("--cases", type=int, default=500)
    args = parser.parse_args()
    root, output = args.gruntz.resolve(), args.output.resolve()
    sys.path.insert(0, str(args.concord.resolve() / "src"))
    from concord.gruntz import Gruntz

    target = Gruntz(root)
    rows = []
    for unit in args.units:
        before, after = build(target, root, unit, output)
        codes = [{f.name: f.data for f in Object(path).fragments if f.code} for path in (before, after)]
        layout = json.loads(layouts(args.concord.resolve(), root, unit).read_text())
        for symbol, code in codes[0].items():
            if not symbol.startswith(("?", "_")) or codes[1].get(symbol, code) == code:
                continue
            row = {"unit": unit, "symbol": symbol, "before_sha256": sha(before), "after_sha256": sha(after)}
            try:
                report = check(before, after, symbol, unit, args.cases, layouts=layout)
                row["report"] = {k: report[k] for k in ("verdict", "differ", "differing_instructions",
                                                        "cases_exercising_difference", "cases_inconclusive")}
                if report["first_difference"]:
                    row["report"]["first_difference"] = {k: report["first_difference"][k] for k in ("seed", "overrides", "categories")}
            except (ValueError, KeyError) as error:
                row["error"] = str(error)
            rows.append(row)
            (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
            print(json.dumps(row), flush=True)
    verdicts = [r.get("report", {}).get("verdict", "error") for r in rows]
    summary = {"units": args.units, "functions": len(rows), "cases_per_function": args.cases,
               **{v: verdicts.count(v) for v in ("agree", "differ", "under-exercised", "error")}}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return int(bool(summary["differ"] or summary["error"]))


if __name__ == "__main__":
    raise SystemExit(main())
