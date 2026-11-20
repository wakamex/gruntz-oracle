"""Check every report-exact function in fixed real Gruntz units against retail."""

import argparse
import json
from pathlib import Path

from mutations import run_check, sha

UNITS = ['brickzcellflags', 'rezlist', 'namerecord', 'chainforward', 'brickz']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gruntz', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--oracle', default='gruntz-oracle')
    parser.add_argument('--cases', type=int, default=5000)
    parser.add_argument('--attempt', type=int, required=True, help='false-difference gate attempt number')
    parser.add_argument('--units', nargs='+', default=UNITS)
    args = parser.parse_args()
    root = args.gruntz.resolve()
    comparison = root / 'build/objdiff/compare-new'
    source = comparison / 'report.json'
    report = json.loads(source.read_text())
    units = {unit['name'].split('/')[-1]: unit for unit in report['units']}
    rows = []
    oracle_root = Path(__file__).resolve().parents[1]
    engine_hashes = {str(path.relative_to(oracle_root)): sha(path)
                     for path in sorted((oracle_root / 'src').rglob('*.py'))}
    args.output.mkdir(parents=True, exist_ok=True)
    for name in args.units:
        exact = [f for f in units[name].get('functions', [])
                 if float(f.get('fuzzy_match_percent') or 0) == 100]
        if not exact:
            raise ValueError(f'{name} has no exact functions')
        before = comparison / 'target' / f'{name}.c.obj'
        after = comparison / 'base' / f'{name}.obj'
        for function in exact:
            row = {'unit': name, 'symbol': function['name'], 'size': int(function['size']),
                   'before_sha256': sha(before), 'after_sha256': sha(after)}
            try:
                row['report'], row['seconds'] = run_check(args.oracle, root, before, after,
                                                         function['name'], name, args.cases)
            except RuntimeError as exc:
                row['error'] = str(exc)
            rows.append(row)
            (args.output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(json.dumps(row), flush=True)
    summary = {'units': args.units, 'functions': len(rows), 'cases_per_function': args.cases,
               'report_sha256': sha(source), 'attempt': args.attempt,
               'engine_sha256': engine_hashes, 'errors': sum('error' in r for r in rows),
               'false_differences': sum(r.get('report', {}).get('verdict') == 'differ' for r in rows)}
    summary['false_difference_rate'] = summary['false_differences'] / len(rows)
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    return int(bool(summary['errors'] or summary['false_differences']))


if __name__ == '__main__':
    raise SystemExit(main())
