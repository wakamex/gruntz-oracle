"""Compile real Gruntz source mutations with concord and measure behavior agreement."""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

SCORE = '?UpdateBestScore@CGameInfo@@QAEHHHH@Z'
NAMES = '?SetNames@CGameInfo@@QAEHPAD0H@Z'
SHOT = '?SaveBackBufferShot@@YAHPAVCRegMgr@@PAVCGruntzMgr@@HHPADH@Z'
LINE = '?LineIsClear@CMapMgr@@QAEHHHHH@Z'
# Expected labels follow directly from the source operation, independently of the oracle.
MUTATIONS = [
    ('constant', 'namerecord', NAMES, False,
     'm_body.m_version = 1;', 'm_body.m_version = 2;'),
    ('comparison', 'namerecord', SCORE, False,
     'if (b->m_score > score)', 'if (b->m_score < score)'),
    ('dropped-store', 'namerecord', SCORE, False,
     '    b->m_score = score;\n', ''),
    ('swapped-arguments', 'chainforward', SHOT, False,
     'SaveScreenshot(leaf, reg, owner, width, height, name, saveFlag)',
     'SaveScreenshot(leaf, reg, owner, height, width, name, saveFlag)'),
    ('loop-bound', 'brickz', LINE, False,
     'for (i32 x = x0; x < x1; x++)', 'for (i32 x = x0; x <= x1; x++)'),
    ('independent-stores', 'namerecord', SCORE, True,
     '    b->m_score = score;\n    b->m_timeMs = timeMs;',
     '    b->m_timeMs = timeMs;\n    b->m_score = score;'),
    ('renamed-local', 'namerecord', SCORE, True,
     'b', 'record'),
    ('named-temporary', 'namerecord', SCORE, True,
     '    b->m_score = score;', '    i32 newScore = score;\n    b->m_score = newScore;'),
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def replace(source, old, new, name):
    if name == 'renamed-local':
        import re
        result, count = re.subn(rb'\bb\b', new.encode(), source)
        if count != 8:
            raise ValueError(f'{name}: expected 8 local identifier matches, got {count}')
        return result
    expected = 2 if name == 'swapped-arguments' else 1
    if source.count(old.encode()) != expected:
        raise ValueError(f'{name}: expected {expected} source matches')
    # Only the first forwarding function is the measured mutation.
    return source.replace(old.encode(), new.encode(), 1)


def build(root, output, concord):
    sys.path.insert(0, str(concord / 'src'))
    from concord.gruntz import Gruntz

    os.environ['CONCORD_JOBS'] = '4'
    target = Gruntz(root)
    manifest = []
    config = tomllib.loads((root / 'config/units.toml').read_text())
    units = {u['unit']: u for u in config['unit']}
    for unit in dict.fromkeys(m[1] for m in MUTATIONS):
        source = target.source_path(unit).read_bytes()
        chosen = [m for m in MUTATIONS if m[1] == unit]
        sources = {'baseline': source}
        for name, _, _, _, old, new in chosen:
            sources[name] = replace(source, old, new, name)
        results = target.evaluate(unit, sources)
        for name, text in sources.items():
            result = results[name]
            if result.object is None or result.error:
                raise RuntimeError(f'{unit}/{name}: {result.error}')
            destination = output / 'objects' / unit
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(result.object, destination / f'{name}.obj')
            (destination / f'{name}.cpp').write_bytes(text)
        for name, _, symbol, preserving, old, new in chosen:
            original = output / 'objects' / unit / 'baseline.obj'
            mutation = output / 'objects' / unit / f'{name}.obj'
            manifest.append({'name': name, 'unit': unit, 'symbol': symbol, 'preserving': preserving,
                                 'old': old, 'new': new, 'original': str(original), 'mutation': str(mutation),
                                 'original_sha256': sha(original), 'mutation_sha256': sha(mutation),
                                 'source_sha256': hashlib.sha256(source).hexdigest(),
                                 'flags': config['flags'][units[unit]['flags']], 'shortcuts': target.using})
        print(json.dumps({'compiled_unit': unit, 'objects': len(sources)}), flush=True)
    metadata = {'target_head': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
                'toolchain_definition_sha256': sha(root / 'nix/toolchain.nix'),
                'toolchain_definition': (root / 'nix/toolchain.nix').read_text(),
                'units_manifest_sha256': sha(root / 'config/units.toml'), 'compile_workers': 4}
    (output / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def run_check(command, root, before, after, symbol, unit, cases):
    start = time.monotonic()
    result = subprocess.run([*shlex.split(command), 'check', str(before), str(after),
                             '--symbol', symbol, '--unit', unit, '--cases', str(cases)],
                            cwd=root, capture_output=True, text=True, check=False)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'oracle output ({result.returncode}): {result.stdout}\n{result.stderr}') from exc
    if result.returncode not in (0, 1):
        raise RuntimeError(f'oracle error: {report}\n{result.stderr}')
    if report.get('verdict') != ('agree' if result.returncode == 0 else 'differ'):
        raise RuntimeError(f'verdict and exit status disagree: {report}')
    return report, time.monotonic() - start


def measure(root, output, command, cases):
    rows = []
    oracle_root = Path(__file__).resolve().parents[1]
    engine_hashes = {str(path.relative_to(oracle_root)): sha(path)
                     for path in sorted((oracle_root / 'src').rglob('*.py'))}
    for mutation in json.loads((output / 'manifest.json').read_text()):
        for key in ('original', 'mutation'):
            if sha(mutation[key]) != mutation[f'{key}_sha256']:
                raise ValueError(f'changed input: {mutation[key]}')
        report, seconds = run_check(command, root, mutation['original'], mutation['mutation'],
                                    mutation['symbol'], mutation['unit'], cases)
        row = {'name': mutation['name'], 'unit': mutation['unit'], 'symbol': mutation['symbol'],
               'preserving': mutation['preserving'], 'report': report, 'seconds': seconds}
        rows.append(row)
        (output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        print(json.dumps(row), flush=True)
    changed = [r for r in rows if not r['preserving']]
    preserved = [r for r in rows if r['preserving']]
    summary = {'cases_per_pair': cases, 'engine_sha256': engine_hashes, 'mutations': len(changed),
               'detected': sum(r['report']['verdict'] == 'differ' for r in changed),
               'preserving_rewrites': len(preserved),
               'false_differences': sum(r['report']['verdict'] == 'differ' for r in preserved)}
    summary['missed'] = summary['mutations'] - summary['detected']
    summary['detection_rate'] = summary['detected'] / len(changed)
    summary['false_difference_rate'] = summary['false_differences'] / len(preserved)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    return int(bool(summary['missed'] or summary['false_differences']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gruntz', type=Path, required=True)
    parser.add_argument('--concord', type=Path, help='concord checkout, required when compiling')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--oracle', default='gruntz-oracle')
    parser.add_argument('--cases', type=int, default=5000)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--build-only', action='store_true')
    mode.add_argument('--run-only', action='store_true')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.run_only:
        if args.concord is None:
            parser.error('--concord is required when compiling')
        build(args.gruntz.resolve(), args.output, args.concord.resolve())
    if not args.build_only:
        return measure(args.gruntz.resolve(), args.output, args.oracle, args.cases)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
