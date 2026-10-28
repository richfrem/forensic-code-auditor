#!/usr/bin/env python3
"""Compare baseline/revised rules on identical current fixtures; no LLM scoring."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def metrics(data):
    tp = fp = fn = 0
    failures = []
    for config in data['results'].values():
        for rule, check in config['checks'].items():
            if not check['passed']: failures.append(rule)
            for match in check['matches'].values():
                expected, actual = set(match['expected_lines']), set(match['reported_lines'])
                tp += len(expected & actual); fp += len(actual - expected); fn += len(expected - actual)
    return dict(tp=tp, fp=fp, fn=fn, precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None, failing_groups=failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True, help='Baseline skill directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    semgrep = shutil.which('semgrep')
    if not semgrep: print('NOT RUN: Semgrep CLI unavailable'); return 77
    baseline_rules = args.baseline / 'references/rules/semgrep'
    if not baseline_rules.is_dir(): parser.error('baseline rules directory missing')
    current = ROOT / 'references/rules/semgrep'
    env = dict(os.environ, SEMGREP_SEND_METRICS='off')
    result = {'tool': subprocess.check_output([semgrep, '--version'], text=True).strip(), 'scope': 'synthetic candidate locations only'}
    with tempfile.TemporaryDirectory(prefix='forensic-semgrep-') as directory:
        for label, rules in [('baseline', baseline_rules), ('revised', current)]:
            corpus = Path(directory) / label; corpus.mkdir()
            for p in current.iterdir():
                if p.suffix != '.yaml': shutil.copy2(p, corpus / p.name)
            for p in rules.glob('*.yaml'): shutil.copy2(p, corpus / p.name)
            run = subprocess.run([semgrep, '--test', '--json', str(corpus)], capture_output=True, text=True, env=env, timeout=120)
            if run.returncode not in (0, 1): raise RuntimeError(run.stderr or run.stdout)
            data = json.loads(run.stdout)
            if data['config_with_errors'] or data['config_missing_tests']: raise RuntimeError(data)
            result[label] = metrics(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__': raise SystemExit(main())
