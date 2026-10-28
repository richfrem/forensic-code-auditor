#!/usr/bin/env python3
"""Compile/analyze isolated CodeQL fixture databases and check regression locations."""
import ast
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    executable = shutil.which('codeql')
    if not executable:
        print('NOT RUN: CodeQL CLI unavailable')
        return 77
    with tempfile.TemporaryDirectory(prefix='forensic-codeql-') as directory:
        work = Path(directory)
        for language, fixture in [('python', 'codeql-py'), ('javascript', 'codeql-js')]:
            pack = work / language
            shutil.copytree(ROOT / 'references/rules/codeql' / language, pack)
            subprocess.run([executable, 'pack', 'install', str(pack)], check=True)
            source = ROOT / 'evals/fixtures' / fixture
            database, sarif = work / (language + '-db'), work / (language + '.sarif')
            subprocess.run([executable, 'database', 'create', str(database), '--language=' + language,
                            '--source-root=' + str(source)], check=True)
            queries = sorted(str(p) for p in pack.glob('*.ql'))
            subprocess.run([executable, 'database', 'analyze', str(database), *queries,
                            '--format=sarif-latest', '--output=' + str(sarif)], check=True)
            hits = {}
            for run in json.loads(sarif.read_text())['runs']:
                for result in run['results']:
                    location = result['locations'][0]['physicalLocation']
                    if location['artifactLocation']['uri'].endswith(('views.py', 'routes.js')):
                        hits.setdefault(result['ruleId'], set()).add(location['region']['startLine'])
            if language == 'javascript':
                actual = hits.get('code-logic-auditor/js/unguarded-state-transition', set())
                if actual != {6, 12, 48}:
                    raise AssertionError(f'JavaScript expected 6,12,48; actual={sorted(actual)}')
            else:
                views = source / 'app/views.py'
                functions = {n.name: set(range(n.lineno, n.end_lineno + 1))
                             for n in ast.parse(views.read_text()).body if isinstance(n, ast.FunctionDef)}
                actual = hits.get('code-logic-auditor/python/unscoped-tenant-lookup', set())
                positives = {'invoice_unscoped', 'invoice_query_param', 'invoice_attacker_tenant',
                             'invoice_excluded_scope', 'invoice_kwargs', 'invoice_bulk', 'invoice_named_auth'}
                negatives = {'invoice_scoped_kw', 'invoice_scoped_relation', 'invoice_chained_scope'}
                for name in positives:
                    if not actual & functions[name]: raise AssertionError(f'missed candidate {name}')
                for name in negatives:
                    if actual & functions[name]: raise AssertionError(f'unscoped false positive {name}')
                review = hits.get('forensic-code-auditor/python/tenant-scope-review', set())
                for name in ('invoice_scoped_kw', 'invoice_chained_scope', 'invoice_kwargs', 'invoice_raw', 'invoice_bulk'):
                    if not review & functions[name]: raise AssertionError(f'missed review boundary {name}')
            print(f'{language}: PASS actual hit lines={hits}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
