#!/usr/bin/env python3
"""Run only the bundled synthetic runtime; emit an actual observation and report."""
import argparse
import csv
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    path = ROOT / 'tests/fixtures/authorization/runtime.py'
    spec = importlib.util.spec_from_file_location('synthetic_runtime', path)
    runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
    configuration, policy = runtime.load('configuration.json'), runtime.load('policy.json')
    intended, policy_source = runtime.intended(policy, 'clerk-1', 'clerk', 'approve', 'north', 'PENDING', 15)
    configured, rows = runtime.effective(configuration['rows'], level=2, role='clerk', resource='APPROVAL_FORM', operation='approve', scope='north', at=15)
    with tempfile.TemporaryDirectory(prefix='forensic-synthetic-') as directory:
        service = runtime.Runtime(Path(directory) / 'fixture.sqlite', configuration['rows'])
        enforced = service.approve('Forms', 'clerk')
        durable = service.durable()
    assert intended is False and configured and enforced and rows == ['L2-rare']
    assert durable == ('APPROVED', 1)
    observation = dict(principal='clerk-1', role='clerk', operation='approve', resource='APPROVAL_FORM',
                       policy_source=policy_source, rows=rows, intended=intended, configured=configured,
                       enforced=enforced, durable_status=durable[0], durable_effects=durable[1],
                       environment='isolated-local-synthetic', oracle_runtime='NOT_VERIFIED')
    (args.output / 'observation.json').write_text(json.dumps(observation, indent=2) + '\n')
    report = json.loads((ROOT / 'templates/assurance-summary.json').read_text())
    report.update(assurance='PARTIAL', conclusion='FINDINGS_REPORTED')
    report['scope'] = [dict(id='synthetic-model', status='verified', critical=True, evidence=['observation.json'], limitations=[]),
                       dict(id='oracle-deployment', status='unknown', critical=True, evidence=[], limitations=['Oracle exports/runtime and dynamic library unavailable'])]
    op = report['operations'][0]; op['id'] = 'approve'
    for item in op['completion'].values():
        item.update(status='complete', evidence=['observation.json; bundled policy/configuration/runtime'], needed='')
    op['completion']['entry_points'].update(status='unresolved', evidence=['configuration.json#callers'], needed='Resolve dynamic legacy library; validate real Oracle entry paths')
    report['findings'] = [dict(id='F-SYNTHETIC-1', operation_id='approve', category='AUTHZ-BYPASS',
        tags=['AUTHZ-DATA-INTEGRITY'], severity='HIGH', evidence_status='CONFIRMED', verification='DYNAMIC_REPRODUCED',
        invariant_source=policy_source, policy_independent=True, policy_violation=True,
        location='tests/fixtures/authorization/configuration.json#L2-rare', proof=['observation.json'],
        test=dict(executed=True, command='python3 scripts/demo_authorization.py --output <local-output>',
                  environment='isolated-local-synthetic', result='clerk approval committed through correct Level 1/2 evaluation',
                  durable_effects='fresh connection: claims.status=APPROVED; effects=1'),
        unresolved=['Oracle deployment NOT VERIFIED; finding applies only to bundled synthetic model'])]
    from validate_report import validate
    assert not validate(report), validate(report)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    with (args.output / 'matrix.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['principal','role','resource','operation','scope','entry_point','state','policy_source','row','intended','configured','enforced','verification'])
        writer.writerow(['clerk-1','clerk','APPROVAL_FORM','approve','north','Forms','PENDING',policy_source,'L2-rare','DENY','ALLOW','ALLOW','DYNAMIC_REPRODUCED (synthetic only)'])
    print('Synthetic wrong-row oracle reproduced; report validated. Oracle deployment NOT VERIFIED.')


if __name__ == '__main__':
    main()
