#!/usr/bin/env python3
"""Validate forensic report structure and evidence/assurance consistency, not truth."""
import argparse
import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def validate(report):
    """Return all structural and semantic errors without mutating the report."""
    schema = json.loads((ROOT / 'templates/report.schema.json').read_text())
    errors = [f'{list(e.path)}: {e.message}' for e in jsonschema.Draft202012Validator(schema).iter_errors(report)]
    if errors:
        return errors
    for collection in ('scope', 'operations', 'findings'):
        ids = [item['id'] for item in report[collection]]
        if len(set(ids)) != len(ids):
            errors.append(f'duplicate {collection} id')
    operation_ids = {op['id'] for op in report['operations']}
    incomplete = not report['operations']
    for op in report['operations']:
        for key, item in op['completion'].items():
            if item['status'] == 'complete' and (not item['evidence'] or item['needed']):
                errors.append(f'{op["id"]}.{key}: complete requires evidence and no missing evidence')
            if item['status'] == 'unresolved':
                incomplete = True
                if not item['needed'].strip():
                    errors.append(f'{op["id"]}.{key}: unresolved requires needed evidence')
    for scope in report['scope']:
        if scope['status'] == 'verified' and (not scope['evidence'] or scope['limitations']):
            errors.append(f'{scope["id"]}: verified scope requires evidence and resolved limitations')
        if scope['status'] != 'verified' and not scope['limitations']:
            errors.append(f'{scope["id"]}: unverified scope requires limitations')
    unverified = any(s['status'] != 'verified' for s in report['scope']) or incomplete
    critical_unverified = any(s['critical'] and s['status'] != 'verified' for s in report['scope'])
    if report['assurance'] == 'VERIFIED_SCOPE' and unverified:
        errors.append('VERIFIED_SCOPE requires complete operations and verified scope')
    if report['conclusion'] == 'NO_FINDINGS_IN_VERIFIED_SCOPE':
        if critical_unverified or incomplete or not any(s['status'] == 'verified' for s in report['scope']):
            errors.append('zero findings cannot qualify unverified critical scope')
    actionable = [f for f in report['findings'] if f['evidence_status'] in ('CONFIRMED', 'SUSPECTED')]
    if actionable and report['conclusion'] != 'FINDINGS_REPORTED':
        errors.append('actionable findings require FINDINGS_REPORTED')
    if not actionable and report['conclusion'] == 'FINDINGS_REPORTED':
        errors.append('FINDINGS_REPORTED requires confirmed/suspected finding')
    assessed = any(s['status'] in ('reviewed', 'verified', 'partially_examined') for s in report['scope'])
    if report['assurance'] == 'NOT_ASSESSED' and (assessed or report['findings']):
        errors.append('NOT_ASSESSED contradicts examined evidence')
    if (report['conclusion'] == 'NOT_ASSESSED') != (report['assurance'] == 'NOT_ASSESSED'):
        errors.append('NOT_ASSESSED conclusion and assurance must agree')
    for finding in report['findings']:
        fid = finding['id']
        if finding['operation_id'] not in operation_ids:
            errors.append(f'{fid}: unknown operation')
        status, verification = finding['evidence_status'], finding['verification']
        if status in ('CONFIRMED', 'REFUTED'):
            if verification not in ('STATIC_PROVEN', 'DYNAMIC_REPRODUCED') or not finding['proof']:
                errors.append(f'{fid}: confirmed/refuted requires executed or complete static proof')
        if status in ('CONFIRMED', 'SUSPECTED') and not finding['invariant_source']:
            errors.append(f'{fid}: violation requires sourced invariant')
        if status in ('SUSPECTED', 'NON LIQUET') and not finding['unresolved']:
            errors.append(f'{fid}: uncertain evidence requires unresolved prerequisites')
        if finding['policy_violation'] and status in ('CONFIRMED', 'SUSPECTED') and not finding['policy_independent']:
            errors.append(f'{fid}: no independent policy baseline; use NON LIQUET')
        test = finding['test']
        if verification == 'DYNAMIC_REPRODUCED':
            if not test['executed'] or any(not test[k].strip() for k in ('command', 'environment', 'result', 'durable_effects')):
                errors.append(f'{fid}: dynamic proof requires actual execution and durable effects')
            if test['environment'] != 'isolated-local-synthetic':
                errors.append(f'{fid}: dynamic proof environment must be isolated-local-synthetic')
        if verification in ('TEST_GENERATED', 'NOT_VERIFIED') and test['executed']:
            errors.append(f'{fid}: executed claim contradicts verification state')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    try:
        errors = validate(json.loads(args.report.read_text()))
    except (OSError, ValueError) as exc:
        parser.exit(2, f'{exc}\n')
    for error in errors:
        print(error)
    print('INVALID' if errors else 'VALID (structure/consistency only)')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
