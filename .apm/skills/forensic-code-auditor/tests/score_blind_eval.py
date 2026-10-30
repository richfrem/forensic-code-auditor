#!/usr/bin/env python3
"""Score attributed findings, protected false positives and missing-policy calibration."""
import argparse
import json
from pathlib import Path


def score(answer,report):
    if answer['variant'] not in ('vulnerable','protected','indeterminate'):
        raise ValueError('unknown variant: '+str(answer['variant']))
    findings=[]
    for item in report.get('findings',[]):
        f=dict(item)
        f.setdefault('verdict',f.get('evidence_status'))
        f.setdefault('row_keys',[r['row_key'] for r in f.get('contributing_rows',[]) if isinstance(r,dict) and 'row_key' in r])
        f.setdefault('policy_ref',f.get('policy_basis',{}).get('ref') or f.get('invariant_source'))
        findings.append(f)
    attributed=[f for f in findings if f.get('operation_id')==answer['operation'] and answer['row_key'] in f.get('row_keys',[])]
    actionable=[f for f in findings if f.get('verdict') in ('CONFIRMED','SUSPECTED')]
    if answer['variant']=='vulnerable':
        success=any(f.get('verdict')=='CONFIRMED' and f.get('policy_ref') for f in attributed)
        return {'attributed_detection':bool(success),'unattributed_actionable':len(actionable)-sum(f in actionable for f in attributed)}
    if answer['variant']=='protected':
        # V2 uses proof + verification; legacy evaluation reports use defense_ref.
        # These are declared evidence indicators, still requiring artifact validation
        # and human adjudication before claiming that a defense actually works.
        defense=any(f.get('verdict')=='REFUTED' and (
            bool(f.get('proof')) and f.get('verification') in ('STATIC_PROVEN','DYNAMIC_REPRODUCED')
            if 'evidence_status' in f else bool(f.get('defense_ref'))
        ) for f in attributed)
        return {'false_positive':bool(actionable),'verified_defense':defense}
    return {'calibrated':not actionable and any(f.get('verdict')=='NON LIQUET' for f in attributed)}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('answer',type=Path);p.add_argument('report',type=Path);a=p.parse_args()
    print(json.dumps(score(json.loads(a.answer.read_text()),json.loads(a.report.read_text())),indent=2))


if __name__=='__main__':main()
