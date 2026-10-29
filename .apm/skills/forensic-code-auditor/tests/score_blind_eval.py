#!/usr/bin/env python3
"""Score attributed findings, protected false positives and missing-policy calibration."""
import argparse
import json
from pathlib import Path


def score(answer,report):
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
    if answer['variant']=='protected':return {'false_positive':bool(actionable),'verified_defense':any(f.get('verdict')=='REFUTED' and f.get('defense_ref') for f in findings)}
    return {'calibrated':not actionable and any(f.get('verdict')=='NON LIQUET' for f in findings)}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('answer',type=Path);p.add_argument('report',type=Path);a=p.parse_args()
    print(json.dumps(score(json.loads(a.answer.read_text()),json.loads(a.report.read_text())),indent=2))


if __name__=='__main__':main()
