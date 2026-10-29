#!/usr/bin/env python3
"""Validate report v2 structure, available evidence and declared discovery coverage.

Does not establish policy authority, honest discovery or semantic vulnerability truth.
"""
import argparse
import json
from pathlib import Path
import sys
import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import all_references, resolve

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = {'ui_entry','menu_node','policy_store','stored_procedure','db_grant','api_route','gateway','queue_consumer','batch_job','scheduler','mcp_tool','db_link','direct_db_access'}
POLICY_CLASSES = {'owner_signed','regulation','requirement_doc','contract'}


def validate(report, *, evidence_root=None):
    schema = json.loads((ROOT / 'templates/report.schema.json').read_text())
    errors = [f'{list(e.path)}: {e.message}' for e in jsonschema.Draft202012Validator(schema).iter_errors(report)]
    if errors: return errors
    if evidence_root is None: return ['v2 requires an explicit evidence root; use validate_report_v1.py only for legacy structural checks']
    for ref in all_references(report):
        try: resolve(ref,evidence_root)
        except (OSError,ValueError,KeyError,TypeError,AttributeError) as exc: errors.append(str(exc))
    if errors: return errors
    categories = report['scope']['categories']; operations = report['operations']; findings = report['findings']
    def unique(items, key):
        ids = [i[key] for i in items]
        if len(set(ids)) != len(ids): errors.append('duplicate '+key)
    for collection,key in [(categories,'category'),(operations,'id'),(findings,'id'),(report['artifacts'],'kind')]: unique(collection,key)
    if {c['category'] for c in categories} != CATEGORIES: errors.append('all discovery categories must be accounted for')
    try:
        discovery = json.loads(resolve(report['discovery'],evidence_root).read_text())
        for ref in all_references(discovery): resolve(ref,evidence_root)
        required = {o['id']:o for o in discovery['operations']}
        if len(required) != len(discovery['operations']): errors.append('duplicate discovered operation')
    except (OSError,ValueError,KeyError,TypeError,AttributeError) as exc: return errors+['invalid discovery manifest: '+str(exc)]
    if not isinstance(discovery.get('edges',[]),list) or any(not isinstance(edge,dict) for edge in discovery.get('edges',[])): return errors+['invalid discovery edges']
    ops = {o['id']:o for o in operations}
    if set(required)-set(ops): errors.append('omitted discovered operations: '+','.join(sorted(set(required)-set(ops))))
    if set(ops)-set(required): errors.append('operations lack discovery provenance')
    incomplete = bool(discovery.get('limitations')) or not operations or any(edge.get('status')!='established' for edge in discovery.get('edges',[]))
    for op in operations:
        if op['class'] != required.get(op['id'],{}).get('class'): errors.append('operation class differs from discovery')
        if op['status']=='deferred':
            incomplete=True
            if not op['reason'].strip(): errors.append('deferred operation requires reason')
        for item in op['completion'].values():
            if item['status']=='unresolved':
                incomplete=True
                if not item['needed'].strip(): errors.append('unresolved completion requires needed evidence')
            elif not item['evidence'] or item['needed']: errors.append('complete item requires evidence and no missing prerequisite')
    for c in categories:
        if not c['evidence']: errors.append('category evidence required, including absence')
        derived_ids=set(c['operation_ids']) | set(discovery.get('categories',{}).get(c['category'],[])) & set(required)
        linked = [required.get(i) for i in derived_ids]
        if any(o is None for o in linked): errors.append('unknown category operation')
        critical = c['status']!='absent' and (c['category']=='policy_store' or any(o and o['class'] in ('value','lifecycle','policy') for o in linked))
        if critical and not c['critical']: errors.append('criticality cannot be downgraded')
        if c['status']=='absent' and discovery.get('categories',{}).get(c['category']): errors.append('false category absence')
        if c['status'] not in ('absent','verified'):
            incomplete=True
            if not c['limitations']: errors.append('unverified category requires limitation')
        elif c['limitations']: errors.append('verified/absent category has unresolved limitations')
    uncertain = any(f['evidence_status'] in ('NON LIQUET','SUSPECTED') for f in findings)
    if report['assurance']=='VERIFIED_SCOPE' and (incomplete or uncertain): errors.append('VERIFIED_SCOPE contradicts unresolved coverage/evidence')
    if report['conclusion']=='NO_FINDINGS_IN_VERIFIED_SCOPE' and (incomplete or uncertain or report['assurance']!='VERIFIED_SCOPE'):
        errors.append('clean conclusion requires verified coverage and no unresolved findings')
    actionable = any(f['evidence_status'] in ('CONFIRMED','SUSPECTED') for f in findings)
    if actionable != (report['conclusion']=='FINDINGS_REPORTED'): errors.append('finding conclusion inconsistent')
    assessed=bool(findings) or any(c['status'] in ('reviewed','verified') for c in categories)
    if report['assurance']=='NOT_ASSESSED' and assessed: errors.append('NOT_ASSESSED contradicts evidence')
    if (report['assurance']=='NOT_ASSESSED') != (report['conclusion']=='NOT_ASSESSED'): errors.append('NOT_ASSESSED axes disagree')
    artifacts={a['kind']:a['ref'] for a in report['artifacts']}
    present={c['category'] for c in categories if c['status']!='absent'}
    needed=set()
    if present & {'stored_procedure','api_route'}: needed.add('operations.json')
    if 'policy_store' in present:
        needed.update({'matrix.csv','coverage.json'})
        if not {'diff.json','owner_questions.json'} & artifacts.keys(): errors.append('policy store requires diff or owner questions')
    if needed-artifacts.keys(): errors.append('missing artifacts: '+','.join(sorted(needed-artifacts.keys())))
    if 'operations.json' in artifacts and artifacts['operations.json'] != report['discovery']:
        errors.append('operations artifact must match discovery ref')
    if 'policy_store' in present and report['assurance']=='VERIFIED_SCOPE' and 'coverage.json' in artifacts:
        try:
            coverage=json.loads(resolve(artifacts['coverage.json'],evidence_root).read_text())
            if any(coverage.get(k)!=1.0 for k in ('row_ratio','node_ratio','decision_ratio')) or coverage.get('semantics_assumed')!=[] or coverage.get('limitations'):
                errors.append('policy coverage incomplete or semantics assumed')
            semantics=coverage.get('semantics_sources',{})
            if set(semantics)!={'inheritance','conflict','null_scope','default','precedence'} or any(not isinstance(ref,dict) or not {'path','sha256'}.issubset(ref) for ref in semantics.values()):
                errors.append('verified policy coverage requires resolvable semantics sources')
            else:
                for ref in semantics.values(): resolve(ref,evidence_root)
            if 'configuration.json' not in artifacts:
                errors.append('verified policy coverage requires original normalized export')
            else:
                configuration=json.loads(resolve(artifacts['configuration.json'],evidence_root).read_text())
                import csv
                with resolve(artifacts['matrix.csv'],evidence_root).open(newline='') as stream: decisions=sum(1 for _ in csv.DictReader(stream))
                if coverage.get('rows_inspected')!=len(configuration['rows']) or coverage.get('nodes_inspected')!=len(configuration['nodes']) or coverage.get('decisions')!=decisions:
                    errors.append('coverage denominator differs from exported data or actual matrix')
        except (OSError,ValueError,TypeError,AttributeError) as exc: errors.append('invalid coverage: '+str(exc))
    for f in findings:
        status=f['evidence_status']; verification=f['verification']
        if f['operation_id'] not in ops: errors.append('finding unknown operation')
        policy_required=f['category'] in ('AUTHZ-BYPASS','TENANT-LEAK','PERIMETER-BYPASS') or any(t.startswith('POLICY-') or t=='AUTHZ-DATA-INTEGRITY' for t in f['tags'])
        if status in ('CONFIRMED','SUSPECTED') and policy_required and (f['policy_basis']['class'] not in POLICY_CLASSES or f['policy_basis']['ref'] is None):
            errors.append('independent policy basis required by classification')
        if status in ('CONFIRMED','REFUTED'):
            if verification not in ('STATIC_PROVEN','DYNAMIC_REPRODUCED') or not f['proof']: errors.append('established verdict requires proof')
            if not f['entry_points'] or not f['paths']: errors.append('established verdict requires entry paths')
            if set(f['entry_points']) != {p['entry_point'] for p in f['paths']}: errors.append('entry point/path mismatch')
            if any(e['status']!='established' for p in f['paths'] for e in p['edges']): errors.append('established verdict cannot contain assumed edges')
        if status in ('NON LIQUET','SUSPECTED') and not f['unresolved']: errors.append('uncertainty requires missing evidence')
        if verification=='DYNAMIC_REPRODUCED':
            if 'run_record' not in f: errors.append('dynamic proof requires run record'); continue
            try:
                record=json.loads(resolve(f['run_record'],evidence_root).read_text())
                from run_repro import validate_record
                errors.extend(validate_record(record,evidence_root))
                if status in ('CONFIRMED','REFUTED') and record.get('observed',{}).get('claim') != ('violation' if status=='CONFIRMED' else 'defense'):
                    errors.append('run claim does not match finding verdict')
                case=record.get('observed',{}).get('case',{})
                if case.get('operation') != f['operation_id']: errors.append('run record is not bound to finding operation')
                if case.get('contributing_rows') is not None and set(case['contributing_rows']) != {r.get('row_key') for r in f['contributing_rows']}:
                    errors.append('run record is not bound to contributing rows')
            except (OSError,ValueError,KeyError,TypeError,AttributeError) as exc: errors.append('invalid run record: '+str(exc))
        elif 'run_record' in f and verification in ('TEST_GENERATED','NOT_VERIFIED'): errors.append('unexecuted verification cannot claim run record')
    for tool in report['tools_executed']:
        if tool['exit_code'] and tool['outcome']!='failed': errors.append('failed scanner cannot report hits/no hits')
    return errors


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('report',type=Path);p.add_argument('--evidence-root',type=Path,required=True);a=p.parse_args()
    try: errors=validate(json.loads(a.report.read_text()),evidence_root=a.evidence_root)
    except (OSError,ValueError,TypeError,AttributeError) as exc: p.exit(2,str(exc)+'\n')
    for error in errors: print(error)
    print('INVALID' if errors else 'VALID: structure, artifact integrity and declared coverage only; semantics require review')
    return int(bool(errors))


if __name__=='__main__':raise SystemExit(main())
