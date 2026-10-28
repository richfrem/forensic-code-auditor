#!/usr/bin/env python3
"""Discover discrepancies from a supplied export and run a synthetic local model.

Default input is a labeled worked example, not a blind benchmark. No expected row ID
is encoded in the demo. Runtime observations apply only to this disposable model.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys

from authz_effective import analyze, write_outputs
from evidence import reference
from run_repro import run
from validate_report import validate, CATEGORIES

ROOT=Path(__file__).resolve().parents[1]
ITEMS=['invariant','entry_points','policy_provenance','execution_trace','competing_defenses','failure_hypothesis','discriminating_proof','classification','coverage']


def demo(output,config_path=None,policy_path=None,without_policy=False):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    config_path=Path(config_path or ROOT/'examples/configuration.json')
    config=json.loads(config_path.read_text())
    policy=None if without_policy else json.loads(Path(policy_path or ROOT/'examples/policy.json').read_text())
    (output/'configuration.json').write_text(json.dumps(config,indent=2)+'\n')
    if policy is not None:(output/'policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    result=analyze(config,policy);write_outputs(result,output)
    config_ref=reference(output/'configuration.json',output)
    operations=[{'id':n['operation'],'class':n.get('operation_class','lifecycle')} for n in config['nodes'] if n.get('operation')]
    graph={'schema_version':1,'operations':operations,'edges':[],'categories':{'policy_store':['configuration'],'menu_node':[n['id'] for n in config['nodes']],'stored_procedure':[o['id'] for o in operations]},'limitations':['Declared normalized example scope only; external callers and deployed DB semantics NOT VERIFIED']}
    (output/'operations.json').write_text(json.dumps(graph,indent=2)+'\n');graph_ref=reference(output/'operations.json',output)
    findings=[];run_ref=None
    if result['diff']:
        runtime=output/'runtime';runtime.mkdir(exist_ok=True)
        for name in ('authz_effective.py','evidence.py'):shutil.copy2(ROOT/'scripts'/name,runtime/name)
        (output/'reproduce.py').write_text('''import json,sqlite3,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path("runtime").resolve()))
from authz_effective import analyze
config=json.loads(Path("configuration.json").read_text());policy=json.loads(Path("policy.json").read_text())
result=analyze(config,policy);case=result["diff"][0]
temporary=tempfile.TemporaryDirectory();db_path=str(Path(temporary.name)/"model.sqlite");db=sqlite3.connect(db_path)
db.executescript("CREATE TABLE claim(status); INSERT INTO claim VALUES('PENDING'); CREATE TABLE effects(action);")
row=next(r for r in result["matrix"] if all(r[k]==case[k] for k in ("role","resource","operation","scope","entry_point","state","effective_at")))
if row["modeled_path_decision"] is True:
    db.execute("UPDATE claim SET status='APPROVED'");db.execute("INSERT INTO effects VALUES('approve')");db.commit()
db.commit();db.close();db=sqlite3.connect(db_path)
status=db.execute("SELECT status FROM claim").fetchone()[0];effects=db.execute("SELECT count(*) FROM effects").fetchone()[0]
print(json.dumps({"claim":"violation","case":case,"assertions":[{"kind":"durable_state","name":"committed status","actual":status,"expected":"APPROVED","passed":status=="APPROVED"},{"kind":"side_effect","name":"effect ledger","actual":effects,"expected":1,"passed":effects==1}]}))
''')
        run_ref=run([sys.executable,'reproduce.py'],root=output,environment='isolated-local-synthetic')
        case=result['diff'][0]
        proof=reference(output/'reproduce.py',output)
        findings.append({'id':'F-MODEL-1','operation_id':case['operation'],'category':'AUTHZ-BYPASS','tags':['AUTHZ-DATA-INTEGRITY'],'severity':'HIGH','evidence_status':'CONFIRMED','verification':'DYNAMIC_REPRODUCED','policy_basis':{'class':policy['basis_class'],'ref':reference(output/'policy.json',output)},'location':dict(config_ref,row_key=case['contributing_rows'][0]) if case['contributing_rows'] else config_ref,'proof':[proof,reference(runtime/'authz_effective.py',output)],'entry_points':[case['entry_point']],'contributing_rows':[dict(config_ref,row_key=key) for key in case['contributing_rows']],'paths':[{'entry_point':case['entry_point'],'edges':[{'from':case['entry_point'],'to':case['operation'],'kind':'synthetic-model-call','status':'established','evidence_ref':proof}]}],'run_record':run_ref,'unresolved':['Verdict applies to local synthetic model only; deployed Oracle NOT VERIFIED']})
    elif result['owner_questions']:
        case=result['owner_questions'][0]
        findings.append({'id':'N-MODEL-1','operation_id':case['operation'],'category':'AUTHZ-BYPASS','tags':['AUTHZ-DATA-INTEGRITY'],'severity':'HIGH','evidence_status':'NON LIQUET','verification':'NOT_VERIFIED','policy_basis':{'class':'none','ref':None},'location':config_ref,'proof':[],'entry_points':[case['entry_point']],'contributing_rows':[dict(config_ref,row_key=key) for key in case['contributing_rows']],'paths':[],'unresolved':['Independent intended policy required'],'obstruction_mechanism':'MISSING-POLICY','telemetry_spec':'Obtain owner-approved permission matrix for this exact role/resource/scope.'})
    report={'schema_version':2,'assurance':'PARTIAL' if policy else 'INSUFFICIENT_EVIDENCE','conclusion':'FINDINGS_REPORTED' if result['diff'] else 'INCONCLUSIVE','scope':{'categories':[{'category':c,'status':'reviewed' if c in graph['categories'] else 'absent','critical':c in ('policy_store','stored_procedure'),'operation_ids':[o['id'] for o in operations] if c=='stored_procedure' else [],'evidence':[config_ref],'limitations':['Only the declared synthetic export is assessed'] if c in graph['categories'] else []} for c in sorted(CATEGORIES)]},'operations':[{'id':o['id'],'class':o['class'],'status':'complete','reason':'','completion':{k:{'status':'complete','evidence':[config_ref],'needed':''} for k in ITEMS}} for o in operations],'findings':findings,'references_loaded':['authorization-data-integrity.md','cross-entrypoint-authorization.md'],'artifacts':[{'kind':n,'ref':reference(output/n,output)} for n in ('operations.json','coverage.json','matrix.csv','diff.json','owner_questions.json')],'discovery':graph_ref,'tools_executed':[]}
    # Known runtime/path gaps are explicitly unresolved even though model execution succeeded.
    for op in report['operations']:op['completion']['entry_points']={'status':'unresolved','evidence':[graph_ref],'needed':'Validate actual deployed callers and database identity'}
    errors=validate(report,evidence_root=output)
    if errors:raise ValueError(errors)
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    (output/'observation.json').write_text(json.dumps({'discrepancies':len(result['diff']),'owner_questions':len(result['owner_questions']),'run_record':run_ref,'oracle_runtime':'NOT_VERIFIED'},indent=2)+'\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--config',type=Path);p.add_argument('--policy',type=Path);p.add_argument('--without-policy',action='store_true');a=p.parse_args()
    try:report=demo(a.output,a.config,a.policy,a.without_policy)
    except (OSError,ValueError,KeyError,TypeError) as exc:p.exit(2,str(exc)+'\n')
    print(f'v2 report generated and artifact-validated: {report["assurance"]}; synthetic model only')


if __name__=='__main__':main()
