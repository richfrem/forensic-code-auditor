#!/usr/bin/env python3
"""Bounded offline effective-authority reconciliation with explicit application semantics.

This models declared exports; it neither supplies universal Oracle policy semantics nor
proves runtime enforcement. No policy means owner questions, never policy violations.
"""
import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys

DEFAULTS={'inheritance':'leaf_only','conflict':'unknown','null_scope':'none','default':'deny','precedence':'priority'}
VALUES={'inheritance':{'leaf_only','nearest','union'},'conflict':{'deny','allow','unknown'},'null_scope':{'none','all'},'default':{'deny','allow'},'precedence':{'priority','specificity'}}
COLUMNS=['principal','role','resource','operation','scope','entry_point','state','effective_at','policy_source','policy_version','contributing_rows','precedence_trace','intended','configured','enforced','exception_source','verification','evidence','unresolved']


def analyze(config,policy=None,*,max_decisions=100000):
    nodes={n['id']:n for n in config['nodes']};rows=config['rows'];roles=config['roles']
    if len(nodes)!=len(config['nodes']) or len({r['id'] for r in rows})!=len(rows):raise ValueError('duplicate node/row identifiers')
    semantics={};assumed=[]
    for key,default in DEFAULTS.items():
        spec=config.get('semantics',{}).get(key,{'value':default,'source_ref':'ASSUMED'})
        value=spec['value']
        if value not in VALUES[key]:raise ValueError('unsupported semantics '+key)
        if not spec.get('source_ref') or spec['source_ref']=='ASSUMED':assumed.append(key)
        semantics[key]=value
    def ancestry(key,lookup,parent_key,trail=()):
        if key in trail:raise ValueError('cyclic hierarchy')
        if key not in lookup:raise ValueError('dangling hierarchy reference: '+str(key))
        parents=lookup[key].get(parent_key) if parent_key=='parent' else lookup[key]
        parents=[] if parents is None else ([parents] if isinstance(parents,str) else parents)
        result=[key]
        for parent in parents:result.extend(ancestry(parent,lookup,parent_key,trail+(key,)))
        return list(dict.fromkeys(result))
    lineages={n:ancestry(n,nodes,'parent') for n in nodes}
    role_lineages={r:ancestry(r,roles,'roles') for r in roles}
    row_index={r:[] for r in [*roles,'*']}
    for row in rows:
        if not isinstance(row.get('allow'),bool) or row.get('node') not in {*nodes,'*'} or row.get('role') not in {*roles,'*'}:
            raise ValueError('invalid exported grant '+str(row.get('id')))
        if row.get('from',0)>=row.get('until',float('inf')):raise ValueError('invalid date interval')
        row_index[row['role']].append(row)
    leaves=[n for n in nodes.values() if 'operation' in n]
    dimensions=[config.get('scopes',['default']),config.get('states',['PENDING']),config.get('time_points',[0]),config.get('entry_points',[{'id':'declared-policy','checks_policy':True}])]
    total=len(leaves)*len(roles)
    for dimension in dimensions:total*=len(dimension)
    if not total or total>max_decisions:raise ValueError('empty or oversized decision domain; export bounded scope explicitly')
    independent=bool(policy and policy.get('basis_class') in {'owner_signed','regulation','requirement_doc','contract'} and policy.get('source_ref'))
    policy_index={}
    for rule in (policy or {}).get('rules',[]):
        policy_index.setdefault((rule['role'],rule['operation'],rule['scope'],rule['state']),[]).append(rule)
    matrix=[];diff=[];questions=[];signals=[];used=set()
    for role,parents in role_lineages.items():
        candidate_rows=[row for parent in [*parents,'*'] for row in row_index[parent]]
        for leaf in leaves:
            lineage=lineages[leaf['id']]
            node_rows=[r for r in candidate_rows if r['node'] in (lineage if semantics['inheritance']!='leaf_only' else [leaf['id']]) or r['node']=='*']
            node_rows=[r for r in node_rows if r.get('operation','*') in ('*',leaf['operation'])]
            for scope in dimensions[0]:
                scoped=[r for r in node_rows if r.get('scope') in (scope,'*') or (r.get('scope') is None and semantics['null_scope']=='all')]
                for state in dimensions[1]:
                    for at in dimensions[2]:
                        active=[r for r in scoped if r.get('from',0)<=at<r.get('until',float('inf')) and r.get('state','*') in ('*',state)]
                        used.update(r['id'] for r in active)
                        matches=list(active)
                        if matches and (semantics['inheritance']=='nearest' or semantics['precedence']=='specificity'):
                            distance=lambda r:lineage.index(r['node']) if r['node'] in lineage else len(lineage)
                            closest=min(distance(r) for r in matches);matches=[r for r in matches if distance(r)==closest]
                        if matches:
                            priority=max(r.get('priority',0) for r in matches);matches=[r for r in matches if r.get('priority',0)==priority]
                            decisions={r['allow'] for r in matches}
                            configured=next(iter(decisions)) if len(decisions)==1 else {'deny':False,'allow':True,'unknown':None}[semantics['conflict']]
                        else:configured=semantics['default']=='allow'
                        principal=config.get('principals',{}).get(role,role)
                        intended=None;source=None;exception=None
                        if independent:
                            exceptions=[r for r in policy.get('exceptions',[]) if r.get('principal',principal)==principal and r.get('role',role)==role and r['operation']==leaf['operation'] and r['scope']==scope and r['state']==state and r.get('from',0)<=at<r.get('until',float('inf'))]
                            rules=exceptions or policy_index.get((role,leaf['operation'],scope,state),[])
                            values={r['allow'] for r in rules}
                            if len(values)==1:
                                intended=next(iter(values));source=(rules[0].get('source_ref') or policy['source_ref'])
                                if exceptions:exception=source
                            elif not rules and policy.get('closed_world') is True:intended=False;source=policy['source_ref']
                        winning=sorted(r['id'] for r in matches)
                        for entry in dimensions[3]:
                            # Entry metadata is a declared adapter, not observed enforcement.
                            if entry.get('checks_policy') is True:modeled=configured
                            elif entry.get('checks_policy') is False:modeled=bool(entry.get('delegated_allow',True))
                            else:modeled=None
                            record={'principal':principal,'role':role,'resource':leaf['id'],'operation':leaf['operation'],'scope':scope,'entry_point':entry['id'],'state':state,'effective_at':at,'policy_source':source,'policy_version':(policy or {}).get('version'),'contributing_rows':winning,'precedence_trace':semantics.copy(),'intended':intended,'configured':configured,'enforced':None,'modeled_path_decision':modeled,'matched_rows':sorted(r['id'] for r in active),'exception_source':exception,'verification':'STATIC_MODEL_ONLY','evidence':[],'unresolved':[]}
                            matrix.append(record)
                            base={k:record[k] for k in ('principal','role','resource','operation','scope','entry_point','state','effective_at','contributing_rows')}
                            if intended is False and (configured is True or modeled is True):
                                diff.append(dict(base,kind='AUTHZ_DATA_DEFECT' if configured is True else 'CROSS_ENTRYPOINT_BYPASS',policy_source=source))
                            if intended is None and (configured is True or modeled is True):
                                score=(100 if leaf.get('operation_class') in ('value','lifecycle','policy') else 0)+(20 if config.get('role_rank',{}).get(role,0)==0 else 0)+(5 if len(winning)==1 else 0)
                                questions.append(dict(base,kind='POLICY_UNRESOLVED',score=score,question='Is this effective grant intended? Supply independent policy; ranking is an anomaly heuristic.'))
                            if configured is None:signals.append(dict(base,kind='conflicting_grants'))
                            if configured and any(r.get('scope') in (None,'*') for r in matches):signals.append(dict(base,kind='wildcard_expansion'))
                            if configured and any(r['node']!=leaf['id'] for r in matches):signals.append(dict(base,kind='inherited_grant'))
                            if configured and leaf.get('operation_class') in ('value','lifecycle','policy') and config.get('role_rank',{}).get(role,0)==0:signals.append(dict(base,kind='privileged_peer_outlier'))
    for row in rows:
        if not any(row.get('from',0)<=at<row.get('until',float('inf')) for at in dimensions[2]):signals.append({'kind':'inactive_rule','contributing_rows':[row['id']]})
    by_operation={}
    for record in matrix:
        key=tuple(record[k] for k in ('role','resource','operation','scope','state','effective_at'))
        by_operation.setdefault(key,[]).append(record)
    for paths in by_operation.values():
        if len({p['modeled_path_decision'] for p in paths})>1:signals.append({'kind':'cross_entrypoint_divergence','operation':paths[0]['operation'],'entry_points':[p['entry_point'] for p in paths]})
    # Scope SoD as a separate review signal; never infer owner policy from role rank.
    for constraint in config.get('sod',[]):
        for role,parents in role_lineages.items():
            if set(constraint.get('roles',[])).issubset(parents):signals.append({'kind':'sod_review','role':role,'source_ref':constraint.get('source_ref','ASSUMED')})
    questions.sort(key=lambda q:(-q['score'],str(q['contributing_rows']),q['entry_point']))
    return {'matrix':matrix,'coverage':{'row_ratio':1.0,'node_ratio':1.0,'decision_ratio':len(matrix)/total,'rows_inspected':len(rows),'active_rows_used':len(used),'nodes_inspected':len(nodes),'decisions':len(matrix),'semantics_assumed':assumed,'limitations':list(config.get('limitations',[]))+([] if independent else ['Independent policy unavailable; intended decisions unresolved'])},'diff':diff,'owner_questions':questions,'signals':signals}


def write_outputs(result,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    with (output/'matrix.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=COLUMNS+['modeled_path_decision','matched_rows']);writer.writeheader()
        for row in result['matrix']:
            writer.writerow({k:json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v for k,v in row.items()})
    for key,name in [('coverage','coverage.json'),('diff','diff.json'),('owner_questions','owner_questions.json'),('signals','anomaly_signals.json')]:
        (output/name).write_text(json.dumps(result[key],indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True);p.add_argument('--policy',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--max-decisions',type=int,default=100000);p.add_argument('--differential',nargs='+');a=p.parse_args()
    try:
        config=json.loads(a.config.read_text());policy=json.loads(a.policy.read_text()) if a.policy else None
        result=analyze(config,policy,max_decisions=a.max_decisions);write_outputs(result,a.output)
        if a.differential:
            command=a.differential
            script=Path(command[1]).resolve() if len(command)>1 else None
            if not script or not script.is_file() or script.suffix!='.py' or any('://' in x for x in command):raise ValueError('differential accepts only a reviewed local Python evaluator')
            run=subprocess.run(command,input=json.dumps(config),capture_output=True,text=True,timeout=30,shell=False,check=True)
            actual=json.loads(run.stdout)
            expected=[r['configured'] for r in result['matrix']]
            (a.output/'differential.json').write_text(json.dumps({'matches':actual==expected,'expected':expected,'actual':actual})+'\n')
            if actual!=expected:return 1
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:p.exit(2,str(exc)+'\n')
    print(f'decisions={len(result["matrix"])} discrepancies={len(result["diff"])} owner_questions={len(result["owner_questions"])}; static modeled authority only')
    return 0


if __name__=='__main__':raise SystemExit(main())
