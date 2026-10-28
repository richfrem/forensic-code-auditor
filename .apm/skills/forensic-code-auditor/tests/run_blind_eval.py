#!/usr/bin/env python3
"""Prepare blind targets/keys separately and dry-run an explicitly supplied agent command.

This harness does not sandbox an agent. The command/provider must enforce visibility.
No paid/model execution occurs without --execute and explicit local operator opt-ins.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from gen_authz import generate


def prepare(seed,destination,variant):
    destination=Path(destination);opaque=hashlib.sha256(f'{seed}:{variant}'.encode()).hexdigest()[:16]
    target=destination/'targets'/('case_'+opaque)
    if target.exists():raise ValueError('refuse to overwrite an evaluation target')
    target.mkdir(parents=True)
    config,policy,key=generate(seed)
    if variant=='protected':
        next(r for r in config['rows'] if r['id']==key['bad_row'])['allow']=False
    # Supply a neutral multi-file synthetic application, not the analysis engine/answer key.
    (target/'authorization.py').write_text("""def allowed(rows, role, node, scope, at):
    active=[r for r in rows if r['role'] in (role,'*') and r['node'] in (node,'*') and r['scope'] in (scope,'*') and r['from'] <= at < r['until']]
    if not active:return False
    priority=max(r['priority'] for r in active)
    return all(r['allow'] for r in active if r['priority']==priority)
""")
    leaf=next(n for n in config['nodes'] if n.get('operation'))
    procedure='op_'+leaf['operation']
    (target/'package.sql').write_text(f"CREATE OR REPLACE PACKAGE BODY pkg_claim AS\nPROCEDURE {procedure} IS\nBEGIN\n IF NOT pkg_acl.allowed(SYS_CONTEXT('APP_CTX','ROLE'),'{leaf['id']}',SYS_CONTEXT('APP_CTX','SCOPE'),15) THEN RAISE denied; END IF;\n UPDATE claim SET status='APPROVED';\nEND {procedure};\nEND pkg_claim;\n/\n")
    (target/'form.xml').write_text(f'<Trigger Name="WHEN-BUTTON-PRESSED">pkg_claim.{procedure}();</Trigger>\n')
    (target/'Route.java').write_text(f'void submit() {{ verifiedDelegation.bindToDatabaseSession(request); pool.prepareCall("{{call pkg_claim.{procedure}()}}"); }}\n')
    (target/'configuration.json').write_text(json.dumps(config,indent=2)+'\n')
    if variant!='indeterminate':(target/'policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    keys=destination/'keys';keys.mkdir(exist_ok=True)
    answer={'seed':seed,'variant':variant,'row_key':key['bad_row'],'operation':next(n['operation'] for n in config['nodes'] if n['id']==key['bad_node']),'expected':'CONFIRMED' if variant=='vulnerable' else ('REFUTED' if variant=='protected' else 'NON LIQUET')}
    (keys/f'{seed}-{variant}.json').write_text(json.dumps(answer,indent=2)+'\n')
    return target,answer


def plan(command,skill,target):
    if not command or not any('{target}' in arg for arg in command):raise ValueError('agent command must bind target')
    return [arg.replace('{skill}',str(Path(skill).resolve())).replace('{target}',str(Path(target).resolve())) for arg in command]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seed',type=int,required=True);p.add_argument('--variant',choices=['vulnerable','protected','indeterminate'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--skill-source',type=Path,required=True);p.add_argument('--command-json',required=True);p.add_argument('--execute',action='store_true');p.add_argument('--allow-model-run',action='store_true');p.add_argument('--sandbox-configured',action='store_true');a=p.parse_args()
    if not (a.skill_source/'SKILL.md').is_file():p.error('skill source must contain SKILL.md')
    if a.execute and not(a.allow_model_run and a.sandbox_configured):p.error('execution requires authorized model run and independently configured visibility sandbox')
    try:
        target,_=prepare(a.seed,a.output,a.variant);command=plan(json.loads(a.command_json),a.skill_source,target)
        manifest={'command':command,'cwd':str(target.resolve()),'dry_run':not a.execute,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in target.iterdir()},'visibility_warning':'cwd is not isolation; provider must hide keys/other targets and evaluator source'}
        if a.execute:
            run=subprocess.run(command,cwd=target,capture_output=True,text=True,timeout=300,shell=False)
            manifest.update(exit_code=run.returncode,stdout=run.stdout,stderr=run.stderr)
        (target.parent/(target.name+'-run.json')).write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
    except (OSError,ValueError,subprocess.SubprocessError) as exc:p.exit(2,str(exc)+'\n')


if __name__=='__main__':main()
