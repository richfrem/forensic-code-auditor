#!/usr/bin/env python3
"""Capture a reviewed local synthetic reproduction; this runner is NOT a network sandbox.

Only explicit argv, a bounded timeout and reviewed files under the evidence root are
accepted. A command filter cannot stop network access performed by supplied code.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

from evidence import reference, resolve


def now(): return datetime.now(timezone.utc).isoformat()


def run(command, *, root, environment, runtime='local-python', timeout=30):
    root=Path(root).resolve()
    if environment!='isolated-local-synthetic': raise ValueError('explicit isolated-local-synthetic opt-in required')
    if not re.fullmatch(r'(?:isolated-local|local|disposable)-[a-z0-9_-]+',runtime) or re.search(r'(?:production|staging|shared|live)',runtime):
        raise ValueError('runtime label contradicts isolated local execution')
    if not command or not 1<=timeout<=300: raise ValueError('invalid command/timeout')
    for arg in command:
        if re.search(r'(?i)://(?!localhost(?=[:/]|$)|127\.0\.0\.1(?=[:/]|$)|\[::1\])',arg): raise ValueError('remote URL forbidden')
        if re.search(r'(?i)(--host|--hostname|--server|--url|--password|--token)(=|$)',arg): raise ValueError('remote/secret flags unsupported')
    # A file-backed reviewed reproduction is required; echo/one-line evals are not tests.
    if len(command)<2 or command[1] in ('-c','-m','-e'):
        raise ValueError('use a reviewed local script, not inline code or an opaque module')
    script=(root/command[1]).resolve()
    if not script.is_relative_to(root) or not script.is_file(): raise ValueError('reproduction script must be under evidence root')
    executable=Path(command[0]).resolve()
    if executable.name not in ('python','python3','python3.11','python3.12','python3.13','python3.14'):
        raise ValueError('only a reviewed Python reproduction is currently supported')
    started=now()
    try:
        result=subprocess.run([str(executable),*command[1:]],cwd=root,capture_output=True,text=True,timeout=timeout,shell=False)
    except subprocess.TimeoutExpired as exc: raise ValueError('reproduction timed out; not verified') from exc
    ended=now(); run_id=uuid.uuid4().hex
    folder=root/'runs'/run_id;folder.mkdir(parents=True)
    stdout,stderr=folder/'stdout.txt',folder/'stderr.txt';stdout.write_text(result.stdout);stderr.write_text(result.stderr)
    try: observed=json.loads(result.stdout)
    except ValueError: observed={}
    record={'schema_version':1,'producer':'forensic-code-auditor/run_repro-v1','command':[str(executable),*command[1:]],'cwd':'.','exit_code':result.returncode,'started':started,'ended':ended,'tool_versions':{'python':sys.version.split()[0]},'environment':environment,'runtime':runtime,'script_ref':reference(script,root),'stdout_ref':reference(stdout,root),'stderr_ref':reference(stderr,root),'observed':observed}
    path=folder/'run.json';path.write_text(json.dumps(record,indent=2)+'\n')
    return reference(path,root)


def validate_record(record,root):
    errors=[]
    required={'schema_version','producer','command','cwd','exit_code','started','ended','tool_versions','environment','runtime','script_ref','stdout_ref','stderr_ref','observed'}
    if set(record)!=required: return ['run record has missing/unknown fields']
    if record['producer']!='forensic-code-auditor/run_repro-v1' or record['schema_version']!=1: errors.append('unknown run producer/version')
    if record['environment']!='isolated-local-synthetic' or record['cwd']!='.': errors.append('invalid run environment/cwd')
    if not isinstance(record['runtime'],str) or not re.fullmatch(r'(?:isolated-local|local|disposable)-[a-z0-9_-]+',record['runtime']) or re.search(r'(?:production|staging|shared|live)',record['runtime']): errors.append('runtime label contradicts isolation declaration')
    if not record['command'] or not record['tool_versions'] or not record['runtime']: errors.append('incomplete run provenance')
    try:
        if datetime.fromisoformat(record['ended'])<datetime.fromisoformat(record['started']): errors.append('invalid run times')
        script=resolve(record['script_ref'],root)
        if len(record['command'])<2 or (Path(root)/record['command'][1]).resolve()!=script: errors.append('command/script mismatch')
        stdout=resolve(record['stdout_ref'],root);resolve(record['stderr_ref'],root)
        if json.loads(stdout.read_text()) != record['observed']: errors.append('run result differs from captured stdout')
        assertions=record['observed'].get('assertions',[])
        if not assertions or not any(a.get('kind')=='durable_state' for a in assertions): errors.append('run lacks durable assertions')
        if any(a.get('passed') is not True or not a.get('name') or 'actual' not in a or 'expected' not in a or a['actual']!=a['expected'] for a in assertions): errors.append('run assertions not satisfied')
        if record['observed'].get('claim') not in ('violation','defense'): errors.append('run lacks claim interpretation')
        if not isinstance(record['exit_code'],int) or record['exit_code']!=0: errors.append('reproduction did not complete asserted observations')
    except (OSError,ValueError,TypeError,KeyError,AttributeError) as exc: errors.append('run artifact unavailable/invalid: '+str(exc))
    return errors


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--environment',required=True);p.add_argument('--runtime',default='local-python');p.add_argument('--timeout',type=int,default=30);p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
    command=a.command[1:] if a.command[:1]==['--'] else a.command
    try: ref=run(command,root=a.evidence_root,environment=a.environment,runtime=a.runtime,timeout=a.timeout)
    except (OSError,ValueError) as exc:p.exit(2,str(exc)+'\n')
    print(json.dumps(ref))


if __name__=='__main__':main()
