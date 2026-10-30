#!/usr/bin/env python3
"""Capture a reviewed local synthetic reproduction; this runner is NOT a network sandbox.

Only explicit argv, a bounded timeout and reviewed files under the evidence root are
accepted. A command filter cannot stop network access performed by supplied code.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from evidence import reference, resolve

SAFE_ENV_KEYS = ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TMPDIR', 'TEMP', 'TMP', 'SYSTEMROOT', 'WINDIR')


def now(): return datetime.now(timezone.utc).isoformat()


def scrubbed_env(root):
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env['HOME'] = str(Path(root).resolve())
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONNOUSERSITE'] = '1'
    return env


def child_python_version(executable, root, env):
    try:
        probe = subprocess.run([str(executable), '-c', 'import platform; print(platform.python_version())'],
                               cwd=root, capture_output=True, text=True, timeout=5, env=env, shell=False)
        version = probe.stdout.strip()
        if probe.returncode == 0 and version:
            return version
    except (OSError, subprocess.SubprocessError):
        pass
    return sys.version.split()[0]


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
    # Bare names follow PATH; explicit relative paths follow the reproduction cwd.
    requested=command[0]
    located=shutil.which(requested if Path(requested).name==requested else str(root/requested))
    if located is None: raise ValueError(f'Python interpreter not found or not executable: {requested}')
    executable=Path(located).resolve()
    if executable.name not in ('python','python3','python3.11','python3.12','python3.13','python3.14'):
        raise ValueError('only a reviewed Python reproduction is currently supported')
    pre_bytes=script.read_bytes()
    pre_ref=reference(script,root)
    run_id=uuid.uuid4().hex
    folder=root/'runs'/run_id;folder.mkdir(parents=True)
    snapshot=folder/'executed_script.py';snapshot.write_bytes(pre_bytes)
    child_env=scrubbed_env(root)
    py_version=child_python_version(executable,root,child_env)
    started=now()
    try:
        result=subprocess.run([str(executable),*command[1:]],cwd=root,capture_output=True,text=True,timeout=timeout,env=child_env,shell=False)
    except subprocess.TimeoutExpired as exc: raise ValueError('reproduction timed out; not verified') from exc
    ended=now()
    post_sha256=hashlib.sha256(script.read_bytes()).hexdigest() if script.is_file() else ''
    stdout,stderr=folder/'stdout.txt',folder/'stderr.txt';stdout.write_text(result.stdout);stderr.write_text(result.stderr)
    try: observed=json.loads(result.stdout)
    except ValueError: observed={}
    record={'schema_version':1,'producer':'forensic-code-auditor/run_repro-v1','command':[str(executable),*command[1:]],'cwd':'.','exit_code':result.returncode,'started':started,'ended':ended,'tool_versions':{'python':py_version},'environment':environment,'runtime':runtime,'script_ref':pre_ref,'executed_script_ref':reference(snapshot,root),'script_mutated':post_sha256!=pre_ref['sha256'],'stdout_ref':reference(stdout,root),'stderr_ref':reference(stderr,root),'observed':observed}
    path=folder/'run.json';path.write_text(json.dumps(record,indent=2)+'\n')
    return reference(path,root)


def validate_record(record,root):
    errors=[]
    required={'schema_version','producer','command','cwd','exit_code','started','ended','tool_versions','environment','runtime','script_ref','stdout_ref','stderr_ref','observed'}
    optional={'executed_script_ref','script_mutated'}
    if not required.issubset(record) or set(record)-(required|optional): return ['run record has missing/unknown fields']
    if record['producer']!='forensic-code-auditor/run_repro-v1' or record['schema_version']!=1: errors.append('unknown run producer/version')
    if record['environment']!='isolated-local-synthetic' or record['cwd']!='.': errors.append('invalid run environment/cwd')
    if not isinstance(record['runtime'],str) or not re.fullmatch(r'(?:isolated-local|local|disposable)-[a-z0-9_-]+',record['runtime']) or re.search(r'(?:production|staging|shared|live)',record['runtime']): errors.append('runtime label contradicts isolation declaration')
    if not record['command'] or not record['tool_versions'] or not record['runtime']: errors.append('incomplete run provenance')
    if record.get('script_mutated') is True: errors.append('reproduction script mutated during execution')
    try:
        if datetime.fromisoformat(record['ended'])<datetime.fromisoformat(record['started']): errors.append('invalid run times')
        script=resolve(record['script_ref'],root)
        if 'executed_script_ref' in record:
            resolve(record['executed_script_ref'],root)
            if record['executed_script_ref']['sha256']!=record['script_ref']['sha256']:
                errors.append('executed script snapshot differs from declared script_ref')
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
