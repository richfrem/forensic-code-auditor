#!/usr/bin/env python3
"""Run pinned real qltests, including extraction counts; no auto-blessing results."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--pack-root',type=Path,default=ROOT/'references/rules/codeql');a=p.parse_args()
    codeql=shutil.which('codeql')
    if not codeql:print('NOT RUN: CodeQL CLI unavailable');return 77
    version=json.loads(subprocess.check_output([codeql,'version','--format=json'],text=True))['version']
    if version!='2.23.3':p.error('tools.lock requires CodeQL 2.23.3; found '+version)
    python=shutil.which('python3')
    if not python or not subprocess.check_output([python,'--version'],text=True).startswith('Python 3.11.'):
        p.error('put Python 3.11 on PATH for reproducible Python extraction')
    print('CodeQL '+version+'; '+subprocess.check_output([python,'--version'],text=True).strip(),flush=True)
    with tempfile.TemporaryDirectory(prefix='forensic-qltests-') as folder:
        for language in ('python','javascript'):
            source=a.pack_root/language;pack=Path(folder)/language
            shutil.copytree(source,pack,ignore=shutil.ignore_patterns('*.testproj','*.actual','*.bqrs','*.qlx','__pycache__','.cache'))
            subprocess.run([codeql,'pack','install',str(pack)],check=True)
            subprocess.run([codeql,'test','run','--threads=2','--ram=4096',str(pack/'test')],check=True)
            print(language+': qltest expectations and extraction count PASS',flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
