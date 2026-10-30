#!/usr/bin/env python3
"""Check a deployed package for private keys/targets and answer-bearing fixture markers."""
import argparse
import json
from pathlib import Path


def check(package,sealed_keys=None):
    errors=[];secrets=[]
    package=Path(package)
    if not package.is_dir() or not any(package.rglob('*')):
        return ['package missing or empty: '+str(package)]
    if sealed_keys and (not Path(sealed_keys).is_dir() or not list(Path(sealed_keys).glob('*.json'))):
        return ['sealed keys missing or empty: '+str(sealed_keys)]
    if sealed_keys:
        for p in Path(sealed_keys).glob('*.json'):
            key=json.loads(p.read_text());secrets.extend(str(key[k]) for k in ('row_key','operation') if key.get(k))
    for p in Path(package).rglob('*'):
        if not p.is_file():continue
        relative=p.relative_to(package)
        if any(part in ('evals-private','tests','evals') for part in relative.parts):errors.append('evaluation material deployed: '+str(relative));continue
        try:text=p.read_text()
        except UnicodeError:
            try:text=p.read_bytes().decode('latin-1',errors='ignore')
            except OSError:continue
        if any(secret in text for secret in secrets):errors.append('sealed identifier leaked: '+str(relative))
        if any(marker in text for marker in ('-- '+'VULNERABLE','-- '+'SAFE DECOY','// '+'EXPECT:')):errors.append('answer marker leaked: '+str(relative))
    return errors


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package-root',type=Path,required=True);p.add_argument('--sealed-keys',type=Path);a=p.parse_args()
    errors=check(a.package_root,a.sealed_keys)
    for error in errors:print(error)
    print('contamination lint: '+('FAIL' if errors else 'PASS (specified keys/markers only)'))
    return int(bool(errors))


if __name__=='__main__':raise SystemExit(main())
