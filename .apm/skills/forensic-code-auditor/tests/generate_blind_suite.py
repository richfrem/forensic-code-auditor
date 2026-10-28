#!/usr/bin/env python3
"""Generate private development/sealed seeds, targets and keys outside the package."""
import argparse
from pathlib import Path
import secrets
from run_blind_eval import prepare


def generate(output,dev_count=5,sealed_count=5):
    output=Path(output)
    if output.exists():raise ValueError('refuse to overwrite private evaluation suite')
    output.mkdir(parents=True);seed_dir=output/'seeds';seed_dir.mkdir()
    dev=list(range(dev_count));sealed=[]
    while len(sealed)<sealed_count:
        value=secrets.randbits(63)
        if value not in dev and value not in sealed:sealed.append(value)
    for name,values in [('dev',dev),('sealed',sealed)]:
        (seed_dir/(name+'.txt')).write_text(''.join(str(value)+'\n' for value in values))
        for seed in values:
            for variant in ('vulnerable','protected','indeterminate'):prepare(seed,output,variant)
    return {'dev_seeds':len(dev),'sealed_seeds':len(sealed),'targets':3*(len(dev)+len(sealed)),'model_runs':0}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--dev-count',type=int,default=5);p.add_argument('--sealed-count',type=int,default=5);a=p.parse_args()
    if not 0<=a.dev_count<=200 or not 0<=a.sealed_count<=200:p.error('counts must be bounded at 0..200')
    try:print(generate(a.output,a.dev_count,a.sealed_count))
    except (OSError,ValueError) as exc:p.exit(2,str(exc)+'\n')


if __name__=='__main__':main()
