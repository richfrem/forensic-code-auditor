#!/usr/bin/env python3
"""Stage runtime content without source-only regressions or private evaluation material."""
import argparse
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[1]


def stage(source,output):
    source=Path(source).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('refuse to overwrite staging directory')
    if output.is_relative_to(source):raise ValueError('stage outside source')
    def ignore(directory,names):
        excluded={'tests','test','evals','evals-private','__pycache__','.cache'}
        return [name for name in names if name in excluded or name.endswith(('.pyc','.qlx','.actual','.bqrs','.testproj')) or (Path(directory).name=='semgrep' and not name.endswith('.yaml') and name!='inventory') or (Path(directory).name=='inventory' and not name.endswith('.yaml'))]
    shutil.copytree(source,output,ignore=ignore)
    return output


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:print(stage(a.source,a.output))
    except (OSError,ValueError) as exc:p.exit(2,str(exc)+'\n')


if __name__=='__main__':main()
