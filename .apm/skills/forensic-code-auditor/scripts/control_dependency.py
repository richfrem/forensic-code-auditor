#!/usr/bin/env python3
"""Model single-control compromise against declared trust edges; no live probing."""
import argparse
import json
from pathlib import Path


def analyze(graph):
    nodes={n['id']:n for n in graph['nodes']}
    if len(nodes)!=len(graph['nodes']) or graph['origin'] not in nodes:raise ValueError('invalid control nodes/origin')
    if any(e['from'] not in nodes or e['to'] not in nodes for e in graph['edges']):raise ValueError('dangling control edge')
    controls=graph['controls'];ids=[c['id'] for c in controls]
    if len(ids)!=len(set(ids)):raise ValueError('duplicate control')
    results=[]
    for failed in [None,*controls]:
        capabilities=set(graph.get('baseline_capabilities',[]))|set(failed.get('grants_on_compromise',[]) if failed else [])
        paths={graph['origin']:[graph['origin']]}
        changed=True
        while changed:
            changed=False
            for edge in graph['edges']:
                if edge['from'] in paths and edge['to'] not in paths and set(edge['requires']).issubset(capabilities):
                    paths[edge['to']]=paths[edge['from']]+[edge['to']];changed=True
        for target,path in paths.items():
            if not nodes[target].get('operation'):continue
            policy=graph.get('policy')
            independent=policy and policy.get('basis_class') in ('owner_signed','regulation','requirement_doc','contract') and policy.get('source_ref')
            results.append({'compromised':failed['id'] if failed else None,'operation':nodes[target]['operation'],'scope':nodes[target].get('scope'),'path':path,'assessment':'MODEL_POLICY_DISCREPANCY' if independent and target not in policy['allowed_nodes'] else ('MODELED_ALLOWED' if independent else 'NON LIQUET'),'verification':'STATIC_MODEL_ONLY','source_ref':graph.get('source_ref'),'limitations':['Declared edge/capability model; reachability and credential strength not dynamically tested']})
    return results


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('graph',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:result=analyze(json.loads(a.graph.read_text()));a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    except (OSError,ValueError,KeyError,TypeError) as exc:p.exit(2,str(exc)+'\n')
    print('Modeled conditional outcomes: '+str(len(result)))


if __name__=='__main__':main()
