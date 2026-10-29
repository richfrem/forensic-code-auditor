"""Seeded multi-branch benchmark generator; no fixed bad identifiers in the engine.

Keys are returned separately. Generated targets/keys belong under temp/evals-private,
never in deployed examples. These are controlled synthetic distributions.
"""
import random


def generate(seed, row_count=500):
    rng=random.Random(seed)
    used=set()
    def identifier():
        while True:
            key=f'{rng.getrandbits(64):016x}'
            if key not in used:used.add(key);return key
    roles=[identifier() for _ in range(40)]
    role_map={r:[] for r in roles}
    rank={r:0 for r in roles};rank[roles[-1]]=3
    nodes=[{'id':identifier(),'parent':None}];leaves=[]
    for i in range(40):
        parent=nodes[0]['id']
        for depth in range(4):
            node={'id':identifier(),'parent':parent};nodes.append(node);parent=node['id']
        node.update(operation=identifier(),operation_class='lifecycle' if i==0 else 'read');leaves.append(node)
    rows=[];rules=[]
    def grant(role,leaf):
        return {'id':identifier(),'role':role,'node':leaf['id'],'operation':leaf['operation'],'scope':'north','allow':True,'priority':1,'from':0,'until':100}
    for _ in range(row_count-4):
        role=rng.choice(roles);leaf=rng.choice(leaves[1:]);rows.append(grant(role,leaf))
        rules.append({'role':role,'operation':leaf['operation'],'scope':'north','state':'PENDING','allow':True})
    rows.append(grant(roles[-1],leaves[0]));rules.append({'role':roles[-1],'operation':leaves[0]['operation'],'scope':'north','state':'PENDING','allow':True})
    exceptions=[]
    for role in roles[1:3]:
        rows.append(grant(role,leaves[0]));exceptions.append({'principal':role,'role':role,'operation':leaves[0]['operation'],'scope':'north','state':'PENDING','allow':True,'from':10,'until':20,'source_ref':'approved-policy#exception'})
    bad=grant(roles[3],leaves[0]);rows.append(bad)
    rng.shuffle(rows)
    semantics={k:{'value':v,'source_ref':'exported-evaluator-spec'} for k,v in {'inheritance':'leaf_only','conflict':'deny','null_scope':'none','default':'deny','precedence':'priority'}.items()}
    config={'nodes':nodes,'rows':rows,'roles':role_map,'role_rank':rank,'semantics':semantics,'scopes':['north'],'states':['PENDING'],'time_points':[15]}
    policy={'closed_world':True,'basis_class':'requirement_doc','source_ref':'approved-policy.json','rules':rules,'exceptions':exceptions}
    key={'bad_row':bad['id'],'bad_role':bad['role'],'bad_node':bad['node'],'exceptions':[r['id'] for r in rows if r['role'] in roles[1:3] and r['node']==leaves[0]['id']]}
    return config,policy,key
