"""Configured semantics, unknown policy and mutation-resistant discovery."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from authz_effective import analyze
from gen_authz import generate


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.config,self.policy,self.key=generate(1)

    def test_opaque_wrong_row_exceptions_missing_policy_and_move(self):
        result=analyze(self.config,self.policy)
        self.assertIn(self.key['bad_row'],{r for d in result['diff'] for r in d['contributing_rows']})
        self.assertFalse(set(self.key['exceptions']) & {r for d in result['diff'] for r in d['contributing_rows']})
        unknown=analyze(self.config,None)
        self.assertEqual(unknown['diff'],[])
        self.assertIn(self.key['bad_row'],{r for q in unknown['owner_questions'][:5] for r in q['contributing_rows']})
        changed=copy.deepcopy(self.config)
        row=next(r for r in changed['rows'] if r['id']==self.key['bad_row']);row['id']='relocated-opaque';row['role']=next(r for r in changed['roles'] if r not in (self.key['bad_role'],*list(self.config['roles'])[1:3],list(self.config['roles'])[-1]))
        self.assertIn('relocated-opaque',{r for d in analyze(changed,self.policy)['diff'] for r in d['contributing_rows']})

    def simple(self):
        c=copy.deepcopy(self.config);leaf=next(n for n in c['nodes'] if n['id']==self.key['bad_node']);role=self.key['bad_role']
        c['roles']={role:[]};c['nodes']=[{'id':'root','parent':None},{'id':'leaf','parent':'root','operation':'approve','operation_class':'lifecycle'}]
        c['rows']=[{'id':'R','role':role,'node':'root','operation':'approve','scope':None,'allow':True,'priority':1,'from':0,'until':20}]
        return c

    def test_null_inheritance_date_and_default(self):
        c=self.simple()
        for inheritance,expected in [('leaf_only',False),('nearest',True),('union',True)]:
            c['semantics']['inheritance']['value']=inheritance;c['semantics']['null_scope']['value']='all'
            self.assertEqual(analyze(c)['matrix'][0]['configured'],expected)
        c['semantics']['null_scope']['value']='none';self.assertFalse(analyze(c)['matrix'][0]['configured'])
        c['semantics']['null_scope']['value']='all';c['time_points']=[20];self.assertFalse(analyze(c)['matrix'][0]['configured'])
        c['semantics']['default']['value']='allow';self.assertTrue(analyze(c)['matrix'][0]['configured'])

    def test_conflicts_precedence_role_inheritance_and_assumptions(self):
        c=self.simple();role=next(iter(c['roles']));c['roles'][role]=['parent'];c['roles']['parent']=[]
        c['rows'][0].update(role='parent',scope='north');c['semantics']['inheritance']['value']='union'
        c['rows'].append(dict(c['rows'][0],id='D',allow=False))
        for conflict,expected in [('deny',False),('allow',True),('unknown',None)]:
            c['semantics']['conflict']['value']=conflict
            self.assertEqual(next(r for r in analyze(c)['matrix'] if r['role']==role)['configured'],expected)
        c['rows'][0]['priority']=2;self.assertTrue(next(r for r in analyze(c)['matrix'] if r['role']==role)['configured'])
        c['semantics']['default']['source_ref']='ASSUMED';self.assertIn('default',analyze(c)['coverage']['semantics_assumed'])

    def test_open_closed_world_exception_expiry_and_bad_graph(self):
        p=copy.deepcopy(self.policy);p['closed_world']=False
        self.assertEqual(analyze(self.config,p)['diff'],[])
        c=copy.deepcopy(self.config);c['time_points']=[20]
        self.assertGreater(len(analyze(c,self.policy)['diff']),len(analyze(self.config,self.policy)['diff']))
        c['nodes'][0]['parent']=c['nodes'][-1]['id']
        with self.assertRaises(ValueError):analyze(c)
        c=self.simple();c['semantics']['inheritance']['value']='unknown-engine'
        with self.assertRaises(ValueError):analyze(c)

    def test_seeded_detection_rates(self):
        detected=exceptions=ranked=0
        for seed in range(200):
            c,p,key=generate(seed)
            observed=analyze(c,p)
            ids={r for d in observed['diff'] for r in d['contributing_rows']}
            detected+=key['bad_row'] in ids;exceptions+=bool(set(key['exceptions'])&ids)
            unknown=analyze(c,None)
            ranked+=key['bad_row'] in {r for q in unknown['owner_questions'][:5] for r in q['contributing_rows']}
        print(f'GENERATOR seeds=200 with-policy detection={detected}/200 exception_false_positives={exceptions}/200 without-policy top5={ranked}/200')
        self.assertEqual(detected,200);self.assertEqual(exceptions,0);self.assertGreaterEqual(ranked,180)


if __name__=='__main__':unittest.main()
