"""Single failure blast radius, scoped guard, exceptions and unavailable policy."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from control_dependency import analyze


class ControlTests(unittest.TestCase):
    def setUp(self):self.graph=json.loads((Path(__file__).parents[1]/'templates/control-graph.json').read_text())
    def test_scoped_backend_guard_and_broad_authority(self):
        self.assertEqual(analyze(self.graph),[])
        self.graph['edges'][-1]['requires']=[]
        self.graph['policy']={'basis_class':'requirement_doc','source_ref':'approved-policy','allowed_nodes':[]}
        cases=analyze(self.graph)
        self.assertEqual(len(cases),1);self.assertEqual(cases[0]['assessment'],'MODEL_POLICY_DISCREPANCY')
        self.graph['policy']['allowed_nodes']=['approve'];self.assertEqual(analyze(self.graph)[0]['assessment'],'MODELED_ALLOWED')
        self.graph['policy']=None;self.assertEqual(analyze(self.graph)[0]['assessment'],'NON LIQUET')
    def test_dangling_edges_fail(self):
        self.graph['edges'][0]['to']='missing'
        with self.assertRaises(ValueError):analyze(self.graph)


if __name__=='__main__':unittest.main()
