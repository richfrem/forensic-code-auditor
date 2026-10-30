"""Known caller accounting and unsupported/dynamic surfaces remain visible."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from build_operation_graph import build


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'claims.sql').write_text('CREATE OR REPLACE PACKAGE BODY pkg_claim AS\nPROCEDURE approve IS\nBEGIN\n UPDATE claim SET status=1;\nEND approve;\nEND pkg_claim;\n/\n')
        (self.root/'form.xml').write_text('<Trigger Name="WHEN-BUTTON-PRESSED">pkg_claim.approve(:GLOBAL.USER_ID);</Trigger>')
        (self.root/'Route.java').write_text('@POST\nvoid submit() { pool.prepareCall("{call pkg_claim.approve(?)}"); }')

    def test_forms_rest_and_backend_guard(self):
        graph=build(self.root,exports={'connections':{'Route.java':'gateway-svc'}})
        op=next(o for o in graph['operations'] if o['id']=='pkg_claim.approve')
        self.assertEqual(op['authz_check'],'none')
        self.assertEqual({e['kind'] for e in graph['edges'] if e['to']==op['id']},{'forms_call','jdbc_call'})
        self.assertEqual(next(e for e in graph['edges'] if e['kind']=='jdbc_call')['connection_identity'],'gateway-svc')
        p=self.root/'claims.sql';p.write_text(p.read_text().replace(' UPDATE',' pkg_sec.assert_operation(SYS_CONTEXT(\'APP_CTX\',\'USER_ID\'));\n UPDATE'))
        guarded=build(self.root,exports={'authorization_functions':['pkg_sec.assert_operation']})
        self.assertEqual(next(o for o in guarded['operations'] if o['id']==op['id'])['authz_check'],'present')
        self.assertTrue(guarded['limitations'])  # A syntactic check is not verified business authority.

    def test_dynamic_sql_synonym_binary_and_omitted_candidate(self):
        (self.root/'dynamic.sql').write_text("CREATE SYNONYM target FOR remote@other;\nEXECUTE IMMEDIATE v_sql;\n")
        (self.root/'hidden.fmb').write_bytes(b'opaque')
        graph=build(self.root)
        self.assertTrue(any(e['status']=='unresolved' for e in graph['edges']))
        self.assertTrue(any('binary' in x for x in graph['limitations']))
        self.assertEqual(len(graph['operations']),1)

    def test_python_ast_failure_and_external_symlink(self):
        (self.root/'view.py').write_text('def handler():\n    account.save()\n')
        graph=build(self.root)
        self.assertTrue(any(o['id'].endswith('handler') for o in graph['operations']))
        (self.root/'broken.py').write_text('def broken(')
        (self.root/'escaped.sql').symlink_to('/etc/hosts')
        graph=build(self.root)
        self.assertTrue(any('parse' in x for x in graph['limitations']))
        self.assertTrue(any('symlink' in x for x in graph['limitations']))

    def test_operation_graph_discovers_copilot_setup_and_ci_workflows(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            wf=root/'.github/workflows/copilot-setup-steps.yml'
            wf.parent.mkdir(parents=True)
            wf.write_text('on: pull_request_target\njobs:\n  setup:\n    steps:\n      - run: echo INERT_SETUP_MARKER\n')
            instr=root/'.github/copilot-instructions.md'
            instr.write_text('<!-- INERT_INSTRUCTION_MARKER -->\n')
            mcp=root/'.vscode/mcp.json'
            mcp.parent.mkdir(parents=True)
            mcp.write_text('{"servers": {"inert-mock-mcp": {"command": "echo"}}}\n')
            img=root/'diagram.jpg'
            img.write_bytes(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00INERT_BINARY')
            graph=build(root)
            paths={f['path'] for f in graph['files']}
            self.assertEqual(paths,{'.github/workflows/copilot-setup-steps.yml','.github/copilot-instructions.md','.vscode/mcp.json','diagram.jpg'})
            self.assertIn('.github/workflows/copilot-setup-steps.yml',graph['categories']['batch_job'])
            self.assertIn('.github/workflows/copilot-setup-steps.yml',graph['categories']['mcp_tool'])
            self.assertIn('.github/copilot-instructions.md',graph['categories']['mcp_tool'])
            self.assertIn('.vscode/mcp.json',graph['categories']['mcp_tool'])
            self.assertEqual(graph['file_status']['.github/workflows/copilot-setup-steps.yml'],'manual_required')
            self.assertEqual(graph['file_status']['diagram.jpg'],'binary_carrier')
            self.assertTrue(any('CI workflow' in x for x in graph['limitations']))
            self.assertTrue(any('agent instruction' in x for x in graph['limitations']))
            self.assertTrue(any('binary/media carrier' in x for x in graph['limitations']))
            reconciled=build(root,exports={'reconciled_files':['.github/copilot-instructions.md','.vscode/mcp.json','diagram.jpg']},manual_operations=[{'id':'ci:copilot_setup','path':'.github/workflows/copilot-setup-steps.yml','class':'lifecycle','category':'batch_job'}])
            self.assertEqual([o['id'] for o in reconciled['operations']],['ci:copilot_setup'])
            self.assertEqual(reconciled['limitations'],[])
            self.assertTrue(all(v=='extracted' for v in reconciled['file_status'].values()))


if __name__=='__main__':unittest.main()
