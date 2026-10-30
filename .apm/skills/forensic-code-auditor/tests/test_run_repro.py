"""Execution records must bind reviewed code, actual output and durable observations."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from evidence import resolve, reference
from run_repro import run, validate_record


class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'probe.py').write_text('import json\nfrom pathlib import Path\np=Path("state.txt");p.write_text("APPROVED")\nprint(json.dumps({"claim":"violation","assertions":[{"kind":"durable_state","name":"status","actual":p.read_text(),"expected":"APPROVED","passed":True}]}))\n')

    def test_actual_run_then_output_and_record_tamper(self):
        ref=run([sys.executable,'probe.py'],root=self.root,environment='isolated-local-synthetic',runtime='isolated-local-postgres-model')
        path=resolve(ref,self.root);record=json.loads(path.read_text())
        self.assertEqual(validate_record(record,self.root),[])
        stdout=self.root/record['stdout_ref']['path'];stdout.write_text('changed')
        self.assertTrue(validate_record(record,self.root))
        path.write_text('{}')
        with self.assertRaises(ValueError):resolve(ref,self.root)

    def test_unsafe_commands_and_opt_in(self):
        for cmd,environment in [([sys.executable,'probe.py'],'production'),([sys.executable,'probe.py','https://example.test'],'isolated-local-synthetic'),([sys.executable,'-c','print(1)'],'isolated-local-synthetic')]:
            with self.assertRaises(ValueError):run(cmd,root=self.root,environment=environment)

    def test_documented_python3_command_resolves_from_path(self):
        executable=shutil.which('python3')
        self.assertIsNotNone(executable)
        ref=run(['python3','probe.py'],root=self.root,environment='isolated-local-synthetic')
        record=json.loads(resolve(ref,self.root).read_text())
        self.assertEqual(record['command'][0],str(Path(executable).resolve()))
        self.assertEqual(validate_record(record,self.root),[])

    def test_relative_interpreter_is_resolved_under_evidence_root(self):
        (self.root/'python3').symlink_to(sys.executable)
        ref=run(['./python3','probe.py'],root=self.root,environment='isolated-local-synthetic')
        record=json.loads(resolve(ref,self.root).read_text())
        self.assertEqual(record['command'][0],str(Path(sys.executable).resolve()))
        self.assertEqual(validate_record(record,self.root),[])

    def test_missing_interpreter_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError,'interpreter not found'):
            run(['nonexistent-forensic-python','probe.py'],root=self.root,environment='isolated-local-synthetic')

    def test_noop_execution_not_dynamic_evidence(self):
        (self.root/'noop.py').write_text('print("ok")')
        ref=run([sys.executable,'noop.py'],root=self.root,environment='isolated-local-synthetic')
        self.assertTrue(validate_record(json.loads(resolve(ref,self.root).read_text()),self.root))

    def test_run_repro_scrubs_ambient_ci_secrets(self):
        from unittest.mock import patch
        (self.root/'env_probe.py').write_text('import json,os\nleaked=bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") or os.environ.get("OPENAI_API_KEY"))\nprint(json.dumps({"claim":"defense","assertions":[{"kind":"durable_state","name":"env_scrubbed","actual":leaked,"expected":False,"passed":not leaked}]}))\n')
        with patch.dict('os.environ',{'GITHUB_TOKEN':'INERT_CANARY_GH_TOKEN_000','ACTIONS_ID_TOKEN_REQUEST_TOKEN':'INERT_CANARY_OIDC_000','OPENAI_API_KEY':'INERT_CANARY_KEY_000'}):
            ref=run([sys.executable,'env_probe.py'],root=self.root,environment='isolated-local-synthetic')
        record=json.loads(resolve(ref,self.root).read_text())
        self.assertEqual(validate_record(record,self.root),[])
        self.assertFalse(record['observed']['assertions'][0]['actual'])

    def test_script_mutation_during_run_is_flagged_and_snapshot_retained(self):
        script=self.root/'mutating.py'
        original='import json\nfrom pathlib import Path\nPath(__file__).write_text("# mutated post-start\\n")\nprint(json.dumps({"claim":"violation","assertions":[{"kind":"durable_state","name":"state","actual":1,"expected":1,"passed":True}]}))\n'
        script.write_text(original)
        ref=run([sys.executable,'mutating.py'],root=self.root,environment='isolated-local-synthetic')
        record=json.loads(resolve(ref,self.root).read_text())
        self.assertTrue(record['script_mutated'])
        snapshot=resolve(record['executed_script_ref'],self.root)
        self.assertEqual(snapshot.read_text(),original)
        errors=validate_record(record,self.root)
        self.assertTrue(any('mutated' in e or 'hash mismatch' in e for e in errors))


if __name__=='__main__':unittest.main()
