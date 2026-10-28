"""Dry-run visibility manifests and scorer/contamination controls; no model invoked."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from contamination_lint import check
from run_blind_eval import prepare,plan
from score_blind_eval import score
from generate_blind_suite import generate


class BlindTests(unittest.TestCase):
    def test_targets_keys_dry_run_and_baseline_command_agnostic(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            self.assertTrue(check(root/'missing'))
            self.assertTrue(check(root))
            for variant in ('vulnerable','protected','indeterminate'):
                target,key=prepare(891,root,variant)
                self.assertEqual(set(p.name for p in target.iterdir()),{'configuration.json','authorization.py','package.sql','form.xml','Route.java'} if variant=='indeterminate' else {'configuration.json','policy.json','authorization.py','package.sql','form.xml','Route.java'})
                self.assertNotIn('bad_row',(target/'configuration.json').read_text())
                for skill in ('baseline-skill','revised-skill'):
                    argv=plan(['agent','{skill}','{target}'],root/skill,target)
                    self.assertEqual(Path(argv[-1]),target.resolve());self.assertNotIn(variant,target.name);self.assertIn(skill,argv[1])
                if variant=='vulnerable':self.assertFalse(score(key,{'findings':[]})['attributed_detection'])
            package=root/'package';package.mkdir();(package/'guide.md').write_text('generic worked procedure')
            self.assertEqual(check(package,root/'keys'),[])
            (package/'guide.md').write_text(key['row_key'])
            self.assertTrue(check(package,root/'keys'))

    def test_private_seed_suite_layout_and_no_model_runs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'private'
            summary=generate(root,1,1)
            self.assertEqual(summary['targets'],6);self.assertEqual(summary['model_runs'],0)
            self.assertTrue((root/'seeds/dev.txt').is_file());self.assertTrue((root/'seeds/sealed.txt').is_file())
            self.assertEqual(len(list((root/'keys').glob('*.json'))),6)

    def test_cli_dry_run_does_not_execute_command(self):
        with tempfile.TemporaryDirectory() as folder:
            command=[sys.executable,str(Path(__file__).parent/'run_blind_eval.py'),'--seed','13','--variant','vulnerable','--output',folder,'--skill-source',str(Path(__file__).parents[1]),'--command-json',json.dumps(['nonexistent-model-command','{target}','{skill}'])]
            run=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertTrue(json.loads(run.stdout)['dry_run'])


if __name__=='__main__':unittest.main()
