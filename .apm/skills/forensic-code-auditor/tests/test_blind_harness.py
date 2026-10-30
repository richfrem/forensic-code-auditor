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


class ScoringTests(unittest.TestCase):
    def score_finding(self,variant,finding):
        return score({'variant':variant,'operation':'approve','row_key':'grant-7'}, {'findings':[finding]})

    def test_legacy_attributed_credit_for_each_variant(self):
        for variant,verdict,metric in [('vulnerable','CONFIRMED','attributed_detection'),('protected','REFUTED','verified_defense'),('indeterminate','NON LIQUET','calibrated')]:
            with self.subTest(variant=variant):
                finding={'operation_id':'approve','row_keys':['grant-7'],'verdict':verdict,'policy_ref':'policy.json','defense_ref':'guard.py'}
                self.assertTrue(self.score_finding(variant,finding)[metric])

    def test_unrelated_operation_or_row_cannot_earn_credit(self):
        for variant,verdict,metric in [('vulnerable','CONFIRMED','attributed_detection'),('protected','REFUTED','verified_defense'),('indeterminate','NON LIQUET','calibrated')]:
            for operation,row in [('other','grant-7'),('approve','other')]:
                with self.subTest(variant=variant,operation=operation,row=row):
                    finding={'operation_id':operation,'row_keys':[row],'verdict':verdict,'policy_ref':'policy.json','defense_ref':'guard.py'}
                    self.assertFalse(self.score_finding(variant,finding)[metric])

    def test_v2_defense_requires_attributed_completed_proof(self):
        for verification,proof,expected in [('STATIC_PROVEN',[{'path':'guard.py','sha256':'a'*64}],True),('DYNAMIC_REPRODUCED',[{'path':'run.json','sha256':'a'*64}],True),('TEST_GENERATED',[{'path':'probe.py','sha256':'a'*64}],False),('NOT_VERIFIED',[],False),('STATIC_PROVEN',[],False)]:
            with self.subTest(verification=verification,proof=proof):
                finding={'operation_id':'approve','contributing_rows':[{'row_key':'grant-7'}],'evidence_status':'REFUTED','verification':verification,'proof':proof}
                self.assertEqual(self.score_finding('protected',finding)['verified_defense'],expected)
                finding['operation_id']='other'
                self.assertFalse(self.score_finding('protected',finding)['verified_defense'])

    def test_actionable_findings_remain_false_positives_and_uncalibrated(self):
        report={'findings':[{'operation_id':'approve','row_keys':['grant-7'],'verdict':'NON LIQUET'}, {'operation_id':'other','row_keys':['other'],'verdict':'SUSPECTED'}]}
        answer={'operation':'approve','row_key':'grant-7'}
        self.assertTrue(score(dict(answer,variant='protected'),report)['false_positive'])
        self.assertFalse(score(dict(answer,variant='indeterminate'),report)['calibrated'])

    def test_unknown_variant_is_not_treated_as_missing_policy(self):
        with self.assertRaisesRegex(ValueError,'unknown variant'):
            self.score_finding('typo',{})


if __name__=='__main__':unittest.main()
