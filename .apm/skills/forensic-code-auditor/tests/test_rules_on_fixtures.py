"""Every bundled rule against the combined fixture corpus, with explicit hit sets."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
SEMGREP=shutil.which('semgrep') or str(Path(sys.executable).parent/'semgrep')


class RuleCorpusTests(unittest.TestCase):
    @unittest.skipUnless(Path(SEMGREP).is_file(),'Semgrep unavailable: corpus scan NOT RUN')
    def test_all_rules_against_all_fixtures(self):
        run=subprocess.run([SEMGREP,'scan','--metrics','off','--disable-version-check','--json','--no-git-ignore','--config',str(ROOT/'references/rules/semgrep'),str(ROOT/'evals/fixtures'),str(ROOT/'references/rules/semgrep')],capture_output=True,text=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stderr)
        data=json.loads(run.stdout);self.assertEqual(data['errors'],[])
        actual={}
        for result in data['results']:
            key=str(Path(result['path']).resolve().relative_to(ROOT))+'|'+result['check_id'].split('.')[-1]
            actual.setdefault(key,set()).add(result['start']['line'])
        expected=json.loads((ROOT/'tests/rule_expectations.json').read_text())
        self.assertEqual({k:sorted(v) for k,v in actual.items()},expected)
        self.assertIn('evals/fixtures/behavior/pkg_security_auth.sql|plsql-auth-function-when-others-allow',actual)
        self.assertIn('evals/fixtures/behavior/pkg_security_auth.sql|plsql-vpd-policy-empty-predicate',actual)


if __name__=='__main__':unittest.main()
