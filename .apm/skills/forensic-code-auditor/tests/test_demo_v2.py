"""End-to-end artifacts and actual local run record, including missing policy."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from demo_authorization import demo
from validate_report import validate


class DemoTests(unittest.TestCase):
    def test_generated_report_and_policy_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            report=demo(root/'with-policy')
            self.assertEqual(validate(report,evidence_root=root/'with-policy'),[])
            self.assertEqual(report['findings'][0]['verification'],'DYNAMIC_REPRODUCED')
            missing=demo(root/'no-policy',without_policy=True)
            self.assertEqual(missing['findings'][0]['evidence_status'],'NON LIQUET')
            self.assertNotIn('run_record',missing['findings'][0])


if __name__=='__main__':unittest.main()
