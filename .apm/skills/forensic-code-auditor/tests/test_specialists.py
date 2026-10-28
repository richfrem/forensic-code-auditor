"""Vulnerable/protected local models. Not validation of target DB or gateway semantics."""
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

CASES = json.loads((Path(__file__).parent / 'fixtures/specialist-cases.json').read_text())


class SpecialistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'synthetic.sqlite'
        with sqlite3.connect(self.path) as db:
            db.executescript("CREATE TABLE state(value); INSERT INTO state VALUES('PENDING'); CREATE TABLE effects(tenant, action);")

    def effects(self):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT tenant, action FROM effects').fetchall()

    def emit(self, tenant, action):
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO effects VALUES(?,?)', (tenant, action))

    def test_05_trust_chain_configuration_and_compensating_control(self):
        def concern(c):
            return (c['credential_policy'] == 'shared-no-rotation'
                    and 'approve:any-scope' in c['backend_operations'] and not c['backend_guard'])
        bad, good = CASES['trust_vulnerable'], CASES['trust_protected']
        self.assertTrue(bad['firewall'] and bad['gateway_tls'])
        self.assertTrue(concern(bad)); self.assertFalse(concern(good))
        self.assertTrue(bad['source'])
        self.assertEqual(self.effects(), [])  # Configuration inspection produces no operation effects.

    def test_revocation_forced_after_check_before_mutation(self):
        for recheck, expected in ((False, [('north', 'approve')]), (True, [])):
            with sqlite3.connect(self.path) as db: db.execute('DELETE FROM effects')
            checked, changed = threading.Event(), threading.Event()
            policy = {'allowed': True}; errors = []
            def worker():
                try:
                    accepted = policy['allowed']
                    checked.set()
                    if not changed.wait(2): raise TimeoutError('revocation did not commit')
                    if accepted and (not recheck or policy['allowed']): self.emit('north', 'approve')
                except Exception as exc: errors.append(exc)
            thread = threading.Thread(target=worker, daemon=True); thread.start()
            self.assertTrue(checked.wait(2))
            policy['allowed'] = False; changed.set()
            thread.join(2); self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
            self.assertEqual(self.effects(), expected)
        # This models policy timing; separate-session Oracle/PG races remain NOT VERIFIED.

    def test_fsm_edge_and_authority_are_separate(self):
        def transition(role, target, enforce_authority):
            with sqlite3.connect(self.path) as db:
                before = db.execute('SELECT value FROM state').fetchone()[0]
                if (before, target) != ('PENDING', 'APPROVED'): return False
                if enforce_authority and role != 'approver': return False
                db.execute('UPDATE state SET value=?', (target,))
                db.execute("INSERT INTO effects VALUES('north','approve')")
            return True
        self.assertFalse(transition('clerk', 'APPROVED', True)); self.assertEqual(self.effects(), [])
        self.assertTrue(transition('clerk', 'APPROVED', False))
        self.assertFalse(transition('approver', 'PENDING', True))  # terminal/illegal edge
        self.assertEqual(self.effects(), [('north', 'approve')])

    def test_tenant_session_reuse_bleed_and_reset(self):
        for reset, expected in ((False, [('A', 'write'), ('A', 'write')]), (True, [('A', 'write')])):
            with sqlite3.connect(self.path) as db: db.execute('DELETE FROM effects')
            pooled = {'tenant': None}
            for tenant in ('A', None):
                if reset: pooled['tenant'] = None
                if tenant is not None: pooled['tenant'] = tenant
                if pooled['tenant'] is not None: self.emit(pooled['tenant'], 'write')
            self.assertEqual(self.effects(), expected)
        # Model exercises missing checkout context; no Oracle/PG session setter is executed.

    def test_webhook_crash_external_effect_replay(self):
        for receiver_dedupes, count in ((False, 2), (True, 1)):
            with sqlite3.connect(self.path) as db: db.execute('DELETE FROM effects')
            committed = set(); receiver = set(); key = ('caller', 'credit', 'fingerprint')
            def deliver(crash=False):
                if key in committed: return
                if not receiver_dedupes or key not in receiver:
                    self.emit('north', 'external-credit'); receiver.add(key)
                if crash: return  # External effect survives local crash/rollback.
                committed.add(key)
            deliver(crash=True); deliver(); deliver()
            self.assertEqual(len(self.effects()), count)

    def test_tool_approval_action_resource_state_expiry_replay(self):
        approval = dict(principal='clerk', action='approve', resource=1, state='PENDING', expires=20, nonce='one')
        used = set()
        def invoke(request, now, guarded=True):
            bound = all(request[k] == approval[k] for k in ('principal','action','resource','state'))
            if guarded and (not bound or now >= approval['expires'] or approval['nonce'] in used): return False
            used.add(approval['nonce']); self.emit('north', f"approve:{request['resource']}"); return True
        self.assertFalse(invoke(dict(approval, resource=2), 15)); self.assertEqual(self.effects(), [])
        self.assertFalse(invoke(approval, 20)); self.assertTrue(invoke(approval, 15))
        self.assertFalse(invoke(approval, 15)); self.assertEqual(self.effects(), [('north', 'approve:1')])
        self.assertTrue(invoke(dict(approval, resource=2), 15, guarded=False))
        self.assertEqual(self.effects(), [('north', 'approve:1'), ('north', 'approve:2')])


if __name__ == '__main__': unittest.main()
