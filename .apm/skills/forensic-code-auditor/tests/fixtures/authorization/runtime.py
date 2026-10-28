"""Synthetic correct evaluators; intentionally bad row lives in configuration.json.

SQLite here asserts sequential committed effects only, never Oracle locking behavior.
No connection strings, network access or external DB credentials are accepted.
"""
import json
import sqlite3
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    return json.loads((HERE / name).read_text())


def effective(rows, *, level, role, resource, operation, scope, at):
    """Apply this fixture's explicit precedence; never universalize it to targets."""
    matches = [r for r in rows if r['level'] == level and r['role'] in (role, '*')
               and r['resource'] in (resource, '*') and r['operation'] in (operation, '*')
               and r['scope'] in (scope, '*') and r['from'] <= at < r['until']]
    if not matches:
        return False, []
    priority = max(r['priority'] for r in matches)
    winners = [r for r in matches if r['priority'] == priority]
    return all(r['allow'] for r in winners), [r['id'] for r in winners]


def intended(policy, principal, role, operation, scope, state, at):
    """Unknown remains unknown when independent evidence is absent or incomplete."""
    if not policy or not policy['independent']:
        return None, None
    for exception in policy['exceptions']:
        if (exception['principal'], exception['operation'], exception['scope'], exception['state']) == (principal, operation, scope, state) and exception['from'] <= at < exception['until']:
            return exception['allow'], exception['source']
    for rule in policy['rules']:
        if (rule['role'], rule['operation'], rule['scope'], rule['state']) == (role, operation, scope, state):
            return rule['allow'], policy['source']
    return None, None


class Runtime:
    """File-backed isolated DB with a committed operation and effect ledger."""
    def __init__(self, path, rows):
        self.path, self.rows = path, rows
        with sqlite3.connect(path) as db:
            db.executescript("CREATE TABLE claims(id PRIMARY KEY, status); INSERT INTO claims VALUES(1,'PENDING'); CREATE TABLE effects(action);")

    def approve(self, entry, role, *, boundary_check=False, delegated=False):
        l1, _ = effective(self.rows, level=1, role=role, resource='Claims', operation='navigate', scope='north', at=15)
        l2, _ = effective(self.rows, level=2, role=role, resource='APPROVAL_FORM', operation='approve', scope='north', at=15)
        if entry == 'Forms' and not (l1 and l2):
            return False
        if boundary_check and not delegated and role != 'approver':
            return False
        with sqlite3.connect(self.path) as db:
            count = db.execute("UPDATE claims SET status='APPROVED' WHERE id=1 AND status='PENDING'").rowcount
            if count:
                db.execute("INSERT INTO effects VALUES('approved')")
        return count == 1

    def durable(self):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT status FROM claims').fetchone()[0], db.execute('SELECT count(*) FROM effects').fetchone()[0]
