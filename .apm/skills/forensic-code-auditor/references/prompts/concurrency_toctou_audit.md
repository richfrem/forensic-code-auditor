# Inspection Prompt: Concurrency & TOCTOU (Time-of-Check to Time-of-Use) Audit

> [!IMPORTANT]
> **Governing Doctrine**: All inspections are governed by `instructions.md` (First-Principles Epistemology, Invariant Sourcing, and Four Evidence Levels). The criteria below are investigative prompts, NOT rigid checklist constraints. Accept verified alternative enforcement mechanisms (e.g. database-level optimistic versioning, atomic conditional updates `UPDATE ... WHERE balance >= :amt`, or deterministic serializable transactions).

Execute this inspection when auditing shared resources, balance updates, token redemptions, inventory decrementing, or critical sections.

## 1. Concurrency Model Extraction & Invariant Sourcing
- Identify the explicit consistency and isolation invariant required by the domain (e.g. "Balance must never drop below 0", "A coupon may only be redeemed once").
- Identify shared mutable state: database rows, in-memory caches, global variables, distributed queues.
- Map the execution concurrency model: multi-threaded, single-threaded event loop (Node.js/asyncio), multi-process workers (Gunicorn/Celery), or distributed microservices.

## 2. Invariant Checklist
- [ ] **Check-Then-Act Gaps**: Is there any non-atomic gap between checking a precondition (e.g. `balance >= cost`, `item.is_available()`) and applying the state mutation?
- [ ] **Locking & Atomic Updates**:
  - Does the system use atomic conditional expressions (`UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt`)?
  - If read-then-write is necessary, is pessimistic row locking (`SELECT ... FOR UPDATE`) held for the full duration of the transaction?
  - Are optimistic concurrency tokens (`version_id`, `ETag`) verified on write?
- [ ] **Distributed Coordination**: If distributed locks are employed, do they include fencing tokens to protect against lock expiration during GC pauses or network delays?
- [ ] **Transaction Demarcation**: Are all dependent mutations enclosed in a transaction with an appropriate isolation level (`REPEATABLE READ` or `SERIALIZABLE`) to prevent non-repeatable reads and lost updates?

## 3. Discriminating Race Simulation (Isolated DB Connections & Barrier)

To prove a real database-level TOCTOU or lost-update race condition across transactions, threads must NOT share an in-memory ORM instance or single test transaction. Use `TransactionTestCase` and explicitly cycle or isolate database connections per worker thread:

> [!WARNING]
> **Database Engine Warning**: SQLite uses database-level locks and serializes all write operations, artificially masking race windows and producing false `REFUTED` outcomes. Dynamic concurrency tests and barriers MUST run against client-server database engines with multi-connection concurrency (e.g. PostgreSQL, Oracle, MySQL).

A barrier before calling the service merely synchronizes starts. Inject a test-only hook after the
relevant read/check and before mutation; use two independent DB sessions and bounded events/barriers:

1. Session A reads allowed/balance; signal `checked`, then wait (bounded) at the mutation hook.
2. Session B revokes authority or performs the competing debit; COMMIT; signal `changed`.
3. Release A, observe commit/rejection, query ledger and durable state from a fresh session.
4. Assert the sourced invariant and all queued/external mock effects, with timeouts and error capture.

Distinguish acceptance-time authorization from execution-time authorization using independent policy.
A permitted in-flight request after revocation may be intended. Examine locks, optimistic versions,
atomic predicates, unique constraints, retry behavior and fencing under the exact DB isolation model.
Do not recommend REPEATABLE READ or SERIALIZABLE without checking engine-specific semantics.

Source-only specialist model tests (`tests/test_specialists.py` in the skill source checkout;
omitted from runtime packages) force revocation after the check using Events.
They verify the interleaving protocol and local model only. Real DB concurrency tests require separate
sessions on a provisioned disposable client-server DB; unavailable runtime is `NOT_VERIFIED`.
