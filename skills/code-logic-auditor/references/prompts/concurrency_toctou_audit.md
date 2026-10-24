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

## 3. Discriminating Race Simulation (Synchronized Barrier)
```python
import threading

def test_concurrent_debit_prevents_double_spend():
    initial_balance = 100
    debit_amount = 100
    account = create_account(balance=initial_balance)
    
    num_threads = 5
    barrier = threading.Barrier(num_threads)
    results = []

    def attempt_debit():
        # Synchronize thread execution at the exact check-then-act window
        barrier.wait()
        res = account.debit(debit_amount)
        results.append(res)

    threads = [threading.Thread(target=attempt_debit) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for r in results if r.is_success)
    assert successes == 1, f"Double-spend detected! Successful debits: {successes}"
    assert account.refresh().balance == 0
```
