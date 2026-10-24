# Inspection Prompt: Concurrency & TOCTOU (Time-of-Check to Time-of-Use) Audit

Execute this inspection when auditing shared resources, balance updates, token redemptions, inventory decrementing, or critical sections.

## 1. Concurrency Model Extraction
- Identify shared mutable state: database rows, in-memory caches, global variables, file system handles.
- Identify the concurrency model: multi-threaded, event loop (Node/asyncio), multi-process workers (Gunicorn/Uvicorn), or distributed nodes.

## 2. Invariant Checklist
- [ ] **Check-Then-Act Gaps**: Is there any non-atomic gap between checking a condition (e.g., `balance >= cost`, `item.is_available()`) and executing the mutation?
- [ ] **Locking Mechanisms**:
  - Is pessimistic row locking (`SELECT ... FOR UPDATE`) used for database transactions?
  - Are optimistic concurrency tokens (`version_id`, `ETag`) validated in update queries (`WHERE id = :id AND version = :version`)?
- [ ] **Distributed Locks**: If Redis or distributed locks are used, is there a fencing token to prevent split-brain execution when a lock expires prematurely?
- [ ] **Atomicity Boundaries**: Are all dependent mutations enclosed in a single transactional unit with appropriate isolation levels (e.g. `SERIALIZABLE` or `REPEATABLE READ`)?

## 3. Discriminating Race Simulation
```python
import concurrent.futures

def test_concurrent_debit_prevents_double_spend():
    initial_balance = 100
    debit_amount = 100
    account = create_account(balance=initial_balance)
    
    # Fire 5 simultaneous debits of full balance
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(account.debit, debit_amount) for _ in range(5)]
        results = [f.result() for f in futures]
    
    successes = sum(1 for r in results if r.is_success)
    assert successes == 1, f"Double-spend detected! Successful debits: {successes}"
    assert account.refresh().balance == 0
```
