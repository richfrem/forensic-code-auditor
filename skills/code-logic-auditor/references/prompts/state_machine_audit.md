# Inspection Prompt: Finite State Machine (FSM) & Lifecycle Audit

Execute this inspection when auditing lifecycle transitions, transaction states, and workflow engines.

## 1. FSM Deconstruction
- Identify all valid states ($S = \{s_0, s_1, ... s_n\}$) and transitions ($T: S \times E \rightarrow S$).
- Extract the exact implementation mechanism: enum check, lookup table, DB constraint, or ad-hoc `if/else` checks.

## 2. Invariant Checklist
- [ ] **Transition Exclusivity**: Are state updates permitted ONLY through a centralized transition dispatcher?
- [ ] **Terminal State Locking**: Once an entity enters a terminal state (`CANCELLED`, `COMPLETED`, `REFUNDED`), is mutation blocked at the storage layer?
- [ ] **Partial Failure & Rollback**: If an intermediate step fails during a transition (e.g. network timeout to external gateway), does the state rollback atomically, or does it leave an orphaned state?
- [ ] **Compensating Transactions**: Are compensating workflows guaranteed to run, or can an unhandled error abort cleanup?

## 3. Discriminating Test Generation
Generate a test demonstrating an illegal transition:
```python
# Verify transition guard rejects out-of-order transition
def test_illegal_transition_rejection():
    entity = create_entity(status="PENDING")
    with pytest.raises(InvalidStateTransitionError):
        # Direct jump from PENDING to COMPLETED bypassing PROCESSING
        entity.complete()
```
