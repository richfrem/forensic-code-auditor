# Adversarial interleaving heuristic

This is a reasoning aid, not an implemented RL or Monte Carlo search algorithm. It carries no
numeric finding rewards and does not establish proof or justify higher confidence.

1. State the independently sourced invariant and identify the shared state or authority snapshot.
2. List meaningful preemption points after read/check, before mutation, before/after commit, and
   between a local write and an external effect.
3. Contrast competing executions: duplicate requests, revocation, failed context reset, crash/retry,
   stale leases and alternative entry points. Inspect locks, predicates, versions and compensating
   controls that could prevent the hypothesized outcome.
4. Choose a discriminating schedule. For a runtime test, hook the actual post-check/pre-write point,
   use independent client-server DB sessions, bounded waits and a fresh-connection ledger assertion.
5. Classify the result using [the execution contract](../instructions.md). Generated code remains
   TEST_GENERATED; absent runtime/policy evidence remains unresolved. A verified defense is useful
   even when no vulnerability is found. Do not suppress NON LIQUET observations to satisfy a quota.
