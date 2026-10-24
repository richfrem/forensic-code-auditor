# Reinforcement Learning & Game-Theoretic Simulation in Logic Auditing

## Executive Summary
This document formalizes the integration of **reinforcement learning (RL) reward shaping**, **game simulation mechanics**, and **adversarial state-space exploration** into the `code-logic-auditor` doctrine.

Traditional linters use passive pattern matching over static ASTs. In contrast, complex business logic flaws (TOCTOU races, FSM jump exploits, authorization perimeter collapse) emerge only through dynamic execution sequences. By framing the codebase as an adversarial game environment—where an agent is rewarded for discovering illegal state reachability, invariant breaches, and authorization asymmetries—we turn vulnerability discovery into an active, objective-driven search.

---

## 1. The Codebase as an Adversarial Game Environment

In game simulation (e.g., AlphaGo, MuZero, or coverage-guided RL fuzzers like Neuzz):
- **Environment**: The target system's finite state machine (FSM), database transactions, and call graph.
- **Agent Action Space**: Legal input vectors, API route invocations, MCP tool calls, parameter mutations, and concurrent operation interleavings.
- **State Space**: The combined state of DB entities, session contexts, tenant discriminators, and in-memory caches.
- **Winning Condition**: Driving the system into an **Invalid Invariant State** (e.g., negative balance, cross-tenant record leakage, unauthenticated execution of a restricted procedure).

```
+-------------------------------------------------------------------------+
|                        Game Environment (Target App)                    |
|                                                                         |
|  [Entry Points / Actions]  ---> [State Transitions] ---> [Entity State] |
|   - API Routes                   - Guards                 - Invariants  |
|   - MCP Tools                    - DB Triggers            - Tenancy     |
|   - Batch Queues                 - Isolation Scopes       - Balances    |
+-------------------------------------------------------------------------+
                                    ^
                                    | Actions (Interleavings / Payloads)
                                    |
                           [Auditor RL Agent]
                                    |
                                    v Reward Signal
+-------------------------------------------------------------------------+
|                           Scoring Engine                                |
|                                                                         |
|  +10 pts: Surface Parity Gap (Route A has guard, Route B missing)       |
|  +25 pts: Fail-Open Exception Swallow                                   |
|  +50 pts: Ambient Header / Perimeter Bypass Path                        |
|  +100 pts: Provable TOCTOU Race or Terminal State Mutate                |
|  -20 pts: False Positive / Unreachable Dead Code                        |
+-------------------------------------------------------------------------+
```

---

## 2. Reward Shaping & Scoring Matrix

To prevent the agent from getting stuck in trivial syntax warnings, the reward function $R(s, a)$ strictly rewards non-syntactic semantic divergence:

| Objective / Action | Points | Invariant Verified |
| :--- | :--- | :--- |
| **New Call-Graph Transition Discovered** | `+5` | Coverage expansion across un-audited internal procedures. |
| **Ingress Path Asymmetry** | `+15` | Identifying that an entity can be modified via an un-guarded alternate vector (e.g. MCP tool or Celery task). |
| **Fail-Open Catch Block Discovered** | `+25` | Pinpointing exception handlers returning `true`/`allow` on DB error. |
| **Un-Scoped Data Query Located** | `+30` | Finding SQL/ORM calls missing `tenant_id` or `org_code` predicates. |
| **Ambient Perimeter Reliance Identified** | `+40` | Proving that an internal procedure executes without localized capability verification. |
| **FSM Transition Guard Bypass** | `+60` | Reaching a terminal or illegal state without passing through intermediate validation. |
| **Deterministic Discriminating Reproducer** | `+100` | Generating a runnable property-based test or script proving the state breach. |
| **Trivial Syntax / Linter Noise** | `-10` | Penalizing the agent for reporting cosmetic style issues (PEP8, formatting). |
| **Unprovable / Hallucinated Exploit** | `-25` | Penalizing false positives that fail compilation or execution. |

---

## 3. Monte Carlo Tree Search (MCTS) over Call Interleavings

Concurrency bugs (TOCTOU, double-spend, distributed lock gaps) are inherently sequential games. An RL/MCTS loop explores the tree of possible execution interleavings:

1. **Selection**: Select two concurrent threads/tasks modifying the same resource balance.
2. **Expansion**: Expand interleaving points (e.g., between `GetBalance()` and `DeductBalance()`, or between `SELECT` and `UPDATE`).
3. **Simulation**: Simulate latency injection, thread preemption, or network pauses at the check-then-act gap.
4. **Backpropagation**: If the simulated interleaving results in a double-spend or duplicate permit generation, backpropagate a high positive reward to that sequence.

---

## 4. Application to `bcgov/raven` & `bcgov/crow`

This game-theoretic model directly solves our two biggest challenges:

1. **Harden Raven's Multi-MCP Gateway**:
   - *Game Objective*: Attempt to trigger a Bitbucket merge, Jira issue mutation, or Server Monitor command using an unprivileged or forged context.
   - *Reward*: Points awarded if an MCP tool executes an action without verifying local authorization claims against SiteMinder/gateway assertions.

2. **Harden Legacy Systems via Crow**:
   - *Game Objective*: Attempt to bypass Oracle Forms `WHEN-VALIDATE-RECORD` rules by invoking lower-level package procedures directly.
   - *Reward*: Points awarded if a PL/SQL package procedure modifies a table without triggering the validation logic normally enforced in the user interface.
