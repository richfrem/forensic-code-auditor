# System Architecture: CROW / RAVEN Analysis (`code-logic-auditor`)

## Contents
- [Executive Architectural Overview](#executive-architectural-overview)
- [The Tripartite Modernization Topology](#the-tripartite-modernization-topology)
- [Repository Layout & Component Isolation](#repository-layout--component-isolation)
- [The Forensic Analytical Engine](#the-forensic-analytical-engine)
- [The 13-Domain Logic Invariants Taxonomy](#the-13-domain-logic-invariants-taxonomy)
- [Empirical Static Verification Architecture](#empirical-static-verification-architecture)
- [Adversarial Game Simulation & MCTS Concurrency](#adversarial-game-simulation--mcts-concurrency)
- [APM Package Distribution Architecture](#apm-package-distribution-architecture)

---

## Executive Architectural Overview

`crow-raven-analysis` houses the **`code-logic-auditor`** skill—a first-principles forensic analysis package engineered to identify architectural vulnerabilities, broken state invariants, check-then-act (TOCTOU) race windows, and authorization perimeter collapse across enterprise legacy and modern cloud software.

Unlike conventional syntactic SAST suites (e.g. SonarQube, Fortify, ESLint) that scan for syntax hygiene or known CVE signatures, `code-logic-auditor` treats software systems as **deterministic state machines governed by hard physical, resource, temporal, and cryptographic boundaries**.

---

## The Tripartite Modernization Topology

```
+-----------------------------------------------------------------------------------------+
|                               Enterprise Modernization Stack                            |
+-----------------------------------------------------------------------------------------+
|  [ RAVEN ] : Enterprise Execution & Autonomous DevOps Pipeline                          |
|  - Multi-MCP server gateway (Bitbucket, Jira, Sonar, Server Monitor, Jenkins).         |
|  - Autonomous AI pipeline detecting production errors, triaging, and generating PRs.    |
+-----------------------------------------------------------------------------------------+
|  [ CROW ] : Agent & Capability Ecosystem (APM Distribution)                             |
|  - APM-distributed collections for brownfield architecture, legacy modernization,       |
|    and security remediation across Java EE, .NET, PHP, and CI/CD pipelines.            |
+-----------------------------------------------------------------------------------------+
|  [ code-logic-auditor ] : The Forensic Invariant Engine (This Package)                  |
|  - Standalone, empirically validated skill operating across Raven and Crow.             |
|  - Powers deep AST analysis, FSM edge checks, and data-driven authorization audits.     |
+-----------------------------------------------------------------------------------------+
```

---

## Repository Layout & Component Isolation

```text
crow-raven-analysis/
├── AGENTS.md                                  # Canonical agent instructions & invariant bounds
├── CLAUDE.md                                  # Minimal bridge to AGENTS.md
├── ARCHITECTURE.md                            # Complete architectural spec (this document)
├── INSTALL.md                                 # APM installation, registry, update & rollback guide
├── apm.yml                                    # APM package manifest
├── README.md                                  # Repository overview and quick start
├── .apm/
│   └── skills/code-logic-auditor/             # APM skill distribution link
├── skills/                                    # Root skills directory
│   └── code-logic-auditor/                    # Canonical skill source tree
│       ├── SKILL.md                           # Authoring-standard router (<= 80 lines)
│       ├── instructions.md                    # Full 7-step procedure, evidence levels & schemas
│       ├── code-logic-auditor-flow.mmd        # State machine execution diagram
│       ├── agents/                            # Agent persona definitions
│       │   └── forensic_systems_analyst.md    # Generalized first-principles directive
│       ├── references/
│       │   ├── logic_invariants_taxonomy.md   # 13 non-syntactic invariant domains
│       │   ├── game_simulation_rl_auditing.md # MCTS & RL reward matrix
│       │   ├── semgrep_logic_rules.md         # Tested Semgrep AST patterns catalog
│       │   ├── codeql_taint_recipes.md        # Modern CodeQL taint recipes guide
│       │   ├── rules/
│       │   │   ├── semgrep/                   # 9 tested YAML files (13 rule IDs) with paired test code
│       │   │   └── codeql/                    # 2 compilable CodeQL packs (python, javascript)
│       │   └── prompts/                       # 7 domain-specific inspection prompts
│       │       ├── state_machine_audit.md     # FSM transitions & terminal state locks
│       │       ├── multi_tenant_context_audit.md # Multi-tenant isolation & scoping
│       │       ├── concurrency_toctou_audit.md # Check-then-act & race windows
│       │       ├── idempotency_replay_audit.md # Idempotency, replay & dual writes
│       │       ├── authorization_perimeter_audit.md # Perimeter collapse & fail-open DB auth
│       │       ├── legacy_forms_authorization_audit.md # Oracle Forms & PL/SQL authorization
│       │       └── agentic_tool_boundary_audit.md # MCP tool authorization & rollback atomicity
│       └── evals/
│           ├── evals.json                     # 20 routing test cases (positive + negative)
│           ├── task-success.json              # Behavioral task-success evaluation cases
│           ├── rule_tests.tsv                 # Empirical CLI execution evidence log
│           └── fixtures/                      # Code fixtures with planted concurrency bugs
├── issues/                                    # Issue tracking templates & findings
├── research/                                  # Security research & safety labs (AI-Security-and-Safety-Lab)
└── repos/                                     # Target working trees under audit (crow, raven)
```

---

## The Forensic Analytical Engine

The auditor operates across an unambiguous **Step 0 + Seven-Step Forensic Procedure** governed by **Four Strict Evidence Levels**:

```
+-------------------------------------------------------------------------+
|                Step 0 + Seven-Step Forensic Sequence                    |
|                                                                         |
|  Step 0: Scope & Triage (Rank by financial/lifecycle blast radius)      |
|  Step 1: Observed Facts (ASTs, CFGs, call sites, schemas - file:line)   |
|  Step 2: Hard Boundary Conditions (Isolation levels, locks, async hops) |
|  Step 3: Competing Reconstructions (Intended vs Adversarial paths)      |
|  Step 4: Degradation & Obfuscation (Swallows, fallbacks, defaults)      |
|  Step 5: Incentive & Trust Dynamics (Caller-controlled ingress state)   |
|  Step 6: Failure Point Mapping (Pinpoint exact line & classify)         |
|  Step 7: Discriminating Tests & Proof (Reproducer or Telemetry Spec)    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                         Evidence Evaluation Gate                        |
|                                                                         |
|  CONFIRMED   --> Reachable trace / reproducer   --> [FINDING-XXX]       |
|  SUSPECTED   --> Unverified assumption          --> [FINDING-XXX]       |
|  NON LIQUET  --> Indeterminate path             --> [NON-LIQUET-XXX]    |
|  REFUTED     --> Verified defense discovered    --> Coverage Note       |
+-------------------------------------------------------------------------+
```

---

## The 13-Domain Logic Invariants Taxonomy

1. **FSM-BYPASS**: Unvalidated status assignments bypassing transition guards.
2. **TRANSACTION-DEMARCATION**: Unintended partial commits (`REQUIRES_NEW`, autonomous transactions, Spring self-invocation).
3. **BALANCE-VIOLATION / LOST-UPDATE**: Broken conservation laws and unprotected read-modify-write sequences.
4. **TENANT-LEAK / AUTHZ-BYPASS**: Missing tenant/org scoping predicates in database queries or storage keys.
5. **TOCTOU-RACE**: Non-atomic check-then-act gaps across database or file locks.
6. **REPLAY-IDEMPOTENCY**: Duplicate message/webhook deliveries causing duplicate business effects.
7. **DUAL-WRITE**: Non-atomic split writes between databases and external queues/APIs lacking outboxes.
8. **INPUT-DOMAIN**: Negative, fractional, or overflowing domain inputs producing invalid states.
9. **RESOURCE-LEAK**: Unclosed database cursors (`OPEN ... FOR`), pooled thread-static state, or unreleased locks.
10. **ERROR-SWALLOW**: Catch blocks returning `true` or continuing through broken multi-step state mutations.
11. **PERIMETER-BYPASS**: Internal procedures relying on upstream reverse-proxy assumptions (SiteMinder) that collapse when invoked directly or via MCP tools.
12. **FAIL-OPEN-AUTH**: Database-backed authorization tables failing open on timeouts or unhandled exceptions.
13. **AGENTIC-TOOL-LEAK**: Autonomous LLM tool-calling boundaries lacking localized principal authorization.

---

## Empirical Static Verification Architecture

The package rejects uncompiled pseudo-code rules:
- **Semgrep Suite**: 9 standalone YAML files holding 13 rule IDs in `references/rules/semgrep/`, each paired with a test fixture annotated with `ruleid:` and `ok:` test assertions. Verified via `semgrep --test`.
- **CodeQL Packs**: 2 compilable packs in `references/rules/codeql/` for Python and JavaScript, implementing modern `DataFlow::ConfigSig` and `TaintTracking::Global` modules (2 query files: `UnscopedTenantLookup.ql`, `UnguardedStateTransition.ql`). Verified against CodeQL CLI 2.27.3.
- **Total Static Logic Rules**: 15 rules across 11 files (13 Semgrep rule IDs + 2 CodeQL queries).

---

## Adversarial Game Simulation & MCTS Concurrency

Rather than relying on passive pattern matching, the engine models the audited codebase as an adversarial game:
- The auditor agent is scored by the explicit **Epistemic Evaluation Matrix** defined in [`instructions.md §6`](skills/code-logic-auditor/instructions.md) and [`references/game_simulation_rl_auditing.md`](skills/code-logic-auditor/references/game_simulation_rl_auditing.md) (+100 for CONFIRMED with reproducer, +50 for REFUTED with verified defense, +30 for NON LIQUET with telemetry spec, -100 for unproven CONFIRMED claims, -50 for un-sourced claims, -30 for syntactic false positives).
- Concurrency race windows are analyzed via **Monte Carlo Tree Search (MCTS)** over execution interleavings between check and act steps.

---

## APM Package Distribution Architecture

`crow-raven-analysis` is structured as a native APM package:
- [`apm.yml`](apm.yml) defines package metadata, targets (`antigravity`, `claude`, `codex`, `copilot`), and auto-inclusion of `.apm/skills/`.
- Deployed globally via `apm install <path-or-url> --global`, materializing directly into user-level runtime skill directories without repo pollution.
