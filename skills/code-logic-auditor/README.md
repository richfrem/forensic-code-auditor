# Code Logic & Invariant Auditor (`code-logic-auditor`)

## Contents
- [Purpose & Operational Mission](#purpose--operational-mission)
- [The Modern Security Imperative: Why Syntax SAST Fails](#the-modern-security-imperative-why-syntax-sast-fails)
- [Ecosystem Synergy: CROW, RAVEN & Code Logic Auditor](#ecosystem-synergy-crow-raven--code-logic-auditor)
- [Target Architectural Stacks](#target-architectural-stacks)
- [Core Analytical Doctrine: The 7-Step Forensic Standard](#core-analytical-doctrine-the-7-step-forensic-standard)
- [Adversarial Game Simulation & RL Reward Shaping](#adversarial-game-simulation--rl-reward-shaping)
- [Skill Package Structure](#skill-package-structure)
- [Verification & Auditing](#verification--auditing)

---

## Purpose & Operational Mission

The `code-logic-auditor` skill is a first-principles forensic analysis engine engineered to detect architectural vulnerabilities, broken invariants, and subtle state corruption that evade conventional syntactic linters and standard SAST suites (e.g., SonarQube, Fortify, Checkmarx, or ESLint).

While standard analyzers focus on code hygiene, style, and known CVE signatures, `code-logic-auditor` treats enterprise software as **deterministic state machines governed by hard physical, temporal, and cryptographic boundary conditions**. It audits systems for state desynchronization, check-then-act (TOCTOU) race windows, perimeter-assumption collapse, data-driven authorization failures, and multi-tenant context leaks.

---

## The Modern Security Imperative: Why Syntax SAST Fails

Enterprise development teams are rapidly shipping larger volumes of AI-generated and legacy-integrated software. However, automated code generation dramatically accelerates the proliferation of **semantic and architectural logic flaws**:

1. **Perimeter-Implicit Authorization ("Default-Allow" Collapse)**:
   - Decades of enterprise legacy systems (Oracle Forms, Java EE, PHP) operated under an implicit *Default-Allow* paradigm internally, relying on external network perimeters (SiteMinder SSO reverse proxies, WebLogic gateways, VPNs) to police access.
   - When modern APIs, microservices, or LLM-driven MCP tools interface with these legacy systems, the ambient perimeter proxy is bypassed—exposing un-guarded internal procedures to unauthorized invocation.
2. **Data-Driven Authorization Decoupling**:
   - Access control policies increasingly reside as data inside database tables (`SEC_USER_ROLES`, `ORG_UNIT_ACCESS`). Traditional static analyzers cannot verify whether dynamic database queries fail-closed on nulls, timeouts, or unexpected empty sets.
3. **Legacy Runtime Exposure (PHP, Java EE, .NET 4.x, Oracle)**:
   - Modern supply chain and runtime vulnerabilities (such as recent PHP runtime exploits, object deserialization traps, FastCGI worker context leaks, and type-juggling flaws) exploit structural assumptions rather than simple syntax typos.
   - Organizations require autonomous systems that actively uncover logic errors and unsafe assumptions *before* code reaches production.

---

## Ecosystem Synergy: CROW, RAVEN & Code Logic Auditor

This skill forms the analytical core of a tripartite enterprise modernization architecture:

* **[bcgov/raven](file:///Users/richardfremmerlid/Projects/crow-raven-analysis/raven)**: The **Enterprise Execution Engine**.
  - Provides local-first multi-MCP server gateways (Bitbucket, Jira, Sonar, Jenkins, Server Monitor) connecting enterprise infrastructure to LLMs.
  - Hosts an autonomous DevOps pipeline that detects production errors, triages root causes with AI, generates code fixes, and creates pull requests.
* **[bcgov/crow](file:///Users/richardfremmerlid/Projects/crow-raven-analysis/crow)**: The **Capability & Agent Catalog**.
  - Distributed via the Agent Package Manager (APM), supplying specialized agents (`crow-security-review`, `crow-security-remediation`, `crow-legacy-modernization`) across Java, .NET, PHP, and CI/CD pipelines.
* **`code-logic-auditor`**: The **Forensic Invariant Brain**.
  - Embeds the non-syntactic logic rules, Seven-Step Forensic Analytical Doctrine, CodeQL taint recipes, Semgrep AST patterns, and discriminating invariant tests directly into `crow` agents and `raven` pipelines.

---

## Target Architectural Stacks

- **Enterprise Legacy Stacks**:
  - **Oracle Forms & PL/SQL**: Trigger cascades (`WHEN-VALIDATE-*` vs `ON-UPDATE`), autonomous transaction rollback leaks (`PRAGMA AUTONOMOUS_TRANSACTION`), cursor exhaustion (`OPEN ... FOR`), and Virtual Private Database (VPD/RLS) bypasses.
  - **Java EE & Spring (EJB 2.x/3.x, Spring Framework 3/4/5/6)**: Broken transaction propagation (`REQUIRES_NEW`), unhandled session bean state, and proxy self-invocation bypasses.
  - **.NET Framework 4.x / WCF / ADO.NET**: Check-then-act balance mutations outside `TransactionScope`, `[ThreadStatic]` state leaks across thread pool task stealing, and unclosed connection handles.
  - **Legacy PHP 5/7/8**: Ambient header trust (`SM_USER`, `X-Forwarded-User`), superglobal session confusion (`$_SESSION`, `$_SERVER`), unscoped dynamic queries, and FastCGI worker state leaks.
- **Modern Cloud & Asynchronous Runtimes**:
  - Python (FastAPI, Django ORM, Celery race windows, SQLAlchemy isolation).
  - TypeScript / Node.js (NestJS, Express, `AsyncLocalStorage` context leaks, unhandled floating promises).
  - Microservices, event queues, and distributed transactional sagas.

---

## Core Analytical Doctrine: The 7-Step Forensic Standard

1. **Observed Facts**: Raw ASTs, control-flow graphs, call sites, state schemas, and database trigger cascades.
2. **Hard Boundary Conditions**: Atomicity boundaries, async context propagation, memory/token ceilings, and transaction demarcation.
3. **Competing Reconstructions**: Contrasting intended business flow against unconstrained execution paths.
4. **Degradation & Obfuscation Correction**: Uncovering silent exception swallows, permissive fallbacks, and missing default-deny branches.
5. **Incentive & Trust Dynamics**: Interrogating assumptions regarding caller sanity, upstream client control, and cross-service trust boundaries.
6. **Failure Point Mapping**: Pinpointing the exact code points, AST nodes, or SQL triggers where state desynchronizes.
7. **Discriminating Tests**: Generating deterministic property-based assertions or invariant verification tests proving the flaw.
- **Non Liquet Protocol**: Formally declaring indeterminacy when dynamic dispatch or missing telemetry obscures execution flow, emitting a precise **Required Telemetry Specification**.

---

## Adversarial Game Simulation & RL Reward Shaping

To escape the limitations of static pattern matching, `code-logic-auditor` incorporates **reinforcement learning reward shaping and game simulation**:
- The codebase is treated as an adversarial game environment where the agent acts as an attacker incentivized by a scoring function:
  - **+100 pts**: Deterministic, runnable reproducer (property test / exploit script).
  - **+60 pts**: FSM transition guard bypass (reaching terminal state without passing validation).
  - **+40 pts**: Ambient perimeter bypass (direct procedure call lacking localized capability proof).
  - **+25 pts**: Fail-open catch block (`catch (e) { return true; }` or `WHEN OTHERS THEN NULL`).
  - **-10 pts**: Cosmetic syntax/linter noise (PEP8, formatting).
  - **-25 pts**: Unprovable or hallucinated false positives.
- Concurrency and TOCTOU races are analyzed via Monte Carlo Tree Search (MCTS) over thread/commit interleavings.

---

## Skill Package Structure

```text
code-logic-auditor/
├── README.md                                  # Purpose, mission, architecture & ecosystem overview
├── SKILL.md                                   # Primary skill router (authoring standard compliant)
├── instructions.md                            # Operational doctrine, 7-step standard, schema & Non Liquet
├── code-logic-auditor-flow.mmd                # Complete Mermaid state machine diagram
├── agents/
│   └── forensic_systems_analyst.md            # Applied Systems Analyst persona (Argon 4 verbatim directive)
├── references/
│   ├── logic_invariants_taxonomy.md           # Systematic invariant taxonomy (13 domains)
│   ├── game_simulation_rl_auditing.md         # Game-theoretic MCTS & RL reward matrix
│   ├── semgrep_logic_rules.md                 # Tested Semgrep AST patterns (PL/SQL, Java, .NET, PHP, TS)
│   ├── codeql_taint_recipes.md                # Modern CodeQL taint recipes (Django ORM, TS FSM)
│   ├── rules/
│   │   ├── semgrep/                           # Standalone tested Semgrep rules with paired test code
│   │   └── codeql/                            # Compilable CodeQL packs (python, javascript)
│   └── prompts/
│       ├── state_machine_audit.md             # FSM & lifecycle transition inspection
│       ├── multi_tenant_context_audit.md      # Tenant isolation & context propagation inspection
│       ├── concurrency_toctou_audit.md        # Check-then-act & race window inspection
│       ├── idempotency_replay_audit.md        # Idempotency, replay & dual writes inspection
│       └── authorization_perimeter_audit.md   # Perimeter inversion & data-driven auth inspection
└── evals/
    ├── evals.json                             # 20 real-world developer routing triggers & negative controls
    ├── task-success.json                      # Behavioral task-success evaluation cases
    ├── rule_tests.tsv                         # Empirical test execution results (Semgrep & CodeQL CLI)
    ├── results.tsv                            # Benchmark scoring results
    └── fixtures/                              # Code fixtures with planted logic & concurrency defects
```

---

## Verification & Auditing

Validated using the APM `authoring-skills` audit suite:
```bash
python3 "${APM_HOME:-$HOME/.apm}/apm_modules/_local/agent-extension-authoring/skills/authoring-skills/scripts/audit_skill.py" \
  skills/code-logic-auditor \
  --mode source
```
All sections, folder structures, navigation TOCs, and references pass with **0 errors and 0 warnings**.
