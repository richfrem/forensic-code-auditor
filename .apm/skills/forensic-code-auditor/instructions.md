# Forensic Code Logic & Invariant Auditor: Instructions

## Contents
- [1. Epistemological Stance & Anti-Fallacy Safeguards](#1-epistemological-stance--anti-fallacy-safeguards)
- [2. Step 0 + Seven-Step Forensic Audit Procedure](#2-step-0--seven-step-forensic-audit-procedure)
- [3. Four Evidence Levels](#3-four-evidence-levels)
- [4. Mandatory Output Schemas](#4-mandatory-output-schemas)
- [5. Report Skeleton & Stop Conditions](#5-report-skeleton--stop-conditions)
- [6. Adversarial Game Simulation & Epistemic Scoring](#6-adversarial-game-simulation--epistemic-scoring)

---

## 1. Epistemological Stance & Anti-Fallacy Safeguards

- **First-Principles Determinism:**
  Treat codebases and operational architectures as deterministic state machines governed by hard physical, resource, and informational limits (latency ceilings, memory consistency, transaction isolation, concurrency limits).
- **Universal Scrutiny & Rejection of Authority, Popularity, and Tradition:**
  - *Appeal to Authority (`ad verecundiam`):* Institutional consensus, official narratives, vendor security certifications (SOC2/ISO), framework "safe-by-default" claims, and passing SAST/SonarQube scans carry zero evidential weight on their own. (Note: Official platform and language runtime specifications—e.g., ANSI SQL standards, DBMS engine locking manuals, HTTP RFCs—are admissible evidence of underlying mechanical semantics, but never proof that a specific application is secure.)
  - *Appeal to Popularity (`ad populum`):* Industry-wide adoption of a design pattern, library, or architecture does not validate its mechanical soundness or invariant safety.
  - *Appeal to Tradition (`ad antiquitatem`):* Legacy longevity ("this code has run in production for 15 years") is not proof of correctness; it often masks silent state corruption, unlogged race conditions, or perimeter-dependent assumptions.
- **Taphonomic & Observational Calibration:**
  Account systematically for survivorship bias, sampling blind spots, and signal decay. Explicitly differentiate between an absence of data that is mechanically expected (e.g., telemetry wiped by an OOM crash, unlogged legacy PL/SQL autonomous blocks, dynamic dispatch blind spots) and an absence that genuinely refutes a model (e.g., verified database ledger balance, unbroken cryptographic state).
- **Convergence Verification:**
  When identical logic flaws appear across modules or services, systematically evaluate three competing drivers:
  1. *Direct Lineage / Transmission* (shared copy-pasted code, common upstream library, inherited doctrine).
  2. *Independent Convergence under Identical Constraints* (developers independently arriving at the same flawed optimization due to latency or lock contention).
  3. *Shared Environmental Realities* (reacting to underlying runtime, connection-pool, or hardware exhaustion).
- **Invariant Sourcing Requirement:**
  Identify the required invariant property and its explicit source (business requirement, API contract, schema constraint, or independently approved API contract; tests and labeled assumptions are investigative leads). Do not report the absence of one specific implementation pattern as a violation when another verified mechanism enforces the property.

---

## 2. Step 0 + Seven-Step Forensic Audit Procedure

### Step 0: Scope and Triage
List entry points (HTTP routes, message consumers, scheduled jobs, DB triggers, Forms triggers, stored procedures, MCP tool handlers). Rank by blast radius:
$$\text{Financial / Value Movement} > \text{Lifecycle State Mutation} > \text{Tenant-Scoped Data Access} > \text{Read-Only Operations}$$
Record reviewed entry points and explicitly document un-reviewed boundaries in the report's Coverage section.

### Step 1: Observed Facts
Extract raw ASTs, control-flow graphs, call sites, state schemas, and database trigger cascades. Record the call chain with `file:line`, state touched, and target data store. Quote, do not paraphrase, the decisive lines of code.

### Step 2: Hard Boundary Conditions
For each state change: map transaction boundaries, transaction isolation levels (and database default), locks acquired, async execution hops, and what happens to security context (tenant, user, session claims) across that hop.

### Step 3: Competing Reconstructions
Contrast the intended business workflow against adversarial execution paths: concurrent duplicate requests, retried requests after network timeouts, crashes between dual writes, direct API or MCP tool calls skipping UI guards, and out-of-order message ingestion. Actively inspect for existing defenses that could disprove suspected flaws.

### Step 4: Degradation & Obfuscation Correction
Systematically identify failures that silently masquerade as success: swallowed exceptions, catch blocks that log and continue, permissive defaults (`role or 'admin'`, `tenant or None` meaning all tenants), un-awaited async promises, and fallback branches that bypass validation.

### Step 5: Incentive & Trust Dynamics
Mark every input the caller controls: IDs in path parameters, ambient headers (`SM_USER`, `X-Forwarded-User`), state fields in request bodies, quantities/amounts (negative, zero, fractional, or overflowing), and client-supplied pricing or discounts.

### Step 6: Failure Point Mapping
Pinpoint the exact AST node, source line, or transaction boundary where state desynchronizes or the invariant breaches. Classify the finding according to the Invariants Taxonomy.

### Step 7: Discriminating Tests & Proof
Formulate a discriminating test: it must fail on current vulnerable code and pass after remediation. For concurrency races, force the relevant interleaving with a hook after read/check and before mutation; use separate database sessions, bounded waits, and durable ledger assertions. Simultaneous starts or arbitrary latency alone do not prove the relevant interleaving. If verification depends on runtime facts not visible in source code, formally declare `NON LIQUET` and emit a Telemetry Specification.

> [!CAUTION]
> **Strict Reproducer Safety Boundary**: Reproducers and race simulations MUST NEVER be executed against production, shared staging, or live enterprise databases. They must run exclusively against isolated local containers, disposable schemas, mock servers, with synthetic data and explicit authorization. Rollback alone is not an isolation boundary; autonomous commits and external effects may survive it.

---

## 3. Four Evidence Levels

Keep evidence status strictly separated from impact severity:

| Level | Definition | Report Treatment |
| :--- | :--- | :--- |
| **`CONFIRMED`** | Concrete reachable violation established through proof-of-concept test, execution trace, or complete verified static call chain. | Emitted as a formal `[FINDING-XXX]`. |
| **`SUSPECTED`** | Specific failure mechanism identified; one or more material prerequisites remain unverified (e.g. database isolation level, deployment runtime config). Clearly enumerate each labeled assumption (`MULTI-ASSUMPTION` supported). | Emitted as a formal `[FINDING-XXX]`, explicitly naming each unverified assumption. |
| **`NON LIQUET`** | Available code and telemetry cannot resolve the execution behavior (obscured by reflection, dynamic dispatch, opaque RPC, or unknown runtime configuration). | Emitted as a formal `[NON-LIQUET-XXX]` with a Required Telemetry Specification. |
| **`REFUTED`** | Rigorous inspection discovered an existing verified defense that defeats the hypothesized failure path. | Documented in Coverage notes, citing the defense's `file:line`. |

---

## 4. Mandatory Output Schemas

### [FINDING-XXX] <Descriptive Title of Invariant Violation>
- **Classification**: `FSM-BYPASS` | `TOCTOU-RACE` | `LOST-UPDATE` | `TENANT-LEAK` | `AUTHZ-BYPASS` | `BALANCE-VIOLATION` | `TRANSACTION-DEMARCATION` | `REPLAY-IDEMPOTENCY` | `DUAL-WRITE` | `INPUT-DOMAIN` | `RESOURCE-LEAK` | `ERROR-SWALLOW` | `PERIMETER-BYPASS` | `FAIL-OPEN-AUTH` | `AGENTIC-TOOL-LEAK`
- **Severity**: `Critical` | `High` | `Medium` | `Low` (Calculated using the 3×3 matrix below; cite explicit justification)
- **Evidence**: `CONFIRMED` | `SUSPECTED` (List all explicitly labeled assumptions if suspected)
- **Location**: `path/file.ext:line` (Ingress entry point) $\rightarrow$ `path/file.ext:line` (Failure point)
- **Invariant & Source**: The exact mathematical/state condition required, citing the source (business rule, schema constraint, API contract, or labeled assumption).
- **Preconditions**: Required attacker or caller capabilities (e.g., authenticated tenant, concurrent session, retry window).
- **Root Failure Mechanism**: Step-by-step trace of how state desynchronizes or invariants breach under load or failure.
- **Existing Defenses Examined**: Specific checks or middleware reviewed and why they fail to prevent the breach.
- **Discriminating Test / Reproducer**: Concrete test code demonstrating failure on current code and success on fixed code.
- **Remediation by Construction**: The structural change that makes the invalid state unrepresentable (e.g., conditional atomic `UPDATE ... WHERE`, database constraint, typestate design).

#### 3×3 Severity Evaluation Matrix
$$\text{Severity} = \text{Impact} \times \text{Reachability}$$

| Impact \ Reachability | **High Reachability**<br>(Public API, ingress webhook, ambient header, or race window exploitable via automated bursts / HTTP/2 multiplexing) | **Medium Reachability**<br>(Authenticated low-privilege tenant, standard multi-tenant route) | **Low Reachability**<br>(Admin role required, physical hardware access, internal air-gapped network only) |
| :--- | :--- | :--- | :--- |
| **High Impact**<br>(Balance drain, cross-tenant leak, arbitrary lifecycle override) | **Critical** | **High** | **Medium** |
| **Medium Impact**<br>(Single-tenant corruption, recoverable resource leak, un-audited state) | **High** | **Medium** | **Low** |
| **Low Impact**<br>(Unlogged exception swallow, transient performance degradation) | **Medium** | **Low** | **Low** |

---

### [NON-LIQUET-XXX] <Indeterminate Execution Path Title>
- **Obstruction Mechanism**: `RUNTIME-CONFIG` | `DYNAMIC-DISPATCH` | `EXTERNAL-RPC-OPAQUE` | `REFLECTION` | `UNTRACKED-TRIGGER` | `MISSING-SCHEMA`
- **Location**: `path/file.ext:line`
- **Candidate Models**:
  - *Model A (Safe)*: Condition under which invariant holds.
  - *Model B (Vulnerable)*: Condition under which invariant breaches.
- **Hypothesis if True**: The finding classification and blast radius if Model B is verified.
- **Required Telemetry Specification**: Exact distributed tracing span, structured log statement, database audit query, or runtime assertion required to empirically confirm or refute the hypothesis.

---

## 5. Report Skeleton & Stop Conditions

### Report Structure
1. **Executive Summary**: Count of findings by severity, evidence breakdown, and the single highest-priority finding to remediate first.
2. **Confirmed Findings**: High-confidence vulnerabilities ordered by severity.
3. **Suspected Findings**: Mechanics identified with labeled assumptions.
4. **Non Liquet Specifications**: Required telemetry for unresolved paths.
5. **Coverage & Scope**: Entry points audited, entry points skipped, rules executed, and confirmed defenses. Apply the mandatory contract below; emit `report.json` validated with `scripts/validate_report.py`. Markdown supplements this artifact.

### Stop Conditions & Execution Precedence
- **Interactive Mode**: If an active user is present and an unverified runtime condition alters the verdict, pause and request clarification.
- **Autonomous / Batch Mode**: Do NOT halt. Apply the following decision rule:
  - **`SUSPECTED`**: Applies when the code path and failure mechanism are proven, and only a deployment/runtime configuration value (e.g. database isolation level `READ COMMITTED` vs `SERIALIZABLE`, or reverse proxy TLS header stripping) is unverified. Classify the finding as `SUSPECTED` with explicit labeled assumptions (`MULTI-ASSUMPTION`).
  - **`NON LIQUET (RUNTIME-CONFIG)`**: Applies when the code execution path itself cannot be determined without runtime telemetry (e.g. dynamic feature flags, conditional runtime reflection, or opaque external plugin dispatch). Emit a formal `[NON-LIQUET-XXX]` with a telemetry specification.
- **Scope Ceilings**: When the audit target exceeds single-pass capacity, triage entry points by blast radius (Step 0) and explicitly record un-audited boundaries in the Coverage section.

---

## 6. Adversarial Game Simulation & Epistemic Scoring

To prevent passive pattern-matching and reward rigorous verification, the auditor operates under the epistemic scoring matrix detailed in [references/game_simulation_rl_auditing.md](./references/game_simulation_rl_auditing.md):
- **+100 pts (`CONFIRMED`)**: Sourced invariant cited; reachable path proven; runnable reproducer generated.
- **+50 pts (`REFUTED`)**: Plausible defect identified, alternative defense (e.g., DB constraint, RLS, atomic conditional `UPDATE`) verified, and invariant proven safe. *(Scored only when resolving an automated rule hit or ranked entry point; capped at max 3 findings / +150 pts per audit pass.)*
- **+30 pts (`NON LIQUET`)**: Indeterminate runtime boundary identified and paired with a concrete Required Telemetry Specification. *(Scored only when resolving an automated rule hit or ranked entry point; capped at max 3 findings / +90 pts per audit pass.)*
- **+10 pts (Coverage)**: Systematic mapping of un-audited entry points, triggers, or MCP tool handlers.
- **-10 pts**: Out-of-scope cosmetic syntax/linter noise.
- **-30 pts**: Syntactic heuristic false positive (flagging missing keywords when an alternative mechanism secures the state).
- **-50 pts**: Un-sourced invariant violation claim.
- **-100 pts**: Claiming `CONFIRMED` without an executed test reproducer or complete verified static call chain.

> [!NOTE]
> **False-Negative Evaluation Check**: While missed findings incur 0 points in static reward tallying, coverage and false-negative suppression are rigorously penalized and gated via the behavioral test suite ([`evals/task-success.json`](./evals/task-success.json)).

## Mandatory discovery and completion contract

Before any conditional prompt selection, inventory state-changing surfaces, authorization data stores,
privileged execution contexts, asynchronous paths, tenant boundaries, and legacy UI/DB paths.
For each record emit `discovered`, `reviewed`, `verified`, `partially_examined`, `unexamined`, or
`unknown`, criticality, evidence reference, and limitations. Include absent and inaccessible surfaces
explicitly; a discovery inventory is not an assertion of exhaustive reachability.

For each selected high-impact protected operation record all nine completion items:
1. Independently sourced invariant (business-owner approved policy, signed-off matrix, regulation,
   requirement, schema constraint, or authoritative API contract).
2. Reachable entry points, backward callers and forward interface-to-sink trace.
3. Policy/data provenance, exact rows, evaluator semantics, policy version, effective scope.
4. Execution and transaction trace including durable state and external/queued side effects.
5. Competing defenses and why they hold or fail.
6. Failure hypothesis, including legitimate service/delegation exceptions.
7. Discriminating test or complete static proof with evidence references.
8. Evidence and verification classification.
9. Coverage and residual uncertainty.

Each item is `complete` with evidence or `unresolved` with the precise evidence needed; never omit it.
Use [operation coverage](templates/operation-coverage.json), [permission matrix](templates/effective-permission-matrix.csv),
and [report contract](templates/report.schema.json). The validator checks structure and cross-field gates;
it cannot certify that a citation is authoritative or that a claimed test really ran. Inspect evidence manually.

### Policy provenance

Existing code, current permission rows, and tests may share the same defect. They are corroboration,
not independent authority for intended permissions. Compare **intended vs configured vs runtime-enforced**
for principal × role × resource × operation × scope × entry point × relevant state and time.
No independent baseline: `NON LIQUET`, policy-validation-needed; do not fabricate a violation.
An explicitly documented exception overrides the general baseline only within its stated scope/time.
Follow [authorization data integrity](references/authorization-data-integrity.md) for every discovered
policy store, even when both authorization evaluators are correct.

### Evidence, verification, severity, assurance

Keep the existing four evidence levels and severity matrix. Add independent verification state:
- `STATIC_PROVEN`: complete reachable static proof, including relevant policy/data and defenses.
- `DYNAMIC_REPRODUCED`: actually executed test; cite command, environment, result and durable effects.
- `TEST_GENERATED`: code produced but not executed. Never runtime confirmation.
- `NOT_VERIFIED`: no discriminating proof available; list exactly what is missing.

`CONFIRMED` requires `STATIC_PROVEN` or `DYNAMIC_REPRODUCED`; `REFUTED` requires verified defense
with the same proof states. A generated reproducer alone establishes neither.
For permission violations, confirmed/suspected findings must identify independent policy and exact row/path.

Assurance is scope coverage, independent of vulnerability severity:
- `VERIFIED_SCOPE`: all declared scope records verified and all selected operation items complete.
  Findings may still exist; the status does not imply correctness or absence of vulnerabilities.
- `PARTIAL`: some examination completed; boundaries remain unresolved.
- `INSUFFICIENT_EVIDENCE`: missing policy/schema/runtime evidence prevents conclusions.
- `NOT_ASSESSED`: no examination performed.

Allowed summary conclusions: `FINDINGS_REPORTED`, `NO_FINDINGS_IN_VERIFIED_SCOPE`,
`INCONCLUSIVE`, `NOT_ASSESSED`. Never emit unqualified `SECURE` or `PASS`.
Zero findings plus unverified critical scope is `INCONCLUSIVE`; explain each boundary.
Run `python3 scripts/validate_report.py report.json` before delivery. Validator failure blocks
report completion, not continued read-only investigation. Report unresolved items explicitly.
