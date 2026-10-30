---
name: forensic-code-auditor
description: >-
  Audit business-logic invariants, wrong authorization-data rows despite correct
  code, obscure Oracle Forms permissions, cross-entrypoint authority, concurrency,
  tenant isolation, replay and privileged agent tools. Detect hidden skill behavior,
  metadata/prompt injection, dormant triggers and memory poisoning through forensic
  source, policy and state-transition reviews across legacy and modern applications.
---

# Forensic Code Auditor

## Contents

[Constraints](#constraints) • [Discovery](#mandatory-discovery-before-routing) • [Workflow](#workflow) • [Routing](#progressive-disclosure) • [Quick start](#quick-start) • [Verification](#verification-and-references)

## Constraints

Read [the execution contract](instructions.md), then apply the required
[analyst reasoning safeguards](agents/forensic_systems_analyst.md). Preserve the four evidence levels,
separate verification/assurance/severity, independent policy provenance and safe local reproductions.
Scanner hits, generated tests and report validity are not proof of vulnerability or safety.
Syntax/style, dependency-CVE-only scans and generic walkthroughs are outside this skill's scope.

## Mandatory discovery before routing

Persist a bounded inventory of protected operations, entry points, permission stores, privileged
execution identities, async paths, tenant boundaries and legacy UI/DB access. Include unsupported,
excluded and dynamic paths explicitly. Run [inventory and path reconstruction](references/cross-entrypoint-authorization.md)
before deciding which specialists apply. Supplement unsupported executable languages manually; an empty
extractor result is not an empty attack surface. Never call candidate extraction exhaustive ground truth.
For agent systems, include ingestion, context/delegation, direct helper execution, memory writes,
remote updates and independent audit paths; route these through the agent runtime reference below.

## Workflow

0. Scope and triage: rank value/lifecycle/tenant sinks and reconcile every discovered candidate.
1. Observed facts: source lines, row keys, navigation and caller evidence.
2. Hard boundaries: transaction, isolation, locks, session identity and effects.
3. Competing reconstructions: intended flow, adversarial schedules and existing defenses.
4. Degradation: exceptions, fallbacks, partial commits and omitted async work.
5. Trust dynamics: originating/delegated/service identity and caller-controlled scope.
6. Failure mapping: exact invariant breach, one primary category and mechanism tags.
7. Discriminating proof: sufficient static trace or executed local reproduction; retain uncertainty.

Complete or explicitly leave unresolved all nine operation-dossier items in the contract.
Correct evaluators consuming incorrect rows, navigation-dependent authority, alternate API/batch
callers and shared identities require joined operation-path analysis, not separate checklist verdicts.

## Progressive disclosure

| Surface | Load |
|---|---|
| Data-driven permissions and hierarchical menus | [Authorization data integrity](references/authorization-data-integrity.md) |
| Multiple entry paths, procedures and grants | [Cross-entrypoint authorization](references/cross-entrypoint-authorization.md) |
| Firewall/gateway/credential/backend dependencies | [Infrastructure trust](references/infrastructure-trust-dependencies.md) |
| Forms, PL/SQL, globals and DB rights | [Legacy Forms](references/prompts/legacy_forms_authorization_audit.md) |
| Concurrency/revocation | [TOCTOU](references/prompts/concurrency_toctou_audit.md), [interleaving heuristic](references/game_simulation_rl_auditing.md) |
| Lifecycle and tenant context | [FSM](references/prompts/state_machine_audit.md), [tenant](references/prompts/multi_tenant_context_audit.md) |
| CI, releases, artifact provenance and deployment/runtime identity | [CI/release authority](references/prompts/ci_release_trust_audit.md), [deployment evidence](references/cicd-deployment-evidence.md) |
| GitHub/Copilot scanner permissions and repository configuration | [GitHub scanner security](references/github-ai-scanner-security.md) |
| Hidden skill behavior, metadata/prompt injection, dormant triggers, MCP or memory poisoning | [Agent runtime threats](references/agent-runtime-threats.md) |
| Replay, perimeter and agent tools | [Replay](references/prompts/idempotency_replay_audit.md), [perimeter](references/prompts/authorization_perimeter_audit.md), [tools](references/prompts/agentic_tool_boundary_audit.md) |

## Quick start

Load the contract and analyst safeguards above, then run `python3 scripts/inventory_sinks.py --source-root TARGET --evidence-root WORKSPACE --output WORKSPACE/operations.json` on authorized offline inputs. Follow the applicable runbook and retain unsupported paths.

## Verification and references

Emit schema-v2 evidence and coverage artifacts; run `scripts/validate_report.py report.json --evidence-root WORKSPACE`.
Keep unverified critical candidates and assumed semantics visible even when there are no findings.
Use [TESTING.md](TESTING.md) for tests and version pins; source regression fixtures are worked examples,
not blind accuracy evidence. [Taxonomy](references/logic_invariants_taxonomy.md),
[Semgrep limits](references/semgrep_logic_rules.md), [CodeQL limits](references/codeql_taint_recipes.md),
[GHAS reporting](references/ghas-security-reporting.md).
For broader reasoning examples, optionally consult the [first-principles prompt](references/prompts/first_principles_forensic_systems_analysis.md);
the execution contract remains authoritative for code-audit proof and classifications.
