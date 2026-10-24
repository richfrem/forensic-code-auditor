# Project Instructions: CROW-RAVEN Analysis (`code-logic-auditor`)

Forensic code logic and invariant auditing repository. Houses the `code-logic-auditor` skill, multi-model consensus evaluations, and forensic security audits for enterprise legacy and modern runtimes (`bcgov/crow` and `bcgov/raven`).

## Quick Navigation
- System Design & Architectural Invariants: See [ARCHITECTURE.md](ARCHITECTURE.md)
- APM Installation, Upgrades & Deployment: See [INSTALL.md](INSTALL.md)
- Primary Skill Router: See [.apm/skills/code-logic-auditor/SKILL.md](.apm/skills/code-logic-auditor/SKILL.md)
- Issue Tracking & Finding Logs: See [issues/](issues/)

## Core Operational Invariants
1. **First-Principles Epistemic Stance**: Agents MUST evaluate code as deterministic state machines bounded by physical, resource, and informational limits.
2. **Rejection of Authority as Proof**: Agents MUST NEVER accept vendor claims, compliance badges (SOC2/ISO), or passing SAST scans as proof of safety (though official platform specifications and DBMS locking manuals are admissible evidence of mechanical semantics).
3. **Four Evidence Levels**: Findings MUST explicitly declare evidence status (`CONFIRMED`, `SUSPECTED`, `NON LIQUET`, `REFUTED`), strictly separating evidence from severity.
4. **Invariant Sourcing Requirement**: Agents MUST cite the explicit source of an invariant (business rule, schema constraint, or API contract) before claiming a breach.
5. **Target & Research Isolation**: External target repositories (`repos/`) and security research labs (`research/`) MUST remain gitignored to prevent submodule pollution.

## Essential Commands

### Skill Authoring & Quality Audit
```bash
# Audit skill against authoring standards (both source and installed modes)
python3 "${APM_HOME:-$HOME/.apm}/apm_modules/_local/agent-extension-authoring/skills/authoring-skills/scripts/audit_skill.py" .apm/skills/code-logic-auditor --mode source
python3 "${APM_HOME:-$HOME/.apm}/apm_modules/_local/agent-extension-authoring/skills/authoring-skills/scripts/audit_skill.py" "$HOME/.gemini/antigravity-cli/skills/code-logic-auditor" --mode installed
```

### Static Rule Verification
```bash
# Test Semgrep AST logic rules against annotated test fixtures
semgrep --test .apm/skills/code-logic-auditor/references/rules/semgrep
```

### Context Bundling
```bash
# Recompile single-file Markdown context bundle for LLM reviews
python3 "$HOME/.gemini/antigravity-cli/skills/bundling-context/scripts/bundle.py" --manifest temp/bundles/code-logic-auditor-manifest.json --bundle temp/bundles/code-logic-auditor-v3.4.md
```
