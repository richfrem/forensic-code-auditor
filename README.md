# CROW / RAVEN Analysis: `code-logic-auditor`

Forensic code logic and invariant auditor engineered to detect business-logic flaws, FSM transition bypasses, TOCTOU race windows, multi-tenant context leaks, and perimeter authorization collapse across enterprise legacy and modern distributed systems.

`crow-raven-analysis` is an independent, open-source forensic engineering and invariant research repository developed under the MIT License, providing audit tooling and reference evaluations for modern and enterprise legacy codebases (including BC Gov NR Sector reference architectures [`bcgov/crow`](https://github.com/bcgov/crow) and [`bcgov/raven`](https://github.com/bcgov/raven)).

For comprehensive installation, registry, update, and rollback documentation, see [INSTALL.md](INSTALL.md). For system architecture and mathematical foundations, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Global Installation with APM

To use `code-logic-auditor` globally across all your repositories (supporting Antigravity, Claude, Codex, and Copilot):

### Option A: Install from Local Clone
```bash
apm install "$(pwd)" --global
```

### Option B: Install from GitHub
```bash
apm install https://github.com/richfrem/crow-raven-analysis#main --global
```

---

## Project Structure

```text
crow-raven-analysis/
├── AGENTS.md                                  # Canonical agent instructions & invariant bounds
├── CLAUDE.md                                  # Minimal bridge to AGENTS.md
├── ARCHITECTURE.md                            # Complete architectural spec & state machines
├── INSTALL.md                                 # APM installation, registry, update & rollback guide
├── apm.yml                                    # APM package manifest
├── README.md                                  # Repository overview and quick start
├── .apm/
│   └── skills/code-logic-auditor/             # Primary authoring source, test suites & APM distribution root
├── issues/                                    # Issue tracking and logged vulnerability reports
├── research/                                  # Security research & safety labs (AI-Security-and-Safety-Lab)
└── repos/                                     # Isolated target codebases under audit (crow, raven)
```

## Validation & Audits

- **Skill Quality**: Passed `audit_skill.py` with 0 errors and 0 warnings.
- **APM Package Compliance**: Passed `validate_apm_package.py`.
- **Empirical Rule Tests**: 9 tested Semgrep YAML files (15 rule IDs) and 2 compilable CodeQL packs (17 static logic rules total).
