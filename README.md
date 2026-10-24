# CROW / RAVEN Analysis: `code-logic-auditor`

Forensic code logic and invariant auditor engineered to detect business-logic flaws, FSM transition bypasses, TOCTOU race windows, multi-tenant context leaks, and perimeter authorization collapse across enterprise legacy and modern distributed systems.

Built and validated for the BC Gov NR Sector modernization ecosystem ([`bcgov/crow`](https://github.com/bcgov/crow) and [`bcgov/raven`](https://github.com/bcgov/raven)).

For comprehensive installation, registry, update, and rollback documentation, see [INSTALL.md](INSTALL.md). For system architecture and mathematical foundations, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Global Installation with APM

To use `code-logic-auditor` globally across all your repositories (supporting Antigravity, Claude, Codex, and Copilot):

### Option A: Install from Local Clone
```bash
apm install /Users/richardfremmerlid/Projects/crow-raven-analysis --global
```

### Option B: Install from GitHub
```bash
apm install https://github.com/richfrem/crow-raven-analysis#main --global
```

---

## Project Structure

```text
crow-raven-analysis/
├── apm.yml                                    # APM package manifest
├── README.md                                  # Repository overview and APM installation guide
├── .apm/
│   └── skills/code-logic-auditor/             # APM skill distribution link
├── skills/
│   └── code-logic-auditor/             # Primary authoring source & test suites
├── issues/                                    # Issue tracking and logged vulnerability reports
├── reviews/                                   # Multi-model review consensus & synthesis roadmap
└── repos/                                     # Isolated target codebases under audit (crow, raven)
```

## Validation & Audits

- **Skill Quality**: Passed `audit_skill.py` with 0 errors and 0 warnings.
- **APM Package Compliance**: Passed `validate_apm_package.py`.
- **Empirical Rule Tests**: 10 tested Semgrep rules and 2 compilable CodeQL packs.
