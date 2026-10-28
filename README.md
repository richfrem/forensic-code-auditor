# Forensic Code Auditor

`forensic-code-auditor` is a standalone APM skill for auditing business logic, state transitions,
authorization data, concurrency, tenant isolation and distributed side effects. It supports modern
applications and legacy Oracle Forms/PL/SQL, Java, .NET and PHP systems.

The auditor starts with state-changing operations, traces their callers and policy sources, and
separates confirmed findings from unresolved evidence. Correct authorization code can still consume
an incorrect permission row; the workflow compares independently intended, configured and enforced access.
Semgrep and CodeQL supply candidates for investigation, never proof of security.

Install with APM using [INSTALL.md](INSTALL.md). The package has **no Crow, Raven, or MCP dependencies**.
Those tools can be installed separately without becoming part of this package.

- [Architecture and evidence contracts](ARCHITECTURE.md)
- [Skill entrypoint](.apm/skills/forensic-code-auditor/SKILL.md)
- [Testing, benchmark protocol and limitations](.apm/skills/forensic-code-auditor/TESTING.md)
- [GHAS and security reporting guidance](.apm/skills/forensic-code-auditor/references/ghas-security-reporting.md)
- [Contributor instructions](AGENTS.md)

## Repository layout

```text
.apm/skills/forensic-code-auditor/  # Canonical source shipped by APM
  SKILL.md                        # Compact routing and discovery gate
  instructions.md                 # Seven-step doctrine and completion contract
  agents/                         # Forensic analyst persona
  references/                     # Specialist procedures and candidate rules
  templates/                      # Structured report schema and evidence artifacts
  scripts/                        # Validators, isolated demo and rule harnesses
  tests/                          # Synthetic local acceptance cases
  evals/                          # Existing routing and behavioral evaluation cases
apm.yml                           # Standalone package manifest
```

Local `repos/`, `temp/`, `issues/`, runtime downloads, installed harness copies and build outputs
are ignored. Optional checkouts in `repos/` are audit targets or development tools, not package dependencies.
Only authored source belongs in `.apm/`; make changes there and install through APM.

The former skill/package name was `code-logic-auditor`. See the migration instructions in
[INSTALL.md](INSTALL.md). Existing CodeQL pack names and original query IDs remain stable for consumers.
