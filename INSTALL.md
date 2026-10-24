# Installation & APM Registry Guide: `code-logic-auditor`

Comprehensive guide for registering, deploying, updating, and verifying the `code-logic-auditor` skill using the Agent Package Manager (APM).

## Contents
- [Prerequisites](#prerequisites)
- [Installation Modes](#installation-modes)
  - [Mode 1: Global Installation (Recommended)](#mode-1-global-installation-recommended)
  - [Mode 2: Project-Local Installation](#mode-2-project-local-installation)
- [Harness Deployment Locations](#harness-deployment-locations)
- [Updating the Skill](#updating-the-skill)
- [Rollback & Uninstallation](#rollback--uninstallation)
- [Quality Audits & Verification](#quality-audits--verification)
- [Troubleshooting & Invariants](#troubleshooting--invariants)

---

## Prerequisites

Ensure your environment satisfies the following tooling requirements:

1. **APM CLI**: Pinned to `apm-cli==0.33.0`.
   ```bash
   apm --version
   # Expected: apm 0.33.0
   ```
   If APM is not installed, install it into your active Python environment:
   ```bash
   python3 -m pip install "apm-cli==0.33.0"
   ```
2. **Python**: Python 3.10 or higher.
3. **Git**: Git 2.30+ installed and configured.

---

## Installation Modes

### Mode 1: Global Installation (Recommended)

Installing globally makes `code-logic-auditor` instantly available across all your coding projects in Antigravity, Claude Code, GitHub Copilot, and OpenAI Codex without requiring project-level configuration.

#### Option A: Install from Local Repository Clone
> [!IMPORTANT]
> **APM Absolute Path Invariant**: When installing a local package directory globally (`--global`), APM requires a full absolute filesystem path. Using `"$(pwd)"` inside the repository directory automatically expands to the absolute path.

```bash
# From within the repository root:
apm install "$(pwd)" --global

# Or pass the explicit absolute path:
apm install /path/to/crow-raven-analysis --global
```

#### Option B: Install Directly from Remote GitHub
To install directly from GitHub pinned to a branch or release tag:

```bash
# Pin to main branch
apm install https://github.com/richfrem/crow-raven-analysis#main --global

# Or pin to an explicit tag / release (recommended for deterministic deployments)
apm install https://github.com/richfrem/crow-raven-analysis#v3.0.0 --global
```

---

### Mode 2: Project-Local Installation

For teams or automated CI/CD pipelines auditing a specific project repository, install `code-logic-auditor` locally within the target repository.

#### Step 1: Add Dependency to `apm.yml`
In the root of the consuming project repository, add `code-logic-auditor` under `dependencies.apm`:

```yaml
name: enterprise-service-audit
version: 1.0.0
targets:
  - claude
  - antigravity
  - codex
dependencies:
  apm:
    - "https://github.com/richfrem/crow-raven-analysis#main"
```

#### Step 2: Install Package & Commit Lockfile
```bash
# Install package into the project
apm install

# In CI/CD pipelines, ensure reproducible execution using frozen lockfile
apm install --frozen
```

#### Step 3: Consuming Project Git Hygiene
Ensure the consuming project's `.gitignore` excludes deployed runtime harness directories:
```gitignore
# APM Deployed Harness Artifacts
.agents/
.claude/skills/
.codex/
.github/skills/
apm_modules/
```

---

## Harness Deployment Locations

When installed globally or locally, APM automatically unpacks and materializes `code-logic-auditor` into the corresponding harness directories:

| Agent / Harness | Global Deployment Path | Project-Local Deployment Path |
|---|---|---|
| **Google Antigravity (`agy`)** | `~/.gemini/antigravity-cli/skills/code-logic-auditor/` | `.agents/skills/code-logic-auditor/` |
| **Claude Code (`claude`)** | `~/.claude/skills/code-logic-auditor/` | `.claude/skills/code-logic-auditor/` |
| **OpenAI Codex CLI (`codex`)** | `~/.agents/skills/code-logic-auditor/` | `.agents/skills/code-logic-auditor/` |
| **GitHub Copilot CLI (`copilot`)** | `~/.agents/skills/code-logic-auditor/` | `.github/skills/code-logic-auditor/` |
| **APM Cache & Registry** | `~/.apm/` (manifest: `apm.yml`, lockfile: `apm.lock.yaml`) | `apm_modules/`, `apm.lock.yaml` |

---

## Updating the Skill

### Updating Global Deployment

To update an existing global deployment after code changes or upstream releases:

```bash
# From local repository clone (re-runs materialization across all targets)
apm install "$(pwd)" --global

# From remote repository (fetches newest commits on target ref)
apm update code-logic-auditor --global
```

### Updating Project-Local Deployment

```bash
apm update code-logic-auditor
git add apm.lock.yaml
git commit -m "chore: bump code-logic-auditor dependency"
```

---

## Rollback & Uninstallation

### Uninstalling Globally
```bash
apm uninstall code-logic-auditor --global
```
APM safely removes the materialized skill directory from all global harness directories (`~/.gemini/antigravity-cli/`, `~/.claude/skills/`, `~/.agents/skills/`).

### Uninstalling Locally
```bash
apm uninstall code-logic-auditor
```

---

## Quality Audits & Verification

The repository incorporates automated quality gates to guarantee strict compliance with Agent Extension Authoring standards.

### 1. Skill Quality & Authoring Standards Audit
Test the canonical skill source tree:
```bash
python3 "${APM_HOME:-$HOME/.apm}/apm_modules/_local/agent-extension-authoring/skills/authoring-skills/scripts/audit_skill.py" \
  skills/code-logic-auditor \
  --mode source
```
*Expected Result:* `PASS` with 0 errors and 0 warnings.

Verify the materialized runtime deployment in Antigravity:
```bash
python3 "${APM_HOME:-$HOME/.apm}/apm_modules/_local/agent-extension-authoring/skills/authoring-skills/scripts/audit_skill.py" \
  "$HOME/.gemini/antigravity-cli/skills/code-logic-auditor" \
  --mode installed
```
*Expected Result:* `PASS` with 0 errors and 0 warnings.

### 2. APM Package Manifest Validation
Verify the top-level package manifest and distribution symlinks:
```bash
python3 "$HOME/.gemini/antigravity-cli/skills/packaging-with-apm/scripts/validate_apm_package.py" --path .
```
*Expected Result:* `✅ VALIDATION PASSED`

### 3. Root Instruction Compliance Audit
Verify that root `AGENTS.md` and `CLAUDE.md` adhere to length, relative link, and anti-leak constraints:
```bash
python3 "$HOME/.gemini/antigravity-cli/skills/authoring-instructions/scripts/audit_agents_md.py" AGENTS.md --strict
python3 "$HOME/.gemini/antigravity-cli/skills/authoring-instructions/scripts/audit_agents_md.py" CLAUDE.md --strict
```
*Expected Result:* `Total: 2 | Passed: 2 | Failed: 0`

### 4. Harness Discovery Check
- **Claude Code**: Run `/skills` and confirm `code-logic-auditor` is registered.
- **Antigravity**: Verify skill definition is indexed from `~/.gemini/antigravity-cli/skills/code-logic-auditor/SKILL.md`.
- **Copilot CLI**: Run `/skills list` and confirm active state.

---

## Troubleshooting & Invariants

| Symptom | Root Cause | Resolution |
|---|---|---|
| `APM error: Path must be absolute` | Providing relative path to `--global` | Use full path: `apm install "$(pwd)" --global` |
| `Duplicate skill name in Claude` | Installed via both APM and legacy `plugin-add` | Remove legacy directory in `~/.claude/plugins/` |
| `SKILL.md exceeds progressive disclosure budget` | Router file exceeds 80 lines | Keep router concise; move deep mechanics to `instructions.md` |
| `Missing Early TOC` | Reference document > 100 lines lacking navigation | Add `## Contents` anchor block within first 100 lines |
| `Submodule pollution in git` | Target repos (`repos/crow`, `repos/raven`) tracked | Keep target repos in `repos/` and gitignored via `.gitignore` |
