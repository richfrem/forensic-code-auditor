# Install Forensic Code Auditor with APM

This is a standalone skill. No Crow, Raven, database server, or MCP service is required to install it.
Scanner CLIs and test dependencies are optional tools for the corresponding verification commands.

## Prerequisites

Use Python 3.10+ and APM 0.33.0 (the version used for package verification):

```bash
python3 -m pip install "apm-cli==0.33.0"
apm --version
```

## Install from a local checkout

From this repository, use its absolute path:

```bash
apm install "$(pwd)" --global
```

For project-local installation, run from the consuming project:

```bash
apm install /absolute/path/to/forensic-code-auditor
```

APM reads the source under `.apm/skills/forensic-code-auditor/` and materializes it for the selected
harness. Select a harness explicitly when needed with `--target codex`, `--target claude`,
`--target copilot`, or `--target antigravity`. Do not edit the installed copies.

## Install from GitHub

Run from the consuming project to install the current default branch for Codex:

```bash
apm install https://github.com/richfrem/forensic-code-auditor --target codex
```

Select multiple harnesses with a comma-separated list:

```bash
apm install https://github.com/richfrem/forensic-code-auditor --target codex,copilot,claude
```

Other supported targets include `antigravity`, `gemini`, `cursor`, `opencode` and `windsurf`.
Use `apm install --help` for the full list. Do not repeat `--target`: only its last value is retained.
`--target all` excludes some explicit-only targets, including Antigravity; list those explicitly when needed.

Add `--global` for user-wide installation instead of project-local installation:

```bash
apm install https://github.com/richfrem/forensic-code-auditor --target codex,copilot,claude --global
```

For reproducible installation, pin an existing commit SHA or release tag. Replace the placeholder;
do not copy it literally:

```bash
apm install "https://github.com/richfrem/forensic-code-auditor#<commit-sha-or-tag>" --target codex,copilot,claude
```

APM can maintain a lockfile in the consuming project for reproducibility. This dependency-free source
repository ignores its own local lockfile because it may describe independently installed development tools.

## Update or roll back

Reinstall the local checkout after source changes, or install the GitHub URL pinned to the desired
new or previous SHA/tag. Keep the previous pin available for rollback. Restart or refresh the
harness's skill discovery after changing an installation.

## Migrate from code-logic-auditor

The source directory, package name and skill identifier changed to `forensic-code-auditor`.
Use APM to remove the old package in the scope where it was installed, then install the new package:

```bash
apm uninstall code-logic-auditor --global
apm install /absolute/path/to/forensic-code-auditor --global
```

For a project-local migration omit `--global`. Update consuming manifests, pinned URLs and automation
that refers to the old skill name. Original CodeQL query IDs and pack names are retained to avoid
unnecessary changes to scanner consumers. No installed copies are changed by editing this repository.

## Verify or package

See [TESTING.md](.apm/skills/forensic-code-auditor/TESTING.md) for executable acceptance and scanner tests.
For a distributable APM bundle, use a separate disposable consumer workspace, install this
package at the desired commit, then pack its resolved deployed files:

```bash
mkdir -p /tmp/forensic-auditor-bundle
cd /tmp/forensic-auditor-bundle
apm install "https://github.com/richfrem/forensic-code-auditor#<commit-sha>" --target codex
apm pack --format apm --archive --output ./dist
```

Replace the placeholder with an existing commit. Running `apm pack` directly in a dependency-free
source checkout does not bundle its authored source; it can emit an empty bundle or use unrelated
locally installed dependencies. The separate consumer keeps local tools out of the distribution.

Temporary builds and private recovery files belong under ignored `temp/`. The review Markdown bundle
at `temp/bundles/forensic-code-auditor-bundle.md` contains the authored skill, root documentation and
selected implementation evidence; it is distinct from an installable APM archive. Installation into real user harnesses is not an acceptance test and
is not performed by the implementation workflow.


## Runtime-only staging and report migration

The development checkout retains regression tests and known examples. For a lean runtime or controlled
blind evaluation, stage only runtime content under the existing temp directory:

```bash
python3 .apm/skills/forensic-code-auditor/scripts/stage_package.py --output temp/runtime-package/.apm/skills/forensic-code-auditor
```

Use a fresh destination; the staging command refuses to overwrite. Copy the standalone `apm.yml`
into `temp/runtime-package/` before installing that staged source through APM in a disposable consumer.
`contamination_lint.py` checks the runtime tree for specified sealed identifiers and fixture markers.
This does not prove that no semantic benchmark information could leak; enforce agent visibility too.

Schema v2 requires `--evidence-root` and structured hashed references. Existing schema-v1 reports
use `validate_report_v1.py` for legacy structural validation, then migrate before claiming v2 evidence
verification. No released version is implied by a local hardening commit; the package version remains
3.4.0 pending release/version selection.
