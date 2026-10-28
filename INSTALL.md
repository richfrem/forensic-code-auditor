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

After the changes have been merged/published, replace the placeholder with an existing commit SHA
or release tag. Do not copy the placeholder literally:

```bash
apm install "https://github.com/richfrem/forensic-code-auditor#<commit-sha-or-tag>" --global
```

Omit `--global` for a consuming-project installation. APM can maintain a lockfile in that project
for reproducibility. This dependency-free source repository ignores its own local lockfile because
it may describe independently installed development tools.

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

Builds and private local recovery files under `build/` are ignored. The review ZIP supplied separately
contains the complete authored skill, root documentation, and implementation evidence; it is distinct
from the installable APM archive. Installation into real user harnesses is not an acceptance test and
is not performed by the implementation workflow.
