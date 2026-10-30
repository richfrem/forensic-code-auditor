# GitHub repository and AI scanner configuration review

## Contents

- [Collect evidence safely](#collect-evidence-safely)
- [Review the scanner and repository](#review-the-scanner-and-repository)
- [Report the residual authority](#report-the-residual-authority)

Use when Copilot or another AI reviewer reads repository content inside GitHub Actions or another
GitHub-connected execution environment. Follow [CI/release authority](prompts/ci_release_trust_audit.md),
[deployment evidence](cicd-deployment-evidence.md) and [agent runtime threats](agent-runtime-threats.md).
Establish which Copilot execution environment is used; product names alone do not establish isolation.

The governing question is: if the scanner follows hostile metadata or repository instructions,
what can its actual credentials, filesystem and execution tools read, change or publish?

## Collect evidence safely

Run the collector from a trusted installation/environment using independently authorized credentials.
Do not give a scanner processing suspect content an administrative token so it can inspect its own
containment. Prefer a separate trusted collection job or owner-supplied sanitized snapshot. Never
run a collector version taken from an untrusted PR with elevated credentials.

```bash
python3 scripts/collect_github_security.py --repo OWNER/REPO \
  --branch main --environment production --run-id 123456 \
  --output WORKSPACE/github-security
```

The output directory must be new. Repeat branch/environment/run arguments for explicitly scoped
targets; omission means those detail queries were not performed. The collector uses installed `gh`
authentication with a scrubbed environment, fixed GitHub.com GET endpoints, bounded pagination,
endpoint-specific JSON payload validation and per-request timeouts. It collects caller identity
(`/user`), repository metadata, Actions permissions/default workflow permissions/selected-action policy,
OIDC subject customization (`/actions/oidc/customization/sub`), ruleset summaries plus up to 20
resolved `/rulesets/{id}` details (`bypass_actors`, `conditions`, `rules`), environment/runner/secret
and cache lists (`/actions/caches`), selected branch protection/effective rules, selected environment
configuration/secrets/deployment-branch-policies and selected run/jobs/artifacts metadata. It never
requests secret values, Actions variable values (which return plaintext values), logs or artifact bodies.

Save the installed `gh --version` alongside the evidence. `manifest.json` records observation times,
caller metadata, `X-OAuth-Scopes` / `X-Accepted-OAuth-Scopes` headers when present (noting that
fine-grained PATs and GitHub App installation tokens omit `X-OAuth-Scopes`), HTTP statuses, exit codes,
`untrusted_server_fields`, `control_coverage` and hashes of raw stdout/stderr artifacts. Protect the
output as private evidence; repository descriptions, branch/job/step names and PR titles remain
untrusted data. Do not claim truncation or JSON escaping prevents prompt injection; enforce privileged
boundaries outside model choice.

Exit 0 means every requested query completed (`collection_complete: true`), not that all required CI
controls were observed (`required_controls_complete`) or that the repository is safe. Exit 1 means one
or more queries are UNKNOWN; exit 2 indicates invalid invocation/setup. Pagination limits, denial,
ambiguous 404, unavailable CLI, timeout or malformed/wrong-shape JSON remain UNKNOWN. Do not convert
them to “no control.” A successful empty list describes that endpoint and caller visibility only.

This collector does not resolve organization runner-group access, organization-secret scope, historical
policy at prior commits, workflow YAML source, effective job runtime permissions, cloud IAM trust policies
or Copilot coding-agent UI settings. Request sanitized owner exports where needed; do not broaden
credentials automatically.

## Review the scanner and repository

For each row record evidence and applicability, then classify the control as **established**,
**contradicted** or **unknown** against sourced requirements. These control assessments do not replace
the canonical finding verdicts. A setting is effective only if the relevant path cannot bypass it.

| Check | Evidence and decision |
|---|---|
| Trusted scanner definition | Locate workflow, prompts, `.apm/skills/`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `.github/agents/*.md`, `AGENTS.md` and validators actually loaded. Determine whether a PR can modify them before execution. `CODEOWNERS` establishes review ownership, not pre-review execution containment; load scanner definitions from a trusted base ref or pinned repository. |
| Copilot and agent profile | Distinguish Copilot coding/cloud agent, Copilot code review and CLI/Actions jobs. Inspect `.github/workflows/copilot-setup-steps.yml` (which runs *before* the agent firewall activates), `.vscode/mcp.json` / `.mcp.json`, dedicated repository/org Copilot Agents secrets/variables (not only legacy `environments/copilot`), `COPILOT_MCP_*` credentials and firewall allowlists. The agent firewall does not directly cover MCP server processes or setup-step processes. |
| Effective job token | Combine repository defaults with workflow/job/reusable-workflow permissions and actual run context. Inspect checkout credential persistence and inherited credentials. A read-only repository default alone does not establish a read-only job; runtime token reductions require workflow source and job log verification. |
| Untrusted triggers | Trace fork/same-repository PR, `pull_request_target`, `workflow_run`, `issue_comment`, manual dispatch and reruns to executed checkout. Do not flag an isolated `pull_request_target` or `workflow_run` scanner that executes trusted base-ref code and treats PR diffs/artifacts strictly as inert data. |
| Secret and OIDC authority | Trace secrets actually supplied, environment approval, deployment-branch policies, `/actions/oidc/customization/sub` and `id-token` permission. Obtain cloud issuer/audience/subject restrictions, role permissions and Key Vault access scope separately; secret-name metadata cannot establish effective access. |
| Scanner write and step bridges | Inspect process sandbox, filesystem/mount permissions, tool allow-lists, subprocess paths, `$GITHUB_ENV`, `$GITHUB_PATH`, `$GITHUB_OUTPUT`, `$GITHUB_STATE`, `$GITHUB_STEP_SUMMARY`, post-action steps and `needs.*.outputs` consumers. While `NODE_OPTIONS` in `GITHUB_ENV` is blocked on modern runners (v2.309.0+), `GITHUB_PATH` prepends, arbitrary environment variables, unquoted output interpolation and post-action state can bridge an unprivileged agent step to a later secret-bearing step in the same or downstream job. |
| Output and cache exfiltration | Review logs, annotations, PR comments, SARIF/artifact uploads, `/actions/caches` and network egress. Masking and an egress firewall do not block exfiltration through permitted GitHub API writes, PR comments, SARIF fields or cross-workflow cache poisoning. |
| Repository protections | Review effective branch rules, classic protection, detailed `/rulesets/{id}` `bypass_actors` and `conditions`, required checks and workflow ownership. Determine which bots, apps or teams have `bypass_mode: "always"`. |
| Runner containment | Establish hosted/self-hosted topology, runner groups, ephemeral/JIT provisioning, mounts, cloud metadata access, credentials and network policy. For private landing zones requiring self-hosted runners, recommend ephemeral/JIT runners and isolated workspaces rather than banning self-hosted runners outright. |
| Deployment binding | Join scan input digest, approved report, `/actions/runs/{id}/artifacts` digests, attestations and consumed deployment digest. Establish which later steps, caches or controllers can mutate content or substitute artifacts after scanning. |
| Independent gate | Approval/deployment verifier must use trusted code and policy inaccessible to the scanner. A valid scanner-authored report or digest alone does not prove an honest analysis. |

Preserve legitimate capabilities required by the task, but source every exception and its scope.
Do not impose blanket filesystem bans that prevent a coding agent from committing to its own work
branch; enforce branch/ruleset protection and separate untrusted analysis jobs from privileged
publishing/autofix jobs. Structured report and SARIF fields remain untrusted strings when rendered
into shells, prompts or markup.

## Report the residual authority

Produce a capability table: principal -> credential -> allowed action/resource -> enforcing boundary
-> evidence -> unknowns. Trace the specific hypothetical abuse (metadata instruction -> tool/helper
-> Key Vault read -> file/report write -> later upload/deployment), marking each prerequisite as
established, defeated or unresolved. Do not claim vault access merely because OIDC is enabled.

Attach hashes/references to the canonical operation dossier. Recommend precise controls for the
reachable authority. Missing configuration limits the affected claim; independently sufficient static
proof can still establish a narrower violation. Collection success is not a vulnerability verdict.

Test containment only with separately authorized synthetic secrets, inert markers and disposable
resources. An injected instruction being rejected once does not establish reliable resistance.
No real secret retrieval, workflow dispatch or repository mutation is part of this collector.

Primary references (check target versions and current API permissions):
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [Actions permissions API](https://docs.github.com/en/rest/actions/permissions)
- [Rules and inherited branch rules](https://docs.github.com/en/rest/repos/rules)
- [Workflow run API](https://docs.github.com/en/rest/actions/workflow-runs)
