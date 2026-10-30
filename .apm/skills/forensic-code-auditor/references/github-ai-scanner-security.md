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
authentication, fixed GitHub.com GET endpoints, bounded pagination and per-request timeouts. It
collects repository metadata, Actions permissions/default workflow permissions/selected-action policy,
ruleset summaries including parents, environment and runner lists, repository secret metadata,
selected branch protection/effective rules, selected environment configuration/secret metadata and
selected run/jobs metadata. It never requests secret values, variable values, logs or artifact bodies.

Save the installed `gh --version` alongside the evidence. `manifest.json` records observation times,
scope, HTTP statuses when available, command exit codes and hashes of raw stdout/stderr artifacts.
Protect the output as private evidence; repository descriptions and other server text remain untrusted
data. Its manifest is a collection artifact, not a schema-v2 finding report or a safety certificate.

Exit 0 means every requested query completed, not that the repository is safe. Exit 1 means one or
more queries are UNKNOWN; exit 2 indicates invalid invocation/setup. Pagination limits, denial,
ambiguous 404, unavailable CLI, timeout or malformed response remain UNKNOWN. Do not convert them
to “no control.” A successful empty list describes that endpoint and caller visibility only.
Collection is sequential and not an atomic snapshot; correlate changes and timestamps.

This collector does not resolve ruleset details/bypass actors, enterprise/organization policy,
runner-group access, organization-secret scope, historical policy, workflow source, effective job
permissions, cloud IAM or Copilot configuration. Request sanitized owner exports where needed;
do not broaden credentials automatically. Ruleset summaries and branch rules need detail review.

## Review the scanner and repository

For each row record evidence and applicability, then classify the control as **established**,
**contradicted** or **unknown** against sourced requirements. These control assessments do not replace
the canonical finding verdicts. A setting is effective only if the relevant path cannot bypass it.

| Check | Evidence and decision |
|---|---|
| Trusted scanner definition | Locate workflow, prompts, skill/scripts and dependencies actually loaded. Determine whether a PR can replace them or introduce instructions through nested references, metadata, tool output or memory. |
| Effective job token | Combine repository defaults with workflow/job/reusable-workflow permissions and actual run context. Inspect checkout credential persistence and inherited credentials. A read-only repository default alone does not establish a read-only job. |
| Untrusted triggers | Trace fork/same-repository PR, `pull_request_target`, `workflow_run`, manual dispatch and reruns to executed checkout. Identify gates before candidate code or package hooks run. |
| Secret and OIDC authority | Trace secrets actually supplied, environment approval and `id-token` permission. Obtain cloud issuer/audience/subject restrictions, role permissions and Key Vault access scope separately; secret-name metadata cannot establish effective access. |
| Scanner write surface | Inspect process sandbox, filesystem/mount permissions, tool allow-lists and subprocess paths. Restrict writes to required reports/temporary files and verify enforcement; `contents: read` does not prevent local source modification. |
| Output exfiltration | Review logs, annotations, PR comments, report/artifact uploads and network egress. Determine whether secrets could enter any output. Masking and an egress firewall alone do not prevent leakage through permitted report uploads. |
| Repository protections | Review effective branch rules, classic protection, detailed rulesets/bypass actors, required checks and workflow ownership/review. Determine who can alter the scanner or mark its checks successful. |
| Runner containment | Establish hosted/self-hosted topology, persistence, mounts, cloud metadata access, credentials and network policy. A separate job on the same persistent runner may retain compromise. |
| Deployment binding | Join scan input digest, approved report, build output and consumed deployment digest. Establish which later jobs, scripts or controllers can mutate content or substitute artifacts after scanning. |
| Independent gate | Approval/deployment verifier must use trusted code and policy inaccessible to the scanner. A valid scanner-authored report or digest alone does not prove an honest analysis. |

Preserve legitimate capabilities required by the task, but source every exception and its scope.
For an analysis-only scan, a suitable baseline is minimal repository-read access, no deployment or
vault credential, isolated disposable execution, restricted writes and narrowly constrained report
publication. A separate trusted publisher may ingest validated reports without executing their
contents. Structured report fields are also untrusted strings when rendered into shells or markup.

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
