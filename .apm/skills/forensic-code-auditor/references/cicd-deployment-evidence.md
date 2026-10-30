# CI/CD deployment evidence runbook

## Contents

- [Inventory and platform map](#inventory-and-platform-map)
- [Collect configuration and execution evidence](#collect-configuration-and-execution-evidence)
- [Verify artifacts and dependencies](#verify-artifacts-and-dependencies)
- [Join deployment and runtime authority](#join-deployment-and-runtime-authority)
- [Bound conclusions and reproduction](#bound-conclusions-and-reproduction)

Use with [CI/release authority](prompts/ci_release_trust_audit.md). Preserve the canonical operation
dossier, independently sourced policy and evidence/verification/assurance distinctions. This is a
manual collection procedure; workflow candidate extraction and live verification are not automated.

## Inventory and platform map

Inventory configuration, resolved includes/templates, scripts, dependency locks, runner images,
credential sources, triggers, deployment destinations and rollback paths. For each job record
untrusted input -> executable revision -> effective identity -> protected effect -> enforcing gate.
Search results identify candidates; generated configuration and externally managed jobs need exports.

| Platform | Inspect source and resolved configuration | Request authorized read-only exports |
|---|---|---|
| GitHub Actions | `.github/workflows/`, event filters, `pull_request_target`, `workflow_run`, reusable/local actions, permissions, checkout refs | Run/jobs metadata, rulesets and branch protection, environments/reviewers, Actions policy, runner groups and secret scope metadata |
| GitLab CI | `.gitlab-ci.yml`, includes/components, rules, child/downstream pipelines and resolved configuration | Protected refs/environments, variable protection/scope metadata, job-token access, runner assignment and deployment approvals |
| Azure Pipelines | Pipeline YAML/templates, checkout, resource triggers and service-connection references | Pipeline resource authorization, approvals/checks, job authorization scope, variable-group metadata, service connections and agent pools |
| Jenkins | Jenkinsfiles, shared-library revisions, multibranch discovery and job definitions | Folder/job permissions, credential bindings, controller/agent configuration, script approvals and build records |
| CircleCI | `.circleci/config.yml`, resolved orbs, contexts and filters | Context restrictions, project settings, runner assignment and workflow/job records |
| Tekton / Argo | Pipeline/Task or Workflow/Template resources, referenced bundles/images and parameter expansion | Controller policy, admission controls, namespace RBAC, service-account bindings and execution resources |

Treat the entries as collection questions, not claims that every version/tier exposes the same API
or semantics. Verify the target version and official platform documentation. Include schedules,
manual/API dispatch, reruns, forks, deployment automation and persistent self-hosted runner state.

## Collect configuration and execution evidence

Keep private exports under the evidence workspace. Record collection time, repository/project ID,
API endpoint/version, pagination, requester permissions, HTTP status and source/run revisions.
Store secret names/scopes and policy metadata only; never retrieve secret values or raw OIDC tokens.
Preserve collector errors: 403, ambiguous 404, empty pages and inaccessible inherited policy are
not evidence that a control is absent. Request a sanitized owner export for each missing dependency.

For GitHub, these authenticated GET examples are templates for an authorized target; replace all
placeholders and capture responses/errors privately. URL-encode branch/environment path segments.

```bash
gh api --paginate 'repos/OWNER/REPO/rulesets'
gh api 'repos/OWNER/REPO/branches/BRANCH/protection'
gh api --paginate 'repos/OWNER/REPO/environments'
gh api 'repos/OWNER/REPO/environments/ENVIRONMENT'
gh api 'repos/OWNER/REPO/actions/runs/RUN_ID'
gh api --paginate 'repos/OWNER/REPO/actions/runs/RUN_ID/jobs'
```

Inspect inherited rules and bypass actors, not merely whether a rule exists. Obtain cloud federation
trust policies separately; repository exports cannot establish cloud IAM authorization. Use equivalent
read-only platform exports for other providers and record effective settings after inheritance.

Tie an existing run to event, originating repo/ref, head SHA, workflow revision, run attempt, resolved
dependencies, runner identity and job conclusions. Distinguish skipped, cancelled, failed and successful
jobs. A green run establishes its observed outcome, not execution of an omitted gate. Tie deployment
records to the exact run and artifact digest; a later config export may not describe historical settings.
Do not dispatch/rerun workflows or alter settings during collection. Sanitize logs before sharing.

## Verify artifacts and dependencies

Trace reviewed source -> builder identity -> artifact digest -> registry -> deployed digest. Check:

1. **Dependencies:** Follow actions/orbs/templates, lifecycle scripts, base images, downloads and cache
   restores. Record immutable revisions and who can replace them. A pinned compromised dependency
   remains compromised; pinning addresses substitution, not behavioral correctness.
2. **Provenance:** Establish the trusted builder, source repository/revision, build definition and
   parameters, dependency/material identities and output subject digest. Verify signature/trust
   roots and compare against independently approved expectations. An attestation stored beside an
   artifact is not proof it was checked before promotion.
3. **Sigstore/Cosign:** Record verifier version, expected signer/key or certificate identity and OIDC
   issuer, artifact digest, trust-root/bundle/log verification settings, exit status and raw result.
   Avoid permissive identity matching or disabling verification. A valid signature establishes only
   the properties actually verified; it does not prove safe source or an authorized release.
4. **SLSA:** Name the specification version, track, claimed level and evidence for each applicable
   requirement, including builder isolation and provenance generation. Do not infer a level from
   the presence of a signature. Evaluate source policy separately from build provenance.
5. **SBOM:** Bind the SBOM/attestation subject to the deployed digest, identify generator and coverage,
   and reconcile dependencies with build inputs and shipped files. An SBOM lists declared components;
   it neither establishes completeness nor proves absence of vulnerabilities or malicious behavior.
6. **Promotion:** Verify checks occur before consumption and bind approval to immutable content.
   Test hypotheses about mutable tags, substituted attestations, cache poisoning, reused artifacts,
   cross-project publication and rollback to obsolete but correctly signed builds.

Primary guidance: [SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts),
[Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/). Apply the target's approved
policy; lack of a particular brand/tool or assurance level alone is not an invariant breach.

## Join deployment and runtime authority

Build a capability table covering principal, credentials/federation, permitted actions/resources,
issuance conditions, expiry, boundary enforcement and evidence for each transition:

`CI actor -> job identity -> cloud deployment role -> registry/cluster writes -> workload identity -> application effects`

Inspect OIDC issuer, audience, subject and repository/ref/environment restrictions, role-assumption
conditions and effective permissions. OIDC availability alone does not establish an assumable role.
Trace which identities can change these conditions or bypass a deployment approval.

For Kubernetes, inspect deployment manifests and effective admission/RBAC policy, service accounts,
cloud workload identity, secret mounts, privileged/host access and mutable configuration. Determine
whether deployment permissions permit selecting a stronger service account, mounting additional
secrets, changing admission policy or replacing the application image. Namespace write access alone
does not prove all these effects; establish applicable restrictions and resource scope.

Join the observed running image digest and configuration to the approved artifact. Review secret
injection and build layers/logs/caches for unintended persistence without exposing values. Distinguish
build-time secrets, deployment credentials and application runtime authority. Trace migrations,
post-deploy jobs, GitOps reconciliation and rollback: the effective actor may be a separate controller.

## Bound conclusions and reproduction

Missing live evidence limits the claim depending on that evidence; it does not automatically make
all findings NON LIQUET. Reachable static proof may still establish a narrower violation. State
known facts, unresolved prerequisites and exactly which export/trace would discriminate competing
models. Keep operational recommendations separate from confirmed deployment behavior.

Use inert local fixtures first: trusted/untrusted event metadata, approved/substituted digest,
expected/wrong signer or issuer, matching/mismatched workload identity and present/absent approval.
Offline validation cannot reproduce hosted event semantics or cloud authorization. If platform proof
is necessary, obtain explicit scope for a disposable project/account with synthetic credentials,
inert artifacts, bounded runner/network/cost limits and cleanup ownership. Never infer authorization
to create repositories, start runners or deploy from permission to inspect source.

Attach results to the canonical dossier without inventing schema fields. Report source review,
configuration observation, actual run observation and modeled behavior separately. Current limits:
no built-in workflow taint/inventory rules, non-GitHub provider collection adapter, hosted CI reproduction harness
or automatic deployment/runtime identity join. Do not claim these gaps were closed by this runbook.

Additional primary references: [GitHub run API](https://docs.github.com/en/rest/actions/workflow-runs),
[GitLab pipeline security](https://docs.gitlab.com/ci/pipeline_security/),
[Azure Pipelines security](https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview?view=azure-devops).

For bounded GitHub configuration collection and AI scanner containment, use
[GitHub scanner security](github-ai-scanner-security.md) and `scripts/collect_github_security.py`.
