# Inspection prompt: CI and release authority

## Contents

- [Scope and source inventory](#scope-and-source-inventory)
- [Trace identity before execution](#trace-identity-before-execution)
- [Check live gates](#check-live-gates)
- [Discriminating cases](#discriminating-cases)
- [Evidence and delivery](#evidence-and-delivery)

## Scope and source inventory

Use the [deployment evidence runbook](../cicd-deployment-evidence.md) for cross-platform inventory,
read-only configuration collection, provenance verification and deployment-to-runtime identity tracing.

For agent extensions, developer tools and CI repositories, protected operations include checkout of
executable content, installation, credentialed tool startup, hook/config writes, artifact publication,
version tags and distribution branches. Do not wait for an application database or HTTP route to
recognize those operations. Rank transitions into release/write authority before routine report and
local cleanup concerns, using actual impact and reachability rather than expected severity counts.

Record every executable language and whether the extractor actually handles it. An empty inventory
from an unsupported file extension is a discovery failure requiring manual supplementation, not an
absence of operations. Keep a source snapshot and a separate list of unreviewed candidates.

When agents ingest PR files, artifact metadata, tool results or mutable external resources, also use
[Agent runtime threats](../agent-runtime-threats.md). Trace extraction through direct helper execution
and model context to actual runner authority; do not assume a poisoned artifact is inevitably read,
obeyed or able to access secrets. Include alternate shell/SDK routes around any proposed proxy.

## Trace identity before execution

Map event → originating actor/repository/ref → triggering workflow → checked-out commit/artifact →
executed code → token/credentials → durable effect. Keep these distinct:

- The repository hosting a workflow run versus its head repository.
- A branch named main versus a push to the trusted repository's main ref.
- A successful PR test versus authorization to execute that candidate with stronger credentials.
- A validated hexadecimal SHA versus a commit established as the approved trusted revision.
- Artifact integrity versus provenance and authorization to publish that artifact.

For chained workflows, inspect both the originating event type and head repository before candidate
checkout or execution. Consult actual event/run metadata and official platform semantics. A trusted
workflow that invokes a validator from an untrusted checkout has already crossed the execution
boundary; checks inside that validator cannot establish trust in the candidate before it runs.

Inspect fetched artifacts, cache restoration, local/reusable actions, package lifecycle scripts and
repository-supplied launchers as alternative execution paths. Follow token scope and where it is
actually supplied. Do not infer organization-admin authority, every secret, protected-branch bypass
or downstream compromise merely from a contents-write token.

## Check live gates

For GitHub/Copilot, use [scanner configuration review](../github-ai-scanner-security.md) and its
read-only collector. Collect administrative evidence independently of the untrusted scanning job.

If a sourced policy depends on environment approval, branch protection, required reviewers, or
publication restrictions, inspect readable live configuration as well as YAML. A named environment
is not evidence that approval rules exist. Keep inaccessible settings unknown, preserve actual
review/provenance/rebuild controls, and record configuration observation time separately from the
source revision. Do not modify settings as part of the audit.

Validate a policy claim against maintainer requirements, an approved contract or the platform's
documented security boundary (`platform_spec`, such as GitHub's `pull_request_target` / `workflow_run`
privilege boundary); do not invent a mandatory review policy solely because a stronger setting would
be preferable. Determine which controls are independent and which share the same mutable candidate,
token or administrator.

## Discriminating cases

Use read-only platform metadata and local synthetic tests first. For each case record whether it was
observed, statically reconstructed, locally modeled or actually exercised in a disposable repository:

| Case | Question |
|---|---|
| Successful fork PR with a trusted-looking branch name | Can base-repository/branch-name predicates accept an untrusted head? |
| Same-repository PR versus trusted push | Does event type change the authorization decision? |
| Candidate replaces its own release/validation script or scanner instructions | Is provenance checked in trusted code before invocation? |
| Artifact from untrusted `workflow_run` / PR extracted before verification | Can downloaded artifact contents overwrite scripts or inputs executed under privileged credentials? |
| Cache key reachable by an untrusted ref restored into a privileged job | Can a lower-trust branch or PR poison a cache key consumed by a release or secret-bearing job? |
| Step-to-step or post-action state bridge (`GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`, `needs.*.outputs`) | Can an unprivileged scanner step alter paths, environment variables, shell-interpolated outputs or post-action state consumed by a later privileged step? |
| Isolated `pull_request_target` / `workflow_run` scanner counterexample | Does the job execute only trusted base-ref code while treating PR diffs/artifacts strictly as inert data? Preserve legitimate fork SARIF/comment workflows as REFUTED when isolated. |
| Environment reference with absent or unreadable protection | Is the asserted approval established, absent, or unknown? |
| Stale/moved commit or artifact | Is approval bound to the same immutable revision and effect? |
| Failure after a write or a helper warning | Does the complete caller repair, compensate, reject or consume the state? |

A local canary using a synthetic token is not an end-to-end GitHub exploit. Do not trigger malicious
PRs, use real write tokens, publish tags or test a live release while collecting proof. If a controlled
platform test is necessary, obtain explicit scope for a disposable repository and synthetic effects.

For a failed helper, follow downstream repair and compensation before declaring a defect. Read the
persisted state after the full command. Preserve a defeated hypothesis as REFUTED with the defense
proof rather than keeping it in the confirmed severity totals.

## Evidence and delivery

Cite the exact trust crossing, invariant source, source locations, credential scope, assumptions,
competing defenses and safe proof. Distinguish distinct root causes from repeated steps in one chain;
state whether multiple defects must combine for the claimed impact. Do not inflate independent counts.

Deliver self-contained maintainer details and negative acceptance cases: an untrusted event must not
reach privileged execution; a legitimate release must still satisfy the intended approval. Mark
predicted scanner coverage separately from measured query results and unknown platform settings.
Use the [GHAS reporting checks](../ghas-security-reporting.md) for report consistency, affected-version
metadata and private advisory preparation. Keep target-specific evidence outside the public skill.

Official platform references:
- [Workflow-run event and privilege boundary](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run)
- [Deployment environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments)
