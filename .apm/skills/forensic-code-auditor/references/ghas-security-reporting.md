# GitHub security reporting and GHAS evidence

Use when reconciling forensic findings with GitHub code scanning or preparing a security report.
This is generic guidance; private target findings and configuration exports stay in ignored local storage.

1. Record repository/commit, scanner/query version, analysis date, branch, permissions and available
   exports. A 403/404 or absent alert export is unavailable evidence, not evidence of zero findings.
   Distinguish code scanning, dependency alerts and secret scanning; do not infer one from another.
2. Reconcile each scanner candidate with the operation/invariant dossier. Record tool/query/alert IDs,
   existing defenses, false-positive reasons and blind spots. “No alerts” does not establish policy,
   runtime authorization, concurrency safety or complete scope. Avoid categorical claims that a scanner
   can never detect a class; actual query packs, models and analyzed code determine coverage.
3. For third-party code scanning, GitHub accepts supported SARIF. Keep stable rule IDs, precise locations,
   distinct findings/fingerprints and source revision. Preserve independent evidence/verification and
   assurance fields in the companion report; SARIF risk metadata must not silently promote a hypothesis.
   Uploading is an external write: prepare/review/redact artifacts first and obtain task authorization.
4. For sensitive vulnerability disclosure, follow the target security policy/private reporting channel.
   Private vulnerability reporting is available when configured by the target. If unavailable, ask for
   a security contact without posting exploit details publicly. Routine nonsensitive issue work can use
   the `managing-github-issues` skill for deduplication, redaction, taxonomy and dry-run payload review.
5. Never include credentials, live connection strings, customer data or private target dossiers in this
   public package or review bundle. A private advisory and a code-scanning SARIF upload are different workflows.

Official references (checked 2026-10-28):
- [About SARIF](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files)
- [SARIF support and fingerprints](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [Upload SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- [Private reporting guidance source](https://github.com/github/docs/blob/main/content/code-security/how-tos/report-and-fix-vulnerabilities/report-privately.md)

## Report and submission completion checks

- Review high-impact boundaries independently of an earlier report's severity distribution. Trace
  workflow event type, base repository, head repository, branch and exact commit separately. Check
  trust before candidate code executes; a validator inside an untrusted checkout cannot authenticate
  that checkout. Verify live environment protection when the sourced policy relies on approval.
- Follow the complete production call path, including downstream repair and compensation. A failing
  isolated helper does not establish a reachable end-to-end defect when a later verified defense
  defeats it. Distinguish full-path reproductions, helper probes, synthetic models and static proof.
- Maintain one disposition per candidate/previous issue: established, refuted or unresolved. Compute
  severity totals from current established findings; exclude refuted claims and label historical
  priorities separately. Call static findings established rather than dynamically reproduced.
- Make the maintainer report self-contained: source revision/lines, invariant, prerequisites, full
  trace, defenses, safe reproduction, observed results, remediation and acceptance criteria. Do not
  require access to local issue files. Separate confirmed findings from unverified backlog/proposals.
- Prepare GUI/API fields: title, summary, details, proof of concept, impact, actual ecosystem/package,
  affected version/range, verified patched version if any, severity or CVSS, and supported CWE IDs.
  The API short `summary` is the title; combine narrative sections in `description`. Use the installed
  `managing-github-issues` GHAS reporting guide for its reviewed private GUI/API submission workflow;
  the audit skill remains usable without installing that optional companion.
- Verify every affected-product row has a supported `vulnerable_version_range` before declaring it
  publication-ready. A commit in the narrative alone is insufficient. Resolve a release tag to the
  audited commit; for one established release use an exact value such as `= 1.2.3`, not an invented
  all-earlier-versions range. Explain non-versioned/configuration-only scope explicitly.
- A private report may be accepted into triage while GitHub still reports missing affected versions.
  Record submission acceptance and publication readiness separately. Correct missing metadata using
  a reviewed GUI edit or authorized advisory PATCH, preserving the full existing product list and
  advisory state. Leave unknown patched versions unset; do not publish or claim a fix to clear a warning.
- A No known CVE notice means no identifier has been assigned, not that the private report failed.
  Keep CVE assignment separate from required affected-version data and optional patched-version
  suggestions. Maintainers can request an identifier through the appropriate workflow; never invent one.
- Read back the returned advisory state, product/range data and visible required-information warnings.
  Capture the GHSA/URL and remaining gaps. Authorization to submit privately is distinct from public
  publication or SARIF upload. Never disclose credentials or private target evidence in this skill.

Submission metadata references:
- [Advisory creation, private reports and updates](https://docs.github.com/en/rest/security-advisories/repository-advisories)
- [Affected-version and advisory-writing guidance](https://docs.github.com/en/code-security/tutorials/fix-reported-vulnerabilities/write-security-advisories)
