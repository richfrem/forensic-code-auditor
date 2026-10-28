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
   public package or review ZIP. A private advisory and a code-scanning SARIF upload are different workflows.

Official references (checked 2026-10-28):
- [About SARIF](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files)
- [SARIF support and fingerprints](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [Upload SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- [Private reporting guidance source](https://github.com/github/docs/blob/main/content/code-security/how-tos/report-and-fix-vulnerabilities/report-privately.md)
