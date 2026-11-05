# Local authority and application handoff runbook

## Contents

- [Scope and principals](#scope-and-principals)
- [Reconstruct handoffs](#reconstruct-handoffs)
- [Discriminating proof and coverage](#discriminating-proof-and-coverage)

## Scope and principals

Use for discovered local daemons/IPC, privileged helpers, native messaging, deep links, file-open
handlers, webviews and mobile exported components. Apply [the contract](../instructions.md). Name the
starting capability: another OS user, another app, sandboxed child, remote frame or untrusted file.
Same-account intended authority is not automatically a privilege boundary. Source actual OS/app
isolation, entitlement and consent requirements; a process name or path is not peer authentication.

## Reconstruct handoffs

1. Inventory processes, sockets/pipes, XPC/Binder/D-Bus interfaces, loopback listeners, URI/file
   registrations, helpers and webview origins. Record effective privilege, peer credentials, callable
   operations, owner/resource scope and final packaging inputs. Missing merged manifests, installer
   ACLs, entitlements or runtime policy remain unavailable evidence.
2. Trace authenticated channel identity into each requested account/profile/action/resource. Inspect
   claimed sender fields, inherited handles, stale channels, request correlation and reconnect/restart
   behavior. Shape validation does not authorize a privileged helper's selected command or destination.
3. Follow normalized file paths and content through install, update, repair and open-file operations.
   Inspect symlink/replacement races, ownership and check/use binding. Identify the final opened object
   and the enforcing control; do not assume a checked pathname still names the consumed bytes.
4. Reconstruct deep-link, OAuth/device-pairing and notification handoffs. Bind pending state to current
   app/session/account, operation, expiry and one-time completion. Compare retry, fallback and aliases.
5. Trace remote/subframe content through navigation, redirects, errors and native bridge dispatch.
   Determine which origin can invoke each privileged operation at call time. Inspect generic bridge
   commands, file/credential returns and required user-presence/action binding.
6. Inspect logout/account switch, stale tabs, background tasks, notifications, local stores and device
   restore. Compare current authority with retained approvals and cached content. Plaintext accessible
   only to its intended OS principal is not independently a cross-principal disclosure.

## Discriminating proof and coverage

Use explicitly authorized disposable local/emulator resources, dummy profiles and inert files only.
Pair permitted and denied peers, then test normalized-resource substitution, stale callbacks, account
switch and a changed webview origin. Independently contain target code; do not interact with other
users' apps, keychains or credentials. Assert final file/state and external mock effects, not merely
UI prompts. A missing OS toolchain or deployed signature/ACL is a bounded verification limit.

Attach the peer/operation matrix, packaging provenance, final-object trace and unavailable controls to
the nine-item dossier. Classify the established authority, tenant, replay or check/use breach with the
existing taxonomy. This reference adds manual operation tracing, not native memory-safety detectors
or proof that every OS interface was discovered.
