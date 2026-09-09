# Security Policy

## Supported versions

| Version | Supported |
| --- | :--: |
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability in GuardEnv

Use GitHub's **private vulnerability reporting** on this repository's Security
tab. Please do not open a public issue.

Include the GuardEnv version, the platform, and a reproduction — a synthetic
input file is ideal. We aim to acknowledge within three working days.

## Reporting a missed detection

A credential format GuardEnv fails to detect is an ordinary bug, not a
vulnerability. Open a public issue with a **synthetic** example of the format.
Never paste a real credential into an issue, even a revoked one.

## Scope

In scope:

- Crashes, hangs or unbounded resource use triggered by a crafted input file
  (catastrophic regex backtracking, decompression or allocation blowups).
- Any path by which GuardEnv writes a credential somewhere it should not — an
  unredacted value in a report, a baseline, a log line or an error message.
- Path traversal or unintended writes during a scan. GuardEnv only ever reads
  the tree it is pointed at.

Out of scope:

- False negatives for credential formats that have no rule yet (open an issue).
- False positives (open an issue).
- Findings in the `examples/` and `tests/` directories — every credential there
  is synthetic and non-functional by design.

## Handling your secrets

GuardEnv is offline by construction, and this is a deliberate design constraint
rather than a missing feature:

- It makes **no network calls**. Findings are never validated against provider
  APIs, because validating would mean transmitting your credentials to a third
  party.
- It sends **no telemetry**.
- It **never writes to the tree it scans**. Reports go to stdout or to a path you
  name with `--output`.
- Reports, previews and baselines carry **redacted** values by default
  (`AKIA********DNPQ`). `--show-secrets` opts into raw values for local triage.
- The browser playground runs entirely client-side. Pasted text never leaves the
  tab, and there is no backend to leave it to.

## After a leak is found

Finding the credential is the easy half. Removing it from the working tree is
not enough — assume anything committed is compromised.

1. **Revoke and rotate at the provider first.** Do this before cleaning history.
2. Remove the value from the working tree and move it into a secrets manager or
   your CI secret store.
3. Purge it from git history (`git filter-repo`, or BFG) and force-push, then
   have every collaborator re-clone.
4. Check the provider's audit log for use of the credential while it was exposed.
5. Record the finding in a baseline only after it is rotated — a baseline
   acknowledges a finding, it does not fix one.
