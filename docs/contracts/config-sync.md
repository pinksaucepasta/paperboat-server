# Configuration Sync Contract

The control plane is authoritative for repository connections, machine assignment,
plaintext-storage consent, machine eligibility, scoped repository access, writer leases,
conflict actions, and status revisions. The assigned `pb` config worker alone reads or
mutates managed home paths and Git worktrees.

## Rollout and compatibility

- `disabled`: no helper config runtime or repository access.
- `read_only`: current eligible machines may restore, poll, report, and preserve
  conflicts. Writer lease acquisition returns `config_writes_disabled`.
- `leased_writes`: current eligible helpers may acquire fenced writer leases.
- Every personal machine additionally requires the current plaintext-storage warning
  consent.
- Missing or unknown runtime mode, policy format, policy revision, machine generation,
  assignment, warning revision, or mandatory exclusions fails disabled.

## Repository and assignment

Repository identity is `(owner_user_id, provider, external_repository_id)`. Provider
owner/name and clone URL are display/transport data, never identity. A repository is
usable only in `active` state with current authorization and scoped-access capability.

Each machine has at most one assignment. Mutations use `expected_version`.
Disconnect, unassign, consent removal, warning change, machine replacement, machine
revocation, and authorization loss stop new credentials/access/leases before cleanup.

`.pbinclude` is the required repository-root allowlist and `.pbignore` is the optional
Gitignore-compatible exclusion file. Empty `.pbinclude` is a healthy no-op. Selected
content is ordinary plaintext in the connected private Git repository; Paperboat does
not discover, classify, recommend, or automatically include paths.

## Writer lease

One repository has at most one current writer. A lease binds repository, assignment,
machine, machine generation, base remote revision, expiry, operation ID, and a
monotonic fencing token. Acquire/renew/release are idempotent. A helper:

1. fetches and observes read-only state without a lease;
2. revalidates current authorization immediately before apply;
3. for a publication, acquires against the observed head, fetches and reconciles again;
4. renews and revalidates authorization/head immediately before a normal fast-forward
   push;
5. never retries an ambiguous push until remote observation proves its outcome.

## Conflict

A same-path non-identical three-way change stops automated work. Conflict revision is
SHA-256 over repository, assignment, remote head, relative path, and base/local/remote
content digests. Both exact sides are retained only in private, permission-protected local
runtime state; server metadata contains only bindings, relative path, byte count, reason,
revisions, and digests.

Resolution is one of `keep_local`, `keep_remote`, or `externally_resolved`, bound to the
current assignment version, remote revision, path, and conflict revision. Stale actions
are rejected. Baseline advancement, landed-resolution acknowledgement, and artifact
cleanup are crash-journaled.

## States and errors

Canonical states are `disabled`, `consent_required`, `restoring`, `watching`, `pending`,
`syncing`, `healthy`, `warning`, `conflict`, `offline`, `revoked`, `sync_uncertain`, and
`error`.

Stable recovery errors include `assignment_required`, `consent_required`,
`warning_revision_stale`, `credential_expired`, `config_writes_disabled`, `lease_busy`,
`lease_lost`, `remote_revision_changed`, `config_conflict`,
`repository_unavailable`, `flush_timeout`, and `sync_uncertain`.

Status is monotonic by sync revision and bound to repository, assignment, environment,
machine generation, warning, and policy revisions. The runtime descriptor includes the
authoritative sync-revision floor so a restarted worker advances beyond the last
accepted revision. A newer status report for the same revision may replace an earlier
status report; an older worker timestamp or revision is rejected. Summaries are bounded
and never contain file contents, absolute paths, credentials, keys, provider responses,
or command output.
