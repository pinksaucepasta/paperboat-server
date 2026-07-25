# Configuration Sync Contract

The control plane is authoritative for repository connections, environment assignment,
BYOD warning consent, helper eligibility, scoped repository access, writer leases,
classification policy, key versions, conflict actions, and status revisions.
`paperboat-helper` alone reads or mutates managed home paths and Git worktrees.

## Rollout and compatibility

- `disabled`: no helper config runtime or repository access.
- `read_only`: current eligible helpers may restore, poll, classify, report, and preserve
  conflicts. Writer lease acquisition returns `config_writes_disabled`.
- `leased_writes`: current eligible helpers may acquire fenced writer leases.
- BYOD additionally requires the current warning consent and the BYOD rollout gate.
- An environment allowlist, when non-empty, is an additional eligibility condition.
- Missing or unknown runtime mode, policy format, policy revision, helper generation,
  assignment, warning revision, key version, or mandatory exclusions fails disabled.

## Repository and assignment

Repository identity is `(owner_user_id, provider, external_repository_id)`. Provider
owner/name and clone URL are display/transport data, never identity. A repository is
usable only in `active` state with current authorization and scoped-access capability.

Each environment has at most one assignment. Mutations use `expected_version`.
Disconnect, unassign, consent removal, warning change, helper replacement, environment
revocation, and authorization loss stop new credentials/access/leases before cleanup.

## Writer lease

One repository has at most one current writer. A lease binds repository, assignment,
environment, helper, helper generation, base remote revision, expiry, operation ID, and a
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
content digests. Both exact sides are retained age-encrypted; plaintext metadata contains
only bindings, relative path, byte count, reason, revisions, and digests.

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
`repository_unavailable`, `encryption_key_stale`, `flush_timeout`, and
`sync_uncertain`.

Status is monotonic by sync revision and bound to repository, assignment, environment,
helper generation, warning, policy, and key revisions. The runtime descriptor includes
the authoritative sync-revision floor so a restarted helper advances beyond the last
accepted revision. A newer status report for the same revision may replace an earlier
status report; an older helper timestamp or revision is rejected. Summaries are bounded
and never contain file contents, absolute paths, credentials, keys, provider responses,
or command output.
