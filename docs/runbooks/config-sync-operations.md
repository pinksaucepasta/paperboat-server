# Configuration Sync Operations

This runbook is metadata-only. Never copy credentials, file contents, absolute home
paths, provider responses, or local conflict variants into tickets or logs.

## Emergency writer stop

1. Set `PAPERBOAT_CONFIG_SYNC_MODE=disabled` and deploy the control plane.
2. Confirm new runtime, repository access, and lease authentication is refused.
3. Revoke active repository leases and scoped access operations through the approved
   operator workflow. Do not re-enable the historical server writer.
4. Preserve canonical statuses and permission-protected local baselines,
   apply/resolution journals, and conflict variants. Do not reset repositories or delete
   worker state.
5. Restore as `read_only` first. Promote explicit environment cohorts to
   `leased_writes` only after their remote heads and pending state are reviewed.

## Authorization loss or stuck lease

- Repository disconnect and assignment/consent removal are the normal immediate stop.
- Reclaim a lease only after recorded expiry or explicit revocation. Never edit fencing
  tokens or force-push.
- For an uncertain push, observe the remote commit ID. Mark it landed only when reachable
  from the configured branch; otherwise retain `sync_uncertain` and reconcile from the
  observed head.

## Stale BYOD consent and offline edits

- A warning-revision change makes prior consent stale immediately. Confirm new
  credentials, repository access, and leases are refused before investigating helper
  state. Never extend the old warning revision to restore service.
- An offline worker keeps only private local reconciliation state. On reconnect it must obtain
  current eligibility and repository access before scanning or applying files.
- Reconcile offline edits from the current remote head under a new lease. Independent
  changes may converge; same-path changes must enter conflict recovery. Never declare the
  cached baseline current or publish it directly.

## Conflict recovery

- Verify the environment reports the current assignment version, remote revision, and
  64-character conflict revision.
- The owner chooses `keep_local`, `keep_remote`, or `externally_resolved`. Never infer a
  choice. After any local, remote, assignment, helper, or policy change, refresh and ask
  again.
- Both sides remain in private local state until the chosen commit/application lands and worker
  acknowledgement is durable.

## Apply journal, disk, and permission failures

- Stop the worker before filesystem repair. Preserve the apply and resolution journals.
- Restore free space and original ownership/permissions without copying their contents.
  Restart the same assignment/helper binding; startup rolls back an incomplete apply and
  retries an unacknowledged landed resolution.
- A journal with another repository or assignment binding is not reusable. Quarantine
  the state directory for review.

## Malicious or unsupported repository

- Stop before apply or publication when `.pbinclude` is absent or invalid, paths escape
  the source root, Git
  configuration/hooks alter execution, or an object exceeds policy bounds.
- Preserve the remote revision and bounded validation reason. Do not execute chezmoi
  source scripts, follow links, inspect content for diagnostics, normalize the repository in
  place, or create a replacement baseline.
- Quarantine the assignment for owner review. Recovery requires a separately verified
  plaintext revision or a newly connected repository.

## Assignment cleanup

- Review `control_config_repository_migration_reviews` and
  `control_config_sync_migration_reviews`. Reconnect repositories through current GitHub
  App authorization and verify local/remote snapshots before enabling writes.
- Historical statuses are evidence, never canonical authority.
- Remove disposable development state that predates the plaintext contract; do not add
  readers or conversion paths for obsolete encrypted formats.

## Rollback evidence

Record redacted server/helper revisions, rollout mode, environment cohort, repository and
assignment IDs, machine generation, lease operation/fencing IDs, remote revisions,
warning revisions, timestamps, and check results. Rollback must preserve pending work and
must never start an unfenced writer.
