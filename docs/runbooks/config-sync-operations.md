# Configuration Sync Operations

This runbook is metadata-only. Never copy credentials, age identities, file contents,
absolute home paths, provider responses, or conflict ciphertext into tickets or logs.

## Emergency writer stop

1. Set `PAPERBOAT_CONFIG_SYNC_MODE=disabled` and deploy the control plane.
2. Confirm new runtime, access, classifier, and lease authentication is refused.
3. Revoke active repository leases and scoped access operations through the approved
   operator workflow. Do not re-enable the historical server writer.
4. Preserve canonical statuses, encrypted baselines, apply/resolution journals, conflict
   artifacts, and key overlap. Do not reset repositories or delete helper state.
5. Restore as `read_only` first. Promote explicit environment cohorts to
   `leased_writes` only after their remote heads and pending state are reviewed.

## Authorization loss or stuck lease

- Repository disconnect and assignment/consent removal are the normal immediate stop.
- Reclaim a lease only after recorded expiry or explicit revocation. Never edit fencing
  tokens or force-push.
- For an uncertain push, observe the remote commit ID. Mark it landed only when reachable
  from the configured branch; otherwise retain `sync_uncertain` and reconcile from the
  observed head.

## Conflict recovery

- Verify the environment reports the current assignment version, remote revision, and
  64-character conflict revision.
- The owner chooses `keep_local`, `keep_remote`, or `externally_resolved`. Never infer a
  choice. After any local, remote, assignment, helper, or policy change, refresh and ask
  again.
- Both sides remain age-encrypted until the chosen commit/application lands and helper
  acknowledgement is durable.

## Apply journal, disk, and permission failures

- Stop the helper before filesystem repair. Preserve `apply-journal.age` and
  `resolution-commit.age`.
- Restore free space and original ownership/permissions without opening encrypted files.
  Restart the same assignment/helper binding; startup rolls back an incomplete apply and
  retries an unacknowledged landed resolution.
- A journal with another repository or assignment binding is not reusable. Quarantine
  the state directory for review.

## Migration quarantine and key rotation

- Review `control_config_repository_migration_reviews` and
  `control_config_sync_migration_reviews`. Reconnect repositories through current GitHub
  App authorization and verify local/remote snapshots before enabling writes.
- Historical statuses are evidence, never canonical authority.
- Retain the previous age key until every active canonical assignment reports the new key
  version. Offline environments delay retirement; they are not silently dropped.

## Rollback evidence

Record redacted server/helper revisions, rollout mode, environment cohort, repository and
assignment IDs, helper generation, lease operation/fencing IDs, remote revisions, warning
and key revisions, timestamps, and check results. Rollback must preserve pending work and
must never start an unfenced writer.
