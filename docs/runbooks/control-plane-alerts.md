# Control-Plane Alerts

The server `/metrics` endpoint is localhost-only. Each helper also exposes metrics only on
its configured numeric loopback listener. Scrape both through trusted host-local
collectors; never expose or route either endpoint publicly.

## Required Alerts

| Signal | Warning | Critical | First response |
| --- | --- | --- | --- |
| `control_operation_oldest_age_seconds` | 60 seconds | 300 seconds | Check worker health, lease expiry, and provider errors. |
| `control_operation_dead_letter_depth` | greater than 0 | greater than 5 | Inspect the operation and use the authenticated recovery workflow only after resolving the cause. |
| `control_reconciliation_oldest_age_seconds` | 60 seconds | 180 seconds | Check database contention, stale desired versions, and tunnel health. |
| `control_stale_node_depth` | greater than 0 for two control intervals | greater than 0 for five intervals | Confirm heartbeat loss, connector fencing, and route reassignment. |
| `hosted_orchestration_queue_depth` | above 10 for 5 minutes | above 50 for 5 minutes | Check orchestrator worker health and database lock/latency; inspect expired leases before restarting workers. |
| `hosted_orchestration_expired_lease_depth` | greater than 0 for 2 minutes | above 5 for 5 minutes | Confirm workers are progressing; expired jobs are reclaimable, but investigate repeated expiry and fencing failures. |
| `hosted_orchestration_oldest_age_seconds` | 120 seconds | 600 seconds | Correlate with queue depth, provider latency, and worker logs. |
| `hosted_provider_uncertain_depth` | greater than 0 | increasing for 10 minutes | Observe provider state using the preserved request ID; for non-observable secret deletion use the admin recovery workflow. |
| `hosted_provider_retryable_depth` | greater than 10 for 5 minutes | greater than 50 for 10 minutes | Check provider capacity/rate limits and allow queued retries to drain; do not manually duplicate mutations. |
| `hosted_provider_oldest_age_seconds` | 120 seconds | 600 seconds | Inspect the provider operation journal and orchestration lease before retrying. |
| `hosted_readiness_failure_depth` | greater than 0 in 15 minutes | greater than 5 in 15 minutes | Inspect the stage (`workspace`, `config_restore`, `helper_health`, `connector_admission`, or `runtime_dependencies`) and routed helper evidence. |
| `hosted_orphan_review_depth` | greater than 0 | greater than 5 | Review the orphan finding and provider inventory; adoption/deletion requires explicit operator approval. |
| `billing_*_uncertain_depth` | greater than 0 | increasing for 15 minutes | Follow `billing-uncertain-operations.md`; verify provider state before retrying. |
| `provider_*_errors_total` | error ratio above 2% for 5 minutes | above 10% for 5 minutes | Check provider status, request latency, credentials, and rate limits. |
| `provider_*_latency_ms_max` | above configured request timeout's 75% | reaches configured timeout | Correlate with errors and operation uncertainty before changing retry policy. |
| `user_machine_bootstrap_failure_depth` | greater than 0 | increasing across two release intervals | Inspect the typed install stage, signed artifact compatibility, administrator denial, and rollback evidence. |
| `user_machine_heartbeat_oldest_age_seconds` | above the configured stale-heartbeat interval | above five intervals | Correlate worker boot scope, renewal, DNS, connector recovery, and host reachability before re-enrollment. |
| `user_machine_availability_drift_depth` | greater than 0 for two heartbeat intervals | increasing for five intervals | Compare desired/observed versions and inspect root host-service diagnostics. |
| `user_machine_privileged_service_error_depth` | greater than 0 | increasing after retry | Inspect logind/pmset errors and restore the captured power baseline before manual changes. |
| `user_machine_unsupported_host_scope_depth` | greater than 0 | any newly bootstrapped machine | Stop rollout; only system scope is a successful privileged bootstrap. |
| `paperboat_helper_restart_total` | repeated restarts within 5 minutes | sustained restart loop | Inspect boot ID/generation, service exit status, and bounded logs. |
| `paperboat_helper_renewal_failures_total` | increasing for two credential refresh attempts | credential expiry without recovery | Check proof freshness, active helper key, revocation, and server signing-key health. |
| `paperboat_helper_connector_recovery_seconds` | above 60 seconds | sustained unavailability after network restoration | Check interface/DNS wakeups, admission, QUIC, and TCP/TLS fallback. |
| `paperboat_helper_update_rollbacks_total` | greater than 0 | repeated for the same release | Stop rollout and inspect paired signatures, journal stage, worker health, and preserved previous versions. |

Every alert record must include the deployment, request or operation ID when
available, first observation time, current depth/age, and recovery decision.
Do not include credentials, signed URLs, request bodies, terminal data, or
provider secrets.

Close an incident only after the metric returns to baseline and the durable
operation, reconciliation, route, or billing record agrees with provider and
tunnel observations.

## Hosted Provider Recovery

For an uncertain hosted secret deletion, an authenticated administrator may call
`POST /v1/admin/hosted-provider-operations/{operation_id}/recover` with either
`confirm_deleted` (after independent provider evidence) or `retry`. The request
must include CSRF protection and an idempotency key. Evidence is hashed before
being persisted or added to the audit log. Never use `confirm_deleted` without
provider-side evidence; use `retry` when the provider state is absent or the
mutation can be safely repeated.
