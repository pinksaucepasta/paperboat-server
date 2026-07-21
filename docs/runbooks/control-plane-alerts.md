# Control-Plane Alerts

The `/metrics` endpoint is localhost-only. Scrape it through the deployment's
trusted metrics collector; never expose it publicly.

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

Every alert record must include the deployment, request or operation ID when
available, first observation time, current depth/age, and recovery decision.
Do not include credentials, signed URLs, request bodies, terminal data, or
provider secrets.

Close an incident only after the metric returns to baseline and the durable
operation, reconciliation, route, or billing record agrees with provider and
tunnel observations.

## Hosted Provider Recovery

For an uncertain hosted secret deletion, an authenticated administrator may call
`POST /api/admin/hosted-provider-operations/{operation_id}/recover` with either
`confirm_deleted` (after independent provider evidence) or `retry`. The request
must include CSRF protection and an idempotency key. Evidence is hashed before
being persisted or added to the audit log. Never use `confirm_deleted` without
provider-side evidence; use `retry` when the provider state is absent or the
mutation can be safely repeated.
