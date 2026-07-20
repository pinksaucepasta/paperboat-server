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
