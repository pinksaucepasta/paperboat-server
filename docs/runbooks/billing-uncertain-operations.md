# Billing Uncertain Operations

Billing provider calls that may have succeeded before a timeout are recorded as
`uncertain`. Do not issue the same mutation with a new idempotency key.

## Triage

1. Locate the operation by its idempotency key in `billing_checkout_reservations`,
   `billing_portal_operations`, `billing_subscription_update_operations`, or
   `credit_auto_topup_attempts`.
2. Compare the provider dashboard and webhook history using the provider
   subscription, checkout, or customer identifiers. Do not copy URLs, tokens, or
   card data into the incident record.
3. If the provider confirms success, replay the corresponding webhook or wait for
   the normal webhook consumer. The server will converge the durable state.
4. If the provider confirms no mutation, retry only with the original
   idempotency key through the normal user workflow, after recording the provider
   decision and operator approval.

Never change an uncertain row directly to `failed` or `succeeded` without provider
evidence. Preserve the original request hash and operation key so a later retry
cannot create a second provider mutation.

When provider evidence proves that no mutation occurred, an administrator may call
`POST /api/admin/billing/uncertain/{kind}/{operation_id}/recover` with the original
operation idempotency key as `operation_id`, a new `Idempotency-Key` for the recovery,
and `{ "evidence_reference": "<opaque-provider-or-incident-reference>" }`. Supported
kinds are `checkout`, `portal`, `subscription_update`, and `auto_topup`.

The endpoint stores and audits only the SHA-256 of the evidence reference. It atomically
moves exactly one still-uncertain record to its existing retryable `failed` state. Exact
recovery retries are no-ops; conflicting keys and non-uncertain targets are rejected. It
never marks a provider mutation successful and never fabricates a URL, order,
subscription, or webhook result.
