# CLI Authorization Contract

Status: Phase 0 frozen implementation target.

This contract owns Paperboat public-client authorization. All JSON responses use the
standard `{ "data": ... }` success envelope or `{ "error": { "code", "message",
"request_id", "details" } }` error envelope. High-entropy secrets are never accepted in
query parameters; only the short `user_code` may appear in the browser approval URL.

## Client And Scopes

The registered client id is `paperboat-cli`. Its exact allowed Paperboat scopes are:

- `account:read`
- `clients:revoke`
- `projects:read`
- `projects:connect`
- `session:refresh`

The CLI must request that exact set. The server rejects missing, duplicate, or additional
scopes; ordering is not significant. Token responses return a normalized space-delimited
list. Unknown clients return `invalid_client`; a non-exact or malformed scope set returns
`invalid_scope`. Other malformed authorization requests return `validation_failed`.

## Device Authorization

`POST /api/auth/device/authorize` is unauthenticated. It accepts `client_id`,
`client_label`, `device_type`, `os`, and `scopes`. `client_label` is presentation-only,
trimmed, and length-limited. `device_type` is one of `desktop`, `server`, or `container`.
The response contains `device_code`, `user_code`, `verification_uri`,
`verification_uri_complete`, `expires_in`, and `interval`.

Device-code lifetime and polling interval are dynamic server configuration. The response is
authoritative for the grant. The initial production defaults are 600 seconds and 5 seconds;
changing them does not change the wire contract. `verification_uri_complete` contains only
the user code. Device codes have at least 256 bits of entropy. User codes use an
unambiguous uppercase alphabet and are formatted for reading, but comparisons ignore the
separator and ASCII case.

`POST /api/auth/device/token` accepts exactly `client_id` and `device_code`. Before approval
it returns HTTP 400 with `authorization_pending`. Polling faster than `interval` returns
HTTP 400 with `slow_down`, includes the next `interval` in `error.details`, and resets the
grant's next allowed poll time. Denial and expiry return HTTP 400 with `access_denied` and
`expired_token`. An unknown, malformed, already-consumed, or client-mismatched device code
returns `invalid_grant`. General rate limiting returns HTTP 429 `rate_limited` with
`Retry-After`; thresholds are dynamic configuration applied independently by network,
device grant, and account.

Approval atomically transitions the grant from `pending` to `approved`; it does not consume
the grant or issue tokens. Exactly one successful token poll atomically transitions the
grant from `approved` to `consumed` while returning
`access_token`, `refresh_token`, `token_type: "Bearer"`, `expires_in`, `scope`, and
`client_session_id`. Access-token lifetime is dynamically configured; the initial production
default is 900 seconds. Poll responses and token responses use `Cache-Control: no-store` and
`Pragma: no-cache`.

Device codes, access tokens, and refresh tokens are stored only as keyed hashes. User-code
lookup uses a separate keyed hash because the short code has low entropy. Raw values are
returned only at issuance and are excluded from logs, traces, audit metadata, and analytics.

## Browser Approval

The dashboard approval endpoints use the HttpOnly WorkOS-backed cookie session. GET requires
the cookie; POST additionally requires the CSRF header and cookie pair.

- `GET /api/auth/device/requests/{user_code}`
- `POST /api/auth/device/requests/{user_code}/approve`
- `POST /api/auth/device/requests/{user_code}/deny`

Lookup returns client label, device type, OS, requested scopes, issue time, expiry, user
code, and state. It never returns the device code or any token. Approval is bound to the
currently authenticated user. Denial and expiry are terminal; approval is an intermediate
state that only the successful token poll may transition to `consumed`. Retrying the same
approve/deny action returns HTTP 200 with the current state and never issues a token set.
Attempting the opposite action returns HTTP 409 `device_request_not_pending`. Acting on
expired or consumed requests returns HTTP
410 `device_request_expired` or `device_request_consumed`.

## Refresh And Revocation

Refresh tokens are bearer credentials sent only as `Authorization: Bearer <refresh_token>`
to `POST /api/auth/token/refresh`; there is no token in the JSON body. Every successful
refresh rotates the refresh token and returns a new access/refresh pair. Reuse of a rotated
token revokes the entire client-session family. Concurrent refresh is serialized per family;
only one request succeeds.

`POST /api/auth/token/revoke` accepts either the current access or refresh token as a bearer
credential and idempotently revokes its client-session family. `GET /api/auth/clients` and
`DELETE /api/auth/clients/{client_session_id}` accept either the WorkOS-backed dashboard
cookie session (with CSRF on DELETE) or an access token. Bearer listing requires
`account:read`; bearer deletion requires `clients:revoke`. The target must belong to the
same Paperboat account. Account suspension, administrative revocation,
logout, refresh replay, and explicit client deletion revoke Paperboat access and all
recorded downstream papercode sessions.

`GET /api/auth/clients` accepts `limit` (1-200, default 50), `offset` (default 0), and an
optional `state=active|revoked`. Its `data` contains `items` and `pagination`. Every item
contains `client_session_id`, `client_id`, `client_label`, `device_type`, `os`, normalized
`scopes`, `state`, `created_at`, `approved_at`, nullable `last_used_at`, nullable
`revoked_at`, nullable `revocation_reason`, and `current`. Pagination contains `limit`,
`offset`, `total`, and nullable `next_offset`. Secrets are never included.

## Credential Profile

Paperboat clients share only a versioned profile contract: issuer/server identity, account
metadata, client-session id, access expiry, and opaque operating-system credential-store
references. Access and refresh values live in macOS Keychain, Windows Credential Manager,
or Linux Secret Service. A plaintext file fallback is disabled by default; explicit headless
fallback requires mode `0600` and a visible warning. Profiles are namespaced by normalized
issuer and updated atomically under an inter-process refresh lock.
