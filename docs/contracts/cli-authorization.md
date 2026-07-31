# CLI Authorization Contract

Status: Contract frozen implementation target.

This contract owns Paperboat public-client authorization. All JSON responses use the
standard `{ "data": ... }` success envelope or `{ "error": { "code", "message",
"request_id", "details" } }` error envelope. High-entropy secrets are never accepted in
query parameters; only the short `user_code` may appear in the browser approval URL.

## Client And Scopes

The registered client id is `paperboat`. Its exact allowed Paperboat scopes are:

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

`POST /v1/auth/device/authorize` is unauthenticated. It accepts `client_id`,
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

`POST /v1/auth/device/token` accepts exactly `client_id` and `device_code`. Before approval
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
`cli_client_session_id`. Access-token lifetime is dynamically configured; the initial production
default is 900 seconds. Poll responses and token responses use `Cache-Control: no-store` and
`Pragma: no-cache`.

Device codes, access tokens, and refresh tokens are stored only as keyed hashes. User-code
lookup uses a separate keyed hash because the short code has low entropy. Raw values are
returned only at issuance and are excluded from logs, traces, audit metadata, and analytics.

## Browser Approval

The dashboard approval endpoints use the HttpOnly WorkOS-backed cookie session. GET requires
the cookie; POST additionally requires the CSRF header and cookie pair.

- `GET /v1/auth/device/requests/{user_code}`
- `POST /v1/auth/device/requests/{user_code}/approve`
- `POST /v1/auth/device/requests/{user_code}/deny`

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
to `POST /v1/auth/token/refresh`; there is no token in the JSON body. Every successful
refresh rotates the refresh token and returns a new access/refresh pair. Reuse of a rotated
token revokes the entire client-session family. Concurrent refresh is serialized per family;
only one request succeeds.

`POST /v1/auth/token/revoke` accepts either the current access or refresh token as a bearer
credential and idempotently revokes its client-session family. Retrying with a known token
from an already-revoked family returns success; an arbitrary or unknown bearer remains an
authentication failure and returns HTTP 401, matching OpenAPI. `GET /v1/auth/cli-client-sessions` and
`DELETE /v1/auth/cli-client-sessions/{cli_client_session_id}` accept either the WorkOS-backed dashboard
cookie session (with CSRF on DELETE) or an access token. Bearer listing requires
`account:read`; bearer deletion requires `clients:revoke`. The target must belong to the
same Paperboat account. Logout is session-scoped: `POST /v1/auth/logout` revokes only the
current WorkOS-backed browser session, while `POST /v1/auth/token/revoke` revokes the
calling CLI client-session family. Browser logout also tears down active downstream access
sessions, but it does not revoke independent CLI installations. Account suspension and
administrative account revocation revoke every CLI client-session family. Refresh replay
and explicit client deletion revoke the affected Paperboat family and mark its linked local
access-session records revoked immediately. Invalidating the actual terminal and file bearer
sessions inside helper requires the signed control-plane revocation endpoint tracked in
downstream integration; until that lands, those short-lived downstream credentials remain usable
until expiry. This capability must remain `Implemented`, not `Complete`, while this dependency is open.

`GET /v1/auth/cli-client-sessions` accepts `limit` (1-200, default 50), `offset` (default 0), and an
optional `state=active|revoked`. Its `data` contains `items` and `pagination`. Every item
contains `cli_client_session_id`, `client_id`, `client_label`, `device_type`, `os`, normalized
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
