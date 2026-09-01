# Private Access Contract

Status: implemented end to end across the server, stable host runtime, and edge.

`paperboat-server` is the authority for private preview and tunnel access. It
does not persist a reusable bearer or proxy application traffic. Every decision
is bound to the current account, resource, route, carrier session, process and
configuration generations, and the authenticated edge node/process epoch.

## Grant issuance

`POST /v1/edge/private-access/grants` is a stable-host-only endpoint. Hostd
supplies its renewable `machine_control` credential in both `Authorization:
Bearer` and `X-Paperboat-Machine-Identity`, plus a strict base64url
`X-Paperboat-Machine-Proof` bound to the exact method, path, and body. Browser
sessions, cookies, and public-request proofs are not accepted. The body is strict `application/json` and
contains only the target and route binding: `resource_kind`, `resource_id`,
`route_id`, audience, expiry, nonce, operation/connector/carrier IDs, all
route, session, process, config, and assignment generation fences, exact edge
node/process, protocol and optional HTTP method/host/path, plus the
idempotency, request and correlation identifiers. Account, device and session
identity are derived from the verified proof and are rejected if supplied in
the body.

## Same-account route discovery

`POST /v1/private-access/routes` uses the same renewable machine credential,
exact-body proof, and matching idempotency key. It returns a bounded
`complete: true` snapshot or fails without publishing a partial snapshot.
Only online, non-revoked machines see current private routes in their account.
Each row carries the accessor public key and thumbprint, authoritative
assignment ID and configuration content hash, exact route match metadata,
carrier identity, edge node/process epoch, and every installation, route,
session, process, config, and assignment generation. Preview ownership and
connector ownership do not grant accessor authority.

Durable tunnel rows also carry validated `tunnel_name` and `route_name` as
safe selector metadata. Stable hostd resolves `pb access tunnel
<tunnel-or-route>` against exact IDs or exact case-sensitive names only inside
this bounded current-machine snapshot. Zero matches are non-enumerating
forbidden access. Multiple matches, including name-to-ID collisions, are
temporarily unavailable and never open a local listener or carrier.

`POST /v1/edge/private-access/carrier-admissions` is edge-only and returns the
same complete secret-free projection for the authenticated current edge
process. Replaced edge epochs and stale assignments return no admission.

The server resolves the exact current private binding, checks revocation and
expiry, and returns one short-lived signed grant. Grant bytes are write-only at
this boundary, are never placed in audit metadata, and are not stored by the
server. Audience is exact: `paperboat-preview-http`,
`paperboat-tunnel-http`, or `paperboat-tunnel-tcp`.

## Edge authorization

`POST /v1/edge/private-access/authorize` requires only edge authentication and accepts the signed grant in
`X-Paperboat-Private-Access-Grant`. Its strict body is the complete signed
request. Accessor identity is derived only from verified signed claims. The server verifies the grant, freshly rechecks machine revocation and installation generation, re-resolves current state, checks the
exact edge node and process epoch, and returns a bounded decision. Denials are
typed internally but do not disclose account, resource, route, or operation
existence. Revocation, route replacement, expiry, generation mismatch, and
edge replacement therefore close access immediately.

The edge may cache an allowed decision only until the returned `expires_at` and
must re-authorize before opening a new stream after expiry. It must fail closed
when authorization or revocation refresh is unavailable. HTTP matching is an
exact host plus path-segment boundary match. TCP uses the same authorization
flow with the `paperboat-tunnel-tcp` audience and has no HTTP fields.

Private HTTP failures use one stable status mapping. `401 Unauthorized` means
the local host runtime did not supply a valid current machine-session grant.
`403 Forbidden` means the authenticated machine is not allowed to use the
resolved route, including revocation and account or route mismatch. `503 Service
Unavailable` means hostd, the edge binding, or the authorization
authority is temporarily unavailable or generation state is uncertain. These
responses never disclose whether a different account owns the hostname or
route. The browser is not redirected to a login flow and receives no Paperboat
cookie or access token.

## Downstream edge requirements

The edge must authenticate its own node/process epoch before calling the
authorize endpoint, preserve streaming after an allowed decision, and never log or
persist the signed grant. The machine proof is consumed only by the grant endpoint
and never enters the carrier or edge. The edge must pass the exact route, carrier
session, connector/session, and process/config generation values from the
current admission. It must reject stale decisions and close active streams on
expiry or a failed revocation/authorization refresh.

For private HTTPS, the internal connection from the authorized carrier to the
TLS terminator must retain an unforgeable, bounded binding to the exact approved
route and generations. A shared internal-listener token alone is insufficient:
after TLS termination the normal host/path match must equal that connection
binding, so a grant for one route cannot select a sibling route or hostname.

Durable tunnel authorization remains fail-closed until the server has a stable
current edge-assignment row containing the node and process epoch. Preview
attachments already carry that binding. No legacy public relay, FRP bearer, or
durable tunnel row is a substitute for this check.
