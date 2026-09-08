# Paperboat P2P Contracts v1

This contract family is approved by the workspace owner for the P2P-primary transport
release. JSON objects are closed world, field names are snake case, timestamps are UTC
RFC 3339 with second precision, and binary values use canonical unpadded base64url.
Unknown fields, duplicate fields, trailing data, non-canonical encodings, zero generations,
expired authority, and generation rollback are terminal protocol failures.

The sections through **Stable errors** describe the running pre-Tailcat v1 contracts.
**Native migration boundaries** below freezes their replacement ownership and retention
rules; it does not claim that the replacement is implemented. The existing schema and
fixture copies in the CLI and server must change together at their migration gates.

## Endpoint certificates

An account has one or more active Ed25519 trusted signing keys, one per enrolled CLI
endpoint. Canonical certificate bytes are the existing `PBEC` binary
encoding: ASCII `PBEC`, version byte `1`, big-endian uint16 account-ID length and bytes,
one role byte (`1` CLI, `2` machine), big-endian uint16 endpoint-ID length and bytes,
32-byte X25519 Noise key, 32-byte Ed25519 QUIC key, then big-endian uint64 generation,
serial, issued Unix second, and expiry Unix second. The final 64 bytes are the Ed25519
signature over every preceding byte. Generation and serial are positive and at most
`9007199254740991`, IDs match
`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`, keys are non-zero, and expiry is after issuance.
The HTTP document contains the signing `key_id`, canonical unpadded-base64url certificate
bytes, and indexed metadata; metadata must exactly equal the parsed bytes. Certificates
are immutable and identified by `(account_id, endpoint_id, generation, serial)`. A
generation may have one active certificate. Supersession and revocation are server-side
state and do not alter certificate bytes. Verification selects the active trusted key by
`key_id`, checks its fingerprint and signature, then checks role, validity, generation,
serial, endpoint binding, supersession, and revocation.

`GET /v1/e2ee/root` returns the authenticated account's complete active trusted-key set.
The first CLI uses idempotent `POST /v1/e2ee/bootstrap` to create its trusted key and its
key-signed generation-1 certificate in one transaction. A fresh CLI bootstrap adds one new
trusted key and certificate without revoking other active endpoints. The CLI endpoint ID
must equal the authenticated CLI session ID. Exact replay returns the same authority; a
different key is an identity conflict. Every trusted-key entry includes its `key_id`,
public key, fingerprint, and generation.

Each machine installation generates and durably retains its own X25519 Noise private key
and Ed25519 QUIC private key. It publishes only the corresponding public keys through
machine-proof-authenticated `POST /v1/machine-peer-identity`, bound to the current machine
ID and installation generation. The server retains the pending request for five minutes.
The host and CLI independently derive the displayed lowercase safety code from the first
five bytes of `BLAKE2s("paperboat-machine-endpoint-v1" || 0x00 || endpoint_id || 0x00 ||
big_endian_generation || noise_public_key || quic_public_key)`, rendered `xxxxx-xxxxx`.
The CLI lists pending requests through `GET /v1/e2ee/pending-endpoints` but signs one only
after the user supplies the exact compared code. Certificate registration must match the
pending endpoint, generation, and both public keys and fulfills that request atomically.
The machine retrieves only the active trusted-key set and its approved certificate through a fresh
machine-proof-authenticated `POST /v1/machine-peer-identity/status`, then verifies the
certificate with its identified trusted key and checks the exact local public-key binding
before persistence. Request/status replay is
deterministic. A missing, expired, mismatched, conflicting, or revoked authority fails
closed. Trusted signing-key private material never enters the machine runtime or server,
and no endpoint private key enters any control-plane request, response, database, log, or
audit.

Registration uses `PUT /v1/endpoints/{endpoint_id}/certificates/{generation}` with the
certificate document and an operation ID. Identical replay succeeds; conflicting replay is
`operation_conflict`. Retrieval uses `GET` on the same resource. Revocation uses `DELETE`
with `If-Match` set to the quoted serial and is idempotent.

## Peer attempt descriptors

`POST /v1/peer-attempts` is authenticated and idempotent by `operation_id`. It returns one
descriptor for an exact intent, endpoint pair, role, attempt generation, and network
generation. Both role views include the account ID, initiating CLI device ID, original
operation ID, current machine installation generation, and current runtime-connector
authorization generation. They include the complete active `trusted_keys` set, and each
entry in `endpoint_certificates` includes the signing `key_id` alongside the certificate.
They also include one exact server-authorized consumer;
interactive authority permits only `terminal`, `exec`, or `ssh`, while every private/probe
purpose permits only its canonical consumer. Both endpoints bind that field into the E2EE
transcript. The server resolves the machine's current admitted runtime connector and a fresh
ready
tunnel node; callers never select signaling, STUN, or relay infrastructure. Direct ICE
credentials are random per intent, encrypted at rest, and replayed exactly for the same
operation. The descriptor expires within five minutes and contains only currently authorized
paths. Clients do not follow redirects. Refresh creates a new attempt generation;
the same generation is never reissued with different authority. Cancellation uses
`DELETE /v1/peer-attempts/{intent_id}/{attempt_generation}` and revokes every included
credential and route handle.

The initiating CLI receives the controlling view directly. The machine retrieves the
controlled view through machine-proof-authenticated
`POST /v1/machine-peer-attempts/next`, fenced by its current installation generation. An
empty queue returns no descriptor. Both views contain identical immutable intent,
generation, certificate, ICE, relay, expiry, and policy authority and differ only in role
and the role-scoped signaling credential. Exact polling replay returns the same active
authority. A stale connector, machine generation, certificate, node, trusted key, client session,
or revoked/expired intent returns no usable descriptor and never downgrades.

Availability, timeout, UDP-blocked, and verified reachability errors are fallback-safe.
Authentication, authorization, certificate, protocol, revocation, generation, malformed
response, and policy errors are terminal and never downgrade.

## Relay admission

The server allocates an opaque route token for the exact intent, reciprocal endpoints,
carrier, attempt/network/route generations, expiry, and directional byte limits. Each
logical stream uses a distinct opaque one-time admission handle. Tokens and handles are
canonical base64url random values with at least 128 bits of entropy. A handle is consumed
atomically before forwarding. Replay, role mismatch, carrier substitution, stale generation,
expiry, revocation, or exhausted limits receives the same external rejection. QUIC and WSS
apply identical admission semantics. Drain rejects new streams while allowing admitted
streams until their deadline; reassignment always increments `route_generation`.
Descriptors advertise only relay carriers implemented by the selected node. A relay entry
must include at least one of `quic_url` or `wss_url`; absent carriers are omitted rather than
represented by an unusable URL.

## Relay PMTU probes

Each relay descriptor includes a `udp://host:port` PMTU endpoint and a distinct signed
`peer_pmtu` credential with exact scope `peer:pmtu`. The credential is bound to the intent,
environment, selected edge node, route allocation, endpoint pair, attempt/network/route
generations, and expiry. It grants no signaling, relay-stream, or application authority.

Relay PMTU datagrams are 1,200 through 1,500 bytes. Their network-byte-order layout is
ASCII `PBMT`, version byte `1`, kind byte (`1` request, `2` response), uint16 exact datagram
length, 16 random nonce bytes, and uint16 credential length. A request carries that many
credential bytes followed by zero padding. A response has zero credential length and zero
padding, with the final 32 bytes replaced by HMAC-SHA256 over every preceding response byte
using the exact PMTU credential bytes as key. The tunnel verifies signature, class, scope,
bindings, expiry, revocation, and rate limits before responding. The client accepts only the
configured source, exact size, nonce, and HMAC. Invalid traffic is silently discarded.
Probes use DF/packet-too-big socket controls; fragmented success is never evidence.

## File-transfer E2EE extension

The operational carrier below remains until the shared native cutover. The native
application replacement uses `file_transfer` operation streams with exact resource
admission and HTTP operation authorization above Paperboat QUIC. Its existing v1
create/status/content/complete/receipt routes retain endpoint-owned batch identity,
offsets, full-file SHA-256, Inbox collision handling and atomic publication.
Native PATCH requires `Upload-Digest: sha256=<lowercase chunk SHA-256>`; each commit
is at most 1 MiB and is verified before advancing its durable offset. The existing
two-writer limit bounds chunk buffering and storage work. Interrupted operations
resume the same batch and original manifests from the receiver's offset; explicit
cancellation removes partials. Native reverse staging requires a live session
recipient and stores payloads only on the source endpoint until receipt or expiry.
Interrupted Inbox reads retain partials without issuing permanent failure receipts.
Native handlers reject content-key envelopes and use no chunk/manifest/receipt AEAD
or transfer-key vault. Task 20 owns shared production startup/cutover; the remaining
operational crypto consumers cannot be removed before that runtime migration.

The existing `/v1/file-transfers` identity, lifecycle, HTTP/3 then HTTP/2 fallback, limits,
expiry, completion, receipt, and cleanup remain authoritative. Version 1 adds an `e2ee`
envelope. Relays see only opaque identifiers, ordinals, ciphertext lengths, and ciphertext.
Transfer-key delivery uses the distinct peer-attempt purpose and private-stream consumer
`file_transfer_key`, with an exact transfer ID, generation, and expiry binding. It admits
one bounded key-control stream over direct QUIC, relay QUIC, or WSS and cannot dispatch an
interactive consumer. The recipient durably stores the key before acknowledging it.
The encrypted manifest binds transfer ID, generation, sender/receiver endpoint certificates,
ordered file metadata, chunk size, total plaintext bytes, and plaintext digest. Each chunk is
independently AEAD-sealed with a nonce derived from transfer generation and ordinal; ordinals
start at zero, never repeat, and resume only at an authenticated committed ordinal. The final
receipt authenticates the manifest digest, final ordinal, plaintext digest, and byte count.
The sender acknowledges the authenticated receipt digest through the existing receipt route;
the recipient retains the key across uncertain completion responses and erases it only after
that acknowledgement or bounded expiry. Receipt acknowledgement is idempotent.
WSS is ineligible for manifest, chunk, receipt, or any other file-content bytes.

## Private-preview E2EE extension

Private-preview streams use the distinct peer-attempt purpose and private-stream consumer
`private_preview`. This purpose cannot authorize terminal, exec, SSH, file-transfer key, or
other interactive application streams.

## Codex E2EE extension

Codex management HTTP and app-server WebSocket connections use the distinct peer-attempt
purpose and private-stream consumer `codex`. It admits only `native-health` and one
`codex-http` stream. The existing session-bound `codex_manage` or `codex_connect` credential
is still authenticated inside that stream. Codex session routes are never exposed by the
tunnel edge, and their logical `machine.paperboat.invalid` authority is not network-routable.
This purpose cannot authorize terminal, exec, SSH, preview, or file-transfer streams.
On the unified native network, an active Codex session projects only the exact
`codex_session` resource ID with capability `codex`; it never inherits terminal or transfer
reachability. A reconnect opens a fresh authorized stream for the same live Codex session.

Authenticated user diagnostics use the distinct peer-attempt purpose and probe-only consumer
`health_probe`. It admits health exchanges on direct QUIC, relay QUIC, or WSS, opens no
application stream, and cannot authorize any interactive or transfer consumer.

## Managed SSH

Client public keys use `PUT/DELETE /v1/ssh/client-keys/{fingerprint}`. Machine targets use
`PUT/GET /v1/machines/{machine_id}/ssh-target`; host-key observations use
`PUT/GET /v1/machines/{machine_id}/ssh-host-keys`. Every mutation requires
`Idempotency-Key`, is replayed by its exact operation ID and request hash, and is fenced by a
positive generation. The first complete host-key set reported through authenticated machine
authority becomes active. A later changed set remains pending and cannot replace the active
set implicitly. Promotion uses
`POST /v1/machines/{machine_id}/ssh-host-keys/{set_id}/promote`, requires user authority, and
is fenced by the machine generation and the pending set's expected aggregate fingerprint.
Successful promotion supersedes the previous active set. Stale observation generations,
machine generations, set IDs, reconciliation versions, or fingerprints fail closed.
Readiness requires an active client key, a ready target, and an active host-key set. Audit
records contain IDs, generations, fingerprints, actor, action, result, and request ID, never
private keys or session content.

## Stable errors

All HTTP failures use the approved common error envelope. P2P contracts use these stable
codes: `authentication_required`, `permission_denied`, `not_found`, `operation_conflict`,
`invalid_request`, `invalid_certificate`, `certificate_expired`, `certificate_revoked`,
`generation_conflict`, `generation_exhausted`, `intent_revoked`, `descriptor_expired`,
`route_unavailable`, `udp_blocked`, `reachability_failed`, `admission_rejected`,
`byte_limit_exhausted`, `transfer_expired`, `ordinal_conflict`, `integrity_failed`,
`ssh_key_rejected`, `ssh_target_not_ready`, `ssh_host_key_changed`, `rate_limited`, and
`temporarily_unavailable`. Retry metadata is present only for `rate_limited`,
`temporarily_unavailable`, `route_unavailable`, `udp_blocked`, or `reachability_failed`.

## Native migration boundaries

These decisions implement the native boundaries in the workspace product plan. Task 7
owns network-identity declarations and their producers/consumers; Tasks 6 and 9 own the
UDP/QUIC adapter. Keep the current runtime until the replacement passes its gate. Do not
reinterpret stored Noise keys as WireGuard keys, introduce a v2 contract, or leave a
compatibility reader after cutover. Task 34 owns final deletion after native migration.

### Identity, authority and configuration

| Boundary | Producer and authoritative location | Consumer and required behavior |
| --- | --- | --- |
| Endpoint identity | Endpoint secure storage in CLI `internal/config/peer_identity.go` and machine identity enrollment; server `internal/peeridentity/{service,certificate,repository}.go` owns approval, active certificate and revocation state | CLI `peertransport/{identitybootstrap,clientauthority,endpointidentity}` and host enrollment verify account, endpoint, role, installation/endpoint generation, signing key, certificate serial and exact local public keys before use. Retain account-rooted Ed25519 approval and the Ed25519 QUIC key; generate a separate upstream WireGuard node key. Private keys never enter the server. Noise enrollment/claims/storage are removed together at Task 34. |
| Network authorization | Server `internal/peersessions` owns signed peer configuration, using current account/device/machine and `peeridentity` authority; `internal/httpapi` exposes it and CLI `internal/api` decodes it | The daemon's `peertransport/tailnet` adapter verifies configuration before installing peers; `paperboat-relay` independently verifies its scoped admission. Tailcat addresses/tokens and successful WireGuard handshakes grant no application operation. |
| Application connection | `peertransport/endpointidentity` owns QUIC TLS expectations; `peerquic` owns QUIC and authenticated first-record binding | Both endpoints must match the approved Ed25519 QUIC key and current endpoint authority, retaining TLS 1.3, `paperboat-peer-v1` ALPN for routed streams or `paperboat-private-http-v1` for an exclusively HTTP/3-owned native private session, and `peercontext`/TLS-exporter operation binding. Network admission cannot substitute another QUIC key or authorize a consumer. |
| Operation stream | Server terminal/session, managed-SSH, transfer and private-access services issue exact-resource credentials; `peertransport/streamauth.Header` remains the application authorization boundary | `nativepeer` and host dispatch validate the credential, operation ID, consumer, stream ID, deadline and byte limit before opening a PTY, file, target socket or other workload. `Header.Resumable` requests recovery; it does not grant permission. Daemon connection caching never caches an operation grant as general machine access. |

Signed network configuration binds the account, endpoint, role, machine where applicable,
WireGuard public key, approved QUIC certificate identity, virtual address, endpoint and
machine generations, authorization generation, permitted peer identities and directional
scope, relay identities/regions/capabilities/limits, issue time and expiry. The server is
the sole allocator of unique virtual addresses; reconnect/path changes reuse the existing
allocation. Key rotation is a new authorized binding, not an implicit address-derived
identity. Tailcat's current key-derived address must not silently override this allocation.
Peer scope is explicit, including for same-account endpoints; cross-account access needs
an explicit resource grant. Configuration is network authority, not a terminal-session
descriptor, and contains no operation content or endpoint private key.

Task 7 updates the existing API/schema owners together with the new network configuration;
the old peer-attempt schema is not a reusable network-authorization schema. Existing
certificate and operation verification remain mandatory during the staged migration.
Relay configuration/admission receives only the routing, authorization and accounting
metadata it needs, never application credentials, environment values or file bytes.

Configuration application is an atomic replacement of the endpoint's authorized peer
set. Empty means deny all. Equal-generation identical replay is idempotent; changed
contents at the same generation, lower generations, wrong identity/key/role, invalid
signatures and expired authority fail closed. Persist generation high-water state so
restart cannot revive revoked authority. Refresh cannot extend authority without a new
verified configuration. During a control-plane partition, already authorized access may
last only until its existing expiry; expiry removes peers and closes their QUIC and relay
access. No offline grace or switch to an edge-decrypted connection is permitted.

Revocation ordering is: server commits the authority-generation advance; endpoints and
relays receive authenticated state; endpoint fences new acquisition/stream dispatch,
removes the peer and closes its QUIC connections; relay fences admission and closes
existing routing. Reconnect obtains current authority and never retries a revoked grant.
An application-scoped revocation closes that operation without tearing down unrelated
authorized streams; endpoint/account revocation invalidates all affected connections.
Task 7 sets the initial refresh/expiry policy below; regional delivery belongs to Task 8.
No unmeasured fleet revocation latency guarantee is implied here.

### Signed network configuration v1

Task 7 adds `peersessions.NetworkService`, the authenticated `/v1/peer-network/{register,config}`
CLI POST routes, and `/v1/machine-peer-network/{register,config}` machine POST routes.
CLI identity comes from the bearer session with `projects:connect`; machine identity
comes from the current machine credential and proof of the exact request. Registration
accepts only `operation_id`, `wireguard_public_key` and the independent
`disco_public_key` (each canonical raw base64url, 32 bytes), `expected_key_generation`
and `quic_certificate_fingerprint` (lowercase SHA-256 hex).
It validates the existing approved endpoint certificate and current account/device/
machine/environment/seat state. Endpoint private keys are never request fields.
Registration returns `key_generation` and `virtual_address`. Key replacement is CAS;
exact registration retries replay, with the newest 64 operations retained per endpoint.
Pruned stale operations cannot bypass the current generation.

Config POST takes `operation_id` and returns `configuration`, an EdDSA JWT with type
`paperboat-network-config+jwt`, audience `paperboat-network`, and `kid` from the existing
server mint/JWKS owner. Each request commits a fresh endpoint configuration generation;
retrying a request can produce a newer configuration. Identical signed-document replay
is idempotent. The decoded payload is specified in
[peer-network-configuration.schema.json](schemas/peer-network-configuration.schema.json).
The `self` and peer `identity` bindings carry account, endpoint, role, machine,
endpoint/machine/key generations, WireGuard and independent discovery public keys, QUIC certificate fingerprint and its approved Ed25519 public key,
and the server's stable /128 address within `fd7a:115c:a1e0::/48`.
Paperboat authority mode derives the connection descriptor from these signed keys and the
admitted regional set and disables Tailcat's optional address PSK. WireGuard, exact peer
admission, pinned QUIC identity and operation authorization remain mandatory; Paperboat
does not claim Tailcat's optional PSK-based post-quantum confidentiality layer.

Network scopes derive from active `user_machine_access_sessions` and active
`codex_sessions`, including their actual machine and CLI. A terminal credential reference
yields network `terminal` and `private_access` reachability; a file credential reference
yields `file_transfer`. A Codex session yields only `codex`. Each scope names its source
row as `machine_access` or `codex_session` / `resource_id`, generation 1, `dial` for the
CLI or `accept` for the machine, port 443 and the source grant expiry.
These capabilities admit network traffic; exact operation JWTs and QUIC identity checks
remain mandatory. Other product grant sources integrate at their owning migration tasks.
No ungranted same-account or cross-account peer is included. This document grants no
relay access; regional/relay authority remains with Tasks 8/10–12.

Each configuration response also carries short-lived `relay_grants`. Every grant is bound
to the endpoint WireGuard key, optional discovery key, approved QUIC certificate, current
configuration generation, and exact relay node generation/process epoch. Its peer entries
contain only current scoped peer keys and scopes. A node registered with both `relay` and
`peer_relay` roles, both `derp_quic` and `peer_relay_udp` transports, and its allocated
WireGuard/discovery/service-address triple contributes a `peer_relay` descriptor only when
the endpoint and every included peer have discovery keys. Existing identities without a
discovery key remain eligible for DERP only until explicit key re-registration; the server
does not fabricate or derive discovery identity. Relay grants expire within 60 seconds and
never beyond their node, certificate, configuration, or source-scope authority.

The issuer bounds documents at 64 peers, 128 total scopes and 128 KiB encoded JWT,
failing rather than truncating authority. Lifetime is at most the existing five-minute
credential ceiling, and never exceeds a contributing certificate or grant expiry.
The consumer normally refreshes every 30 seconds with jitter and a ten-second request
deadline; active regional recovery shortens this to approximately ten seconds so signed
15-second health observations remain fresh. Explicit
self-denial removes attached engines immediately; a control outage cannot extend the
current expiry. Grant removal yields a signed replacement without that grant. Database
triggers advance generations with authoritative lifecycle changes; wall-clock expiry is
also checked on every issuance and by the consumer timer. These are policy bounds, not
a measured fleet-wide revocation latency claim.

`tailnet.Authority` validates before installing allocated-address peers; empty denies
all. It pins local approved QUIC identity, checks exact local key custody, rejects stale
or changed same-generation documents, and persists the configuration high-water before
network application. The existing secure store holds one account/issuer/endpoint-scoped
v1 record with active and pending upstream WireGuard keys, key/config generations,
allocated address and configuration hash. Pending keys survive interrupted registration;
only a verified matching configuration commits rotation. Failed durable writes prevent
installation. Noise/QUIC storage is untouched. `Authority.Listen`/`Client` attach engines,
`Run` owns refresh/cancellation, and removal/expiry closes their affected UDP leases.
The CLI adapter uses one authority-mode engine for all admitted machine peers; symmetric
admission enables no inbound CLI application port, peer removal preserves unrelated
routes, and the 64-flow bound is aggregate across the engine. The daemon's shared runtime
and live QUIC/session invalidation are integrated and verified by Tasks 9 and 20.

### Virtual UDP, QUIC and resource ownership

`paperboatd` owns one endpoint network engine, not a Tailcat client per terminal or file.
`peertransport/tailnet` is the sole upstream adapter and lifecycle owner. It accepts
verified local identity and peer configuration, installs/removes peers, opens authorized
virtual UDP flows, observes paths/network changes, and shuts down the engine. Product
adapters receive authorized application streams, never physical-carrier selectors.

The virtual UDP boundary is `net.PacketConn` with datagrams preserved, exact virtual
source/destination addresses and ports, deadline/concurrent-I/O/close behavior, and a
declared maximum payload. A connected `tailcat.ConnPacketConn` is acceptable for a peer
flow; it is not evidence of a wildcard listener or arbitrary multi-peer socket. The
adapter must reject writes to another peer, enforce authorized address/port filters before
QUIC/application dispatch, and bound flow/queue creation. No generic subnet forwarding
permission follows from enabling a Paperboat QUIC port.

`peerquic` owns the `quic.Transport`, listener and connection created over each leased
virtual socket. The adapter owns the socket and closes it when its lease is returned or
revoked; lease release is idempotent, including during engine shutdown. Failed setup
releases the socket lease and closes all partial QUIC resources. Normal release closes an operation
stream; the daemon's session manager releases shared QUIC only when its leases/drain
policy permit. Revocation overrides leases. Shutdown fences new work, cancels outstanding
opens, closes QUIC/listeners and sockets, then closes the engine and joins owned workers
within the caller's deadline. Cancellation must unblock I/O and cannot publish a late
connection. Closing one flow must not stop unrelated peer traffic.

Task 6 replaces `peerquic`'s `net.Conn`/`fixedpacket` adaptation at this boundary, retaining
QUIC TLS and stream protocols. The pinned Tailcat source declares a 1,232-byte virtual UDP
payload maximum at its 1,280-byte IPv6 MTU; Paperboat currently initializes QUIC packets
at 1,200 bytes. The adapter must constrain QUIC's maximum as well as its initial size;
neither generic UDP echo nor initial-packet fit proves sustained QUIC works. Underlay
PMTU/path changes belong to upstream networking, not a second Paperboat probe protocol.

The Task 6 implementation exposes `tailnet.UDPServer` / `UDPClient` socket leases
and `peerquic.ListenPacket` / `DialPacket`. Static nonempty WireGuard key admission
and one served port are required; no subnet forwarding is enabled. Task 7 layers
`tailnet.Authority` over these leases for signed, replaceable admission; product runtime
cutover remains Task 9. A failed
QUIC setup releases its lease. Each engine admits at most 64 queued/leased flows;
there is no adapter packet queue, reads use at most 1,233 bytes of scratch storage,
and the pinned netstack UDP socket buffers default to 32 KiB each. Existing QUIC
receive-window ceilings remain 4 MiB per stream and 16 MiB per connection.

Virtual QUIC disables path MTU discovery and keeps its configured initial packet
size (normally 1,200 bytes) within the 1,232-byte ceiling. The socket rejects oversized
writes and received datagrams; its source/destination addresses remain stable after
close. Consumers handle admitted flows concurrently with bounded handshake deadlines:
late UDP packets can reopen a retired tuple without completing another QUIC handshake.
Close every lease on failure or retirement; closing one lease leaves other peers usable.

### Paths, errors and recovery

Paperboat DERP/WSS uses `wss://<eligible relay endpoint>/derp` with the
`paperboat-derp-v1` WebSocket subprotocol, TLS client-certificate binding, compression
disabled, and the same signed relay grant used by DERP/QUIC. Standard HTTP proxy
selection, including CONNECT for WSS, follows the endpoint process environment. WSS
packet and control frames retain the 2,048-byte packet, 128-KiB control, 64-entry
connection queue, 16-connection account and 256-connection relay bounds. QUIC and WSS
legs register in one relay peer table and are re-authorized before dequeue; revocation,
generation fencing and drain apply identically across mixed legs.

WSS is a last-resort reachability carrier: its single ordered TCP stream introduces
head-of-line blocking when packets are lost. Only transport and reachability failures
permit selection of WSS. Identity, authorization, certificate and protocol failures are
terminal and cannot select WSS. A healthy DERP/QUIC carrier replaces WSS; the relay
closes the superseded registration for the same WireGuard key. Configuring the Paperboat
carrier factory excludes standard DERP TCP/TLS as an additional path.

The adapter emits only `direct`, `peer_relay`, `derp_quic`, or `derp_wss` for an observed
active native path. No active path is absent, not a fifth carrier or an invented direct
success. Connection/recovery state and region are separate fields. The old
`connectionmanager.PathDirectQUIC/PathRelayQUIC/PathWSS` values must not be relabeled as
the four target paths: old relay QUIC and terminal WSS are different protocols.

Preserve the typed error boundary in `connectionmanager.Failure`, moving classification
to the adapter as carrier racing is removed. Its reachability, timeout, UDP-blocked, NAT
and transient classes permit bounded path recovery. Authentication, authorization,
certificate, protocol, revoked, generation and internal/unknown failures do not permit
fallback; unknown errors fail closed. Cancellation and caller deadline exhaustion stop
work rather than start another attempt. Policy/limit denials remain operation errors;
changing relay cannot obtain a different grant or evade a limit. Callers use typed
causes, never error strings. User diagnostics retain actionable stable API errors without
exposing keys, credentials or workload content.

Magicsock owns underlay recovery and preferred-path upgrades. A path change must not
re-enroll the endpoint, allocate an address, mint an operation, or replace a usable QUIC
connection. When QUIC cannot recover, the daemon's application-session manager reconnects
with current authority and reports recovery to the owning protocol. It must not rerun a
command with uncertain delivery. `hostruntime/session` retains session/process generation,
input decisions and replay offsets; `resumablestream` retains acknowledged byte recovery
and bounds; `filetransfer` retains verified offsets, integrity and atomic publication.
Host reboot is a lost/restarted process generation, never uninterrupted execution.

Preserve `localdaemon.MachineTransportInvalidator`'s distinction between authority
invalidation and observed route retirement. The former aborts affected logical operations;
the latter allows their protocol-specific recovery. A missing peer in a verified full
configuration removes authority; an unavailable/incomplete control response must not be
treated as an authoritative empty inventory. Config/env delivery and updater journals
remain owned by their existing services, independent of this path/session state.


### Pair-aware regional recovery (Task 13)

`Authority.ConfigureRegionalRelays` installs the verified eligible inventory in the
existing engine. `Owner` starts one authority-owned coordinator; individual streams do
not dial carriers. The coordinator prepares up to four candidates with two concurrent
workers, five-second deadlines, 2.4–3.6-second sweep jitter and 3/6/12-second per-node
failure backoff. Inventory and failed-node state are bounded by 32 signed candidates.
It retains the selected node, a prepared backup and an improvement candidate while
exploring the remainder. Direct discovery and peer-relay selection remain in magicsock.

Both endpoints prove connectivity to the same exact node before promotion. Control uses
upstream WireGuard node-key sealed boxes, random challenges, monotonic sequences and
node/generation/epoch binding; it carries no application data. Ten-second proofs cannot
be replayed onto another node or peer. Metadata has a 2,048-byte packet bound and bounded
64-entry queues/proofs. Combined pair round-trip latency and fresh capacity rank candidates.
Elective switches require both 10 ms and 15% improvement, three observations spanning ten
seconds and ten-second dwell. Failures/removal bypass dwell. A different failure-domain
backup reports available redundancy; one mutually reachable node reports reduced redundancy.
No mutual candidate reports an explicit unavailable state and continues bounded discovery.

`Authority.RegionalStatus` exposes selected node/region, combined RTT, ready backup,
redundancy, reason, and each endpoint's observed QUIC/WSS relay leg. This is relay
preparation status; it does not falsely identify a relay as the active application path
when magicsock is using direct or peer-relay traffic. QUIC/WSS carrier recovery preserves
the same endpoint identity and uses reusable transport legs; compatible registration
replacement closes the old physical connection without inventing an authorization denial.
A preferred QUIC attempt has a shared two-second Connect/Ping budget. Failed recovery
attempts back off from five to ten seconds with jitter; ten seconds is the hard retry
ceiling. Every upgrade proves current authenticated connectivity before promotion.

`native.ReconnectRequiredError` marks an established QUIC idle timeout, stateless reset,
unexpected transport loss or remote graceful close. Its cause and peer identity remain
typed. Local close, cancellation, caller deadlines, stream resets and authorization or
protocol failures are not relabeled as recoverable. The application owner reacquires
current authority and resumes its protocol; this layer never replays a command or stream.

### DERP over QUIC carrier (Task 11)

The consumed Tailcat/magicsock carrier and `paperboat-relay/derpquic` library use
QUIC with TLS 1.3 and ALPN `paperboat-derp-v1`. One bidirectional stream carries
authentication, ready, reliable peer control, and ping/pong frames. Its frame header
is one byte of kind and a four-byte big-endian payload length; payloads are bounded
to 128 KiB. Reliable peer control contains a 32-byte destination/source WireGuard
public key and 1–2,048 bytes of opaque control. WireGuard packets stay in QUIC
datagrams; no oversized-data stream fallback is implemented.

Each datagram has a 43-byte header: uint64 sequence, 32-byte destination/source key,
uint16 original packet length, and uint8 fragment index. Integers are big-endian.
Original packets are 1–2,048 bytes; fragments contain at most 1,024 payload bytes,
so each packet has at most two fragments. Reassembly permits 64 incomplete packets
per connection, expires incomplete state after two seconds when processing new
fragments, and suppresses completed/replayed sequences in a 128-sequence window.
Unauthorized destinations allocate no reassembly state. This permits a 1,312-byte
WireGuard packet carrying a 1,280-byte IPv6 packet without assuming a larger initial
QUIC packet size. It does not establish migration or throughput qualification.

Admission verifies an Ed25519-signed `paperboat-relay-grant+jwt`, issuer,
`paperboat-relay` audience, v1, endpoint/account, WireGuard key, approved endpoint-certificate
fingerprint and Ed25519 QUIC public key, relay node ID/generation and process epoch. The
presented bounded self-signed TLS leaf must use that exact key and have a valid self-signature. Grants
last at most 60 seconds, contain at most 64 peers and 128 scopes, and authorize only
matching account/resource/generation/capability/port with complementary dial/accept
directions. Current scopes cover terminal, private access, file transfer, or an exact
Codex session on port 443. The carrier refreshes credentials every 15 seconds; endpoint authority refresh
uses the normal 30-second interval with ±20% jitter, shortened to approximately ten
seconds during regional recovery. Expired authority fails closed.

The relay derives packet source identity from the authenticated connection, checks
both peers before enqueueing and again before forwarding, and fences superseded or
revoked registrations. Identical signed authority may replace an overlapping live
connection; changed same-generation authority and older generations are rejected.
Identity, authorization, certificate and protocol failures are fatal. Cancellation
stops work; transport failures and drain/capacity errors remain retryable without
changing authorization. A configured Tailcat carrier factory never selects native
DERP TCP/TLS. DERP/WSS and mixed legs belong to Task 12.

Bounds include 256 connections, 16 per account, 64 queued packets per peer, eight
queued ping replies and eight pending client pings. Authenticated datagram work uses
per-connection and per-account token budgets of 256 burst / 4,096 per second; reliable
control also consumes the connection and account budgets. QUIC address validation is required
and 0-RTT is not enabled. `Snapshot` exposes accepted/denied/forwarded/dropped counters,
connection count and drain state without packet content or credentials.

`Server.Revoke` and `Server.Drain` are driven by the authenticated native node lifecycle.
Preprovisioned startup claims a new generation/epoch; three-second observations report
readiness/capacity and obtain endpoint revocation floors. Ordinary configuration renewal
does not revoke an unchanged connection. Adding an access session advances the next
configuration generation without revoking existing narrower grants; the new resource
requires fresh reciprocal scopes. Access-session updates, including revocation and
lease shortening, retain the revocation fence. Registry validity is 60 seconds, signed health
freshness is 15 seconds, and the node independently closes on control-lease expiry after
15 seconds. The command reads a static trusted JWKS; rotation uses a controlled restart.
Connected lifecycle tests are not a production deployment, migration qualification or
sustained throughput evidence.

## Authorized UDP peer relay v1

The selected DERP/QUIC node may also advertise a signed `peer_relay` service identity.
Its WireGuard routing key, discovery key and allocated virtual address are bound to the
same node generation/process epoch as the endpoint grant. Tailcat installs that service
as discovery-only state with the upstream `RelayTarget` capability; it receives no
application port or WireGuard allowed-IP grants.

Reliable DERP control carries upstream sealed `AllocateUDPRelayEndpointRequest` and
response messages to the local service. The service checks the signed sender discovery
key before opening the envelope, requires the requester to participate in the pair,
and resolves both discovery keys to active authenticated connections with complementary
current scopes. Replies echo the upstream request generation and preserve upstream
VNI, Lamport identity, server discovery key and bind lifetimes. They are fenced to the
requesting connection through the existing reliable writer.

Data uses upstream UDP/Geneve binding, source-address challenge and packet forwarding.
Active forwarding checks current pair authority on every packet. Absolute expiry is no
later than either grant; only refreshed compatible signed authority can renew it.
An existing allocation follows retained verified capabilities across DERP control
reconnects, not the lifetime of a control socket. New allocations and control replies
still require their current authenticated connection owners; retained authority never
extends signed expiry or overrides newer incompatible grants or revocation.
Revocation invalidates forwarding immediately at that check; a 250 ms owner loop releases
invalid allocations. Restart loses bindings and requires the upstream challenge/rebind.
No relay retains private file content for later delivery.

The initial workload limits are 128 allocations per relay and 16 per account, with eight
allocation requests per second/burst per account. Forwarding allows 2,048 packet bytes
plus the eight-byte Geneve header, at 4,096 validated packets/s and a 256-packet burst per
account (at most 8 MiB/s before carrier overhead). Unbound/spoofed source packets cannot
debit an account's forwarding budget. Limits suit the bounded terminal/transfer slice;
sustained load and regional qualification remain Tasks 35/36. Counters expose allocation
admission, denial and authorized forwarding without packet bodies or credentials.
