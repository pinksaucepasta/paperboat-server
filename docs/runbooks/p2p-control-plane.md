# P2P Control-Plane Runbook

The server owns authorization and public E2EE metadata, never private session or file bytes. Record
stable request, operation, endpoint, machine, node, and generation identifiers only. Do not collect
credentials, candidate addresses, commands, paths, payloads, private keys, or encrypted resources.

## Snapshot gap, rejected delta, or stuck fan-out

1. Compare the active session lease, process epoch, acknowledged sequence, pending count/bytes/age,
   and authoritative projection generation.
2. Fence stale sessions and request a full snapshot when resume history is unavailable. Never skip
   a gap or edit an acknowledgement.
3. If one target is blocked, preserve ordered per-target delivery while other targets progress;
   restart only after the durable queue and lease state are understood.
4. Verify snapshot-before-delta ordering, exact resume, bounded queues, overlapping-session fencing,
   and atomic projection publication.

## Projection failure or identity collision

1. Stop issuance for the affected target while retaining the last valid immutable projection.
2. Rebuild from authoritative rows in one transaction and publish only after validation. Do not
   merge conflicting machine, account, endpoint, or generation identities.
3. For a binding collision, revoke the ambiguous pending operation and require supported re-pairing.
4. Verify stale results cannot commit and unrelated targets remain available.

## Endpoint rotation, recovery loss, or explicit reset

1. Revoke the affected endpoint generation. For account-root compromise, revoke all endpoint
   certificates and advance the account authorization generation.
2. The server must not generate, escrow, or recover the account private root. Use the explicit
   client-owned recovery/reset ceremony and re-pair every endpoint.
3. Keep pending certificates fail-closed until root-signed enrollment completes; never activate a
   hand-edited database row or trust document.
4. Verify old credentials, descriptors, relay admission, replayed handshakes, and transfer resources
   fail, then verify fresh direct and relay operations with the new generations.

## Relay usage or regional-selection divergence

1. Compare signed usage sequence, route subject, node generation, endpoint latency vectors, score,
   capacity, and hysteresis category without inspecting private bytes or addresses.
2. Preserve uncertain or out-of-order reports for idempotent reconciliation. Never delete counters
   or attach ephemeral relay subjects to unrelated control routes.
3. Drain an unhealthy region from new assignments while keeping stable sessions and a healthy
   fallback available.
4. Verify two-ended scoring, no-flap hysteresis, exact signed usage replay behavior, and recovery to
   the preferred region after independent endpoint probes stabilize.

## Global P2P disablement

1. Use the authoritative feature/admission control to stop new P2P issuance. Do not alter FRP,
   expose raw ports, or manufacture a compatibility path.
2. Allow active bounded leases to drain or revoke them when the incident requires immediate stop.
3. Preserve public preview and unrelated control-plane functions only when their health and policy
   remain independent.
4. Re-enable by staged region after trust, signaling, relay, WSS, usage, and synthetic probes pass;
   verify revoked generations remain rejected.

