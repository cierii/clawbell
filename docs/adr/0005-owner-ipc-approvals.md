# 0005 — Owner-private terminal monitor and one-use rendezvous

Status: implements the constitution; no independent execution permission is added.

## Decision

A Unix domain socket in an existing owner-controlled 0700 directory carries
bounded newline JSON frames. The socket is 0600, peers are checked using kernel
credentials, and existing paths are never overwritten. All ancestors must be
trusted and the directory must remain outside child mounts. This is a local IPC
boundary, not the future HTTP panel: no browser access, HTTP tokens or CORS apply.
A same-UID compromised owner remains outside the threat model.

The Monitor redacts complete display units with its session-scoped Vault before
broadcast. Register owner-known secrets before publishing data. Heuristics are
not exhaustive. Only redacted values enter its bounded history. Telemetry drops
on lag; a slow IPC writer disconnects after two seconds. Each frame is bounded,
as are pending approvals (32), event history (128), and connection count (one).
Terminal controls from peers are escaped; ANSI originates only in the renderer.

PolicyGate keeps its immutable policy and pinned compiled schemas throughout a
call. Only RequireApproval creates a rendezvous. The owner sees the session,
configured server identity, tool, argument SHA-256, policy version, declared effect,
affected paths and redacted arguments. Overlarge approval displays are refused.
The channel sender refers to exactly that suspended invocation. IDs monotonically
increase in a Monitor and are removed on decision; they are never transferable
capabilities. Rejection, timeout (25 seconds), cancellation, unavailable owner,
overload or any independent deny cannot permit execution. Reconnects require new
PolicyGate sessions. Changes to catalogs still terminate sessions. Audit intent
still must succeed in the inner Gate before forwarding. Monitor history is not an
audit log. Restored local arguments requiring approval remain refused by synchronous
revalidation; no implicit second approval or raw-secret display is introduced.

## Integration and migration

Existing callers remain fail-closed without with_monitor. A trusted composition
creates Monitor, registers known secrets, spawns serve in a supervised task and
attaches a clone to each PolicyGate. Use separate monitor instances for independent
owner trust domains. Publish runner-verified server status separately; PolicyGate
reports sandbox status as unattested and must never infer isolation from MCP data.
Client: `clawbell monitor --socket /trusted/private/monitor.sock`.
Commands are `a ID`, `d ID`, `q`, followed by Enter. Terminal remains in cooked mode;
no raw-mode restoration is needed. A disconnected UI does not stop allowed calls.

The existing repository still lacks a deployable audit/runner CLI composition.
This change exposes the monitor client and production integration APIs; it does
not substitute an allow-all audit adapter to fabricate a working firewall command.
Future HTTP integration requires its own token/Host/Origin/CSRF boundary.

## Validation limits

Tests cover actual IPC approval before forwarding, one-use consumption, rejection,
missing owner, framing bounds, registered synthetic secret redaction and terminal
control escaping. The release experiment checks 2000 warmed telemetry publications
below 5 ms each. It excludes durable audit, kernel scheduling guarantees, network
and human wait. Full production proxy latency is not certified by this experiment.
