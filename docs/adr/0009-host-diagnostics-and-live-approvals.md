# 0009 — Active host diagnostics and production owner approvals

Status: implemented; follows existing isolation and IPC boundaries.

The production launcher optionally attaches the existing Monitor to PolicyGate.
It serves the private endpoint concurrently with the bounded stdio session.
Monitor service failure cancels the session; no execution permission derives
from telemetry. Disconnect drops all pending reply senders before reconnect,
so an old rendezvous cannot survive a new owner connection. The existing
25-second timeout and exact-call one-use sender remain mandatory. Endpoint
ancestors are checked by the launcher, and workspace/runtime exposure refuses.
Without the explicit endpoint option, approval-required calls continue to deny.
No database migration or reusable approval capability is introduced.

Host diagnostics run fixed trusted probes in the real NativeRunner, never the
configured upstream. Synthetic outside files and SQLite fault injection live
in private temporary directories. The audit probe exercises AuditGate and checks
its error before any forwarding. Child creation is allowed inside pids.max;
cancellation must empty the whole cgroup, including detached children.

Fedora 44 is the single bootstrap target. A user service with DelegateSubgroup
keeps the delegation root empty. The bootstrap is repeatable, refuses conflicting
unit files and does not install packages, require root or weaken kernel settings.
Removal requires stopping clients first. No change to existing bindings is needed;
owners opt into a unique monitor socket when launching manually.

References queried through Context7: systemd CGROUP_DELEGATION.md (Delegate,
DelegateSubgroup and explicit subtree controller enablement), Tokio task
cancellation and select semantics. Runtime measurements still require an idle
host; no hard realtime guarantee is claimed.
