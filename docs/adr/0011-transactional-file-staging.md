# 0011 — Transactional regular-file staging and trusted change inspection

Status: accepted for isolated staging and inspection by the owner's implementation
request; publication remains a proposed contract, disabled in this increment.
Follow-up: [ADR 0012](0012-approved-handle-committer.md) enables a separate
explicitly approved handle committer and records its narrower publication and
recovery contract. The historical staging-only decision below remains unchanged.

## Boundary and decision (recorded before implementation)

The current read-only NativeRunner remains the default. A separate Linux-only
Transaction supervisor owns one isolated execution and one private staging tree.
Owner configuration, not MCP annotations or skill text, declares ReadOnly or Write.
The upstream never receives host write access: /original is a descriptor-pinned
read-only mount; /workspace is a private copy on host tmpfs. Namespaces, empty
environment, socket-denying seccomp and whole-tree cgroups remain mandatory.
Only the supervisor can inspect the host staging directory. It kills the complete
cgroup and confirms populated=0 before scanning. Exit of the direct child or an
MCP response is not proof that descendants have stopped. Inspection consumes the
transaction; it cannot be restarted or reused. Cancellation/drop never publishes.

Copying and inspection use pinned directory handles and no-follow opens for each
component. Only directories and singly linked regular files are accepted. Symlinks,
hardlinks, devices, sockets, FIFOs, extended attributes other than the host SELinux label, and privileged permission
bits refuse. Bounded depth, entry count and cumulative file bytes bound inspection.
Snapshot and inspection have ten-second deadlines. A timed-out blocking syscall
may finish later, but its result is discarded, no untrusted code is launched and
no candidate is published. The initial copy is independent (never hardlinked). A content/mode/type baseline
comes from that private copy before execution. Source files changing during copying
refuse when detected; this is not an atomic snapshot of a concurrently edited tree.
Owners must quiesce external writers when a coherent multi-file snapshot is needed.
Changes to directories, creation, deletion, content, permissions, ownership,
mtime/ctime or the SELinux label enter a sorted
structural diff. ReadOnly with any surviving change refuses, independent of server
claims or tool annotations. An unsupported final node refuses the entire result.
Writes leaving identical inspected state are not detected: this is final-state
inspection, not syscall provenance. Atime is excluded to permit ordinary reads. Private /tmp scratch is outside the candidate
workspace; it is never eligible for publication.

Staging names and file bytes are sensitive, untrusted data. Errors contain fixed
codes; reports have no Debug/serialization and are for trusted callers only. No raw
content diff enters audit, model responses, panel or stderr. Tmpfs must be available;
the root-owned sticky /dev/shm parent is checked; there is no disk-backed or
unisolated fallback. New pages written by the upstream
are charged to its existing memory cgroup; initial copies are separately bounded.
Crash leftovers may remain in private 0700 tmpfs directories until reboot/owner
cleanup; cleanup is best effort and never follows staged symlinks to delete targets.

## Unsafe adapter review

Only sys.rs contains added unsafe code: dup2 for the owned staging descriptor 5
and bounded fstatfs/flistxattr/fgetxattr calls. Descriptor sources are duplicated
above 9, remain owned through spawn and are CLOEXEC except intentional bubblewrap
setup descriptors. Bubblewrap consumes/closes mount descriptors after verifying
the mounted identity. Output storage is correctly sized, initialized bytes are
read only on successful syscalls, and the post-fork callback allocates nothing.
O_PATH pins entries before I/O so FIFOs/devices cannot trigger blocking reads or
side effects before rejection. No unsafe code enters policy or packet processing.

## Proposed publication contract and migration

1. Ship the isolated library boundary without enabling writes in the CLI/proxy or
   changing existing approvals. Callers must authorize and durably audit execution
   before spawn, bound/drain pipes, and withhold output until inspection succeeds.
   This increment supplies staging/inspection, not a production MCP write endpoint.
2. Add a dedicated per-operation proxy protocol: serialize operations, bind policy
   snapshot/server/schema/arguments/session and effect before execution, reject
   concurrent requests, inspect before releasing responses, audit fixed outcomes.
   A persistent writable session cannot attribute hidden writes to individual calls.
3. Add owner approval of a redacted manifest bound to original identities, baseline
   and candidate digests, policy version, session and expiry. Validate DLP on complete
   candidate files, supported formats, paths and semantic changes. Approval does not
   override deny. Recheck originals through beneath/no-symlink directory handles;
   external edits and unsupported metadata refuse instead of overwriting.
4. Implement a trusted publisher for ordinary files only: durable intent first,
   exclusive temporary files beside targets, bounded verified copies, fsync files,
   atomic rename and fsync parent directories. Single-file replacement can be atomic;
   multiple renames are NOT an atomic filesystem transaction. Multi-file publication
   requires an explicit journal/recovery contract, conflict detection and reporting
   of partial/unknown outcomes, never automatic replay after a crash.
5. Review bypass/fault/crash tests before enabling publication. Existing policies
   migrate explicitly; no write permission is inferred from old tool annotations.
   Keep old read-only sessions unchanged and fail closed on unsupported platforms.

No publisher, approval UI, background replay, remote-server write guarantees or
arbitrary metadata preservation is added by this increment.

## Performance and validation

Snapshot/diff are operation lifecycle work, not packet-path work; do not traverse
files for ordinary MCP packets. Keep the existing <5 ms bounded warmed proxy packet
release gates. Copy/inspection cost is proportional to the bounded tree and must
be measured separately, not claimed to fit a universal 5 ms filesystem transaction.
Run adversarial tests for links/special nodes, byte/depth/count limits, chmod,
creation/deletion, read-only lies, detached descendants, socket/original write
refusal, cleanup failures and unchanged original synthetic secret canaries.

## Sources

Context7 queried official [bubblewrap](https://github.com/containers/bubblewrap)
for descriptor mounts and namespace isolation, and
[rustix](https://github.com/bytecodealliance/rustix/blob/main/src/fs/openat2.rs)
for descriptor-relative no-symlink path resolution. Implementation reuses the
existing libc adapter; no new dependency or custom cryptography is required.
See also [ADR 0004](0004-native-process-containment.md) for native supervision.
