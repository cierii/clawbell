# 0004 — Native process containment and explicit platform capability gaps

Status: Linux implemented; macOS incomplete and refused by the production runner.
No exception to the constitution's mandatory resource/supervision contract is made.

## Decision

Implement `NativeRunner` at the existing `Runner` boundary. On Linux it creates a
fresh cgroup v2 in an owner-delegated subtree, configures memory.max, zero swap,
memory.oom.group, pids.max and cpu.max, and enrolls the child **before exec**.
A failed enrollment cannot execute bubblewrap or the requested program. The
trusted subtree and its ancestors must not be writable by untrusted processes.
The process runs unprivileged; there is no root/setuid or Docker fallback.

Bubblewrap isolates user, PID, mount, network, IPC and UTS namespaces, drops all
capabilities, disables nested user namespaces, exposes only read-only system
runtime and a pinned workspace, and supplies a private bounded tmpfs. HOME points
to an empty sandbox directory. Environment inheritance is disabled. The owner
must supply credential-free code/data, never a whole home or credentials tree.
Opening the workspace pins the directory across renames; symlinks outside exposed
mounts resolve to unavailable targets. Mount setup uses a separate descriptor,
so stdin/stdout remain usable for MCP. `--ro-bind-fd` consumes/closes the
workspace descriptor; close_range(CLOEXEC) prevents unrelated host descriptors
from being inherited. The attack test checks for descriptor leaks as well. The executable and arguments remain an
argument vector; the runner never synthesizes shell source.

An anonymous BPF descriptor applies seccomp before untrusted exec. It rejects
foreign syscall architectures/x32 and denies sockets, ptrace/process_vm access,
namespace/mount mutation, kernel modules, keyrings, BPF/perf, io_uring and
open-by-handle. This is defense in depth, not a syscall allowlist. Namespace and
mount restrictions remain mandatory. Supported Linux architectures are x86-64
and AArch64; only x86-64 was exercised here.

Explicit termination and Drop write cgroup.kill, covering detached descendants.
The absolute lifetime watchdog kills the group even if traffic continues.
Bubblewrap's parent-death/PID-namespace behavior also covers loss of the direct
child/future. Termination waits for populated=0; asynchronous Drop cleanup retries
empty-directory reclamation. Runtime output must go through `stdio::run`, whose
bounded frame readers and stderr drain enforce output/backpressure limits. Do not
read raw pipes into unbounded buffers or forward raw stderr to users.

The packet path has no new filesystem traversal, cgroup operations or process
creation. Isolation is installed once per upstream session. A new explicit
release experiment measures 2000 warmed ping round trips through the native
runner and proxy. The fixture Gate does not implement durable audit, DLP or
policy evaluation; this measurement cannot certify those costs or a universal
hard real-time guarantee.

## macOS boundary

`macos::profile` builds a deny-default Seatbelt component, with no host writes,
network, Mach IPC or fork permission. A native macOS test exercises direct open(2)
against an existing synthetic SSH key and a symlink. Profile generation is NOT a
complete runner. Resource enforcement, workspace identity and reliable process
lifecycle supervision must be composed and verified before production launch.
`NativeRunner::new` refuses macOS and other unsupported systems. The requested
macOS implementation therefore remains unfinished; passing string-generation
unit tests must not be reported as OS enforcement evidence.

No macOS host was available during this change. The macOS test is explicit and
fails if Seatbelt is unavailable. A future implementation needs native tests of
resource ceilings and lifetime/cancellation, including exec/fork behavior. Do not
substitute a process-group kill loop or assume that Linux cgroup semantics apply.

## Unsafe adapter review and migration

The only new dependency is libc, already present transitively. It supplies the
native ABI for memfd, descriptor duplication, filesystem identification and the
post-fork cgroup/no-new-privileges setup. Workspace unsafe lint is `deny` (instead
of `forbid`) solely to permit documented local exceptions in sys.rs and the memfd
constructor. The callback performs only async-signal-safe calls; descriptor
sources are owned and duplicated above the stdio/setup range before forking.
Errors carry a static reason and do not expose paths or payloads. No unsafe code
is added to policy evaluation or the packet path. Review checks include ownership
transfer only after successful syscalls, initialized output reads only on success,
no allocation/locks in pre_exec, and no untrusted code before cgroup enrollment.

Existing APIs retain mandatory Gate and Runner boundaries. Pass `NativeRunner` to
`stdio::run` after owner authorization and durable launch audit. No policy grants,
HTTP behavior, credentials, database migrations or executable CLI are added. The
CLI still requires the existing missing composition work, outside this task.

## Sources

- [Bubblewrap source and options](https://github.com/containers/bubblewrap), queried
  through Context7 for descriptor, seccomp and namespace contracts.
- [Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
  for controller delegation and cgroup.kill semantics.
- [Apple XNU resource implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_resource.c)
  for platform-specific resource semantics; these need validation on target macOS.
- [Chromium macOS sandbox design](https://www.chromium.org/developers/design-documents/sandbox/osx-sandboxing-design/)
  for Seatbelt inheritance and confinement boundaries. Context7 did not return an
  Apple Seatbelt library, so primary implementation/design references supplement it.
