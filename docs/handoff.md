# Handoff — 2026-10-30: native OS containment

## Objective and completion status

Requested native OS sandbox, Linux and macOS implementations, direct SSH-key-read
attack denial, <5 ms proxy packet overhead, repository secret review, commit/push.
Linux Runner and cross-platform selection are implemented. **The complete task is
NOT finished:** macOS has a Seatbelt profile builder and explicit native attack
test, but no complete resource/lifecycle supervisor. NativeRunner refuses macOS
instead of silently weakening AGENTS.md. A macOS host/runner was requested; none
was available in this session. Do not label this as complete macOS support.

## Changes

- sandbox/native.rs: trusted owner configuration and resource budgets, NativeRunner
  selecting Linux and refusing missing/unsupported enforcement.
- sandbox/linux.rs: pre-exec cgroup enrollment, cpu/memory/pids limits, zero swap,
  bubblewrap namespace isolation, read-only pinned workspace, private 16 MiB tmpfs,
  empty environment, no network, literal command/arguments, process-tree kill,
  absolute watchdog and asynchronous empty-cgroup reclamation.
- sandbox/sys.rs and seccomp.rs: small documented unsafe syscall adapters, anonymous
  BPF filter (architecture/x32 checks and dangerous syscall denial). Descriptor
  sources are duplicated above setup range; close_range(CLOEXEC) prevents host fd
  inheritance; --ro-bind-fd consumes and closes the workspace descriptor. An extra
  attack test caught the initial descriptor leak; the corrected implementation
  passes that regression. libc is the only added direct dependency, already locked
  transitively. Workspace unsafe lint changed forbid -> deny for local exceptions.
- sandbox/macos.rs: deny-default Seatbelt component; no permission for network,
  Mach IPC, fork or host writes. Does not claim to pin workspace or enforce budgets.
- tests/fixtures: synthetic malicious/echo MCP scripts, never real keys.
- sandbox/tests/native.rs: actual direct open/cat/symlink denial, no descriptor
  leak, socket/write denial, cgroup limits, detached descendants under termination,
  Drop and deadline. Refuses fake cgroups before creating effects.
- sandbox/tests/macos.rs: direct open(2) via Perl under Seatbelt, requires real macOS
  and is not executed here. Unit tests only validate SBPL input/profile construction.
- proxy/tests/native_runner.rs: actual NativeRunner composed with stdio::run using
  a synthetic Gate, warmed 2000-packet release latency experiment.
- scripts/test-native-linux.sh: test-only systemd user scope delegation helper.
- English README and ADR 0004 document prerequisites, contracts and platform gaps.
  AGENTS.md remains unchanged at 199 lines. CLI remains the pre-existing scaffold;
  audited production composition and UI were not added or bypassed.

## Validation

Passed fmt, clippy --workspace --all-targets --locked -D warnings, workspace tests
and release build. Explicit real Linux attack/lifecycle test passed in a fresh
systemd user scope with Delegate=yes (outside the tool's restricted mount view).
The release native proxy experiment measured 2000 packets: p99 78.659 microseconds,
maximum 488.546 microseconds; all <5 ms. Includes isolated Python peer/pipe round
trip and proxy transport; excludes startup and production Gate audit/DLP/policy.
It is not a hard bound on a completed production proxy or arbitrary packet sizes.

MacOS kernel enforcement and AArch64 execution are NOT verified. No UI tests apply.
The new attack/latency tests are explicitly ignored by the ordinary suite because
they need host delegation; they were separately run and passed on Linux. The test
script fails on missing prerequisites instead of substituting a successful skip.

Gitleaks history and exact candidate snapshot scans are performed before commit,
with redacted output and reports outside the repository. No real key was accessed
or put into fixtures. Such scanning cannot prove absence of every secret or inspect
remote forks. Git fetch updates remote refs before the final history scan.

## Next required work

Complete a macOS native Runner without relaxing resource/lifecycle invariants;
validate native memory/CPU/task ceilings and cancellation against exec/fork/daemon
behavior and direct system calls. A Seatbelt profile alone is insufficient. The
current Runner API returns an owned Tokio Child, so macOS supervision must account
for ownership/reaping and PID reuse rather than guessing from a stored PID. Keep
unsupported capabilities fail-closed. Confirm the host's Seatbelt availability and
resource syscall semantics; Apple APIs differ from cgroups. Context7 supplied
bubblewrap contracts but no relevant Apple library; ADR links primary sources.

Linux deployment: provide a trusted delegated cgroup v2 parent with cpu, memory
and pids enabled. Keep it and its ancestors inaccessible to untrusted writers.
Do not expose credential-containing workspaces. Use NativeRunner only through
bounded stdio::run with the existing mandatory audited Gate.

Environment toolchain: RUSTUP_HOME=/tmp/clawbell-rustup,
CARGO_HOME=/tmp/clawbell-cargo, /tmp/clawbell-cargo/bin/cargo.
