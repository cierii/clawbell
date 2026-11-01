# Owner security profiles

These are complete policies, not fragments to merge automatically. Inspect tool
names, declared effects and JSON pointers against your pinned upstream before use.
`workspace` is a logical relative path prefix, not a host directory mount setting.

- `read-only.toml`: allows `read_file` under `workspace`; denies writes and shell.
- `reviewed-writes.toml`: adds approval-required `write_file` under
  `workspace/output`; all other writes deny.
- `default.toml`: existing general example retained for compatibility.

Validate a selected profile before binding it:

```bash
cargo run --locked -p clawbell -- policy check --file policies/read-only.toml
cargo run --locked -p clawbell -- policy check --file policies/reviewed-writes.toml
```

Both profiles explicitly deny `.ssh` and `.env` paths (including `.env.local`) in
serialized arguments. Absolute paths, traversal and unknown tools already fail
closed. The conservative regex may also reject innocent text containing these
names. It is defense in depth, not a secret detector or a filesystem sandbox.
Opaque shell operations always deny, regardless of spelling or regex matches;
`rm -rf`, alternate option ordering and indirect shell invocation get no grant.
Skills and network capabilities receive no grants in these profiles.

Use only a credential-free mounted workspace. A process can read mounted files
without making a `read_file` call. Symlink/TOCTOU enforcement belongs to the native
runner, not lexical rules. A remote upstream's filesystem is outside this control.
Approval-required writes also need an available owner approval channel and a
separately configured write/transaction capability; the profile itself grants no
host mount or automatic approval. Missing capabilities refuse execution.

Tests in `crates/core/tests/profiles.rs` exercise actual profile files and negative
cases. See [architecture](../ARCHITECTURE.md) for the complete request path.
