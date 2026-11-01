//! Regression coverage for the shipped owner profiles, with synthetic paths only.
use clawbell_core::policy::{Decision, Policy};
use serde_json::json;

#[test]
fn profiles_allow_only_scoped_operations_and_refuse_credentials_and_shells()
-> Result<(), Box<dyn std::error::Error>> {
    for (source, write) in [
        (
            include_str!("../../../policies/read-only.toml"),
            Decision::Deny,
        ),
        (
            include_str!("../../../policies/reviewed-writes.toml"),
            Decision::RequireApproval,
        ),
    ] {
        let policy = Policy::parse(source)?;
        assert_eq!(
            policy
                .evaluate("read_file", &json!({"path":"workspace/docs/a.md"}))
                .decision,
            Decision::Allow
        );
        assert_eq!(
            policy
                .evaluate("write_file", &json!({"path":"workspace/output/a.txt"}))
                .decision,
            write
        );
        for path in [
            "~/.ssh/id_ed25519",
            "/home/example/.ssh/id_rsa",
            "workspace/.ssh/key",
            "workspace/.ssh",
            "workspace/nested/.env",
            "workspace/.env.local",
            "workspace/../outside",
            "workspace-other/a",
        ] {
            assert_eq!(
                policy.evaluate("read_file", &json!({"path":path})).decision,
                Decision::Deny,
                "{path}"
            );
            assert_eq!(
                policy
                    .evaluate("write_file", &json!({"path":path}))
                    .decision,
                Decision::Deny,
                "{path}"
            );
        }
        for command in [
            "rm -rf /",
            "rm -fr workspace",
            "sh -c 'rm -rf workspace'",
            "echo harmless",
        ] {
            assert_eq!(
                policy
                    .evaluate("shell", &json!({"command":command}))
                    .decision,
                Decision::Deny
            );
        }
        assert_eq!(
            policy.evaluate("unknown", &json!({})).decision,
            Decision::Deny
        );
        assert!(!policy.skill_permission().permits_execution());
    }
    Ok(())
}
