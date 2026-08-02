# Use exact-target approval for stateless SSH read-only tools

> **Refined by [ADR 0004](0004-load-ssh-inspection-tools-after-target-approval.md).** Inspection calls remain stateless and target-explicit, but `sshro_connect` is now the initially active bootstrap that loads their definitions on demand.

After the Inspection Tool Suite is loaded, the agent can use `sshro_*` tools directly alongside normal local tools. Each call includes an explicit `target`, for example `sshro_read({ target, path })` or `sshro_ls({ target, path, recursive: true })`.

Agent-initiated target use still preserves human control. The extension validates the target and checks `SSHRO_HOST_WHITELIST`, a comma-separated list of exact target strings read from the pi process environment. If the requested target is present, the tool can run immediately. If it is absent and the exact target has not already been approved in this Pi session, the extension prompts the human for approval before making any SSH inspection attempt. In non-interactive modes, non-whitelisted requests fail closed because approval is impossible.

`SSHRO_HOST_WHITELIST` is an automatic approval list, not an access-control denylist. Non-whitelisted targets can still be used after explicit human approval. Human-initiated `/sshro <target>` and `pi --ssh-ro <target>` now pre-approve that exact target for the current Pi session; `/sshro logout` clears session approvals.

Whitelist and session approval matching intentionally compare the literal target string after trimming. The extension does not canonicalize hostnames or parse SSH configuration, so `binney` and `adam@binney` are distinct targets. OpenSSH still resolves aliases, ProxyJump, identities, ports, ControlMaster sockets, and other configuration normally when the tool runs.

The modal `sshro_connect` / `sshro_disconnect` workflow is no longer the primary agent path. Stateless target-explicit tools avoid hidden connection state, allow agents to interleave remote inspection with local repository tools, and avoid stale tool-schema loops after delayed human approval.
