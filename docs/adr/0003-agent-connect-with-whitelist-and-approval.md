# Allow agent-initiated SSH Read-only connections with whitelist auto-approval

The agent can now request entry into SSH Read-only Mode with `sshro_connect({ target })` instead of always asking the human to type `/sshro <target>`.

Agent-initiated connection requests preserve human control. The extension validates the target and checks `SSHRO_HOST_WHITELIST`, a comma-separated list of exact target strings read from the pi process environment. If the requested target is present, the extension connects immediately. If it is absent, the extension prompts the human for approval before making any SSH connection attempt. In non-interactive modes, non-whitelisted requests fail closed because approval is impossible.

`SSHRO_HOST_WHITELIST` is an auto-connect approval list, not an access-control denylist. Non-whitelisted targets can still be used after explicit human approval, and human-initiated `/sshro <target>` and `pi --ssh-ro <target>` keep working as before without consulting the whitelist.

Whitelist matching intentionally compares the literal target string passed to `sshro_connect` after trimming entries and dropping empty comma-separated values. The extension does not canonicalize hostnames or parse SSH configuration, so `binney` and `adam@binney` are distinct whitelist entries. OpenSSH still resolves aliases, ProxyJump, identities, ports, and other configuration normally when the connection is made.

The `sshro_connect` tool hint includes the configured whitelist target strings, truncated after 20 entries, so the agent can prefer auto-approved targets instead of guessing and triggering unnecessary approval prompts. The hint explicitly says that automatic approval requires using the target exactly as listed. If no targets are configured, the hint says the whitelist has no configured targets.

Once SSH Read-only Mode is active, the active agent tool surface becomes the curated read-only diagnostic tools plus `sshro_disconnect`, which lets the agent leave SSH Read-only Mode without human approval. A successful `sshro_connect` result explicitly says the connection is active and tells the agent not to call `sshro_connect` again while connected.

Because non-whitelisted approval can happen long after the model produced the original tool call, the model may continue with a stale pre-connection tool schema. To avoid repeated `sshro_connect` loops, successful and already-active `sshro_connect` results terminate the stale turn and queue a follow-up message so the next turn starts with the updated `sshro_*` tool set.

If a stale `sshro_connect` call still reaches the extension while SSH Read-only Mode is active, the tool returns a non-error "already connected" message with the active target and remote cwd instead of a generic tool-gate error. If `sshro_*` inspection tools or `sshro_disconnect` are called while disconnected, they return clear reconnect guidance.

The existing tool gate continues to block all other tool calls.
