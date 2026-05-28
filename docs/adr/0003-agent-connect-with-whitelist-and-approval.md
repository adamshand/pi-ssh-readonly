# Allow agent-initiated SSH Read-only connections with whitelist auto-approval

The agent can now request entry into SSH Read-only Mode with `sshro_connect({ target })` instead of always asking the human to type `/sshro <target>`.

Agent-initiated connection requests preserve human control. The extension validates the target and checks `SSHRO_HOST_WHITELIST`, a comma-separated list of exact target strings. If the requested target is present, the extension connects immediately. If it is absent, the extension prompts the human for approval before making any SSH connection attempt. In non-interactive modes, non-whitelisted requests fail closed because approval is impossible.

`SSHRO_HOST_WHITELIST` is an auto-connect approval list, not an access-control denylist. Non-whitelisted targets can still be used after explicit human approval, and human-initiated `/sshro <target>` keeps working as before.

Whitelist matching intentionally compares the literal target string passed to `sshro_connect`. The extension does not canonicalize hostnames or parse SSH configuration. OpenSSH still resolves aliases, ProxyJump, identities, ports, and other configuration normally when the connection is made.

Once SSH Read-only Mode is active, `sshro_connect` is removed from the active tool set. The active agent tool surface remains exactly the curated read-only diagnostic tools, and the existing tool gate continues to block all other tool calls.
