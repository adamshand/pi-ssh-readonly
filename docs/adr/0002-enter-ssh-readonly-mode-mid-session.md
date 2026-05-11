# Enter SSH Read-only Mode mid-session with /sshro

SSH Read-only Mode can now be entered during an existing pi session with `/sshro <target>` and exited with `/sshro logout`, while keeping `--ssh-ro <target>` as a startup path. This preserves conversation context and avoids requiring users to quit and restart pi with `-c` or `--session`.

The slash command intentionally uses the short form `/sshro <target>` rather than subcommands like `/sshro login` or `/sshro connect`; logout remains explicit because it is the only non-target command. While active, attempts to connect to another target are rejected with instructions to run `/sshro logout` first. We avoid implicit target switching to keep the read-only boundary obvious.

The status bar shows only `SSH RO <target>`. The remote working directory remains visible in the mode note and prompt context, where it matters for relative path behavior, but it is omitted from the persistent status to reduce clutter.

The extension uses OpenSSH `StrictHostKeyChecking=yes` in addition to `BatchMode=yes`, so hosts must already be trusted in the user's OpenSSH known_hosts flow. Unknown hosts fail closed rather than prompting or being added during tool execution.
