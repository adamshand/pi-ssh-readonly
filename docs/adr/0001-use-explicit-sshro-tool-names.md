# Use explicit sshro tool names for SSH read-only tools

SSH read-only inspection uses explicit tools such as `sshro_read`, `sshro_ls`, `sshro_locate`, and `sshro_grep` instead of overriding pi's built-in `read`, `ls`, `find`, and `grep` names. We chose clarity and auditability over native built-in-name ergonomics: explicit names avoid local/remote ambiguity while still allowing the tools to be available alongside normal local tools.

Tool names describe investigation intent rather than backend implementation. For example, recursive live listing remains `sshro_ls({ recursive: true })` even when implemented with `eza`, and indexed path search is exposed separately as `sshro_locate` because `plocate` results may be stale.
