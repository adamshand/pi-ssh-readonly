# Use explicit sshro tool names for SSH Read-only Mode

SSH Read-only Mode uses explicit tools named `sshro_read`, `sshro_ls`, `sshro_find`, and `sshro_grep` instead of overriding pi's built-in `read`, `ls`, `find`, and `grep` names. We chose clarity and auditability over native built-in-name ergonomics: explicit names make it easier to verify the active tool surface, avoid local/remote ambiguity, and fail closed when any unexpected agent tool is called.
