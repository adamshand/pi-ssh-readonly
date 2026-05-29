# SSH Read-only Extension

This context covers a pi extension that lets agents inspect remote Linux servers over SSH without exposing mutation tools.

## Language

**SSH Read-only Tool**:
An explicit `sshro_*` tool whose behavior is implemented against a remote server over SSH while preserving familiar read/list/search parameters where useful.
_Avoid_: overloaded built-in tool names, local/remote ambiguity

**Target Approval**:
The per-session approval state for an exact SSH target string used by stateless `sshro_*` tools.
_Avoid_: canonical host approval, hidden current host

**SSHRO Host Whitelist**:
The `SSHRO_HOST_WHITELIST` environment variable whose comma-separated exact target strings allow agent-initiated `sshro_*` calls to run without prompting the human.
_Avoid_: denylist, canonical host policy, SSH config parser

**Fixed Remote Command Template**:
A remote shell command assembled from known read-only command shapes with every user-controlled path, pattern, and option shell-quoted.
_Avoid_: arbitrary remote shell, server-side helper script

**Elevated Read-only Command**:
A fixed command run through `sudo -n` only after `sudo -n -l <exact command ...>` confirms the SSH user may run that exact command without a password.
_Avoid_: blind sudo attempt, password prompt, NOPASSWD ALL

**System SSH Client**:
The local OpenSSH command-line client used by the extension for remote access, preserving normal SSH config behavior such as aliases, ProxyJump, ControlMaster sockets, ports, and identities.
_Avoid_: SSH library, custom SSH config parser

**Visible Search Errors**:
Permission and traversal errors returned by remote search tools so the agent can distinguish absence of evidence from inaccessible evidence.
_Avoid_: hidden permission errors, silent stderr suppression

## Relationships

- The extension is a **Global Auto-loaded Extension** and registers the `sshro_*` tools alongside normal local pi tools; it no longer requires a modal remote-only state for agent tool use.
- Every `sshro_*` tool call requires an explicit `target` parameter. The extension does not keep a hidden current SSH host for agent tools.
- `/sshro <target>` and `--ssh-ro <target>` pre-approve that exact target for the current Pi session. `/sshro logout` clears session approvals.
- The current read-only tool set is `sshro_read`, `sshro_ls`, `sshro_locate`, `sshro_grep`, `sshro_journalctl`, `sshro_systemctl`, `sshro_ps`, `sshro_ss`, `sshro_df`, `sshro_docker_ps`, `sshro_docker_inspect`, `sshro_docker_stats`, and `sshro_dig`.
- If a target exactly matches `SSHRO_HOST_WHITELIST`, the tool runs without prompting. If the target was previously approved in the same Pi session, the tool runs without prompting. Otherwise the extension asks the human to approve that exact target before any SSH inspection command is attempted.
- Target approval is exact-string and in-memory/session-only. `binney` and `adam@binney` are distinct targets even if OpenSSH resolves them to the same host.
- Non-whitelisted tool calls fail closed when no UI is available because human approval is impossible.
- OpenSSH still resolves aliases, ProxyJump, identities, ControlMaster sockets, and other SSH configuration normally when a tool runs.
- SSH uses `BatchMode=yes` and `StrictHostKeyChecking=yes`; authentication and host verification must already be configured.
- Agent-initiated local `bash` calls are blocked from invoking common SSH client commands or SSH transport URLs so the agent uses audited `sshro_*` tools instead. Human-run `!` and `!!` commands are not blocked.
- Paths are remote paths. Relative paths resolve from the SSH login directory for that tool call. `~` expansion is rejected; use absolute home paths such as `/home/name` or paths relative to the remote login directory.
- The extension does not install a server-side helper, SUID binary, forced command gateway, or root SSH account. Elevated access is delegated entirely to the server's sudoers policy.
- Before any elevated command is run, the tool checks `sudo -n -l <exact fixed command ...>`. The extension only runs `sudo -n <command ...>` when that check succeeds.
- If `sudo -n -l` reports that a password/tty is required or the exact command is not allowed, the tool falls back to the non-sudo command and reports that elevated access was unavailable.
- Sudo capability checks are cached per Pi session by target, command path, and exact arguments.
- If a non-sudo fallback fails with permission denied and sudo was unavailable, tool output includes a human-facing sudoers setup hint for the relevant fixed command.
- Each SSH command appends a remote time marker to stderr; `sshExec` strips the marker from stderr and tool results include a footer such as `[ssh-ro: target | remote time: 2026-05-29T22:14:03+12:00]` for log/mtime context.
- `sshro_read` keeps `path`, `offset`, and `limit`. It reads through fixed `cat -- path`, optionally via sudo after approval, then applies line slicing with remote `head`/`tail`.
- `sshro_ls` returns metadata, includes hidden files by default, and supports `recursive: true` for live recursive listings.
- Recursive `sshro_ls` prefers `eza -1l --absolute=on -R --color=never --icons=never -- path`, filters eza grouping-folder headers, and falls back to `ls -laR` when `eza` is unavailable.
- `sshro_locate` uses `plocate` for fast indexed path search. Results may be stale. No regex option is exposed initially.
- `sshro_grep` uses `grep -E` by default, searches directories recursively with `grep -R`, skips binary files, supports `glob`, and uses `grep -F` when `literal: true`.
- Direct content reads and recursive grep exclude `.env`, `*.env`, shell history, private key/certificate extensions, `.git`, `node_modules`, and common credential/history/password-manager/dotfile-manager paths by default. This is not a chroot or adversarial DLP boundary.
- Tool paths and patterns reject newlines/control characters while allowing ordinary spaces and punctuation through shell quoting.
- Tool-specific SSH timeouts and pi-like output limits bound remote inspections.
- Docker tools are optional runtime diagnostics. `sshro_docker_inspect` uses `target` for the SSH target and `object` for the Docker object name/ID.
- Docker inspect output redacts environment variables and sensitive-looking labels and omits image `GraphDriver.Data`.

## Example dialogue

> **Dev:** "Can the agent inspect a remote server and then read local project files?"
> **Domain expert:** "Yes — the `sshro_*` tools are stateless and target-explicit, so local tools remain available in the same conversation."
>
> **Dev:** "If the agent uses `sshro_ls({ target: \"root@server\", path: \"/etc\", recursive: true })`, is `/etc` confined by where pi was launched?"
> **Domain expert:** "No — paths are remote paths. The local launch directory is irrelevant, and absolute remote paths remain accessible subject to tool guardrails and remote OS permissions."

## Flagged ambiguities

- Tool names could either be SSH-specific or reuse pi built-in names; resolved: use explicit `sshro_*` names for clarity and auditability.
- Recursive path discovery could be exposed as `sshro_find`, `sshro_eza`, or `sshro_ls`; resolved: use `sshro_ls({ recursive: true })` because the agent asks for intent-level listing and should not need to know the backend implementation.
- Locate pattern could be regex by default or expose a regex option; resolved: plain `plocate` pattern only until regex proves necessary.
- Elevated access could use a helper binary, root SSH, or direct sudo; resolved: no helper or root account, use direct fixed sudo commands only after `sudo -n -l` confirms access.
- Elevated tools could blindly try sudo first; resolved: check `sudo -n -l` first because failed sudo commands can notify admins.
