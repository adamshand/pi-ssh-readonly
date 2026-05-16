# SSH Read-only Extension

This context covers a pi extension that lets agents inspect remote Linux servers over SSH without exposing mutation tools.

## Language

**SSH Read-only Mode**:
A pi operating mode in which the agent's available SSH-backed tools can only read, list, and search the remote server.
_Avoid_: SSH mode, remote mode, read-only session

**Global Auto-loaded Extension**:
A pi extension installed in the user's global extension directory so its `/sshro` command and `--ssh-ro` flag are available from any working directory.
_Avoid_: manually loaded extension, project extension

**Remote Working Directory**:
The SSH user's login directory used to resolve relative tool paths during **SSH Read-only Mode**.
_Avoid_: chroot, jail, root boundary, `target:/path`

**SSH Read-only Tool**:
An explicit `sshro_*` tool whose behavior is implemented against the remote server over SSH while preserving familiar read/list/search parameters where useful.
_Avoid_: overloaded built-in tool names, local tool ambiguity, whole-file local slicing

**SSH Read-only Tool Gate**:
The runtime enforcement policy that allows only the registered `sshro_*` diagnostic tools to be active or callable during **SSH Read-only Mode**.
_Avoid_: registered-tool ban, extension blacklist

**User Bash Escape Hatch**:
The existing pi `!` and `!!` mechanism for human-supervised shell commands. During **SSH Read-only Mode**, the extension routes these commands to the SSH target instead of the local host; `!!` keeps pi's existing no-context behavior.
_Avoid_: agent bash, remote bash tool

**Non-interactive SSH Authentication**:
SSH authentication that completes without prompting during tool execution, typically via keys or an SSH agent.
_Avoid_: password prompt, interactive login

**System SSH Client**:
The local OpenSSH command-line client used by the extension for remote access, preserving normal SSH config behavior such as aliases, ProxyJump, host canonicalization, ports, and identities.
_Avoid_: SSH library, custom SSH config parser

**Visible Search Errors**:
Permission and traversal errors returned by remote search tools so the agent can distinguish absence of evidence from inaccessible evidence.
_Avoid_: hidden permission errors, silent stderr suppression

**Remote Prompt Context**:
The minimal factual system-prompt context that presents the SSH target and fixed remote working directory as the active environment for SSH read-only tools, including the facts that `~` expansion is not supported and recursive search prunes `.git`, `node_modules`, and common credential paths.
_Avoid_: duplicated local cwd, behavioral over-instruction, explicit inactive-tool warnings in v1

**Fixed Remote Command Template**:
A remote shell command assembled from a known read-only template with every user-controlled path, pattern, and option shell-quoted.
_Avoid_: arbitrary remote shell, stdin helper script in v1

## Relationships

- **SSH Read-only Mode** is provided by a **Global Auto-loaded Extension** in v1 at `~/.pi/agent/extensions/ssh-readonly/index.ts`.
- A **Remote Working Directory** is not a confinement boundary; absolute remote paths remain accessible in v1.
- `/sshro <target>` and `--ssh-ro <target>` accept only an SSH target; the **Remote Working Directory** is resolved when entering **SSH Read-only Mode** as the SSH user's login directory and remains fixed until logout.
- **SSH Read-only Mode** exposes `sshro_read`, `sshro_ls`, `sshro_find`, `sshro_grep`, `sshro_journalctl`, `sshro_systemctl`, `sshro_ps`, `sshro_ss`, `sshro_df`, `sshro_docker_ps`, `sshro_docker_inspect`, `sshro_docker_stats`, and `sshro_dig` as **SSH Read-only Tools**.
- The `sshro_read`, `sshro_ls`, `sshro_find`, and `sshro_grep` tools mirror the practical built-in read-only tool schemas where possible.
- The `sshro_read` tool keeps the familiar `path`, `offset`, and `limit` interface but performs line-range extraction on the remote server rather than downloading whole files for local slicing; positive offsets use remote `head`/`tail` instead of `sed`, and negative offsets read from the end of the file using remote `tail` for efficient log inspection.
- When no `offset` or `limit` is provided, `sshro_read` returns the beginning of the file up to pi-like truncation limits and can be adjusted later if logfile investigation proves this insufficient.
- `sshro_read` is text-only in v1, uses remote `file` output to classify non-text files, shows that classification in the tool result, and refuses binary content rather than preserving built-in image support.
- `sshro_grep` uses remote `grep -E` extended regex semantics by default, searches directories recursively, prunes `.git`, `node_modules`, and common credential paths, skips binary files by default, supports simple file-selection globs such as `*.conf` or `*.log` to reduce tool calls, and uses fixed-string `grep -F` matching when `literal: true`.
- Remote `grep` and `find` return **Visible Search Errors** as summaries alongside any successful results so permission errors do not consume the match/result budget; callers can request detailed errors with `showErrors: true` and bound them with `errorLimit`.
- The **SSH Read-only Tool Gate** requires active tools to be exactly the registered `sshro_*` tools, warns about unrelated inactive tools, and blocks all other tool calls.
- v1 does not keep non-file helper tools such as questionnaire active during **SSH Read-only Mode**.
- The **User Bash Escape Hatch** remains available without extra warnings; **SSH Read-only Mode** restricts agent tools, not experienced sysadmin actions.
- The agent may suggest human-run commands without special read-only prompting; the sysadmin remains responsible for deciding whether to run them.
- **SSH Read-only Mode** requires **Non-interactive SSH Authentication** and a pre-existing OpenSSH known_hosts entry; SSH uses `BatchMode=yes` and `StrictHostKeyChecking=yes` so unknown hosts fail closed instead of prompting.
- v1 requires the remote server to provide standard tools needed by the SSH-backed implementation, including `file` for read classification, and checks critical external commands such as `file`, `find`, `grep`, `head`, `sed`, `stat`, `tail`, and `ls` at startup.
- If **SSH Read-only Mode** is requested but startup checks fail, v1 fails closed by clearing active tools, blocking all tool calls, and showing a fatal status/error instead of continuing in normal local mode.
- **SSH Read-only Mode** can be entered at startup with `--ssh-ro <target>` or mid-session with `/sshro <target>`; `/sshro logout` leaves SSH Read-only Mode and restores the previous active tool set.
- When **SSH Read-only Mode** is inactive, the global extension is mostly invisible: it registers only the `/sshro` command and `--ssh-ro` flag, and does not activate SSH read-only tools, alter active tools, change prompts, or show UI.
- When **SSH Read-only Mode** is active, the extension registers `sshro_read`, `sshro_ls`, `sshro_find`, `sshro_grep`, `sshro_journalctl`, `sshro_systemctl`, `sshro_ps`, `sshro_ss`, `sshro_df`, `sshro_docker_ps`, `sshro_docker_inspect`, `sshro_docker_stats`, and `sshro_dig`, sets the active tool list to exactly those tools, and blocks all other agent tool calls defensively; local built-in tools are not active.
- v1 uses the **System SSH Client** rather than an SSH library; IPv6 target parsing is out of scope.
- v1 allows any SSH target accepted by the **System SSH Client**, including root login targets such as `root@server`.
- v1 does not support sudo escalation; use an SSH target with the desired read visibility.
- v1 uses **Fixed Remote Command Templates** for SSH execution rather than installing helpers or sending scripts over stdin; templates are executed through remote `sh -c` so non-POSIX login shells such as fish do not parse the templates.
- **Remote Prompt Context** replaces the normal local current-working-directory line with the fixed **Remote Working Directory** and states that `sshro_*` tools operate on the SSH target.
- During **SSH Read-only Mode**, user `!` and `!!` commands execute on the SSH target from the fixed **Remote Working Directory**; `!!` still excludes output from model context, and displayed remote command output begins with an `[ssh-ro target]$ ...` prompt line.
- v1 applies best-effort credential guardrails: direct content reads/searches are blocked for common credential directories/files, shell history files, password-manager paths, and chezmoi paths. Recursive `sshro_grep` prunes common credential/history/password-manager/dotfile-manager paths by default. This is not a chroot or adversarial DLP boundary.
- v1 does not expand `~` in tool paths; use absolute home paths such as `/home/name` or paths relative to the **Remote Working Directory**.
- v1 rejects tool paths and patterns containing newlines or control characters while allowing ordinary spaces and punctuation through shell quoting.
- v1 uses tool-specific SSH command timeouts, with shorter bounds for startup/read/list/diagnostic operations and longer bounds for recursive `grep`/`find` and journal inspection.
- v1 uses pi-like output limits by default: roughly 50KB or 2000 lines for reads, 1000 entries/results/matches for listing and search, and bounded visible error output.
- `sshro_ls` returns investigation-oriented metadata such as type, permissions, owner, size, modification time, symlink targets, and name, and includes hidden files by default. Parent listings show blocked credential/history/password-manager entries but append a compact `[blocked]` marker plus one footnote rather than hiding them, so the agent knows they exist without direct access.
- `sshro_find` uses remote POSIX `find`; patterns without `/` are filename globs via `-name`, while patterns containing `/` are path globs via `-path`.
- `sshro_find` includes hidden files by default, shows matching blocked credential/history/password-manager/dotfile-manager entries with a compact `[blocked]` marker, and does not descend into blocked directories during broad traversal, so parent searches may not enumerate blocked children.
- `sshro_journalctl` reads recent systemd journal output with optional unit, time range, priority, grep, and line-limit filters; it does not make `journalctl` a startup requirement because not every target is systemd-based.
- `sshro_systemctl` exposes only fixed read-only systemd inspections: failed units, service lists, status, and selected `systemctl show` properties.
- `sshro_ps` reads the process table with optional user/pattern filtering and cpu/memory/pid sorting; process command lines can reveal sensitive arguments, so this is read-only but not secret-redacting. Header-only filtered results are reported as `No matching processes`.
- `sshro_ss` reads TCP/UDP socket state with `ss`, defaulting to listening sockets without process ownership; process info is optional and may require privileges. If process info is requested but not visible, the tool appends a note explaining the likely permission limitation.
- `sshro_df` reads filesystem usage with `df`, defaulting to `df -l` local filesystems only to reduce risk from slow or hanging network mounts; callers can opt into non-local filesystems explicitly.
- Docker tools are optional runtime diagnostics and are not part of startup health checks; `docker` is not included in startup `REQUIRED_REMOTE_COMMANDS`, and each Docker tool returns a clear tool error if Docker is missing or inaccessible to the SSH user.
- Docker tools use fixed read-only Docker command templates, shell-quote all user-controlled Docker object names/filters, reject control characters/newlines, do not accept arbitrary Docker subcommands, do not require remote `jq`, and parse/pretty-print Docker JSON locally where available.
- Docker object names/IDs are not filesystem paths and are not passed through **Remote Working Directory** resolution or filesystem credential path policy; they still receive control-character and `~` validation.
- `sshro_docker_ps` reads compact `docker ps --no-trunc` table output by default, includes only active containers unless `all=true`, supports Docker's `--filter name=...`, and returns a friendly `No active Docker containers. Use all=true to include stopped/exited containers.` message when only the table header is returned. `limit` must be at least 1, and row truncation appends an explicit note such as `[ssh-ro output truncated to 10 containers]`.
- `sshro_docker_inspect` runs fixed `docker inspect [--type kind] target`, accepts only `container`, `image`, `network`, or `volume` as `kind`, and returns pretty JSON using Docker's native field names/shape with targeted redaction/omission. Environment variable values are never shown; if present, `Env` is visibly marked as `[redacted]` so the agent can ask the human operator for help if needed. There is no parameter to reveal environment values in curated output. Docker labels with sensitive-looking keys such as token/secret/password/key/credential are redacted. Image `GraphDriver.Data` is omitted because it exposes Docker storage internals such as `/var/lib/docker/overlay2/...`. Volume mountpoints and network topology/container mappings may be visible.
- `sshro_docker_stats` reads one-shot `docker stats --no-stream --format '{{json .}}'` output, parses Docker JSON rows locally, and never starts Docker's streaming stats mode. `limit` must be at least 1, and row truncation appends an explicit note such as `[ssh-ro output truncated to 10 stat rows]`. If stats JSON output is unavailable or unparseable, it returns a clear tool error. CPU percentages can be noisy; the agent can call the tool multiple times a few seconds apart to compare.
- `sshro_dig` performs fixed bounded DNS lookups from the remote host using `dig +time=3 +tries=1`, with optional record type, DNS server, and `+short` output. `dig` is checked at tool runtime rather than startup; if missing, the tool returns a clear error.
- On successfully entering SSH Read-only Mode, the extension emits one visible `ssh-ro-info` message containing the same concise mode note that is appended to the agent system prompt, reducing drift between human-visible and agent-visible guidance.
- If `/sshro <target>` is used while already active, the extension rejects the request and tells the user to run `/sshro logout` first; it does not switch targets implicitly.
- The SSH Read-only Mode status bar shows only the target, not the remote cwd; the remote cwd remains visible in the mode note and prompt context.

## Example dialogue

> **Dev:** "Can I enter **SSH Read-only Mode** from any directory?"
> **Domain expert:** "Yes — v1 uses a **Global Auto-loaded Extension**, so `/sshro root@server` and `pi --ssh-ro root@server` are available wherever pi is launched."
>
> **Dev:** "If I start at `/var/www`, can the agent inspect `/etc/nginx`?"
> **Domain expert:** "Yes — `/var/www` is only the **Remote Working Directory**, not a chroot."

## Flagged ambiguities

- "SSH mode" was used broadly; resolved: v1 means **SSH Read-only Mode**, not arbitrary remote shell execution.
- "root" or path suffixes in `user@host:/path` could mean either a confinement boundary or starting location; resolved: v1 does not support `target:/path` and uses the SSH login directory as the **Remote Working Directory**.
- Tool names could either be SSH-specific or reuse pi built-in names; resolved: v1 uses explicit **SSH Read-only Tools** named `sshro_read`, `sshro_ls`, `sshro_find`, and `sshro_grep` for clarity and auditability.
- Unexpected registered tools could be fatal or ignored; resolved: the **SSH Read-only Tool Gate** is strict for active tools and SSH-backed tool ownership, but only warns about unrelated inactive tools.
- User `!` and `!!` commands could be blocked, warned, left local, or routed to the active SSH target; resolved: during **SSH Read-only Mode**, route both to the SSH target because local execution while visually investigating a remote host is more confusing. `!!` still excludes output from model context.
- The agent could be restricted to suggesting only read-only human-run commands; resolved: do not add special restrictions because the sysadmin chooses what risk to accept.
