<img width="1983" height="793" alt="ChatGPT Image May 5, 2026, 07_10_05 PM" src="https://github.com/user-attachments/assets/4cb21b80-08e6-4bb0-b109-feb53f2d6d1a" />

# pi-ssh-readonly

I sometimes work with legacy servers where configuration has been managed by hand for years. Agent assistance on these servers is extremely valuable.  However the risk of an agent making an undetected change to a production server isn't acceptable.

This extension adds stateless read-only SSH tools alongside pi's normal local tools. It initially exposes only `sshro_connect`, which lets the agent discover or request approval for an exact target and then dynamically loads the detailed inspection tools. This keeps agent-initiated remote debugging available without putting every SSH tool schema into unrelated conversations.

Every inspection call requires an explicit SSH `target`, so agents can inspect a server and then immediately read/edit local project files without entering a modal remote-only state. The tool set is:

- sshro_connect
- sshro_read
- sshro_ls
- sshro_locate
- sshro_grep
- sshro_journalctl
- sshro_systemctl
- sshro_ps
- sshro_ss
- sshro_df
- sshro_docker_ps
- sshro_docker_inspect
- sshro_docker_stats
- sshro_dig

Targets in `SSHRO_HOST_WHITELIST` are approved automatically. Other exact target strings require explicit human approval through `sshro_connect` or a detailed inspection call and are remembered for the rest of the Pi session. After `sshro_connect` approves or discovers an available target, the detailed tools become available on the next agent turn.

It redacts and filters obvious password/secret risks, but doesn't try and catch everything (eg. passwords in `ps` output).  If this is critical in your environment you may want to make changes.

⚠️ ⚠️ ⚠️ This extension is vibe coded. **Use at your own risk.** It's working well for me and hasn't eaten anyone's homework yet. 🤞 🤞 🤞

## Install

Requires Pi `0.83.x` and Node.js `22.19` or newer.

```
pi install git:git@github.com:adamshand/pi-ssh-readonly
```

## Usage

The agent can initiate remote debugging by loading the inspection tools itself:

```text
sshro_connect({ target: "adam@server" })
```

If the target is not whitelisted, Pi asks for human approval. `sshro_connect` does not open an SSH connection; after approval, the agent receives the detailed tool definitions and can use them by passing the exact target on every call:

```text
sshro_read({ target: "adam@server", path: "/etc/nginx/nginx.conf" })
sshro_ls({ target: "adam@server", path: "/etc", recursive: true })
sshro_locate({ target: "adam@server", pattern: "nginx" })
```

Calling `sshro_connect` without a target lists whitelist and session-approved targets. The list is bounded, and if at least one target is available it also loads the inspection tools. Despite its name, `sshro_connect` performs no network probe or SSH connection; the first inspection call verifies connectivity.

You can pre-approve a target and load the inspection tools during an existing pi session:

```text
/sshro adam@server
```

Bare `/sshro` opens a picker containing whitelist targets and literal aliases discovered from `~/.ssh/config` and includes below `~/.ssh`. A discovered alias is only a suggestion: selecting it is the human approval action. Wildcard and negated `Host` patterns are never offered.

Inspect or clear current state:

```text
/sshro status
/sshro logout
```

The footer shows a compact approved-target and loaded-tool count. Target approvals and activation survive `/reload`, but are cleared on process restart, `/new`, `/resume`, and `/fork`. Logout also clears cached remote command and sudo capability checks.

You can also start pi with a pre-approved target and the inspection tools already loaded:

```bash
pi --ssh-ro adam@server
```

Target approval is exact-target based:

- Targets are single OpenSSH destination arguments. Empty values, control characters, whitespace, option-shaped values beginning with `-`, `target:/path`, and IPv6 syntax are rejected in v1.
- Whitelist matches use the exact target string passed to each `sshro_*` tool; `binney` and `adam@binney` are different entries.
- Non-whitelisted targets prompt on first use, then remain approved for the rest of the Pi session.
- Human-initiated `/sshro <target>` and `pi --ssh-ro <target>` pre-approve that exact target without consulting the whitelist.

**Requires passwordless SSH and an existing known_hosts entry. It will not prompt for a password or accept unknown hosts.**

Paths are remote paths. Relative paths resolve from the SSH login directory for that tool call. `~` is not expanded; use absolute paths like `/home/adam/...` or relative paths from the remote login directory. Existing content paths are resolved with remote `realpath -e` and checked both before and after canonicalization, so an allowed-looking symlink cannot be used to read a blocked credential/history path. Targets therefore require a `realpath` implementation.

You can run a local shell command and automatically feed it back to the agent by using the `!` command, eg.

```bash
! echo 'the agent can see this'
```

Whenever this extension is loaded, agent-initiated `bash` tool calls are blocked from directly invoking common SSH client commands. The agent should use the `sshro_*` tools instead. User-run `!` and `!!` commands are not blocked by this guard.

Git-over-SSH is intentionally allowed, including explicit `git@host:path` and `ssh://` remote URLs and the standard `GIT_SSH` / `GIT_SSH_COMMAND` environment variables. This permits normal clone, fetch, pull, and push workflows; **pushes can modify a remote repository**. The bash guard is only a best-effort tripwire against accidental direct SSH use—not a process or network sandbox. Indirect SSH execution and non-SSH network tools remain possible. For an actual security boundary, run agent-controlled local tools in a sandbox such as Gondolin while leaving the fixed `sshro_*` tools and SSH credentials in the trusted host process.

## Architecture

The detailed tools are activated additively, preserving local tools and tools from other extensions. On models with Pi's native deferred-tool support, their definitions are anchored at the `sshro_connect` result so the stable prompt prefix remains cacheable. Other models receive the expanded tool list normally on the next request, causing at most a one-time cache-prefix change when SSH inspection is first needed. Lazily loaded tools rely on their normal tool descriptions rather than active-only prompt snippets or guidelines.

Inspection names are collected from the definitions as they are registered, preventing activation metadata from drifting away from the actual tool suite. An instance-scoped controller owns approval, activation, pending prompts, and caches. A small session entry preserves approval and activation across hot reload only; it is deliberately ignored and reset for a fresh process or replacement session.

Remote pipelines emit an out-of-band producer-status marker so filters such as `sed` cannot turn a failed inspection into a successful result. Genuine failures are thrown so Pi marks the tool result as an error; expected states such as grep finding no matches, `systemctl status` reporting an inactive unit, or a bounded reader receiving SIGPIPE after `head` has enough data remain successful information. Process stdout and stderr are bounded independently, retain final status markers, and report truncation. Normal agent-facing results use Pi's standard 2,000-line/50KB truncation helpers.

SSH transport construction, target policy, command resolution, approval state, path policy, and output parsing live in separate modules with testable boundaries. Command lookup caches only completed remote lookups: transport failures remain retryable and are not misreported as missing binaries.

## Configuration

The extension uses OpenSSH with `BatchMode=yes` and `StrictHostKeyChecking=yes`, so authentication and host verification must already be configured before using the `sshro_*` tools.

`SSHRO_HOST_WHITELIST` is an automatic approval list for agent-initiated `sshro_*` tool calls. Set it in the environment before starting pi:

```bash
SSHRO_HOST_WHITELIST="web1,adam@legacy,prod-readonly" pi
```

It is not an access-control denylist: non-whitelisted targets can still be used after explicit human approval. Values are comma-separated, trimmed, validated as single destination arguments, and matched exactly against the target string the agent passes. Invalid entries are ignored and counted in the tool hint. OpenSSH still resolves aliases, ProxyJump, identities, and other SSH config normally when the tool runs. SSH config discovery is only a human-picker convenience and never extends this automatic-approval set.

The configured target strings are included in every `sshro_*` tool hint so the agent knows which targets can be used without prompting. The hint explicitly says that automatic approval requires using the target exactly as listed, so a whitelist entry like `binney` does not imply `adam@binney`. If more than 20 targets are configured, the hint shows the first 20 and reports how many more are present.

Not required but configuring SSH to use connection sharing will speed things up.

```text
# ~/.ssh/config
Host *
  ControlMaster auto
  ControlPath ~/.ssh/sockets/%r@%h:%p
  ControlPersist 900
```

`index.ts` includes a basic list of files/folders which the agent is not allowed to read (eg. `.env`, `*.env`, shell history files, SSH/cloud credential directories, password-manager data, chezmoi data). Listings still show blocked entries with a compact `[blocked]` marker where possible so the agent knows they exist and can ask for help if needed. Recursive `sshro_grep` excludes blocked credential/history/password-manager paths. `sshro_grep` uses extended regex (`grep -E`) by default; use `literal=true` for fixed-string search. If you have specific requirements edit this.

`sshro_ls` supports `recursive=true` for live recursive listings. Recursive listing uses `eza -1l --absolute=on -R --color=never --icons=never` when available, filters eza grouping headers, and falls back to `ls -laR` otherwise.

`sshro_locate` uses `plocate` for very fast indexed path search. Results may be stale depending on how often the server updates its locate database.

Tool results include a compact footer with the SSH target and remote server time, e.g. `[ssh-ro: white | remote time: 2026-05-29T22:14:03+12:00]`, so log and mtime output has clock context without a separate tool call.

Some tools can use elevated read-only access when sudoers allows the exact fixed command with `NOPASSWD`. Before running any elevated command the extension checks `sudo -n -l -- <command ...>` and requires the matching sudoers output to include `NOPASSWD:`; if sudo requires a password or the command is not allowed, the tool falls back to the non-sudo command and reports that elevated access was unavailable. This avoids noisy failed sudo command attempts. Example sudoers additions for a trusted account on servers you control:

```sudoers
agent ALL=(root) NOPASSWD: /usr/bin/cat *
agent ALL=(root) NOPASSWD: /usr/bin/ls *
agent ALL=(root) NOPASSWD: /usr/bin/grep *
agent ALL=(root) NOPASSWD: /usr/bin/eza -1l --absolute=on -R --color=never --icons=never -- *
agent ALL=(root) NOPASSWD: /usr/bin/plocate *
agent ALL=(root) NOPASSWD: /usr/bin/journalctl *
agent ALL=(root) NOPASSWD: /usr/bin/systemctl --no-pager status *
```

Avoid broad rules such as `NOPASSWD: ALL`, `/usr/bin/find *`, or shell access.

`sshro_read` supports negative `offset` values for efficient tail-style reads of large files, e.g. `offset=-100` reads the last 100 lines. Before returning content, it samples the same `cat` command it would use for the read, runs the sample through remote `file --mime-type`, and refuses non-text content.

Docker tools are optional and checked when the tool runs, not at startup. `sshro_docker_ps` returns compact `docker ps --no-trunc` table output, defaults to active containers only, and reports `No active Docker containers` when only the header is returned. Use `all=true` to include stopped/exited containers. `sshro_docker_stats` returns parsed JSON using Docker's native field names and rejects `limit` values below 1. If output is row-limited, Docker row tools append an `[ssh-ro output truncated ...]` note. `sshro_docker_inspect` uses `target` for the SSH target and `object` for the Docker object name/ID, and returns Docker-shaped JSON with targeted redaction: environment variables are visibly redacted, sensitive-looking label values are redacted, and image `GraphDriver.Data` is omitted. Docker command strings, mountpoints, and network topology may be visible. `sshro_docker_stats` always uses one-shot `--no-stream` mode; call it multiple times a few seconds apart to compare noisy CPU readings.

`sshro_dig` runs bounded DNS lookups from the remote host using `dig +time=3 +tries=1`. `dig` is checked when the tool runs and returns a clear error if missing.

## Trust boundaries and known issues

“Read-only” means the extension offers fixed inspection command shapes rather than arbitrary remote mutation commands. It does **not** guarantee that the remote system observes zero writes: SSH authentication can update login/audit logs, reads can update access times, DNS inspection sends queries, and remote shell startup hooks or command implementations may have side effects. The local OpenSSH configuration, SSH client, remote login shell, and remote inspection binaries are trusted parts of the execution path.

- The agent `bash` guard is deliberately not a security boundary. Git-over-SSH is allowed, and indirect SSH execution or other remote mutation protocols cannot be reliably blocked by inspecting shell command text.
- Canonical path checks prevent direct and symlinked reads of known credential/history paths, but this remains a denylist rather than a chroot or adversarial data-loss-prevention boundary. Allowed files, process arguments, logs, Docker metadata, and command output can still contain secrets.
- Path canonicalization and the subsequent read are separate remote operations, so a hostile remote user able to replace symlinks concurrently could create a time-of-check/time-of-use race.
- SSH aliases outside `~/.ssh`, complex quoted `Include` forms, and wildcard aliases are not shown by the picker; they can still be entered explicitly.
- Provided tools are intentionally limited.

## Development

```bash
npm install
npm run check
```

`npm run check` performs a strict TypeScript typecheck, unit tests, fake-Pi lifecycle tests, shell-level pipeline tests through a fake SSH executable, and a real-extension smoke check without contacting a model. The transport tests cover option boundaries, completed-vs-failed remote execution, large bounded reads, and timeout behavior.

## Future

- Investigate sandboxing all tools inside `systemd-run` to provide a layer of protection in case of bugs in the tools.
- Give the agent a way to perform web searches.
- Consider `sshro_ps` argument redaction for obvious secret patterns and/or clearer guidance that process command lines can disclose secrets.
- Consider optional pruning/avoidance for network shares during broad recursive listings/grep scans if this becomes a real problem on target servers.
- Consider read-only HTTP healthcheck tooling, possibly with an approval step because it performs outbound requests from the remote host.
