<img width="1983" height="793" alt="ChatGPT Image May 5, 2026, 07_10_05 PM" src="https://github.com/user-attachments/assets/4cb21b80-08e6-4bb0-b109-feb53f2d6d1a" />

# pi-ssh-readonly

I sometimes work with legacy servers where configuration has been managed by hand for years. Agent assistance on these servers is extremely valuable.  However the risk of an agent making an undetected change to a production server isn't acceptable.

This extension adds stateless read-only SSH tools alongside pi's normal local tools. Every `sshro_*` call requires an explicit SSH `target`, so agents can inspect a server and then immediately read/edit local project files without entering a modal remote-only state. The current read-only tool set is:

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

Targets in `SSHRO_HOST_WHITELIST` are approved automatically. Other exact target strings require explicit human approval on first use and are remembered for the rest of the Pi session.

It redacts and filters obvious password/secret risks, but doesn't try and catch everything (eg. passwords in `ps` output).  If this is critical in your environment you may want to make changes.

⚠️ ⚠️ ⚠️  This is extension is vibe coded.  **Use at your own risk.**  It's working well for me, and hasn't eaten anyones homework yet. 🤞 🤞 🤞

## Install

```
pi install git:git@github.com:adamshand/pi-ssh-readonly
```

## Usage

Use the tools by passing a target on each call, for example:

```text
sshro_read({ target: "adam@server", path: "/etc/nginx/nginx.conf" })
sshro_ls({ target: "adam@server", path: "/etc", recursive: true })
sshro_locate({ target: "adam@server", pattern: "nginx" })
```

You can pre-approve a target during an existing pi session:

```text
/sshro adam@server
```

Clear session approvals:

```text
/sshro logout
```

You can also start pi with a pre-approved target:

```bash
pi --ssh-ro adam@server
```

Connection approval is exact-target based:

- Whitelist matches use the exact target string passed to each `sshro_*` tool; `binney` and `adam@binney` are different entries.
- Non-whitelisted targets prompt on first use, then remain approved for the rest of the Pi session.
- Human-initiated `/sshro <target>` and `pi --ssh-ro <target>` pre-approve that exact target without consulting the whitelist.

**Requires passwordless SSH and an existing known_hosts entry. It will not prompt for a password or accept unknown hosts.**

Paths are remote paths. Relative paths resolve from the SSH login directory for that tool call. `~` is not expanded; use absolute paths like `/home/adam/...` or relative paths from the remote login directory.

You can run a local shell command and automatically feed it back to the agent by using the `!` command, eg.

```bash
! echo 'the agent can see this'
```

Whenever this extension is loaded, agent-initiated `bash` tool calls are blocked from invoking common SSH client commands or SSH transport URLs. The agent should use the `sshro_*` tools instead. User-run `!` and `!!` commands are not blocked by this guard.

## Configuration

The extension uses OpenSSH with `BatchMode=yes` and `StrictHostKeyChecking=yes`, so authentication and host verification must already be configured before using the `sshro_*` tools.

`SSHRO_HOST_WHITELIST` is an automatic approval list for agent-initiated `sshro_*` tool calls. Set it in the environment before starting pi:

```bash
SSHRO_HOST_WHITELIST="web1,adam@legacy,prod-readonly" pi
```

It is not an access-control denylist: non-whitelisted targets can still be used after explicit human approval. Values are comma-separated, trimmed, and matched exactly against the target string the agent passes; OpenSSH still resolves aliases, ProxyJump, identities, and other SSH config normally when the tool runs.

The configured target strings are included in every `sshro_*` tool hint so the agent knows which targets can be used without prompting. The hint explicitly says that automatic approval requires using the target exactly as listed, so a whitelist entry like `binney` does not imply `adam@binney`. If more than 20 targets are configured, the hint shows the first 20 and reports how many more are present.

Not required but configuring SSH to use connection sharing will speed things up.

```text
# ~/.ssh/config
Host *
  ControlMaster auto
  ControlPath ~/.ssh/sockets/%r@%h:%p
  ControlPersist 900
```

`index.ts` includes a basic list of files/folders which the agent is not allowed to read (eg. .env, shell history files, SSH/cloud credential directories, password-manager data, chezmoi data). Listings still show blocked entries with a compact `[blocked]` marker where possible so the agent knows they exist and can ask for help if needed. Recursive `sshro_grep` excludes blocked credential/history/password-manager paths. `sshro_grep` uses extended regex (`grep -E`) by default; use `literal=true` for fixed-string search. If you have specific requirements edit this.

`sshro_ls` supports `recursive=true` for live recursive listings. Recursive listing uses `eza -1l --absolute=on -R --color=never --icons=never` when available, filters eza grouping headers, and falls back to `ls -laR` otherwise.

`sshro_locate` uses `plocate` for very fast indexed path search. Results may be stale depending on how often the server updates its locate database.

Some tools can use elevated read-only access when sudoers allows the exact fixed command. Before running any elevated command the extension checks `sudo -n -l <command ...>`; if sudo requires a password or the command is not allowed, the tool falls back to the non-sudo command and reports that elevated access was unavailable. This avoids noisy failed sudo command attempts. Example sudoers additions for a trusted account on servers you control:

```sudoers
agent ALL=(root) NOPASSWD: /usr/bin/cat *
agent ALL=(root) NOPASSWD: /usr/bin/ls *
agent ALL=(root) NOPASSWD: /usr/bin/grep *
agent ALL=(root) NOPASSWD: /usr/bin/eza -1l --absolute=on -R --color=never --icons=never -- *
agent ALL=(root) NOPASSWD: /usr/bin/plocate *
```

Avoid broad rules such as `NOPASSWD: ALL`, `/usr/bin/find *`, or shell access.

`sshro_read` supports negative `offset` values for efficient tail-style reads of large files, e.g. `offset=-100` reads the last 100 lines.

Docker tools are optional and checked when the tool runs, not at startup. `sshro_docker_ps` returns compact `docker ps --no-trunc` table output, defaults to active containers only, and reports `No active Docker containers` when only the header is returned. Use `all=true` to include stopped/exited containers. `sshro_docker_stats` returns parsed JSON using Docker's native field names and rejects `limit` values below 1. If output is row-limited, Docker row tools append an `[ssh-ro output truncated ...]` note. `sshro_docker_inspect` uses `target` for the SSH target and `object` for the Docker object name/ID, and returns Docker-shaped JSON with targeted redaction: environment variables are visibly redacted, sensitive-looking label values are redacted, and image `GraphDriver.Data` is omitted. Docker command strings, mountpoints, and network topology may be visible. `sshro_docker_stats` always uses one-shot `--no-stream` mode; call it multiple times a few seconds apart to compare noisy CPU readings.

`sshro_dig` runs bounded DNS lookups from the remote host using `dig +time=3 +tries=1`. `dig` is checked when the tool runs and returns a clear error if missing.

## Known Issues

- Currently doesn't stop protected paths being accessed via a symlink.
- Provided tools are quite limited.  

## Future

- Investigate sandboxing all tools inside `systemd-run` to provide a layer of protection in case of bugs in the tools.
- Give the agent a way to perform web searches.
- Consider `sshro_ps` argument redaction for obvious secret patterns and/or clearer guidance that process command lines can disclose secrets.
- Consider optional pruning/avoidance for network shares during broad recursive listings/grep scans if this becomes a real problem on target servers.
- Consider read-only HTTP healthcheck tooling, possibly with an approval step because it performs outbound requests from the remote host.
