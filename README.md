<img width="1983" height="793" alt="ChatGPT Image May 5, 2026, 07_10_05 PM" src="https://github.com/user-attachments/assets/4cb21b80-08e6-4bb0-b109-feb53f2d6d1a" />

# pi-ssh-readonly

I sometimes work with legacy servers where configuration has been managed by hand for years. Agent assistance on these servers is extremely valuable.  However the risk of an agent making an undetected change to a production server isn't acceptable.

This extension disables all built in tools and adds a new set of read only tools.  The current set of tools is:

- sshro_read
- sshro_ls
- sshro_find
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

⚠️ ⚠️ ⚠️  This is extension is vibe coded.  **Use at your own risk.**  It's working well for me, and hasn't eaten anyones homework yet. 🤞 🤞

## Usage

You must start a new `pi` session the `--ssh-ro` argument, eg.

```bash
pi --ssh-ro adam@server
```

**Requires passwordless SSH. It will not prompt for a password.**

Paths are remote paths. Relative paths resolve from the remote login directory reported at startup. `~` is not expanded; use absolute paths like `/home/adam/...` or relative paths from the remote working directory.

You can run a shell command and automatically feed it back to the agent by using the `!` command, eg.

```bash
! echo 'the agent can see this'
```

## Configuration

Not required but configuring SSH to use connection sharing will speed things up.

```text
# ~/.ssh/config
Host *
  ControlMaster auto
  ControlPath ~/.ssh/sockets/%r@%h:%p
  ControlPersist 900
```

`index.ts` includes a basic list of files/folders which the agent is not allowed to read (eg. .env, shell history files, SSH/cloud credential directories, password-manager data, chezmoi data). Listings and find results still show blocked entries with a compact `[blocked]` marker so the agent knows they exist and can ask for help if needed. `sshro_find` does not descend into blocked directories, so parent searches may not enumerate blocked children. Recursive `sshro_find`/`sshro_grep` summarize permission errors by default so errors do not consume match budget; use `showErrors=true` for details. `sshro_grep` uses extended regex (`grep -E`) by default; use `literal=true` for fixed-string search. If you have specific requirements edit this.

`sshro_read` supports negative `offset` values for efficient tail-style reads of large files, e.g. `offset=-100` reads the last 100 lines using remote `tail`.

Docker tools are optional and checked when the tool runs, not at startup. `sshro_docker_ps` returns compact `docker ps --no-trunc` table output, defaults to active containers only, and reports `No active Docker containers` when only the header is returned. Use `all=true` to include stopped/exited containers. `sshro_docker_stats` returns parsed JSON using Docker's native field names and rejects `limit` values below 1. If output is row-limited, Docker row tools append an `[ssh-ro output truncated ...]` note. `sshro_docker_inspect` returns Docker-shaped JSON with targeted redaction: environment variables are visibly redacted, sensitive-looking label values are redacted, and image `GraphDriver.Data` is omitted. Docker command strings, mountpoints, and network topology may be visible. `sshro_docker_stats` always uses one-shot `--no-stream` mode; call it multiple times a few seconds apart to compare noisy CPU readings.

`sshro_dig` runs bounded DNS lookups from the remote host using `dig +time=3 +tries=1`. `dig` is checked when the tool runs and returns a clear error if missing.

## Known Issues

- Currently doesn't stop protected paths being accessed via a symlink.
- Provided tools are quite limited.  

## Future

- Investigate sandboxing all tools inside `systemd-run` to provide a layer of protection in case of bugs in the tools.
- Give the agent a way to perform web searches.
- Give the agent the ability to read files it doesn't have permissions for.
- Consider `sshro_ps` argument redaction for obvious secret patterns and/or clearer guidance that process command lines can disclose secrets.
- Consider optional pruning/avoidance for network shares during broad recursive `find`/`grep` scans if this becomes a real problem on target servers.
- Consider read-only HTTP healthcheck tooling, possibly with an approval step because it performs outbound requests from the remote host.
