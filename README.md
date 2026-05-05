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

⚠️ ⚠️ ⚠️  This is extension is vibe coded.  **Use at your own risk.**  It's working well for me, and hasn't eaten anyones homework yet. 🤞 🤞

## Usage

You must start a new `pi` session the `--ssh-ro` argument, eg.

```bash
pi --sshro adam@server
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

`index.ts` includes a basic list of files/folders which the agent is not allowed to read (eg. .env, shell history files, SSH/cloud credential directories, password-manager data, chezmoi data). Listings and find results still show blocked entries with a compact `[blocked]` marker so the agent knows they exist and can ask for help if needed. `sshro_find` does not descend into blocked directories, so parent searches may not enumerate blocked children. If you have specific requirements edit this.

## Known Issues

- Currently doesn't stop protected paths being accessed via a symlink.
- Provided tools are quite limited.  

## Future

- Investigate sandboxing all tools inside `systemd-run` to provide a layer of protection in case of bugs in the tools.
- Give the agent a way to perform web searches.
- Give the agent the ability to read files it doesn't have permissions for.
