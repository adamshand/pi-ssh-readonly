<img width="1983" height="793" alt="ChatGPT Image May 5, 2026, 07_10_05 PM" src="https://github.com/user-attachments/assets/4cb21b80-08e6-4bb0-b109-feb53f2d6d1a" />

# pi-ssh-readonly

I work with legacy servers where configuration has been managed by hand for years. Agent assistance on these servers is extremely valuable.  However the risk of an agent making an undetected change to a production server isn't acceptable.

This extension disables all built in tools and adds a new set of read only tools.  Currently the set of tools included is:

- sshro_read
- sshro_ls
- sshro_find
- sshro_grep



⚠️ ⚠️ ⚠️ This is extension is vibe coded.  **Use at your own risk.**  It's working well for me, and hasn't eaten anyones homework yet. 🤞🏻 🤞🏻 🤞🏻

## Usage

Connect using a new `pi` session with the `--ssh-ro` argument, eg.

`````bash
pi --sshro adam@server
`````

**Requires passwordless SSH. It won't prompt for a password.**



## Configuration

Not required but configuring SSH to use connection sharing will speed things up.

```text
# ~/.ssh/config
Host *
  ControlMaster auto
  ControlPath ~/.ssh/sockets/%r@%h:%p
  ControlPersist 900
```

`index.ts` includes a basic list of files/folders which the agent is not allowed to read (eg. .env).  If you have specific requirements edit this.

## Known Issues

- Currently doesn't stop protected paths being accessed via a symlink.

## Future

The current set of tools is very basic and additional tools will probably be required since there's no bash tool.  I'll play with this for a while.  Once I'm happy that it's sane, I'll add additional tools to help the agent debug problems (eg. `ps`, `netstat`, `ifconfig`, `journalctl`, `systemd` etc).
