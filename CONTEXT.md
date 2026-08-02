# SSH Read-only Extension

This context covers a pi extension that lets agents inspect remote Linux servers over SSH without exposing remote mutation capabilities.

## Language

**SSH Read-only Tool**:
A target-explicit capability that inspects a remote server without offering arbitrary shell execution or mutation.
_Avoid_: overloaded built-in tool, remote command tool, SSH shell

**SSH Read-only Bootstrap Tool**:
The minimal agent-facing capability that discovers or requests Target Approval before making the Inspection Tool Suite available. It does not inspect or connect to a remote host.
_Avoid_: connection, probe, remote session

**Inspection Tool Suite**:
The detailed collection of SSH Read-only Tools made available on demand after a target can be used without another approval.
_Avoid_: remote mode, implicit-target tools

**Exact Target**:
The literal single-argument OpenSSH destination string supplied to a tool, such as `server` or `user@server`. Distinct strings remain distinct even if OpenSSH resolves them to the same host. Option-shaped, whitespace-containing, control-character, path-suffixed, and IPv6 values are rejected in v1.
_Avoid_: canonical host, active host

**Target Approval**:
Human consent for the agent to use one Exact Target during the current Pi session. Approval authorizes the fixed Inspection Tool Suite, not arbitrary remote execution.
_Avoid_: connection approval, host trust, unrestricted SSH access

**SSHRO Host Whitelist**:
A configured set of Exact Targets that may receive Target Approval automatically.
_Avoid_: denylist, SSH config aliases, network access policy

**Suggested Target**:
A literal alias discovered from trusted local SSH configuration and shown to the human as a convenience. Discovery alone never grants Target Approval.
_Avoid_: approved alias, whitelisted host

**Fixed Remote Command Template**:
A known read-only command shape whose variable values are validated and shell-quoted.
_Avoid_: arbitrary remote shell, user-authored command

**Canonical Remote Path**:
The existing remote path obtained after resolving symlinks and normalization, used for content-access policy decisions.
_Avoid_: raw path, display path

**Elevated Read-only Command**:
A Fixed Remote Command Template run with non-interactive sudo only after policy inspection confirms that exact command is permitted without a password.
_Avoid_: blind sudo attempt, password prompt, privileged shell

**Visible Search Errors**:
Search diagnostics that let the agent distinguish no evidence from inaccessible evidence.
_Avoid_: hidden permission errors, silent traversal failure

## Invariants and relationships

- `sshro_connect` is the only SSH read-only tool active initially. It approves or discovers an Exact Target and additively enables the Inspection Tool Suite; it does not open a network connection.
- Every Inspection Tool remains target-explicit. There is no hidden active host or remote-only mode, and unrelated local/extension tools remain available.
- Suggested Targets come only from bounded parsing of trusted local SSH configuration. Suggestions never extend the SSHRO Host Whitelist and become approved only through a human action.
- Automatic approval compares validated Exact Targets literally. Human approval is branch-independent process-memory state for the current Pi session, survives hot reload through the latest versioned non-context session snapshot, and does not cross process restart or session replacement.
- `--ssh-ro` applies only at initial process startup. `/sshro logout` remains effective across later hot reloads.
- Pending approval results are generation-bound: logout or shutdown invalidates stale confirmations before they can mutate approval state.
- OpenSSH receives an option terminator before the Exact Target. Remote command discovery is cached only after the remote wrapper completes, so transport failure remains visible and retryable.
- Existing content paths are checked lexically and again as Canonical Remote Paths. This blocks ordinary symlink bypasses but does not eliminate remote time-of-check/time-of-use races.
- Producer status is carried outside remote filters. Expected no-match/inactive states and intentional bounded-read SIGPIPE are informative success; other failures are Pi tool errors.
- “Read-only” describes the capabilities offered by this extension, not zero observable writes: SSH/audit logs, access times, DNS queries, shell startup hooks, and remote binaries can have side effects.
- The agent bash guard is an accidental-use tripwire, not a process/network sandbox. Git-over-SSH, including mutation by push, remains intentionally allowed.

## Decision index

- [ADR 0001](docs/adr/0001-use-explicit-sshro-tool-names.md): explicit SSH tool names
- [ADR 0003](docs/adr/0003-agent-connect-with-whitelist-and-approval.md): exact-target approval
- [ADR 0004](docs/adr/0004-load-ssh-inspection-tools-after-target-approval.md): lazy Inspection Tool Suite activation
- [ADR 0005](docs/adr/0005-preserve-target-approval-across-hot-reload.md): approval lifecycle across reload and replacement
