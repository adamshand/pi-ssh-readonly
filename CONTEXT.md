# SSH Read-only Extension

This context covers a pi extension for inspecting remote Linux servers safely by default, with separately human-granted unrestricted access for selected targets.

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
The literal single-argument OpenSSH destination string supplied to a tool, such as `server` or `user@server`. Distinct strings remain distinct even if OpenSSH resolves them to the same host.
_Avoid_: canonical host, active host

**Target Approval**:
Human consent for the agent to use one Exact Target during the current Pi session. Approval authorizes the fixed Inspection Tool Suite, not arbitrary remote execution.
_Avoid_: connection approval, host trust, unrestricted SSH access

**Write Grant**:
Separately confirmed human consent for unrestricted execution on one Exact Target for the current session. A Write Grant is not implied by Target Approval or the SSHRO Host Whitelist.
_Avoid_: whitelist exception, read-write mode, permanent trust

**Unrestricted SSH Tool**:
The separately enabled capability to execute arbitrary remote commands under a Write Grant, without read-only path restrictions or secret redaction.
_Avoid_: read-only shell, bash guard bypass

**SSHRO Host Whitelist**:
A configured set of Exact Targets that may receive Target Approval automatically.
_Avoid_: denylist, SSH config aliases, network access policy

**Suggested Target**:
A literal alias discovered from trusted local SSH configuration and shown to the human as a convenience. Discovery alone never grants Target Approval.
_Avoid_: approved alias, whitelisted host

**Fixed Remote Command Template**:
A known read-only command shape whose variable values are validated as operands and shell-quoted.
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
