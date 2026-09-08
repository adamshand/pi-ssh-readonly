# Architecture and invariants

- `sshro_connect` is the only SSH tool active initially. It approves or discovers an Exact Target and additively enables the Inspection Tool Suite; it does not open a network connection.
- Every inspection remains target-explicit. There is no hidden active host or remote-only mode, and unrelated local/extension tools remain available.
- Suggested Targets come only from bounded parsing of trusted local SSH configuration. Suggestions never extend the SSHRO Host Whitelist and become approved only through a human action.
- Automatic approval compares validated Exact Targets literally. Human approvals and Write Grants are branch-independent process-memory state for the current Pi session, survive hot reload through the latest versioned non-context session snapshot, and do not cross process restart or session replacement. An invalid latest snapshot clears state rather than resurrecting older grants.
- `--ssh-ro` applies only at initial process startup and grants read-only approval, never a Write Grant. `/sshro logout` remains effective across later hot reloads.
- Pending approval results are generation-bound: logout or shutdown invalidates stale confirmations before they can mutate approval state. Revoking write access also invalidates pending grant confirmations.
- The unrestricted tool is registered separately and checks Write Grants at execution time, irrespective of tool visibility. Only human confirmation in the slash command grants unrestricted execution.
- OpenSSH receives an option terminator before the Exact Target. Targets are not IP-pinned: trusted local SSH configuration still controls resolution and transport. Remote command discovery is cached only after the remote wrapper completes, so transport failure remains visible and retryable.
- Existing content paths are checked lexically and again as Canonical Remote Paths. This blocks ordinary symlink bypasses but does not eliminate remote time-of-check/time-of-use races. Recursive grep derives conservative basename exclusions from the same policy and does not follow descendant symlinks.
- Shell quoting is not option validation. Inspection operands reject option-shaped values, and command templates use explicit operand boundaries where supported.
- Producer and individual filter statuses travel outside remote output filters. Expected no-match/inactive states and intentional bounded-read SIGPIPE are informative success; other failures are Pi tool errors. Bounded row filters disclose omissions and drain input to preserve late producer failures.
- The shared result boundary bounds success and error text. Docker inspect fails closed on parsing/redaction errors and never includes raw inspect output in its error messages.
- Local transport timeout/cancellation settles independently of inherited pipe closure. POSIX execution owns and kills a process group, but remote processes may survive and mutations are not undone.
- “Read-only” describes the inspection capabilities, not zero observable writes: SSH/audit logs, access times, DNS queries, shell startup hooks, and remote binaries can have side effects. Unrestricted execution is intentionally outside these inspection restrictions.
- The agent bash guard is an accidental-use tripwire, not a process/network sandbox. Git-over-SSH, including mutation by push, remains intentionally allowed.

## Decision index

- [ADR 0001](adr/0001-use-explicit-sshro-tool-names.md): explicit SSH tool names
- [ADR 0003](adr/0003-agent-connect-with-whitelist-and-approval.md): exact-target approval
- [ADR 0004](adr/0004-load-ssh-inspection-tools-after-target-approval.md): lazy Inspection Tool Suite activation
- [ADR 0005](adr/0005-preserve-target-approval-across-hot-reload.md): approval lifecycle across reload and replacement
- [ADR 0006](adr/0006-separate-session-write-grants.md): separate human-confirmed unrestricted access
