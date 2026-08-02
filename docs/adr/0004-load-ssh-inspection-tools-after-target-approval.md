# Load SSH inspection tools after target approval

Only `sshro_connect` is initially active for the agent. It can discover pre-approved targets or request exact-target human approval, then additively activates the detailed `sshro_*` inspection tools during its tool execution. Human-initiated `/sshro <target>` and `--ssh-ro <target>` approvals activate the same suite directly, while every inspection call remains target-explicit.

We chose on-demand activation over keeping every SSH schema permanently active or requiring a human-only mode switch. This preserves agent-initiated debugging while avoiding unrelated tool-schema overhead. Detailed inspection tools omit active-only prompt snippets and guidelines so models with native deferred-tool loading can anchor their definitions at the `sshro_connect` result without rebuilding the system prompt; other models pay a one-time expanded-tool-list cache change when SSH inspection is first needed.

Inspection tool names are collected while their definitions are registered, rather than maintained as a second list. Activation is purely additive during `sshro_connect` execution and reports tools rejected by Pi's allow/exclude policy. Approval persistence across runtime reloads is decided separately in [ADR 0005](0005-preserve-target-approval-across-hot-reload.md).
