const SSH_CLIENT_COMMAND_PATTERN = String.raw`(?:ssh|scp|sftp|sshfs|ssh-keyscan|sshpass|autossh|mosh|slogin|plink|pscp|psftp)`;
const SSH_COMMAND_RE = new RegExp(
	String.raw`(^|[\n;&|(){}])\s*` +
		String.raw`(?:(?:sudo|doas|command|builtin|exec|nohup|time|setsid)\s+|env\s+(?:-[^\s]+\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]+)\s+)*)*` +
		String.raw`(?:[^\s;&|()<>]+/)?${SSH_CLIENT_COMMAND_PATTERN}(?=$|[\s;&|()<>])`,
	"i",
);
const SHELL_C_SSH_RE = new RegExp(
	String.raw`\b(?:sh|bash|zsh|fish|dash|ksh)\s+(?:-[A-Za-z]*c[A-Za-z]*|-c)\s+(?:"[^"]*${SSH_CLIENT_COMMAND_PATTERN}\b|'[^']*${SSH_CLIENT_COMMAND_PATTERN}\b)`,
	"i",
);
const SSH_ENV_RE = /\bRSYNC_RSH\s*=/i;

/**
 * Best-effort guard against accidentally invoking an SSH client directly.
 *
 * Git-over-SSH transport URLs and Git's SSH environment variables are
 * intentionally allowed. This is not a process or network sandbox: indirect
 * SSH execution and other network tools remain possible and require an
 * external sandbox for enforcement.
 */
export function bashSshBlockReason(command: string): string | undefined {
	if (SSH_COMMAND_RE.test(command) || SHELL_C_SSH_RE.test(command)) {
		return "The pi-ssh-readonly extension blocks agent bash from directly invoking SSH client commands. Use sshro_* for supported read-only inspection with an explicit target. For one human-reviewed operation or interactive authentication, use stage_command if available; otherwise ask the user to run it. Use ssh_exec only for an exact target already granted unrestricted access by the human. Do not seek a broad grant just to avoid individual approvals.";
	}
	if (SSH_ENV_RE.test(command)) {
		return "The pi-ssh-readonly extension blocks agent bash from configuring rsync SSH transport environment variables.";
	}
	return undefined;
}
