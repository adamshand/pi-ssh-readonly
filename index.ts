import { spawn } from "node:child_process";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import Type from "typebox";

const SSHRO_HOST_WHITELIST_ENV = "SSHRO_HOST_WHITELIST";
const DEFAULT_LINE_LIMIT = 2000;
const DEFAULT_BYTE_LIMIT = 50 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const DENIED_DIR_NAMES = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".terraform", ".terraform.d", ".cloudflared", ".cloudflare", ".password-store"];
const DENIED_PATH_PARTS = ["/.config/gcloud", "/.config/gh", "/.config/Bitwarden CLI", "/.config/Bitwarden", "/.config/bitwarden", "/.config/1Password", "/.config/op", "/.config/keepassxc", "/.config/KeePass", "/.config/keepass", "/.config/gopass", "/.config/chezmoi", "/.local/share/fish", "/.local/share/nano", "/.local/share/keepassxc", "/.local/share/gopass", "/.local/share/chezmoi", "/.gem/credentials", "/.cargo/credentials"];
const DENIED_FILE_NAMES = [".env", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials", "terraform.tfstate", ".chezmoi.toml", ".chezmoi.yaml", ".chezmoi.json", ".chezmoiignore", ".bash_history", ".zsh_history", ".zhistory", ".fish_history", "fish_history", ".sh_history", ".ash_history", ".history", "search_history", ".mysql_history", ".psql_history", ".sqlite_history", ".python_history", ".node_repl_history", ".rediscli_history", ".lesshst", ".wget-hsts"];
const DENIED_FILE_SUFFIXES = [".pem", ".key", ".p12", ".pfx", "_history"];
const DENIED_FILE_PREFIXES = [".env.", "terraform.tfstate."];
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
const SSH_TRANSPORT_RE = /\b(?:ssh|sftp|scp):\/\/|\bgit@[-A-Za-z0-9_.]+:/i;
const SSH_ENV_RE = /\b(?:GIT_SSH|GIT_SSH_COMMAND|RSYNC_RSH)\s*=/i;

let toolsRegistered = false;
const approvedTargets = new Set<string>();
const remoteCommandCache = new Map<string, string | undefined>();
const sudoCheckCache = new Map<string, { allowed: boolean; reason: string }>();

function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function hasControlChars(value: string): boolean {
	return /[\x00-\x1f\x7f]/.test(value);
}

function validateTarget(target: string): void {
	if (!target.trim()) throw new Error("--ssh-ro target is empty");
	if (hasControlChars(target)) throw new Error("--ssh-ro target contains control characters");
	if (target.includes(":")) throw new Error("--ssh-ro v1 accepts only an SSH target, not target:/path or IPv6 syntax");
}

function whitelistedHosts(): Set<string> {
	return new Set((process.env[SSHRO_HOST_WHITELIST_ENV] ?? "").split(",").map((host) => host.trim()).filter(Boolean));
}

function isWhitelistedHost(target: string): boolean {
	return whitelistedHosts().has(target);
}

function whitelistedHostsPromptHint(): string {
	const hosts = [...whitelistedHosts()];
	const maxShown = 20;
	const shown = hosts.slice(0, maxShown).join(", ");
	const suffix = hosts.length > maxShown ? `, ... (${hosts.length - maxShown} more)` : "";
	const list = hosts.length === 0 ? "no targets configured" : `${shown}${suffix}`;
	return `SSH connection requests require approval unless the target is on the whitelist. For automatic approval, use the target exactly as listed.\n\nWhitelist: ${list}.`;
}

function validatePathLike(value: string, label: string): void {
	if (hasControlChars(value)) throw new Error(`${label} contains a newline or control character`);
	if (value === "~" || value.startsWith("~/")) throw new Error(`${label}: ~ expansion is not supported in SSH Read-only Mode v1`);
}

function bashSshBlockReason(command: string): string | undefined {
	if (SSH_COMMAND_RE.test(command) || SHELL_C_SSH_RE.test(command)) return "The pi-ssh-readonly extension blocks agent bash from invoking SSH client commands. Use the stateless sshro_* tools with an explicit target, or user-run ! commands instead.";
	if (SSH_TRANSPORT_RE.test(command)) return "The pi-ssh-readonly extension blocks agent bash from using SSH transport URLs.";
	if (SSH_ENV_RE.test(command)) return "The pi-ssh-readonly extension blocks agent bash from configuring SSH transport environment variables.";
	return undefined;
}

function normalizeRemotePathForPolicy(path: string): string {
	const absolute = path.startsWith("/");
	const parts: string[] = [];
	for (const part of path.replace(/\/+/g, "/").split("/")) {
		if (!part || part === ".") continue;
		if (part === "..") {
			if (parts.length > 0) parts.pop();
			else if (!absolute) parts.push(part);
			continue;
		}
		parts.push(part);
	}
	const normalized = `${absolute ? "/" : ""}${parts.join("/")}`;
	return normalized || (absolute ? "/" : ".");
}

function remotePath(input: string | undefined, cwd: string): string {
	const p = input && input.length > 0 ? input : ".";
	validatePathLike(p, "path");
	if (p.startsWith("/")) return normalizeRemotePathForPolicy(p);
	if (p === ".") return normalizeRemotePathForPolicy(cwd);
	return normalizeRemotePathForPolicy(`${cwd.replace(/\/+$/, "")}/${p}`);
}

function denyReasonForPath(path: string): string | undefined {
	const normalized = normalizeRemotePathForPolicy(path);
	const parts = normalized.split("/").filter(Boolean);
	const base = parts[parts.length - 1] ?? "";
	const deniedDir = parts.find((part) => DENIED_DIR_NAMES.includes(part));
	if (deniedDir) return `path is inside blocked credential directory ${deniedDir}`;
	const deniedPart = DENIED_PATH_PARTS.find((part) => normalized === part.slice(1) || normalized.includes(part));
	if (deniedPart) return `path is inside blocked credential path ${deniedPart}`;
	if (DENIED_FILE_NAMES.includes(base)) return `blocked credential-like file ${base}`;
	const deniedPrefix = DENIED_FILE_PREFIXES.find((prefix) => base.startsWith(prefix));
	if (deniedPrefix) return `blocked credential-like file pattern ${deniedPrefix}*`;
	const deniedSuffix = DENIED_FILE_SUFFIXES.find((suffix) => base.endsWith(suffix));
	if (deniedSuffix) return `blocked credential-like file pattern *${deniedSuffix}`;
	return undefined;
}

function assertPathAllowed(path: string): void {
	const reason = denyReasonForPath(path);
	if (reason) throw new Error(`SSH Read-only Mode blocks this path by default: ${reason}`);
}

function findDenyPredicates(): string {
	const dirPrunes = [...DENIED_DIR_NAMES, ".git", "node_modules"].map((name) => `-name ${shellQuote(name)}`).join(" -o ");
	const pathPrunes = DENIED_PATH_PARTS.map((part) => `-path ${shellQuote(`*${part}`)}`).join(" -o ");
	return [dirPrunes, pathPrunes].filter(Boolean).join(" -o ");
}

function findDenyExpression(): string {
	return `\\( ${findDenyPredicates()} \\) -prune -o `;
}

function findMarkedDenyExpression(matchPredicate: string): string {
	return `\\( ${findDenyPredicates()} \\) \\( ${matchPredicate} -print -o -true \\) -prune -o `;
}

function findFileDenyPredicates(): string {
	const exact = DENIED_FILE_NAMES.map((name) => `! -name ${shellQuote(name)}`);
	const prefixes = DENIED_FILE_PREFIXES.map((prefix) => `! -name ${shellQuote(`${prefix}*`)}`);
	const suffixes = DENIED_FILE_SUFFIXES.map((suffix) => `! -name ${shellQuote(`*${suffix}`)}`);
	return [...exact, ...prefixes, ...suffixes].join(" ");
}

function truncateText(text: string, maxLines = DEFAULT_LINE_LIMIT, maxBytes = DEFAULT_BYTE_LIMIT): string {
	let out = text;
	const lines = out.split("\n");
	let lineTruncated = false;
	if (lines.length > maxLines) {
		out = lines.slice(0, maxLines).join("\n");
		lineTruncated = true;
	}
	let byteTruncated = false;
	const b = Buffer.from(out);
	if (b.length > maxBytes) {
		out = b.subarray(0, maxBytes).toString("utf8");
		byteTruncated = true;
	}
	if (lineTruncated || byteTruncated) {
		out += `\n\n[ssh-ro output truncated${lineTruncated ? ` to ${maxLines} lines` : ""}${byteTruncated ? ` to ${maxBytes} bytes` : ""}]`;
	}
	return out;
}

function spawnSsh(target: string, command: string) {
	// Force POSIX sh for remote command templates. OpenSSH normally passes the
	// command through the user's login shell; many legacy/admin accounts use
	// fish/csh/etc., which do not understand POSIX for/if syntax.
	const remoteCommand = `sh -c ${shellQuote(command)}`;
	return spawn(
		"ssh",
		["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", target, remoteCommand],
		{ stdio: ["ignore", "pipe", "pipe"] },
	);
}

function sshExec(target: string, command: string, signal?: AbortSignal, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<{ stdout: string; stderr: string; code: number | null }> {
	return new Promise((resolve, reject) => {
		const child = spawnSsh(target, command);
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
		}, timeoutMs);
		const onAbort = () => child.kill("SIGTERM");
		signal?.addEventListener("abort", onAbort, { once: true });
		child.stdout.on("data", (d) => stdout.push(Buffer.from(d)));
		child.stderr.on("data", (d) => stderr.push(Buffer.from(d)));
		child.on("error", (err) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
			reject(err);
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
			if (signal?.aborted) reject(new Error("SSH command aborted"));
			else if (timedOut) reject(new Error(`SSH command timed out after ${timeoutMs / 1000}s`));
			else resolve({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), code });
		});
	});
}

async function sshChecked(target: string, command: string, signal?: AbortSignal, timeoutMs?: number): Promise<string> {
	const r = await sshExec(target, command, signal, timeoutMs);
	if (r.code !== 0) {
		throw new Error(`ssh exited ${r.code}: ${(r.stderr || r.stdout).trim()}`);
	}
	return r.stdout;
}

function targetParam() {
	return Type.String({ description: `SSH target to connect to, e.g. user@host or an OpenSSH Host alias. Must match whitelist entries exactly for automatic approval. ${whitelistedHostsPromptHint()}` });
}

async function authorizeTarget(target: string, ctx: ExtensionContext, signal?: AbortSignal): Promise<string> {
	const trimmed = target.trim();
	validateTarget(trimmed);
	if (isWhitelistedHost(trimmed) || approvedTargets.has(trimmed)) return trimmed;
	if (!ctx.hasUI) throw new Error(`SSH read-only tool call to ${trimmed} requires human approval because it is not in ${SSHRO_HOST_WHITELIST_ENV}, but no UI is available.`);
	const approved = await ctx.ui.confirm(
		"Approve SSH read-only tool access?",
		`The agent wants to run read-only SSH inspection tools against:\n\n${trimmed}\n\nApproval is remembered for this Pi session only and matches this exact target string.`,
		{ signal },
	);
	if (!approved) throw new Error(`SSH read-only tool access to ${trimmed} was denied by the human.`);
	approvedTargets.add(trimmed);
	return trimmed;
}

async function resolveRemoteCommand(target: string, command: string, signal?: AbortSignal): Promise<string | undefined> {
	const key = `${target}\0${command}`;
	if (remoteCommandCache.has(key)) return remoteCommandCache.get(key);
	const r = await sshExec(target, `command -v ${shellQuote(command)} 2>/dev/null || true`, signal, 10_000);
	const resolved = r.stdout.trim().split(/\r?\n/).find(Boolean);
	remoteCommandCache.set(key, resolved);
	return resolved;
}

function commandString(commandPath: string, args: string[]): string {
	return [commandPath, ...args].map(shellQuote).join(" ");
}

function sudoSetupHint(commandPath: string, argsHint = "*"): string {
	return `If elevated access was expected, configure a NOPASSWD sudoers rule for this SSH user, e.g.:\n\n  <user> ALL=(root) NOPASSWD: ${commandPath} ${argsHint}\n\nNo elevated command is run unless sudo -n -l confirms it first.`;
}

async function checkSudoAllowed(target: string, commandPath: string, args: string[], signal?: AbortSignal): Promise<{ allowed: boolean; reason: string }> {
	const key = `${target}\0${commandPath}\0${args.join("\0")}`;
	const cached = sudoCheckCache.get(key);
	if (cached) return cached;
	const r = await sshExec(target, `sudo -n -l ${commandString(commandPath, args)} >/dev/null`, signal, 10_000);
	const result = { allowed: r.code === 0, reason: (r.stderr || r.stdout).trim() };
	sudoCheckCache.set(key, result);
	return result;
}

async function chooseCommand(target: string, command: string, args: string[], signal?: AbortSignal): Promise<{ commandPath: string; command: string; usedSudo: boolean; sudoReason: string }> {
	const commandPath = await resolveRemoteCommand(target, command, signal);
	if (!commandPath) throw new Error(`${command} not found on remote host`);
	const sudo = await checkSudoAllowed(target, commandPath, args, signal);
	const base = commandString(commandPath, args);
	return { commandPath, command: sudo.allowed ? `sudo -n ${base}` : base, usedSudo: sudo.allowed, sudoReason: sudo.reason };
}

function sudoNote(usedSudo: boolean, sudoReason: string): string {
	if (usedSudo) return "[ssh-ro note] Used sudo: yes";
	if (/password is required|a terminal is required|no tty/i.test(sudoReason)) return "[ssh-ro note] Used sudo: no; sudo requires a password/tty for this command.";
	return "[ssh-ro note] Used sudo: no; sudo permission was not available for this command.";
}

function appendSudoNote(output: string, usedSudo: boolean, sudoReason: string): string {
	return `${output.trimEnd()}\n\n${sudoNote(usedSudo, sudoReason)}`;
}

function permissionDenied(text: string): boolean {
	return /permission denied|operation not permitted/i.test(text);
}

function textResult(text: string, isError = false) {
	return { content: [{ type: "text" as const, text }], isError };
}

function errorResult(err: unknown) {
	return textResult(err instanceof Error ? err.message : String(err), true);
}

function optionalString(value: unknown): string | undefined {
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function shellWord(value: string, label: string): string {
	validatePathLike(value, label);
	return shellQuote(value);
}

function joinRemotePath(parent: string, child: string): string {
	return normalizeRemotePathForPolicy(`${parent.replace(/\/+$/, "")}/${child}`);
}

function appendBlockedFootnote(output: string): string {
	return output.includes(" [blocked]") ? `${output}\n\n[blocked] = content access is blocked by SSH Read-only Mode credential/history guardrails; ask the user to inspect manually if needed.` : output;
}

function markBlockedLsEntries(output: string, listedPath: string): string {
	const marked = output
		.split("\n")
		.map((line) => {
			if (!line || line.startsWith("total ") || line.startsWith("[stderr]")) return line;
			const match = line.match(/^(\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+)(.+)$/);
			if (!match) return line;
			const name = match[2].split(" -> ", 1)[0];
			if (name === "." || name === "..") return line;
			return denyReasonForPath(joinRemotePath(listedPath, name)) ? `${line} [blocked]` : line;
		})
		.join("\n");
	return appendBlockedFootnote(marked);
}

function markBlockedFindEntries(output: string): string {
	const marked = output
		.split("\n")
		.map((line) => {
			if (!line.trim() || line.startsWith("find:")) return line;
			return denyReasonForPath(line.trim()) ? `${line} [blocked]` : line;
		})
		.join("\n");
	return appendBlockedFootnote(marked);
}

function summarizeSearchErrors(stderr: string, showErrors: boolean, errorLimit: number): string {
	const lines = stderr.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
	if (lines.length === 0) return "";
	const permission = lines.filter((line) => /permission denied/i.test(line));
	const other = lines.filter((line) => !/permission denied/i.test(line));
	const notes: string[] = [];
	if (permission.length > 0) notes.push(`[ssh-ro note] ${permission.length} paths skipped: permission denied`);
	if (other.length > 0) notes.push(`[ssh-ro note] ${other.length} search errors${showErrors ? ":" : " omitted; use showErrors=true to include details"}`);
	if (showErrors) {
		const shown = lines.slice(0, errorLimit);
		notes.push("[ssh-ro errors]", ...shown);
		if (lines.length > shown.length) notes.push(`[ssh-ro note] ${lines.length - shown.length} additional errors omitted`);
	}
	return notes.join("\n");
}

function appendSearchErrorSummary(output: string, stderr: string, showErrors: boolean, errorLimit: number): string {
	const summary = summarizeSearchErrors(stderr, showErrors, errorLimit);
	return summary ? `${output.trimEnd()}\n\n${summary}`.trim() : output;
}

function psHasOnlyHeader(output: string): boolean {
	const lines = output.split(/\r?\n/).filter((line) => line.trim().length > 0);
	return lines.length === 1 && /^\s*PID\s+PPID\s+USER\s+STAT\s+ELAPSED\s+%CPU\s+%MEM\s+COMMAND/.test(lines[0]);
}

const DOCKER_KINDS = ["container", "image", "network", "volume"] as const;
const DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "CAA", "SRV"] as const;
const SENSITIVE_LABEL_KEY_RE = /(token|secret|password|passwd|key|credential|creds)/i;

function validateDockerRef(value: string, label: string): void {
	validatePathLike(value, label);
}

function validatePositiveLimit(value: unknown, label: string, defaultValue: number): number {
	const limit = value === undefined ? defaultValue : Math.floor(Number(value));
	if (!Number.isFinite(limit) || limit < 1) throw new Error(`${label} must be >= 1`);
	return Math.min(DEFAULT_LINE_LIMIT, limit);
}

function parseNdjson(output: string): unknown[] {
	return output
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => JSON.parse(line));
}

function prettyJson(value: unknown, maxLines = DEFAULT_LINE_LIMIT): string {
	return truncateText(JSON.stringify(value, null, 2), maxLines);
}

function prettyJsonRows(rows: unknown[], limit: number, label: string): string {
	const sliced = rows.slice(0, limit);
	let output = prettyJson(sliced);
	if (rows.length > limit) output += `\n\n[ssh-ro output truncated to ${limit} ${label}]`;
	return output;
}

function truncateRowsWithHeader(output: string, limit: number, label: string): string {
	const lines = output.split(/\r?\n/).filter((line) => line.trim().length > 0);
	if (lines.length <= limit + 1) return output.trimEnd();
	return `${lines.slice(0, limit + 1).join("\n")}\n\n[ssh-ro output truncated to ${limit} ${label}]`;
}

function hasOnlyHeader(output: string): boolean {
	return output.split(/\r?\n/).filter((line) => line.trim().length > 0).length <= 1;
}

function dockerUnavailableMessage(stderr: string, stdout: string): string {
	return stderr.trim() || stdout.trim() || "Docker command failed without output";
}

function redactLabelValue(value: unknown): unknown {
	if (value === undefined || value === null || value === "") return value;
	return "[redacted]";
}

function redactDockerLabels(labels: unknown): unknown {
	if (!labels) return labels;
	if (typeof labels === "string") {
		return labels
			.split(",")
			.map((entry) => {
				const [key, ...rest] = entry.split("=");
				if (!key || rest.length === 0) return entry;
				return SENSITIVE_LABEL_KEY_RE.test(key) ? `${key}=[redacted]` : entry;
			})
			.join(",");
	}
	if (typeof labels === "object") {
		const out: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(labels as Record<string, unknown>)) {
			out[key] = SENSITIVE_LABEL_KEY_RE.test(key) ? redactLabelValue(value) : value;
		}
		return out;
	}
	return labels;
}

function redactDockerEnvs(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(redactDockerEnvs);
	if (!value || typeof value !== "object") return value;
	const out: Record<string, unknown> = {};
	for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
		if (key === "Env") out[key] = Array.isArray(child) && child.length > 0 ? "[redacted]" : child ?? null;
		else if (key === "Labels") out[key] = redactDockerLabels(child);
		else if (key === "GraphDriver" && child && typeof child === "object") out[key] = { ...(child as Record<string, unknown>), Data: "[omitted]" };
		else out[key] = redactDockerEnvs(child);
	}
	return out;
}

function curateDockerInspect(items: unknown[]): unknown {
	return items.map(redactDockerEnvs);
}


function registerSshRoTools(pi: ExtensionAPI): void {
	if (toolsRegistered) return;
	toolsRegistered = true;
	const readParams = Type.Object({
		target: targetParam(),
		path: Type.String({ description: "Path to the file to read on the SSH target (relative to the remote login cwd, or absolute)" }),
		offset: Type.Optional(Type.Number({ description: "Line number to start reading from (1-indexed). Use a negative value to read from the end of the file, e.g. -100 for the last 100 lines." })),
		limit: Type.Optional(Type.Number({ description: "Maximum number of lines to read" })),
	});
	const lsParams = Type.Object({
		target: targetParam(),
		path: Type.Optional(Type.String({ description: "Remote path to list, default remote login cwd" })),
		recursive: Type.Optional(Type.Boolean({ description: "Recursively list descendants. Uses eza when available and falls back to ls -laR." })),
		limit: Type.Optional(Type.Number({ description: "Maximum output lines, default 500, max 2000" })),
	});
	const locateParams = Type.Object({
		target: targetParam(),
		pattern: Type.String({ description: "plocate search pattern. Results come from the locate database and may be stale." }),
		limit: Type.Optional(Type.Number({ description: "Maximum matches returned, default 500, max 2000" })),
	});
	const grepParams = Type.Object({
		target: targetParam(),
		path: Type.String({ description: "File or directory path to search" }),
		pattern: Type.String({ description: "Extended regular expression to search for by default; use literal=true for fixed-string search" }),
		glob: Type.Optional(Type.String({ description: "Optional filename glob for recursive directory search, e.g. *.log" })),
		ignoreCase: Type.Optional(Type.Boolean({ description: "Case-insensitive search" })),
		literal: Type.Optional(Type.Boolean({ description: "Use fixed-string grep -F instead of extended regex grep -E" })),
		context: Type.Optional(Type.Number({ description: "Context lines before/after each match, max 20" })),
		limit: Type.Optional(Type.Number({ description: "Maximum matching output lines, default 500, max 2000" })),
		showErrors: Type.Optional(Type.Boolean({ description: "Include detailed search errors, default false. Permission errors are summarized either way." })),
		errorLimit: Type.Optional(Type.Number({ description: "Maximum detailed error lines when showErrors=true, default 20, max 2000" })),
	});
	const journalctlParams = Type.Object({
		target: targetParam(),
		unit: Type.Optional(Type.String({ description: "systemd unit to filter, e.g. nginx.service" })),
		since: Type.Optional(Type.String({ description: "journalctl --since value, e.g. '1 hour ago'" })),
		until: Type.Optional(Type.String({ description: "journalctl --until value" })),
		priority: Type.Optional(Type.Union([Type.Literal("emerg"), Type.Literal("alert"), Type.Literal("crit"), Type.Literal("err"), Type.Literal("warning"), Type.Literal("notice"), Type.Literal("info"), Type.Literal("debug")])),
		grep: Type.Optional(Type.String({ description: "Filter output with remote grep -i" })),
		lines: Type.Optional(Type.Number({ description: "Maximum recent journal lines, default 200, max 2000" })),
	});
	const systemctlParams = Type.Object({
		target: targetParam(),
		action: Type.Union([Type.Literal("failed"), Type.Literal("status"), Type.Literal("show"), Type.Literal("list")]),
		unit: Type.Optional(Type.String({ description: "Unit name for status/show, e.g. nginx.service" })),
	});
	const psParams = Type.Object({
		target: targetParam(),
		user: Type.Optional(Type.String({ description: "Filter to this process owner" })),
		pattern: Type.Optional(Type.String({ description: "Filter command lines with grep -i" })),
		sort: Type.Optional(Type.Union([Type.Literal("cpu"), Type.Literal("mem"), Type.Literal("pid")])),
		limit: Type.Optional(Type.Number({ description: "Maximum output lines, default 80, max 2000" })),
	});
	const ssParams = Type.Object({
		target: targetParam(),
		listeningOnly: Type.Optional(Type.Boolean({ description: "Show only listening sockets, default true" })),
		tcp: Type.Optional(Type.Boolean({ description: "Include TCP sockets, default true" })),
		udp: Type.Optional(Type.Boolean({ description: "Include UDP sockets, default true" })),
		processInfo: Type.Optional(Type.Boolean({ description: "Include process info with ss -p; may require privileges" })),
		limit: Type.Optional(Type.Number({ description: "Maximum output lines, default 500, max 2000" })),
	});
	const dfParams = Type.Object({
		target: targetParam(),
		path: Type.Optional(Type.String({ description: "Optional path/filesystem to inspect" })),
		localOnly: Type.Optional(Type.Boolean({ description: "Use df -l to avoid remote/network filesystems, default true" })),
		human: Type.Optional(Type.Boolean({ description: "Human-readable sizes, default true" })),
	});
	const dockerPsParams = Type.Object({
		target: targetParam(),
		all: Type.Optional(Type.Boolean({ description: "Include stopped containers, default false" })),
		name: Type.Optional(Type.String({ description: "Optional Docker name filter substring/pattern" })),
		limit: Type.Optional(Type.Number({ description: "Maximum containers returned, default 100, max 2000" })),
	});
	const dockerInspectParams = Type.Object({
		target: targetParam(),
		object: Type.String({ description: "Docker object name or ID to inspect" }),
		kind: Type.Optional(Type.String({ description: "Optional Docker object kind: container, image, network, or volume" })),
	});
	const dockerStatsParams = Type.Object({
		target: targetParam(),
		container: Type.Optional(Type.String({ description: "Optional container name or ID" })),
		limit: Type.Optional(Type.Number({ description: "Maximum containers returned, default 100, max 2000" })),
	});
	const digParams = Type.Object({
		target: targetParam(),
		name: Type.String({ description: "DNS name or address to query" }),
		type: Type.Optional(Type.Union([Type.Literal("A"), Type.Literal("AAAA"), Type.Literal("CNAME"), Type.Literal("MX"), Type.Literal("TXT"), Type.Literal("NS"), Type.Literal("SOA"), Type.Literal("PTR"), Type.Literal("CAA"), Type.Literal("SRV")], { description: "DNS record type, default A" })),
		server: Type.Optional(Type.String({ description: "Optional DNS server, e.g. 1.1.1.1 or dns.example.com" })),
		short: Type.Optional(Type.Boolean({ description: "Use dig +short output, default false" })),
	});

	pi.registerTool({
		name: "sshro_read",
		label: "sshro_read",
		description: "Read a text file from an SSH target. Requires target on every call. Uses sudo only when sudo -n -l confirms the fixed cat command is allowed.",
		promptSnippet: "sshro_read: Read a text file from an SSH target with optional line offset/limit. Requires target. May use sudo after sudo -n -l confirms access.",
		parameters: readParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const p = remotePath(params.path, ".");
				assertPathAllowed(p);
				const rawOffset = params.offset === undefined ? 1 : Math.floor(Number(params.offset));
				if (!Number.isFinite(rawOffset)) throw new Error("offset must be a number");
				const offset = rawOffset === 0 ? 1 : rawOffset;
				const limit = validatePositiveLimit(params.limit, "limit", DEFAULT_LINE_LIMIT);
				const rangeLabel = offset < 0 ? `last ${Math.abs(offset)} lines${params.limit !== undefined ? `, limited to ${limit}` : ""}` : `${offset}-${offset + limit - 1}`;
				const read = await chooseCommand(target, "cat", ["--", p], signal);
				const slice = offset < 0
					? `tail -n ${Math.abs(offset)}${params.limit !== undefined ? ` | head -n ${limit}` : ""}`
					: offset === 1
						? `head -n ${limit}`
						: `tail -n +${offset} | head -n ${limit}`;
				const script = `printf 'path: %s
lines: %s
---
' ${shellQuote(p)} ${shellQuote(rangeLabel)}; ${read.command} | ${slice}`;
				const r = await sshExec(target, script, signal);
				let output = r.stdout;
				if (r.stderr) output += `
[stderr]
${r.stderr}`;
				const failed = r.code !== 0 || r.stderr.trim().length > 0;
				if (failed && permissionDenied(output) && !read.usedSudo) output += `

${sudoSetupHint(read.commandPath)}`;
				return textResult(appendSudoNote(truncateText(output), read.usedSudo, read.sudoReason), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_read"))} ${theme.fg("accent", args.path ?? "...")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_ls",
		label: "sshro_ls",
		description: "List a remote SSH target path. Requires target on every call. Supports recursive listings using eza when available, falling back to ls -laR.",
		promptSnippet: "sshro_ls: List files on an SSH target. Requires target. Set recursive=true for a live recursive listing; uses eza if available and falls back to ls.",
		parameters: lsParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const p = remotePath(params.path, ".");
				assertPathAllowed(p);
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const recursive = params.recursive === true;
				const ezaPath = recursive ? await resolveRemoteCommand(target, "eza", signal) : undefined;
				const commandName = ezaPath ? "eza" : "ls";
				const args = ezaPath ? ["-1l", "--absolute=on", "-R", "--color=never", "--icons=never", "--", p] : [recursive ? "-laR" : "-la", "--", p];
				const chosen = await chooseCommand(target, commandName, args, signal);
				const filter = ezaPath ? ` | grep -Ev '^(/|$)'` : "";
				const r = await sshExec(target, `LC_ALL=C ${chosen.command}${filter} | sed -n '1,${limit}p'`, signal, recursive ? 45_000 : 30_000);
				const stdout = r.code === 0 && !recursive ? markBlockedLsEntries(r.stdout, p) : r.stdout;
				let combined = `${stdout}${r.stderr ? `
[stderr]
${r.stderr}` : ""}`;
				const failed = r.code !== 0 || r.stderr.trim().length > 0;
				if (failed && permissionDenied(combined) && !chosen.usedSudo) combined += `

${sudoSetupHint(chosen.commandPath, ezaPath ? "-1l --absolute=on -R --color=never --icons=never -- *" : "*")}`;
				return textResult(appendSudoNote(truncateText(combined, limit), chosen.usedSudo, chosen.sudoReason), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ls"))} ${theme.fg("accent", args.path ?? ".")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_locate",
		label: "sshro_locate",
		description: "Search the remote plocate database for paths. Results are indexed and may be stale; no regex option is exposed.",
		promptSnippet: "sshro_locate: Quickly search indexed remote paths with plocate. Requires target. Results may be stale; use sshro_ls recursive for live listings.",
		parameters: locateParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				validatePathLike(params.pattern, "pattern");
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const locate = await chooseCommand(target, "plocate", ["--", params.pattern], signal);
				const r = await sshExec(target, `${locate.command} | sed -n '1,${limit}p'`, signal, 20_000);
				let output = r.stdout.trim().length ? r.stdout : "No matches";
				if (r.stderr) output += `
[stderr]
${r.stderr}`;
				output = `Results are from plocate and may be stale.

${output}`;
				if (r.code !== 0 && permissionDenied(output) && !locate.usedSudo) output += `

${sudoSetupHint(locate.commandPath)}`;
				return textResult(appendSudoNote(truncateText(output, limit), locate.usedSudo, locate.sudoReason), r.code !== 0 && r.stdout.trim().length === 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_locate"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_grep",
		label: "sshro_grep",
		description: "Search remote files on an SSH target. Requires target. Uses grep with fixed wrapper options and may use sudo after sudo -n -l confirms access.",
		promptSnippet: "sshro_grep: Search text files on an SSH target using grep -E by default; use literal=true for grep -F. Requires target. Recursive directory searches use grep -R with credential guardrail excludes.",
		parameters: grepParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				validatePathLike(params.pattern, "pattern");
				if (params.glob) validatePathLike(params.glob, "glob");
				const base = remotePath(params.path, ".");
				assertPathAllowed(base);
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const showErrors = params.showErrors === true;
				const errorLimit = validatePositiveLimit(params.errorLimit, "errorLimit", 20);
				const grepArgs = ["-nH", "-I"];
				if (params.ignoreCase) grepArgs.push("-i");
				grepArgs.push(params.literal ? "-F" : "-E");
				if (params.context !== undefined) grepArgs.push("-C", String(Math.max(0, Math.min(20, Math.floor(params.context)))));
				const test = await sshExec(target, `[ -d ${shellQuote(base)} ]`, signal, 10_000);
				if (test.code === 0) {
					grepArgs.push("-R");
					for (const dir of [...DENIED_DIR_NAMES, ".git", "node_modules"]) grepArgs.push(`--exclude-dir=${dir}`);
					for (const name of DENIED_FILE_NAMES) grepArgs.push(`--exclude=${name}`);
					for (const prefix of DENIED_FILE_PREFIXES) grepArgs.push(`--exclude=${prefix}*`);
					for (const suffix of DENIED_FILE_SUFFIXES) grepArgs.push(`--exclude=*${suffix}`);
					if (params.glob) grepArgs.push(`--include=${params.glob}`);
				}
				grepArgs.push("--", params.pattern, base);
				const grep = await chooseCommand(target, "grep", grepArgs, signal);
				const r = await sshExec(target, `${grep.command} | sed -n '1,${limit}p'`, signal, 60_000);
				const failed = r.code !== 0 && r.stdout.trim().length === 0 && r.stderr.trim().length > 0;
				let output = r.stdout.trim().length ? truncateText(r.stdout, limit) : "No matches";
				if (failed && permissionDenied(r.stderr) && !grep.usedSudo) output += `

${sudoSetupHint(grep.commandPath)}`;
				output = appendSearchErrorSummary(output, r.stderr, showErrors, errorLimit);
				return textResult(appendSudoNote(output, grep.usedSudo, grep.sudoReason), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_grep"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.path ?? ".")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_journalctl",
		label: "sshro_journalctl",
		description: "Read recent systemd journal logs from the SSH target with optional unit/time/priority filters.",
		promptSnippet: "sshro_journalctl: Inspect recent systemd journal logs by unit, time range, priority, and grep filter.",
		parameters: journalctlParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const lines = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.lines ?? 200)));
				const args = ["--no-pager", "--output=short-iso", "-n", String(lines)];
				const unit = optionalString(params.unit);
				const since = optionalString(params.since);
				const until = optionalString(params.until);
				const priority = optionalString(params.priority);
				const grep = optionalString(params.grep);
				if (unit) args.push("-u", shellWord(unit, "unit"));
				if (since) args.push("--since", shellWord(since, "since"));
				if (until) args.push("--until", shellWord(until, "until"));
				if (priority) args.push("-p", shellWord(priority, "priority"));
				if (grep) validatePathLike(grep, "grep");
				const base = `command -v journalctl >/dev/null 2>&1 || { echo 'journalctl not found on remote host' >&2; exit 127; }; journalctl ${args.join(" ")} 2>&1`;
				const script = grep ? `${base} | grep -i -- ${shellQuote(grep)} | sed -n '1,${lines}p'` : `${base} | sed -n '1,${lines}p'`;
				const r = await sshExec(target, script, signal, 45_000);
				const output = r.stdout + r.stderr;
				return textResult(output.trim().length ? truncateText(output, lines) : "No journal output", r.code !== 0 && output.trim().length === 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_journalctl"))} ${theme.fg("accent", args.unit ?? args.priority ?? "recent")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_systemctl",
		label: "sshro_systemctl",
		description: "Inspect systemd unit state on the SSH target. Supports failed, list, status, and show actions only.",
		promptSnippet: "sshro_systemctl: Inspect systemd failed units, service lists, unit status, and selected unit properties.",
		parameters: systemctlParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const action = params.action;
				const unit = optionalString(params.unit);
				if ((action === "status" || action === "show") && !unit) throw new Error(`sshro_systemctl action '${action}' requires unit`);
				if (unit) validatePathLike(unit, "unit");
				let cmd: string;
				if (action === "failed") cmd = "systemctl --no-pager --plain --failed";
				else if (action === "list") cmd = "systemctl --no-pager --plain list-units --type=service --all";
				else if (action === "status") cmd = `systemctl --no-pager --plain status ${shellQuote(unit!)}`;
				else cmd = `systemctl show ${shellQuote(unit!)} --property=Id,Names,Description,LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainCode,ExecMainStatus,MainPID,FragmentPath,DropInPaths,Requires,Wants,After,Before,Restart,RestartUSec,StartLimitBurst,StartLimitIntervalUSec`;
				const script = `command -v systemctl >/dev/null 2>&1 || { echo 'systemctl not found on remote host' >&2; exit 127; }; ${cmd} 2>&1 | sed -n '1,${DEFAULT_LINE_LIMIT}p'`;
				const r = await sshExec(target, script, signal, 30_000);
				const output = r.stdout + r.stderr;
				return textResult(truncateText(output || "No systemctl output"), r.code !== 0 && output.trim().length === 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_systemctl"))} ${theme.fg("accent", args.action ?? "...")} ${theme.fg("muted", args.unit ?? "")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_ps",
		label: "sshro_ps",
		description: "Inspect the remote process table with optional user/pattern filtering and cpu/memory sorting.",
		promptSnippet: "sshro_ps: Inspect remote processes, optionally filtered by owner or command-line pattern.",
		parameters: psParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const user = optionalString(params.user);
				const pattern = optionalString(params.pattern);
				if (user) validatePathLike(user, "user");
				if (pattern) validatePathLike(pattern, "pattern");
				const limit = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.limit ?? 80)));
				const sort = params.sort === "mem" ? "--sort=-%mem" : params.sort === "pid" ? "--sort=pid" : "--sort=-%cpu";
				let script = `ps -eo pid,ppid,user,stat,etime,%cpu,%mem,args ${sort} 2>&1`;
				if (user) script += ` | awk -v u=${shellQuote(user)} 'NR==1 || $3 == u'`;
				if (pattern) script += ` | grep -i -- ${shellQuote(pattern)}`;
				script += ` | sed -n '1,${limit}p'`;
				const r = await sshExec(target, script, signal, 20_000);
				const output = r.stdout + r.stderr;
				const noMatches = output.trim().length === 0 || psHasOnlyHeader(output);
				const filters = [user ? `user=${user}` : undefined, pattern ? `pattern=${pattern}` : undefined].filter(Boolean).join(" ");
				return textResult(noMatches ? `No matching processes${filters ? ` for ${filters}` : ""}` : truncateText(output, limit), r.code !== 0 && output.trim().length === 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ps"))} ${theme.fg("accent", args.pattern ?? args.user ?? "processes")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_ss",
		label: "sshro_ss",
		description: "Inspect remote TCP/UDP sockets using ss. Defaults to listening TCP/UDP sockets without process info.",
		promptSnippet: "sshro_ss: Inspect remote TCP/UDP socket state, especially listening ports.",
		parameters: ssParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const includeTcp = params.tcp !== false;
				const includeUdp = params.udp !== false;
				const proto = includeTcp || includeUdp ? `${includeTcp ? "t" : ""}${includeUdp ? "u" : ""}` : "tu";
				const flags = `-${proto}${params.listeningOnly === false ? "a" : "l"}n${params.processInfo ? "p" : ""}`;
				const limit = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.limit ?? 500)));
				const script = `command -v ss >/dev/null 2>&1 || { echo 'ss not found on remote host' >&2; exit 127; }; ss ${flags} 2>&1 | sed -n '1,${limit}p'`;
				const r = await sshExec(target, script, signal, 20_000);
				let output = r.stdout + r.stderr;
				if (params.processInfo && output.trim().length > 0) {
					output += output.includes("users:(")
						? "\n[ssh-ro note] processInfo=true was requested; process ownership details may still be partial without elevated privileges.\n"
						: "\n[ssh-ro note] processInfo=true was requested, but no process ownership details were visible. This usually means the SSH user lacks permission to inspect socket owners.\n";
				}
				return textResult(output.trim().length ? truncateText(output, limit) : "No socket output", r.code !== 0 && output.trim().length === 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ss"))} ${theme.fg("accent", args.listeningOnly === false ? "all sockets" : "listening sockets")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_df",
		label: "sshro_df",
		description: "Inspect remote filesystem free space using df. Defaults to local filesystems only to reduce risk from hanging network mounts.",
		promptSnippet: "sshro_df: Inspect remote filesystem free space; defaults to df -l for local filesystems only.",
		parameters: dfParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const remoteCwd = ".";
				const path = optionalString(params.path);
				const resolvedPath = path ? remotePath(path, remoteCwd) : undefined;
				if (resolvedPath) assertPathAllowed(resolvedPath);
				const flags = ["-P"];
				if (params.human !== false) flags.push("-h");
				if (params.localOnly !== false) flags.push("-l");
				const script = `df ${flags.join(" ")}${resolvedPath ? ` ${shellQuote(resolvedPath)}` : ""} 2>&1 | sed -n '1,${DEFAULT_LINE_LIMIT}p'`;
				const r = await sshExec(target, script, signal, 15_000);
				const output = r.stdout + r.stderr;
				return textResult(output.trim().length ? truncateText(output) : "No df output", r.code !== 0 && output.trim().length === 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_df"))} ${theme.fg("accent", args.path ?? "filesystems")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_docker_ps",
		label: "sshro_docker_ps",
		description: "List Docker containers on the SSH target using compact Docker table output. Docker is checked at tool runtime.",
		promptSnippet: "sshro_docker_ps: List active Docker containers with docker ps --no-trunc. Use all=true to include stopped/exited containers.",
		parameters: dockerPsParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const limit = validatePositiveLimit(params.limit, "limit", 100);
				const name = optionalString(params.name);
				if (name) validateDockerRef(name, "name");
				const args = [params.all ? "--all" : "", "--no-trunc"].filter(Boolean);
				if (name) args.push("--filter", shellQuote(`name=${name}`));
				const script = `command -v docker >/dev/null 2>&1 || { echo 'docker not found on remote host' >&2; exit 127; }; docker ps ${args.join(" ")}`;
				const r = await sshExec(target, script, signal, 20_000);
				if (r.code !== 0) return textResult(`docker ps failed: ${dockerUnavailableMessage(r.stderr, r.stdout)}`, true);
				if (hasOnlyHeader(r.stdout)) {
					return textResult(params.all ? "No Docker containers found." : "No active Docker containers. Use all=true to include stopped/exited containers.");
				}
				return textResult(truncateRowsWithHeader(r.stdout, limit, "containers"));
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_ps"))} ${theme.fg("accent", args.name ?? "containers")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_docker_inspect",
		label: "sshro_docker_inspect",
		description: "Inspect a Docker object on the SSH target. Returns curated JSON with environment variables visibly redacted.",
		promptSnippet: "sshro_docker_inspect: Inspect Docker metadata as JSON; curated output redacts environment variables by default.",
		parameters: dockerInspectParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				validateDockerRef(params.object, "object");
				const kind = optionalString(params.kind);
				if (kind && !(DOCKER_KINDS as readonly string[]).includes(kind)) throw new Error(`kind must be one of: ${DOCKER_KINDS.join(", ")}`);
				const args = kind ? [`--type`, shellQuote(kind), shellQuote(params.object)] : [shellQuote(params.object)];
				const script = `command -v docker >/dev/null 2>&1 || { echo 'docker not found on remote host' >&2; exit 127; }; docker inspect ${args.join(" ")}`;
				const r = await sshExec(target, script, signal, 20_000);
				if (r.code !== 0) return textResult(`docker inspect failed: ${dockerUnavailableMessage(r.stderr, r.stdout)}`, true);
				try {
					const parsed = JSON.parse(r.stdout);
					const output = curateDockerInspect(Array.isArray(parsed) ? parsed : [parsed]);
					return textResult(prettyJson(output));
				} catch (err) {
					return textResult(`docker inspect JSON output was unparseable: ${err instanceof Error ? err.message : String(err)}\n\n${truncateText(r.stdout + r.stderr)}`, true);
				}
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_inspect"))} ${theme.fg("accent", args.object ?? "...")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_docker_stats",
		label: "sshro_docker_stats",
		description: "Show one-shot Docker container stats on the SSH target as JSON where Docker supports it. Never streams.",
		promptSnippet: "sshro_docker_stats: Show one-shot Docker container CPU/memory/network/block stats; uses --no-stream. CPU can be noisy; call again a few seconds later to compare.",
		parameters: dockerStatsParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const limit = validatePositiveLimit(params.limit, "limit", 100);
				const container = optionalString(params.container);
				if (container) validateDockerRef(container, "container");
				const script = `command -v docker >/dev/null 2>&1 || { echo 'docker not found on remote host' >&2; exit 127; }; docker stats --no-stream --format '{{json .}}'${container ? ` ${shellQuote(container)}` : ""}`;
				const r = await sshExec(target, script, signal, 20_000);
				if (r.code !== 0) return textResult(`docker stats failed: ${dockerUnavailableMessage(r.stderr, r.stdout)}`, true);
				try {
					const rows = parseNdjson(r.stdout);
					return textResult(prettyJsonRows(rows, limit, "stat rows"));
				} catch (err) {
					return textResult(`docker stats JSON output was unavailable or unparseable: ${err instanceof Error ? err.message : String(err)}\n\n${truncateText(r.stdout + r.stderr)}`, true);
				}
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_stats"))} ${theme.fg("accent", args.container ?? "containers")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_dig",
		label: "sshro_dig",
		description: "Run a bounded read-only DNS lookup from the SSH target using dig. dig is checked at tool runtime.",
		promptSnippet: "sshro_dig: Debug DNS resolution from the remote host using dig +time=3 +tries=1. Optional server uses @server; short=true uses +short.",
		parameters: digParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const name = optionalString(params.name);
				if (!name) throw new Error("name is required");
				validatePathLike(name, "name");
				const type = optionalString(params.type) ?? "A";
				if (!(DNS_TYPES as readonly string[]).includes(type)) throw new Error(`type must be one of: ${DNS_TYPES.join(", ")}`);
				const server = optionalString(params.server);
				if (server) validatePathLike(server, "server");
				const args = ["+time=3", "+tries=1", params.short ? "+short" : "", server ? shellQuote(`@${server}`) : "", shellQuote(name), shellQuote(type)].filter(Boolean);
				const script = `command -v dig >/dev/null 2>&1 || { echo 'dig not found on remote host' >&2; exit 127; }; dig ${args.join(" ")}`;
				const r = await sshExec(target, script, signal, 10_000);
				const output = r.stdout + r.stderr;
				return textResult(output.trim().length ? truncateText(output, 500) : "No DNS answer", r.code !== 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_dig"))} ${theme.fg("accent", args.name ?? "...")}`, 0, 0);
		},
	});
}

export default function sshReadonlyExtension(pi: ExtensionAPI) {
	pi.registerFlag("ssh-ro", {
		type: "string",
		description: "Pre-approve an exact SSH target for stateless sshro_* tool calls, e.g. pi --ssh-ro user@server",
	});

	registerSshRoTools(pi);

	pi.registerCommand("sshro", {
		description: "Pre-approve an exact SSH target for stateless sshro_* tool calls, or clear approvals with /sshro logout",
		handler: async (args, ctx) => {
			const value = (args ?? "").trim();
			if (value === "logout") {
				approvedTargets.clear();
				ctx.ui.notify("SSH read-only session approvals cleared", "info");
				return;
			}
			if (!value) {
				ctx.ui.notify("Usage: /sshro user@host  or  /sshro logout", "info");
				return;
			}
			try {
				validateTarget(value);
				approvedTargets.add(value);
				ctx.ui.notify(`SSH read-only target approved for this Pi session: ${value}`, "info");
			} catch (err) {
				ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
			}
		},
	});

	pi.on("session_start", async (_event, ctx) => {
		const raw = pi.getFlag("ssh-ro");
		if (typeof raw !== "string" || raw.length === 0) return;
		try {
			const target = raw.trim();
			validateTarget(target);
			approvedTargets.add(target);
			ctx.ui.notify(`SSH read-only target approved for this Pi session: ${target}`, "info");
		} catch (err) {
			ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
		}
	});

	pi.on("tool_call", (event) => {
		if (event.toolName !== "bash") return;
		const command = typeof (event.input as { command?: unknown }).command === "string" ? (event.input as { command: string }).command : "";
		const reason = bashSshBlockReason(command);
		if (reason) return { block: true, reason };
	});
}
