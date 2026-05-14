import { spawn } from "node:child_process";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createLsTool } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import Type from "typebox";

type SshRoState =
	| { active: false; fatal?: undefined }
	| { active: true; target: string; remoteCwd: string; fatal: false }
	| { active: true; target: string; remoteCwd?: string; fatal: true; reason: string };

const TOOL_NAMES = ["sshro_read", "sshro_ls", "sshro_find", "sshro_grep", "sshro_journalctl", "sshro_systemctl", "sshro_ps", "sshro_ss", "sshro_df", "sshro_docker_ps", "sshro_docker_inspect", "sshro_docker_stats", "sshro_dig"] as const;
const REQUIRED_REMOTE_COMMANDS = ["file", "find", "grep", "head", "sed", "stat", "tail", "ls"];
const DEFAULT_LINE_LIMIT = 2000;
const DEFAULT_BYTE_LIMIT = 50 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const DENIED_DIR_NAMES = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".terraform", ".terraform.d", ".cloudflared", ".cloudflare", ".password-store"];
const DENIED_PATH_PARTS = ["/.config/gcloud", "/.config/gh", "/.config/Bitwarden CLI", "/.config/Bitwarden", "/.config/bitwarden", "/.config/1Password", "/.config/op", "/.config/keepassxc", "/.config/KeePass", "/.config/keepass", "/.config/gopass", "/.config/chezmoi", "/.local/share/fish", "/.local/share/nano", "/.local/share/keepassxc", "/.local/share/gopass", "/.local/share/chezmoi", "/.gem/credentials", "/.cargo/credentials"];
const DENIED_FILE_NAMES = [".env", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials", "terraform.tfstate", ".chezmoi.toml", ".chezmoi.yaml", ".chezmoi.json", ".chezmoiignore", ".bash_history", ".zsh_history", ".zhistory", ".fish_history", "fish_history", ".sh_history", ".ash_history", ".history", "search_history", ".mysql_history", ".psql_history", ".sqlite_history", ".python_history", ".node_repl_history", ".rediscli_history", ".lesshst", ".wget-hsts"];
const DENIED_FILE_SUFFIXES = [".pem", ".key", ".p12", ".pfx", "_history"];
const DENIED_FILE_PREFIXES = [".env.", "terraform.tfstate."];

let state: SshRoState = { active: false };
let toolsRegistered = false;
let previousActiveTools: string[] | undefined;

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

function validatePathLike(value: string, label: string): void {
	if (hasControlChars(value)) throw new Error(`${label} contains a newline or control character`);
	if (value === "~" || value.startsWith("~/")) throw new Error(`${label}: ~ expansion is not supported in SSH Read-only Mode v1`);
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

function sshExec(target: string, command: string, signal?: AbortSignal, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<{ stdout: string; stderr: string; code: number | null }> {
	return new Promise((resolve, reject) => {
		// Force POSIX sh for remote command templates. OpenSSH normally passes the
		// command through the user's login shell; many legacy/admin accounts use
		// fish/csh/etc., which do not understand POSIX for/if syntax.
		const remoteCommand = `sh -c ${shellQuote(command)}`;
		const child = spawn(
			"ssh",
			["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", target, remoteCommand],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
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

function textResult(text: string, isError = false) {
	return { content: [{ type: "text" as const, text }], isError };
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

function sshRoModeNote(target: string, remoteCwd: string): string {
	return `SSH Read-only Mode active: ${target}\nRemote cwd: ${remoteCwd}\n\nAvailable tools:\n${TOOL_NAMES.join(", ")}\n\nPath notes:\n- Paths are remote paths; relative paths resolve from the remote cwd.\n- ~ is not expanded; use absolute paths like /home/name/... or relative paths from the remote cwd.\n- [blocked] means credential/history/password-manager content is blocked; ask the user to inspect manually if needed.\n- sshro_find shows matching blocked entries but does not descend into blocked directories, so parent searches may not enumerate blocked children.\n- sshro_df defaults to local filesystems only to reduce risk from slow network mounts.
- Docker tools are optional fixed read-only inspections. sshro_docker_ps returns compact Docker table output by default; sshro_docker_inspect returns curated JSON and visibly redacts environment variables because Docker metadata can contain secrets.
- sshro_read supports negative offset values to read from the end of large files using tail.
- sshro_dig performs fixed, bounded DNS lookups with dig when available on the remote host.`;
}

function requireHealthy(): { target: string; remoteCwd: string } {
	if (!state.active) throw new Error("SSH Read-only Mode is not active");
	if (state.fatal) throw new Error(`SSH Read-only Mode startup failed: ${state.reason}`);
	return { target: state.target, remoteCwd: state.remoteCwd };
}

async function startupCheck(target: string): Promise<string> {
	const script = [
		"printf '%s\\n' __PI_SSHRO_PWD_START__",
		"pwd",
		"printf '%s\\n' __PI_SSHRO_PWD_END__",
		"printf '%s\\n' __PI_SSHRO_CHECKS_START__",
		`for c in ${REQUIRED_REMOTE_COMMANDS.map(shellQuote).join(" ")}; do command -v "$c" >/dev/null 2>&1 || echo "MISSING:$c"; done`,
		"printf '%s\\n' __PI_SSHRO_CHECKS_END__",
	].join("; ");
	const out = await sshChecked(target, script, undefined, 15_000);
	const lines = out.trim().split(/\r?\n/);
	const pwdStart = lines.indexOf("__PI_SSHRO_PWD_START__");
	const pwdEnd = lines.indexOf("__PI_SSHRO_PWD_END__");
	const checksStart = lines.indexOf("__PI_SSHRO_CHECKS_START__");
	const checksEnd = lines.indexOf("__PI_SSHRO_CHECKS_END__");
	if (pwdStart === -1 || pwdEnd === -1 || pwdEnd <= pwdStart) {
		throw new Error(`could not find startup check markers in SSH output: ${out.trim()}`);
	}
	const cwd = lines.slice(pwdStart + 1, pwdEnd).find((l) => l.startsWith("/"));
	if (!cwd) throw new Error(`could not resolve remote working directory from pwd output: ${out.trim()}`);
	const checkLines = checksStart !== -1 && checksEnd !== -1 && checksEnd > checksStart ? lines.slice(checksStart + 1, checksEnd) : lines;
	const missing = checkLines.filter((l) => l.startsWith("MISSING:")).map((l) => l.slice("MISSING:".length));
	if (missing.length > 0) throw new Error(`remote host is missing required commands: ${missing.join(", ")}`);
	return cwd;
}

function registerSshRoTools(pi: ExtensionAPI): void {
	if (toolsRegistered) return;
	toolsRegistered = true;
	const cwd = process.cwd();
	const readParams = Type.Object({
		path: Type.String({ description: "Path to the file to read (relative or absolute)" }),
		offset: Type.Optional(Type.Number({ description: "Line number to start reading from (1-indexed). Use a negative value to read from the end of the file, e.g. -100 for the last 100 lines." })),
		limit: Type.Optional(Type.Number({ description: "Maximum number of lines to read" })),
	});
	const lsParams = createLsTool(cwd).parameters;
	const findParams = Type.Object({
		path: Type.Optional(Type.String({ description: "Directory path to search from, default remote cwd" })),
		pattern: Type.String({ description: "File name/path glob. Patterns without '/' match names; patterns with '/' match paths." }),
		limit: Type.Optional(Type.Number({ description: "Maximum matches returned, default 500, max 2000" })),
		showErrors: Type.Optional(Type.Boolean({ description: "Include detailed search errors, default false. Permission errors are summarized either way." })),
		errorLimit: Type.Optional(Type.Number({ description: "Maximum detailed error lines when showErrors=true, default 20, max 2000" })),
	});
	const grepParams = Type.Object({
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
		unit: Type.Optional(Type.String({ description: "systemd unit to filter, e.g. nginx.service" })),
		since: Type.Optional(Type.String({ description: "journalctl --since value, e.g. '1 hour ago'" })),
		until: Type.Optional(Type.String({ description: "journalctl --until value" })),
		priority: Type.Optional(Type.Union([Type.Literal("emerg"), Type.Literal("alert"), Type.Literal("crit"), Type.Literal("err"), Type.Literal("warning"), Type.Literal("notice"), Type.Literal("info"), Type.Literal("debug")])),
		grep: Type.Optional(Type.String({ description: "Filter output with remote grep -i" })),
		lines: Type.Optional(Type.Number({ description: "Maximum recent journal lines, default 200, max 2000" })),
	});
	const systemctlParams = Type.Object({
		action: Type.Union([Type.Literal("failed"), Type.Literal("status"), Type.Literal("show"), Type.Literal("list")]),
		unit: Type.Optional(Type.String({ description: "Unit name for status/show, e.g. nginx.service" })),
	});
	const psParams = Type.Object({
		user: Type.Optional(Type.String({ description: "Filter to this process owner" })),
		pattern: Type.Optional(Type.String({ description: "Filter command lines with grep -i" })),
		sort: Type.Optional(Type.Union([Type.Literal("cpu"), Type.Literal("mem"), Type.Literal("pid")])),
		limit: Type.Optional(Type.Number({ description: "Maximum output lines, default 80, max 2000" })),
	});
	const ssParams = Type.Object({
		listeningOnly: Type.Optional(Type.Boolean({ description: "Show only listening sockets, default true" })),
		tcp: Type.Optional(Type.Boolean({ description: "Include TCP sockets, default true" })),
		udp: Type.Optional(Type.Boolean({ description: "Include UDP sockets, default true" })),
		processInfo: Type.Optional(Type.Boolean({ description: "Include process info with ss -p; may require privileges" })),
		limit: Type.Optional(Type.Number({ description: "Maximum output lines, default 500, max 2000" })),
	});
	const dfParams = Type.Object({
		path: Type.Optional(Type.String({ description: "Optional path/filesystem to inspect" })),
		localOnly: Type.Optional(Type.Boolean({ description: "Use df -l to avoid remote/network filesystems, default true" })),
		human: Type.Optional(Type.Boolean({ description: "Human-readable sizes, default true" })),
	});
	const dockerPsParams = Type.Object({
		all: Type.Optional(Type.Boolean({ description: "Include stopped containers, default false" })),
		name: Type.Optional(Type.String({ description: "Optional Docker name filter substring/pattern" })),
		limit: Type.Optional(Type.Number({ description: "Maximum containers returned, default 100, max 2000" })),
	});
	const dockerInspectParams = Type.Object({
		target: Type.String({ description: "Docker object name or ID to inspect" }),
		kind: Type.Optional(Type.String({ description: "Optional Docker object kind: container, image, network, or volume" })),
	});
	const dockerStatsParams = Type.Object({
		container: Type.Optional(Type.String({ description: "Optional container name or ID" })),
		limit: Type.Optional(Type.Number({ description: "Maximum containers returned, default 100, max 2000" })),
	});
	const digParams = Type.Object({
		name: Type.String({ description: "DNS name or address to query" }),
		type: Type.Optional(Type.Union([Type.Literal("A"), Type.Literal("AAAA"), Type.Literal("CNAME"), Type.Literal("MX"), Type.Literal("TXT"), Type.Literal("NS"), Type.Literal("SOA"), Type.Literal("PTR"), Type.Literal("CAA"), Type.Literal("SRV")], { description: "DNS record type, default A" })),
		server: Type.Optional(Type.String({ description: "Optional DNS server, e.g. 1.1.1.1 or dns.example.com" })),
		short: Type.Optional(Type.Boolean({ description: "Use dig +short output, default false" })),
	});

	pi.registerTool({
		name: "sshro_read",
		label: "sshro_read",
		description: "Read a text file from the SSH Read-only Mode target. Supports path, offset, and limit. Negative offset reads from the end of the file. Binary/non-text files are refused.",
		promptSnippet: "sshro_read: Read a text file from the SSH Read-only Mode target with optional line offset/limit. Use negative offset to read from the end of large logs.",
		parameters: readParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
				const p = remotePath(params.path, remoteCwd);
				assertPathAllowed(p);
				const rawOffset = params.offset === undefined ? 1 : Math.floor(Number(params.offset));
				if (!Number.isFinite(rawOffset)) throw new Error("offset must be a number");
				const offset = rawOffset === 0 ? 1 : rawOffset;
				const limit = validatePositiveLimit(params.limit, "limit", DEFAULT_LINE_LIMIT);
				const rangeLabel = offset < 0 ? `last ${Math.abs(offset)} lines${params.limit !== undefined ? `, limited to ${limit}` : ""}` : `${offset}-${offset + limit - 1}`;
				const readCommand = offset < 0
					? `tail -n ${Math.abs(offset)} "$p"${params.limit !== undefined ? ` | head -n ${limit}` : ""}`
					: offset === 1
						? `head -n ${limit} "$p"`
						: `tail -n +${offset} "$p" | head -n ${limit}`;
				const q = shellQuote(p);
				const script = `p=${q}; if [ ! -e "$p" ]; then echo "not found: $p" >&2; exit 2; fi; if [ ! -f "$p" ]; then echo "not a regular file: $p" >&2; exit 2; fi; if [ ! -r "$p" ]; then echo "not readable: $p" >&2; exit 2; fi; mt=$(file --mime-type -b "$p" 2>/dev/null || true); case "$mt" in text/*|inode/x-empty|application/json|application/xml|application/x-shellscript|application/x-perl|application/x-python|application/javascript|application/x-yaml) ;; *) echo "refusing non-text file ($mt): $p" >&2; exit 3;; esac; printf 'path: %s\\nmime: %s\\nlines: %s\\n---\\n' "$p" "$mt" ${shellQuote(rangeLabel)}; ${readCommand}`;
				const out = await sshChecked(target, script, signal);
				return textResult(truncateText(out));
			} catch (err) {
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_read"))} ${theme.fg("accent", args.path ?? "...")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_ls",
		label: "sshro_ls",
		description: "List a remote SSH Read-only Mode path. Includes hidden files and ls -la style metadata.",
		promptSnippet: "sshro_ls: List files on the SSH Read-only Mode target, including hidden files and metadata.",
		parameters: lsParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
				const p = remotePath(params.path, remoteCwd);
				assertPathAllowed(p);
				const limit = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.limit ?? 500)));
				const script = `p=${shellQuote(p)}; if [ -d "$p" ]; then LC_ALL=C ls -la "$p"; else LC_ALL=C ls -ld "$p"; fi`;
				const r = await sshExec(target, script, signal);
				const stdout = r.code === 0 ? markBlockedLsEntries(r.stdout, p) : r.stdout;
				const combined = `${stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}`;
				return textResult(truncateText(combined, limit), r.code !== 0);
			} catch (err) {
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ls"))} ${theme.fg("accent", args.path ?? ".")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_find",
		label: "sshro_find",
		description: "Find remote paths on the SSH Read-only Mode target. Patterns without '/' match names; patterns with '/' match paths. Recursive search prunes .git and node_modules unless the search path is inside one of them.",
		promptSnippet: "sshro_find: Find paths on the SSH Read-only Mode target using POSIX find-style name/path matching.",
		parameters: findParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
				validatePathLike(params.pattern, "pattern");
				const base = remotePath(params.path, remoteCwd);
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const showErrors = params.showErrors === true;
				const errorLimit = validatePositiveLimit(params.errorLimit, "errorLimit", 20);
				const pathPattern = params.pattern.includes("/") && !params.pattern.startsWith("/") ? `*/${params.pattern}` : params.pattern;
				const pred = params.pattern.includes("/") ? `-path ${shellQuote(pathPattern)}` : `-name ${shellQuote(params.pattern)}`;
				if (denyReasonForPath(base)) return textResult(appendBlockedFootnote(`${base} [blocked]`));
				const shouldPrune = !base.includes("/.git") && !base.includes("/node_modules") && !denyReasonForPath(`${base}/placeholder`);
				const prune = shouldPrune ? findMarkedDenyExpression(pred) : "";
				const script = `find ${shellQuote(base)} ${prune}${pred} -print | sed -n '1,${limit}p'`;
				const r = await sshExec(target, script, signal, 45_000);
				const matches = markBlockedFindEntries(r.stdout);
				const output = matches.trim().length ? truncateText(matches, limit) : "No matches";
				return textResult(appendSearchErrorSummary(output, r.stderr, showErrors, errorLimit), r.code !== 0 && r.stdout.trim().length === 0 && r.stderr.trim().length === 0);
			} catch (err) {
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_find"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.path ?? ".")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_grep",
		label: "sshro_grep",
		description: "Search remote files on the SSH Read-only Mode target. Recursive for directories, skips binary files, uses extended regex by default, and supports glob, ignoreCase, literal, context, and limit.",
		promptSnippet: "sshro_grep: Search text files on the SSH Read-only Mode target using grep -E by default; use literal=true for grep -F. Recursive directory searches prune .git and node_modules by default and summarize permission errors unless showErrors=true.",
		parameters: grepParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
				validatePathLike(params.pattern, "pattern");
				if (params.glob) validatePathLike(params.glob, "glob");
				const base = remotePath(params.path, remoteCwd);
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const showErrors = params.showErrors === true;
				const errorLimit = validatePositiveLimit(params.errorLimit, "errorLimit", 20);
				const opts = ["-nH", "-I"];
				if (params.ignoreCase) opts.push("-i");
				opts.push(params.literal ? "-F" : "-E");
				if (params.context !== undefined) opts.push("-C", String(Math.max(0, Math.min(20, Math.floor(params.context)))));
				const globPred = params.glob ? ` -name ${shellQuote(params.glob)}` : "";
				assertPathAllowed(base);
				const shouldPrune = !base.includes("/.git") && !base.includes("/node_modules") && !denyReasonForPath(`${base}/placeholder`);
				const prune = shouldPrune ? findDenyExpression() : "";
				const fileDeny = findFileDenyPredicates();
				const script = `if [ -d ${shellQuote(base)} ]; then find ${shellQuote(base)} ${prune}-type f ${fileDeny}${globPred} -exec grep ${opts.join(" ")} -- ${shellQuote(params.pattern)} {} + | sed -n '1,${limit}p'; else grep ${opts.join(" ")} -- ${shellQuote(params.pattern)} ${shellQuote(base)} | sed -n '1,${limit}p'; fi`;
				const r = await sshExec(target, script, signal, 60_000);
				const output = r.stdout.trim().length ? truncateText(r.stdout, limit) : "No matches";
				return textResult(appendSearchErrorSummary(output, r.stderr, showErrors, errorLimit));
			} catch (err) {
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_grep"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.path ?? ".")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_journalctl",
		label: "sshro_journalctl",
		description: "Read recent systemd journal logs from the SSH Read-only Mode target with optional unit/time/priority filters.",
		promptSnippet: "sshro_journalctl: Inspect recent systemd journal logs by unit, time range, priority, and grep filter.",
		parameters: journalctlParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_journalctl"))} ${theme.fg("accent", args.unit ?? args.priority ?? "recent")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_systemctl",
		label: "sshro_systemctl",
		description: "Inspect systemd unit state on the SSH Read-only Mode target. Supports failed, list, status, and show actions only.",
		promptSnippet: "sshro_systemctl: Inspect systemd failed units, service lists, unit status, and selected unit properties.",
		parameters: systemctlParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
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
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
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
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
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
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_df"))} ${theme.fg("accent", args.path ?? "filesystems")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_docker_ps",
		label: "sshro_docker_ps",
		description: "List Docker containers on the SSH Read-only Mode target using compact Docker table output. Docker is checked at tool runtime.",
		promptSnippet: "sshro_docker_ps: List active Docker containers with docker ps --no-trunc. Use all=true to include stopped/exited containers.",
		parameters: dockerPsParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_ps"))} ${theme.fg("accent", args.name ?? "containers")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_docker_inspect",
		label: "sshro_docker_inspect",
		description: "Inspect a Docker object on the SSH Read-only Mode target. Returns curated JSON with environment variables visibly redacted.",
		promptSnippet: "sshro_docker_inspect: Inspect Docker metadata as JSON; curated output redacts environment variables by default.",
		parameters: dockerInspectParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
				validateDockerRef(params.target, "target");
				const kind = optionalString(params.kind);
				if (kind && !(DOCKER_KINDS as readonly string[]).includes(kind)) throw new Error(`kind must be one of: ${DOCKER_KINDS.join(", ")}`);
				const args = kind ? [`--type`, shellQuote(kind), shellQuote(params.target)] : [shellQuote(params.target)];
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
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_inspect"))} ${theme.fg("accent", args.target ?? "...")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_docker_stats",
		label: "sshro_docker_stats",
		description: "Show one-shot Docker container stats on the SSH Read-only Mode target as JSON where Docker supports it. Never streams.",
		promptSnippet: "sshro_docker_stats: Show one-shot Docker container CPU/memory/network/block stats; uses --no-stream. CPU can be noisy; call again a few seconds later to compare.",
		parameters: dockerStatsParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_stats"))} ${theme.fg("accent", args.container ?? "containers")}`, 0, 0);
		},
	});

	pi.registerTool({
		name: "sshro_dig",
		label: "sshro_dig",
		description: "Run a bounded read-only DNS lookup from the SSH Read-only Mode target using dig. dig is checked at tool runtime.",
		promptSnippet: "sshro_dig: Debug DNS resolution from the remote host using dig +time=3 +tries=1. Optional server uses @server; short=true uses +short.",
		parameters: digParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target } = requireHealthy();
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
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_dig"))} ${theme.fg("accent", args.name ?? "...")}`, 0, 0);
		},
	});
}

function failClosed(pi: ExtensionAPI, ctx: ExtensionContext, target: string, reason: string): void {
	state = { active: true, target, fatal: true, reason };
	pi.setActiveTools([]);
	ctx.ui.setStatus("ssh-ro", ctx.ui.theme.fg("error", `SSH RO failed: ${target}`));
	ctx.ui.notify(`SSH Read-only Mode startup failed for ${target}: ${reason}`, "error");
}

async function activateSshRo(pi: ExtensionAPI, ctx: ExtensionContext, target: string): Promise<void> {
	if (state.active && !state.fatal) {
		throw new Error(`SSH Read-only Mode is already active for ${state.target}. Run /sshro logout first.`);
	}
	validateTarget(target);
	registerSshRoTools(pi);
	const remoteCwd = await startupCheck(target);
	previousActiveTools = pi.getActiveTools();
	state = { active: true, target, remoteCwd, fatal: false };
	pi.setActiveTools([...TOOL_NAMES]);
	ctx.ui.setStatus("ssh-ro", ctx.ui.theme.fg("accent", `SSH RO ${target}`));
	ctx.ui.notify(`SSH Read-only Mode: ${target} (remote cwd ${remoteCwd})`, "info");
	pi.sendMessage({
		customType: "ssh-ro-info",
		content: sshRoModeNote(target, remoteCwd),
		display: true,
		details: { target, remoteCwd, tools: TOOL_NAMES },
	});
}

function deactivateSshRo(pi: ExtensionAPI, ctx: ExtensionContext): void {
	if (!state.active) {
		ctx.ui.notify("SSH Read-only Mode is not active", "info");
		return;
	}
	state = { active: false };
	if (previousActiveTools) pi.setActiveTools(previousActiveTools);
	previousActiveTools = undefined;
	ctx.ui.setStatus("ssh-ro", undefined);
	ctx.ui.notify("SSH Read-only Mode ended", "info");
}

export default function sshReadonlyExtension(pi: ExtensionAPI) {
	pi.registerFlag("ssh-ro", {
		type: "string",
		description: "Start SSH Read-only Mode against an SSH target, e.g. pi --ssh-ro user@server",
	});

	pi.registerCommand("sshro", {
		description: "Enter SSH Read-only Mode for a known SSH host, or leave it with /sshro logout",
		handler: async (args, ctx) => {
			const value = (args ?? "").trim();
			if (value === "logout") {
				deactivateSshRo(pi, ctx);
				return;
			}
			if (!value) {
				ctx.ui.notify("Usage: /sshro user@host  or  /sshro logout", "info");
				return;
			}
			try {
				await activateSshRo(pi, ctx, value);
			} catch (err) {
				ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
			}
		},
	});

	pi.on("session_start", async (_event, ctx) => {
		const raw = pi.getFlag("ssh-ro");
		if (typeof raw !== "string" || raw.length === 0) {
			state = { active: false };
			return;
		}

		try {
			await activateSshRo(pi, ctx, raw.trim());
		} catch (err) {
			const target = typeof raw === "string" ? raw.trim() : "<unknown>";
			failClosed(pi, ctx, target, err instanceof Error ? err.message : String(err));
		}
	});

	pi.on("tool_call", (event) => {
		if (!state.active) return;
		if (state.fatal) return { block: true, reason: `SSH Read-only Mode startup failed: ${state.reason}` };
		if (!TOOL_NAMES.includes(event.toolName as (typeof TOOL_NAMES)[number])) {
			return { block: true, reason: `SSH Read-only Mode allows only: ${TOOL_NAMES.join(", ")}` };
		}
	});

	pi.on("before_agent_start", (event) => {
		if (!state.active || state.fatal) return;
		const localCwd = process.cwd();
		const remoteLine = `Current working directory: ${state.remoteCwd} (SSH Read-only Mode target: ${state.target})`;
		let systemPrompt = event.systemPrompt.replace(`Current working directory: ${localCwd}`, remoteLine);
		systemPrompt += `\n\n${sshRoModeNote(state.target, state.remoteCwd)}\n`;
		return { systemPrompt };
	});
}
