import { StringEnum } from "@earendil-works/pi-ai";
import {
	DEFAULT_MAX_BYTES,
	DEFAULT_MAX_LINES,
	formatSize,
	truncateHead,
	type ExtensionAPI,
	type ExtensionContext,
	type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import Type, { type TSchema } from "typebox";
import { bashSshBlockReason } from "./src/bash-ssh-guard.ts";
import { boundedReadFailed, grepFailed, locateFailed, systemctlFailed } from "./src/exit-policy.ts";
import { discoverSshConfigAliases } from "./src/ssh-config.ts";
import { resolveRemoteCommandCached } from "./src/remote-command.ts";
import { statusPreservingPipeline } from "./src/ssh-output.ts";
import {
	captureTruncationNote,
	requireCompleteCapture,
	requireRemoteExecution,
	shellQuote,
	sshExec,
	type SshExecutor,
} from "./src/ssh-transport.ts";
import { normalizeSshTarget, parseSshTargetList } from "./src/target-policy.ts";
import {
	canonicalPathForPolicy,
	DENIED_DIR_NAMES,
	DENIED_FILE_NAMES,
	DENIED_FILE_PREFIXES,
	DENIED_FILE_SUFFIXES,
	denyReasonForPath,
	joinRemotePath,
	remotePath,
	validatePathLike,
} from "./src/path-policy.ts";
import { SshRoController, type ActivationReport } from "./src/sshro-controller.ts";
import { SSHRO_CONNECT_TOOL_NAME } from "./src/tool-activation.ts";

const SSHRO_HOST_WHITELIST_ENV = "SSHRO_HOST_WHITELIST";
const DEFAULT_LINE_LIMIT = DEFAULT_MAX_LINES;
const DEFAULT_BYTE_LIMIT = DEFAULT_MAX_BYTES;
const SSHRO_APPROVAL_STATE_ENTRY = "sshro-approval-state";
const SSHRO_STATUS_KEY = "sshro";
const MAX_DISCOVERED_TARGETS = 100;

function validateTarget(target: string): void {
	normalizeSshTarget(target);
}

function whitelistConfig() {
	return parseSshTargetList(process.env[SSHRO_HOST_WHITELIST_ENV]);
}

function whitelistedHosts(): Set<string> {
	return whitelistConfig().targets;
}

function whitelistedHostsPromptHint(): string {
	const hosts = [...whitelistedHosts()];
	const maxShown = 20;
	const shown = hosts.slice(0, maxShown).join(", ");
	const suffix = hosts.length > maxShown ? `, ... (${hosts.length - maxShown} more)` : "";
	const list = hosts.length === 0 ? "no targets configured" : `${shown}${suffix}`;
	const rejected = whitelistConfig().rejected;
	const invalidNote = rejected > 0 ? ` ${rejected} invalid whitelist ${rejected === 1 ? "entry was" : "entries were"} ignored.` : "";
	return `SSH connection requests require approval unless the target is on the whitelist. For automatic approval, use the target exactly as listed.\n\nWhitelist: ${list}.${invalidNote}`;
}

function truncateText(text: string, maxLines = DEFAULT_LINE_LIMIT, maxBytes = DEFAULT_BYTE_LIMIT): string {
	const truncation = truncateHead(text, { maxLines, maxBytes });
	if (!truncation.truncated) return truncation.content;
	return `${truncation.content}\n\n[ssh-ro output truncated: ${truncation.outputLines}/${truncation.totalLines} lines, ${formatSize(truncation.outputBytes)}/${formatSize(truncation.totalBytes)}]`;
}


function targetParam() {
	return Type.String({ description: `SSH target to connect to, e.g. user@host or an OpenSSH Host alias. Must match whitelist entries exactly for automatic approval. ${whitelistedHostsPromptHint()}` });
}

function commandString(commandPath: string, args: string[]): string {
	return [commandPath, ...args].map(shellQuote).join(" ");
}

function sudoSetupHint(commandPath: string, argsHint = "*"): string {
	return `If elevated access was expected, configure a NOPASSWD sudoers rule for this SSH user, e.g.:\n\n  <user> ALL=(root) NOPASSWD: ${commandPath} ${argsHint}\n\nNo elevated command is run unless sudo -n -l confirms it first.`;
}

async function checkSudoAllowed(controller: SshRoController, executeSsh: SshExecutor, target: string, commandPath: string, args: string[], signal?: AbortSignal): Promise<{ allowed: boolean; reason: string }> {
	const key = `${target}\0${commandPath}\0${args.join("\0")}`;
	const cached = controller.getCachedSudoCheck(key);
	if (cached) return cached;
	const r = await executeSsh(target, `sudo -n -l -- ${commandString(commandPath, args)} 2>&1`, signal, 10_000);
	requireCompleteCapture(r, "sudo policy check");
	requireRemoteExecution(r, "sudo policy check");
	const output = `${r.stdout}\n${r.stderr}`.trim();
	const hasNoPasswd = /\bNOPASSWD\s*:/i.test(output);
	const result = r.code === 0 && hasNoPasswd
		? { allowed: true, reason: output }
		: { allowed: false, reason: r.code === 0 ? "sudo command is allowed but is not marked NOPASSWD" : output };
	controller.cacheSudoCheck(key, result);
	return result;
}

async function chooseRemoteCommand(controller: SshRoController, executeSsh: SshExecutor, target: string, command: string, args: string[], signal?: AbortSignal): Promise<{ commandPath: string; command: string; usedSudo: boolean; sudoReason: string }> {
	const commandPath = await resolveRemoteCommandCached(controller, executeSsh, target, command, signal);
	if (!commandPath) throw new Error(`${command} not found on remote host`);
	const sudo = await checkSudoAllowed(controller, executeSsh, target, commandPath, args, signal);
	const base = commandString(commandPath, args);
	return { commandPath, command: sudo.allowed ? `sudo -n ${base}` : base, usedSudo: sudo.allowed, sudoReason: sudo.reason };
}

function sudoMeta(usedSudo: boolean, sudoReason: string): string {
	if (usedSudo) return "sudo: yes";
	if (/password is required|not marked NOPASSWD|a terminal is required|no tty/i.test(sudoReason)) return "sudo: no (password/tty required)";
	return "sudo: no (not allowed)";
}

function remoteMetaFooter(target: string, remoteTime?: string, sudo?: string): string {
	return `[ssh-ro: ${[target, sudo, remoteTime ? `remote time: ${remoteTime}` : undefined].filter(Boolean).join(" | ")}]`;
}

function appendRemoteMeta(output: string, target: string, remoteTime?: string, sudo?: string): string {
	return `${output.trimEnd()}\n\n${remoteMetaFooter(target, remoteTime, sudo)}`;
}

function appendSudoNote(output: string, usedSudo: boolean, sudoReason: string, target?: string, remoteTime?: string): string {
	return target ? appendRemoteMeta(output, target, remoteTime, sudoMeta(usedSudo, sudoReason)) : `${output.trimEnd()}\n\n[ssh-ro: ${sudoMeta(usedSudo, sudoReason)}]`;
}

function isAllowedTextMime(mime: string): boolean {
	return mime.startsWith("text/") || ["inode/x-empty", "application/x-empty", "application/json", "application/xml", "application/x-shellscript", "application/x-perl", "application/x-python", "application/javascript", "application/x-yaml"].includes(mime);
}

function permissionDenied(text: string): boolean {
	return /permission denied|operation not permitted/i.test(text);
}

function textResult(text: string, failed = false) {
	if (failed) throw new Error(text);
	return { content: [{ type: "text" as const, text }], details: {} };
}

function errorResult(err: unknown): never {
	throw err instanceof Error ? err : new Error(String(err));
}

function optionalString(value: unknown): string | undefined {
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function appendBlockedFootnote(output: string): string {
	return output.includes(" [blocked]") ? `${output}\n\n[blocked] = content access is blocked by SSH read-only credential/history guardrails; ask the user to inspect manually if needed.` : output;
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

function markBlockedRecursiveLsEntries(output: string): string {
	const marked = output
		.split("\n")
		.map((line) => {
			const match = line.match(/(\/.*?)(?: -> |$)/);
			if (!match) return line;
			return denyReasonForPath(match[1].trim()) ? `${line} [blocked]` : line;
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


function registerSshRoTools(pi: ExtensionAPI, controller: SshRoController, executeSsh: SshExecutor, onStateChanged: (ctx: ExtensionContext) => void): string[] {
	const sshExec = executeSsh;
	const inspectionToolNames: string[] = [];
	const registerInspectionTool = <TParams extends TSchema, TDetails = unknown, TState = unknown>(definition: ToolDefinition<TParams, TDetails, TState>) => {
		inspectionToolNames.push(definition.name);
		pi.registerTool(definition);
	};
	const authorizeTarget = async (target: string, ctx: ExtensionContext, signal?: AbortSignal) => {
		const authorized = await controller.authorize(target, ctx, signal);
		onStateChanged(ctx);
		return authorized;
	};
	const resolveRemoteCommand = (target: string, command: string, signal?: AbortSignal) => resolveRemoteCommandCached(controller, executeSsh, target, command, signal);
	const chooseCommand = (target: string, command: string, args: string[], signal?: AbortSignal) => chooseRemoteCommand(controller, executeSsh, target, command, args, signal);
	const canonicalRemotePath = async (target: string, input: string | undefined, signal?: AbortSignal) => {
		const lexicalPath = remotePath(input, ".");
		return canonicalPathForPolicy(lexicalPath, async (path) => {
			const realpathCommand = await resolveRemoteCommand(target, "realpath", signal);
			if (!realpathCommand) throw new Error("realpath not found on remote host; canonical path verification is required");
			const result = await sshExec(target, commandString(realpathCommand, ["-e", "--", path]), signal, 10_000);
			requireCompleteCapture(result, "realpath");
			requireRemoteExecution(result, "realpath");
			if (result.code !== 0) throw new Error(`unable to resolve remote path ${path}: ${(result.stderr || result.stdout).trim()}`);
			const canonical = result.stdout.trim().split(/\r?\n/, 1)[0];
			if (!canonical) throw new Error(`realpath returned no canonical path for ${path}`);
			return canonical;
		});
	};

	pi.registerTool({
		name: SSHRO_CONNECT_TOOL_NAME,
		label: SSHRO_CONNECT_TOOL_NAME,
		description: "Approve or discover an exact SSH read-only target and load the detailed sshro_* inspection tools. Omit target to discover whitelist and session-approved targets.",
		promptSnippet: "sshro_connect: Approve or discover exact SSH targets and load detailed read-only SSH inspection tools on demand.",
		promptGuidelines: [
			"Use sshro_connect when remote server inspection would help and either the exact target or detailed sshro_* tools are not yet available; pass a target to request approval, or omit it to discover pre-approved targets.",
		],
		parameters: Type.Object({
			target: Type.Optional(targetParam()),
		}),
		executionMode: "sequential",
		async execute(_id, params, signal, _onUpdate, ctx) {
			const requestedTarget = optionalString(params.target);
			const targets = requestedTarget
				? [await controller.authorize(requestedTarget, ctx, signal)]
				: controller.availableTargets();
			if (targets.length === 0) {
				return textResult("No SSH read-only targets are currently pre-approved. Call sshro_connect again with an exact target to request human approval.\n\nNo SSH connection was opened.");
			}

			const activation = controller.activateInspectionTools();
			onStateChanged(ctx);
			const shownTargets = targets.slice(0, MAX_DISCOVERED_TARGETS);
			const omittedTargets = targets.length - shownTargets.length;
			const targetSummary = targets.length === 1
				? `SSH read-only target available: ${targets[0]}`
				: `SSH read-only targets available: ${shownTargets.join(", ")}${omittedTargets > 0 ? `, … (${omittedTargets} more omitted)` : ""}`;
			const toolSummary = activation.active.length > 0
				? `${activationSummary(activation)}. Capabilities: files, search, services, processes, sockets, filesystems, Docker, and DNS.`
				: "No SSH read-only inspection tools could be activated; current Pi tool allow/exclude settings block them.";
			return textResult(`${targetSummary}\n\n${toolSummary}\n\nEvery sshro_* inspection call must include an exact target string. No SSH connection was opened by sshro_connect.`);
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_connect"))} ${theme.fg("accent", args.target ?? "discover")}`, 0, 0);
		},
	});

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
		priority: Type.Optional(StringEnum(["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"] as const)),
		grep: Type.Optional(Type.String({ description: "Filter output with remote grep -i" })),
		lines: Type.Optional(Type.Number({ description: "Maximum recent journal lines, default 200, max 2000" })),
	});
	const systemctlParams = Type.Object({
		target: targetParam(),
		action: StringEnum(["failed", "status", "show", "list"] as const),
		unit: Type.Optional(Type.String({ description: "Unit name for status/show, e.g. nginx.service" })),
	});
	const psParams = Type.Object({
		target: targetParam(),
		user: Type.Optional(Type.String({ description: "Filter to this process owner" })),
		pattern: Type.Optional(Type.String({ description: "Filter command lines with grep -i" })),
		sort: Type.Optional(StringEnum(["cpu", "mem", "pid"] as const)),
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
		type: Type.Optional(StringEnum(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "CAA", "SRV"] as const, { description: "DNS record type, default A" })),
		server: Type.Optional(Type.String({ description: "Optional DNS server, e.g. 1.1.1.1 or dns.example.com" })),
		short: Type.Optional(Type.Boolean({ description: "Use dig +short output, default false" })),
	});

	registerInspectionTool({
		name: "sshro_read",
		label: "sshro_read",
		description: "Read a text file from an SSH target. Requires target on every call. Uses sudo only when sudo -n -l confirms the fixed cat command is allowed.",
		parameters: readParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const p = await canonicalRemotePath(target, params.path, signal);
				const rawOffset = params.offset === undefined ? 1 : Math.floor(Number(params.offset));
				if (!Number.isFinite(rawOffset)) throw new Error("offset must be a number");
				const offset = rawOffset === 0 ? 1 : rawOffset;
				const limit = validatePositiveLimit(params.limit, "limit", DEFAULT_LINE_LIMIT);
				const rangeLabel = offset < 0 ? `last ${Math.abs(offset)} lines${params.limit !== undefined ? `, limited to ${limit}` : ""}` : `${offset}-${offset + limit - 1}`;
				const read = await chooseCommand(target, "cat", ["--", p], signal);
				const mimeCheck = await sshExec(target, statusPreservingPipeline(`${read.command} 2>/dev/null`, "head -c 4096 | file --mime-type -b -"), signal, 15_000);
				if (boundedReadFailed(mimeCheck.code)) throw new Error(`unable to sample file for MIME detection: ${(mimeCheck.stderr || mimeCheck.stdout).trim()}`);
				const mime = mimeCheck.stdout.trim().split(/\r?\n/, 1)[0] || "unknown";
				if (!isAllowedTextMime(mime)) throw new Error(`refusing non-text file (${mime}): ${p}`);
				const slice = offset < 0
					? `tail -n ${Math.abs(offset)}${params.limit !== undefined ? ` | head -n ${limit}` : ""}`
					: offset === 1
						? `head -n ${limit}`
						: `tail -n +${offset} | head -n ${limit}`;
				const script = `printf 'path: %s\nmime: %s\nlines: %s\n---\n' ${shellQuote(p)} ${shellQuote(mime)} ${shellQuote(rangeLabel)}; ${statusPreservingPipeline(read.command, slice)}`;
				const r = await sshExec(target, script, signal);
				let output = r.stdout;
				if (r.stderr) output += `
[stderr]
${r.stderr}`;
				const failed = boundedReadFailed(r.code) || r.stderr.trim().length > 0;
				if (failed && permissionDenied(output) && !read.usedSudo) output += `

${sudoSetupHint(read.commandPath)}`;
				return textResult(appendSudoNote(truncateText(output) + captureTruncationNote(r), read.usedSudo, read.sudoReason, target, r.remoteTime), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_read"))} ${theme.fg("accent", args.path ?? "...")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_ls",
		label: "sshro_ls",
		description: "List a remote SSH target path. Requires target on every call. Supports recursive listings using eza when available, falling back to ls -laR.",
		parameters: lsParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const p = await canonicalRemotePath(target, params.path, signal);
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const recursive = params.recursive === true;
				const ezaPath = recursive ? await resolveRemoteCommand(target, "eza", signal) : undefined;
				const commandName = ezaPath ? "eza" : "ls";
				const args = ezaPath ? ["-1l", "--absolute=on", "-R", "--color=never", "--icons=never", "--", p] : [recursive ? "-laR" : "-la", "--", p];
				const chosen = await chooseCommand(target, commandName, args, signal);
				const filter = ezaPath ? "grep -Ev '^(/|$)'" : "cat";
				const r = await sshExec(target, statusPreservingPipeline(`LC_ALL=C ${chosen.command}`, `${filter} | sed -n '1,${limit}p'`), signal, recursive ? 45_000 : 30_000);
				const stdout = r.code === 0 ? (recursive ? markBlockedRecursiveLsEntries(r.stdout) : markBlockedLsEntries(r.stdout, p)) : r.stdout;
				let combined = `${stdout}${r.stderr ? `
[stderr]
${r.stderr}` : ""}`;
				const failed = r.code !== 0 || r.stderr.trim().length > 0;
				if (failed && permissionDenied(combined) && !chosen.usedSudo) combined += `

${sudoSetupHint(chosen.commandPath, ezaPath ? "-1l --absolute=on -R --color=never --icons=never -- *" : "*")}`;
				return textResult(appendSudoNote(truncateText(combined, limit) + captureTruncationNote(r), chosen.usedSudo, chosen.sudoReason, target, r.remoteTime), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ls"))} ${theme.fg("accent", args.path ?? ".")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_locate",
		label: "sshro_locate",
		description: "Search the remote plocate database for paths. Results are indexed and may be stale; no regex option is exposed.",
		parameters: locateParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				validatePathLike(params.pattern, "pattern");
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const locate = await chooseCommand(target, "plocate", ["--", params.pattern], signal);
				const r = await sshExec(target, statusPreservingPipeline(locate.command, `sed -n '1,${limit}p'`), signal, 20_000);
				let output = r.stdout.trim().length ? r.stdout : "No matches";
				if (r.stderr) output += `
[stderr]
${r.stderr}`;
				output = `Results are from plocate and may be stale.

${output}`;
				if (r.code !== 0 && permissionDenied(output) && !locate.usedSudo) output += `

${sudoSetupHint(locate.commandPath)}`;
				const failed = locateFailed(r.code, r.stderr);
				return textResult(appendSudoNote(truncateText(output, limit) + captureTruncationNote(r), locate.usedSudo, locate.sudoReason, target, r.remoteTime), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_locate"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_grep",
		label: "sshro_grep",
		description: "Search remote files on an SSH target. Requires target. Uses grep with fixed wrapper options and may use sudo after sudo -n -l confirms access.",
		parameters: grepParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				validatePathLike(params.pattern, "pattern");
				if (params.glob) validatePathLike(params.glob, "glob");
				const base = await canonicalRemotePath(target, params.path, signal);
				const limit = validatePositiveLimit(params.limit, "limit", 500);
				const showErrors = params.showErrors === true;
				const errorLimit = validatePositiveLimit(params.errorLimit, "errorLimit", 20);
				const grepArgs = ["-nH", "-I"];
				if (params.ignoreCase) grepArgs.push("-i");
				grepArgs.push(params.literal ? "-F" : "-E");
				if (params.context !== undefined) grepArgs.push("-C", String(Math.max(0, Math.min(20, Math.floor(params.context)))));
				const test = await sshExec(target, `[ -d ${shellQuote(base)} ]`, signal, 10_000);
				requireRemoteExecution(test, "remote directory check");
				if (test.code !== 0 && test.code !== 1) throw new Error(`remote directory check failed with exit ${test.code}`);
				if (test.code === 0) {
					grepArgs.push("-r");
					if (params.glob) grepArgs.push(`--include=${params.glob}`);
					for (const dir of [...DENIED_DIR_NAMES, ".git", "node_modules"]) grepArgs.push(`--exclude-dir=${dir}`);
					for (const name of DENIED_FILE_NAMES) grepArgs.push(`--exclude=${name}`);
					for (const prefix of DENIED_FILE_PREFIXES) grepArgs.push(`--exclude=${prefix}*`);
					for (const suffix of DENIED_FILE_SUFFIXES) grepArgs.push(`--exclude=*${suffix}`);
				}
				grepArgs.push("--", params.pattern, base);
				const grep = await chooseCommand(target, "grep", grepArgs, signal);
				const r = await sshExec(target, statusPreservingPipeline(grep.command, `sed -n '1,${limit}p'`), signal, 60_000);
				const failed = grepFailed(r.code);
				let output = r.stdout.trim().length ? truncateText(r.stdout, limit) : "No matches";
				if (failed && permissionDenied(r.stderr) && !grep.usedSudo) output += `

${sudoSetupHint(grep.commandPath)}`;
				output = appendSearchErrorSummary(output, r.stderr, showErrors, errorLimit);
				return textResult(appendSudoNote(output + captureTruncationNote(r), grep.usedSudo, grep.sudoReason, target, r.remoteTime), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_grep"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.path ?? ".")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_journalctl",
		label: "sshro_journalctl",
		description: "Read recent systemd journal logs from the SSH target with optional unit/time/priority filters.",
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
				if (unit) { validatePathLike(unit, "unit"); args.push("-u", unit); }
				if (since) { validatePathLike(since, "since"); args.push("--since", since); }
				if (until) { validatePathLike(until, "until"); args.push("--until", until); }
				if (priority) { validatePathLike(priority, "priority"); args.push("-p", priority); }
				if (grep) validatePathLike(grep, "grep");
				const journalctl = await chooseCommand(target, "journalctl", args, signal);
				const base = `${journalctl.command} 2>&1`;
				const script = statusPreservingPipeline(base, grep ? `grep -i -- ${shellQuote(grep)} | sed -n '1,${lines}p'` : `sed -n '1,${lines}p'`);
				const r = await sshExec(target, script, signal, 45_000);
				let output = r.stdout + r.stderr;
				if (/not seeing messages from other users and the system/i.test(output) && !journalctl.usedSudo) output += `

${sudoSetupHint(journalctl.commandPath)}`;
				return textResult(appendSudoNote((output.trim().length ? truncateText(output, lines) : "No journal output") + captureTruncationNote(r), journalctl.usedSudo, journalctl.sudoReason, target, r.remoteTime), r.code !== 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_journalctl"))} ${theme.fg("accent", args.unit ?? args.priority ?? "recent")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_systemctl",
		label: "sshro_systemctl",
		description: "Inspect systemd unit state on the SSH target. Supports failed, list, status, and show actions only.",
		parameters: systemctlParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const action = params.action;
				const unit = optionalString(params.unit);
				if ((action === "status" || action === "show") && !unit) throw new Error(`sshro_systemctl action '${action}' requires unit`);
				if (unit) validatePathLike(unit, "unit");
				let args: string[];
				if (action === "failed") args = ["--no-pager", "--plain", "--failed"];
				else if (action === "list") args = ["--no-pager", "--plain", "list-units", "--type=service", "--all"];
				else if (action === "status") args = ["--no-pager", "status", unit!];
				else args = ["show", unit!, "--property=Id,Names,Description,LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainCode,ExecMainStatus,MainPID,FragmentPath,DropInPaths,Requires,Wants,After,Before,Restart,RestartUSec,StartLimitBurst,StartLimitIntervalUSec"];
				const systemctl = await chooseCommand(target, "systemctl", args, signal);
				const r = await sshExec(target, statusPreservingPipeline(`${systemctl.command} 2>&1`, `sed -n '1,${DEFAULT_LINE_LIMIT}p'`), signal, 30_000);
				const output = r.stdout + r.stderr;
				const failed = systemctlFailed(action, r.code);
				return textResult(appendSudoNote(truncateText(output || "No systemctl output") + captureTruncationNote(r), systemctl.usedSudo, systemctl.sudoReason, target, r.remoteTime), failed);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_systemctl"))} ${theme.fg("accent", args.action ?? "...")} ${theme.fg("muted", args.unit ?? "")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_ps",
		label: "sshro_ps",
		description: "Inspect the remote process table with optional user/pattern filtering and cpu/memory sorting.",
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
				const pipelineFilters: string[] = [];
				if (user) pipelineFilters.push(`awk -v u=${shellQuote(user)} 'NR==1 || $3 == u'`);
				if (pattern) pipelineFilters.push(`grep -i -- ${shellQuote(pattern)}`);
				pipelineFilters.push(`sed -n '1,${limit}p'`);
				const script = statusPreservingPipeline(`ps -eo pid,ppid,user,stat,etime,%cpu,%mem,args ${sort} 2>&1`, pipelineFilters.join(" | "));
				const r = await sshExec(target, script, signal, 20_000);
				const output = r.stdout + r.stderr;
				const noMatches = output.trim().length === 0 || psHasOnlyHeader(output);
				const filterLabel = [user ? `user=${user}` : undefined, pattern ? `pattern=${pattern}` : undefined].filter(Boolean).join(" ");
				return textResult(appendRemoteMeta((noMatches ? `No matching processes${filterLabel ? ` for ${filterLabel}` : ""}` : truncateText(output, limit)) + captureTruncationNote(r), target, r.remoteTime), r.code !== 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ps"))} ${theme.fg("accent", args.pattern ?? args.user ?? "processes")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_ss",
		label: "sshro_ss",
		description: "Inspect remote TCP/UDP sockets using ss. Defaults to listening TCP/UDP sockets without process info.",
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
				const script = `command -v ss >/dev/null 2>&1 || { echo 'ss not found on remote host' >&2; exit 127; }; ${statusPreservingPipeline(`ss ${flags} 2>&1`, `sed -n '1,${limit}p'`)}`;
				const r = await sshExec(target, script, signal, 20_000);
				let output = r.stdout + r.stderr;
				if (params.processInfo && output.trim().length > 0) {
					output += output.includes("users:(")
						? "\n[ssh-ro note] processInfo=true was requested; process ownership details may still be partial without elevated privileges.\n"
						: "\n[ssh-ro note] processInfo=true was requested, but no process ownership details were visible. This usually means the SSH user lacks permission to inspect socket owners.\n";
				}
				return textResult(appendRemoteMeta((output.trim().length ? truncateText(output, limit) : "No socket output") + captureTruncationNote(r), target, r.remoteTime), r.code !== 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_ss"))} ${theme.fg("accent", args.listeningOnly === false ? "all sockets" : "listening sockets")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_df",
		label: "sshro_df",
		description: "Inspect remote filesystem free space using df. Defaults to local filesystems only to reduce risk from hanging network mounts.",
		parameters: dfParams,
		executionMode: "parallel",
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const target = await authorizeTarget(params.target, ctx, signal);
				const path = optionalString(params.path);
				const resolvedPath = path ? await canonicalRemotePath(target, path, signal) : undefined;
				const flags = ["-P"];
				if (params.human !== false) flags.push("-h");
				if (params.localOnly !== false) flags.push("-l");
				const script = statusPreservingPipeline(`df ${flags.join(" ")}${resolvedPath ? ` ${shellQuote(resolvedPath)}` : ""} 2>&1`, `sed -n '1,${DEFAULT_LINE_LIMIT}p'`);
				const r = await sshExec(target, script, signal, 15_000);
				const output = r.stdout + r.stderr;
				return textResult(appendRemoteMeta((output.trim().length ? truncateText(output) : "No df output") + captureTruncationNote(r), target, r.remoteTime), r.code !== 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_df"))} ${theme.fg("accent", args.path ?? "filesystems")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_docker_ps",
		label: "sshro_docker_ps",
		description: "List Docker containers on the SSH target using compact Docker table output. Docker is checked at tool runtime.",
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
				if (r.code !== 0) return textResult(appendRemoteMeta(`docker ps failed: ${dockerUnavailableMessage(r.stderr, r.stdout)}`, target, r.remoteTime), true);
				if (hasOnlyHeader(r.stdout)) {
					return textResult(appendRemoteMeta(params.all ? "No Docker containers found." : "No active Docker containers. Use all=true to include stopped/exited containers.", target, r.remoteTime));
				}
				return textResult(appendRemoteMeta(truncateRowsWithHeader(r.stdout, limit, "containers") + captureTruncationNote(r), target, r.remoteTime));
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_ps"))} ${theme.fg("accent", args.name ?? "containers")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_docker_inspect",
		label: "sshro_docker_inspect",
		description: "Inspect a Docker object on the SSH target. Returns curated JSON with environment variables visibly redacted.",
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
				if (r.code !== 0) return textResult(appendRemoteMeta(`docker inspect failed: ${dockerUnavailableMessage(r.stderr, r.stdout)}`, target, r.remoteTime), true);
				requireCompleteCapture(r, "docker inspect");
				try {
					const parsed = JSON.parse(r.stdout);
					const output = curateDockerInspect(Array.isArray(parsed) ? parsed : [parsed]);
					return textResult(appendRemoteMeta(prettyJson(output), target, r.remoteTime));
				} catch (err) {
					return textResult(appendRemoteMeta(`docker inspect JSON output was unparseable: ${err instanceof Error ? err.message : String(err)}\n\n${truncateText(r.stdout + r.stderr)}`, target, r.remoteTime), true);
				}
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_inspect"))} ${theme.fg("accent", args.object ?? "...")} ${theme.fg("muted", args.target ?? "")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_docker_stats",
		label: "sshro_docker_stats",
		description: "Show one-shot Docker container stats on the SSH target as JSON where Docker supports it. Never streams.",
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
				if (r.code !== 0) return textResult(appendRemoteMeta(`docker stats failed: ${dockerUnavailableMessage(r.stderr, r.stdout)}`, target, r.remoteTime), true);
				requireCompleteCapture(r, "docker stats");
				try {
					const rows = parseNdjson(r.stdout);
					return textResult(appendRemoteMeta(prettyJsonRows(rows, limit, "stat rows"), target, r.remoteTime));
				} catch (err) {
					return textResult(appendRemoteMeta(`docker stats JSON output was unavailable or unparseable: ${err instanceof Error ? err.message : String(err)}\n\n${truncateText(r.stdout + r.stderr)}`, target, r.remoteTime), true);
				}
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_docker_stats"))} ${theme.fg("accent", args.container ?? "containers")}`, 0, 0);
		},
	});

	registerInspectionTool({
		name: "sshro_dig",
		label: "sshro_dig",
		description: "Run a bounded read-only DNS lookup from the SSH target using dig. dig is checked at tool runtime.",
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
				return textResult(appendRemoteMeta((output.trim().length ? truncateText(output, 500) : "No DNS answer") + captureTruncationNote(r), target, r.remoteTime), r.code !== 0);
			} catch (err) {
				return errorResult(err);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_dig"))} ${theme.fg("accent", args.name ?? "...")}`, 0, 0);
		},
	});

	controller.setInspectionToolNames(inspectionToolNames);
	return inspectionToolNames;
}

type PersistedApprovalState = { version: 1; targets: string[]; toolsActive: boolean; writeTargets: string[] };

function approvalSnapshot(controller: SshRoController): PersistedApprovalState {
	return {
		version: 1,
		targets: controller.approved(),
		writeTargets: controller.writeTargets(),
		toolsActive: controller.inspectionToolsActive(),
	};
}

function latestPersistedApprovalState(ctx: ExtensionContext): PersistedApprovalState | undefined {
	const entries = ctx.sessionManager.getEntries();
	for (let index = entries.length - 1; index >= 0; index--) {
		const entry = entries[index] as { type?: string; customType?: string; data?: unknown };
		if (entry.type !== "custom" || entry.customType !== SSHRO_APPROVAL_STATE_ENTRY || !entry.data || typeof entry.data !== "object") continue;
		const data = entry.data as { version?: unknown; targets?: unknown; toolsActive?: unknown; writeTargets?: unknown };
		if (data.version !== undefined && data.version !== 1) continue;
		if (!Array.isArray(data.targets) || !data.targets.every((target) => typeof target === "string")) continue;
		const writeTargets = data.writeTargets ?? [];
		if (!Array.isArray(writeTargets) || !writeTargets.every((target) => typeof target === "string")) return undefined;
		return { version: 1, targets: data.targets, toolsActive: data.toolsActive === true, writeTargets };
	}
	return undefined;
}

function activationSummary(report: ActivationReport): string {
	const loaded = report.added.length > 0 ? `${report.added.length} inspection tools loaded` : `${report.active.length} inspection tools active`;
	return report.blocked.length > 0 ? `${loaded}; ${report.blocked.length} blocked by Pi tool policy` : loaded;
}

function updateStatus(controller: SshRoController, ctx: ExtensionContext): void {
	if (!ctx.hasUI) return;
	const writeTargets = controller.writeTargets();
	if (writeTargets.length > 0) {
		ctx.ui.setStatus(SSHRO_STATUS_KEY, ctx.ui.theme.fg("warning", `⚠ SSH WRITE: ${writeTargets.join(", ")}`));
		return;
	}
	const approved = controller.approved();
	const toolCount = controller.activeInspectionToolNames().length;
	if (approved.length === 0 && toolCount === 0) {
		ctx.ui.setStatus(SSHRO_STATUS_KEY, undefined);
		return;
	}
	const targetLabel = approved.length === 1 ? approved[0] : approved.length > 1 ? `${approved.length} approved` : "whitelist";
	ctx.ui.setStatus(SSHRO_STATUS_KEY, ctx.ui.theme.fg("accent", `SSH RO: ${targetLabel} · ${toolCount} tools`));
}

export type SshReadonlyExtensionOptions = {
	sshExecutor?: SshExecutor;
};

export default function sshReadonlyExtension(pi: ExtensionAPI, options: SshReadonlyExtensionOptions = {}) {
	const executeSsh = options.sshExecutor ?? sshExec;
	let controller!: SshRoController;
	let lastPersistedSnapshot: string | undefined;
	const persistState = () => {
		const snapshot = approvalSnapshot(controller);
		const serialized = JSON.stringify(snapshot);
		if (serialized === lastPersistedSnapshot) return;
		pi.appendEntry(SSHRO_APPROVAL_STATE_ENTRY, snapshot);
		lastPersistedSnapshot = serialized;
	};
	controller = new SshRoController({
		pi,
		whitelistedTargets: whitelistedHosts,
		validateTarget,
	});
	let suggestedTargets = [...whitelistedHosts()].sort();

	pi.registerFlag("ssh-ro", {
		type: "string",
		description: "Pre-approve an exact SSH target and load stateless sshro_* inspection tools, e.g. pi --ssh-ro user@server",
	});

	registerSshRoTools(pi, controller, executeSsh, (ctx) => {
		persistState();
		updateStatus(controller, ctx);
	});

	const syncWriteTool = () => {
		const active = pi.getActiveTools().filter((name) => name !== "ssh_exec");
		if (controller.writeTargets().length > 0) active.push("ssh_exec");
		pi.setActiveTools(active);
	};

	pi.registerTool({
		name: "ssh_exec",
		label: "SSH unrestricted execution",
		description: "Execute arbitrary POSIX shell commands on an exact target granted write access by the human via /sshro allow-write. No read-only path restrictions or secret redaction. Unapproved targets fail without prompting. Non-interactive; commands start in the remote login directory. Output is bounded to 2,000 lines/50KB. Revocation, cancellation and timeout do not undo changes or guarantee remote processes stop.",
		parameters: Type.Object({
			target: Type.String({ description: "Exact target string granted by the human; aliases and other users are separate targets." }),
			command: Type.String({ minLength: 1, description: "Arbitrary remote POSIX shell script. Use heredocs to write files; no interactive stdin or TTY." }),
			timeout: Type.Optional(Type.Integer({ minimum: 1, maximum: 3600, description: "Timeout in seconds (default 120, maximum 3600)." })),
		}),
		executionMode: "sequential",
		async execute(_id, params, signal) {
			const target = controller.requireWriteTarget(params.target);
			if (!params.command.trim() || params.command.includes("\0")) throw new Error("command must be nonempty and contain no NUL bytes");
			const timeout = params.timeout ?? 120;
			if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600) throw new Error("timeout must be an integer from 1 to 3600 seconds");
			// Quote the script as a separate shell argument so comments, heredocs and
			// exit cannot consume or bypass the transport's status/time wrapper.
			const result = await executeSsh(target, `sh -c ${shellQuote(params.command)}`, signal, timeout * 1000);
			const output = truncateText(result.stdout + (result.stderr ? `\n[stderr]\n${result.stderr}` : "")) + captureTruncationNote(result);
			return textResult(`${output}\n\n[ssh WRITE: ${target} | exit: ${result.code ?? "unknown"}${result.remoteTime ? ` | remote time: ${result.remoteTime}` : ""}]`, result.code !== 0);
		},
		renderCall(args, theme) {
			const title = theme.fg("toolTitle", theme.bold("ssh_exec"));
			const target = theme.fg("accent", args.target ?? "...");
			const timeout = args.timeout === undefined ? "" : theme.fg("dim", ` · timeout ${args.timeout}s`);
			return new Text(`${title} ${target}${timeout}\n${theme.fg("muted", args.command ?? "...")}`, 0, 0);
		},
	});

	pi.on("before_agent_start", () => {
		const targets = controller.writeTargets();
		if (targets.length === 0) return;
		return { message: { customType: "sshro-write-access", content: `Current session unrestricted SSH grants (use ssh_exec with the exact target): ${targets.join(", ")}. All sshro_* tools remain read-only.`, display: false } };
	});

	pi.registerCommand("sshro", {
		description: "Approve a read-only target, allow-write/revoke-write <target>, status, or logout",
		getArgumentCompletions: (prefix) => {
			const values = ["status", "logout", "allow-write ", "revoke-write ", ...suggestedTargets,
				...suggestedTargets.map((target) => `allow-write ${target}`),
				...controller.writeTargets().map((target) => `revoke-write ${target}`)];
			const matches = [...new Set(values)]
				.filter((value) => value.startsWith(prefix))
				.map((value) => ({ value, label: value, description: value === "status" ? "Show SSH approvals and write grants" : value === "logout" ? "Clear all approvals and unload SSH tools" : value.startsWith("allow-write ") ? "Grant unrestricted execution after confirmation" : value.startsWith("revoke-write ") ? "Revoke unrestricted execution" : "Approve this exact read-only target" }));
			return matches.length > 0 ? matches : null;
		},
		handler: async (args, ctx) => {
			let value = (args ?? "").trim();
			const writeCommand = /^(allow-write|revoke-write)(?:\s+(.*))?$/.exec(value);
			if (writeCommand) {
				try {
					if (!writeCommand[2]) throw new Error(`Usage: /sshro ${writeCommand[1]} <target>`);
					const granting = writeCommand[1] === "allow-write";
					const target = granting
						? await controller.allowWriteHumanInitiated(writeCommand[2], ctx)
						: controller.revokeWrite(writeCommand[2]);
					syncWriteTool();
					persistState();
					updateStatus(controller, ctx);
					ctx.ui.notify(granting
						? `Unrestricted SSH access granted: ${target}. ${pi.getActiveTools().includes("ssh_exec") ? "ssh_exec enabled." : "ssh_exec is blocked by Pi tool policy."}`
						: `Write access revoked: ${target}. Already-started remote processes may continue; changes are not undone.`, "warning");
				} catch (err) {
					ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
				}
				return;
			}
			if (value === "status") {
				const approved = controller.approved();
				const available = controller.availableTargets();
				const shownAvailable = available.slice(0, MAX_DISCOVERED_TARGETS);
				const omittedAvailable = available.length - shownAvailable.length;
				const active = controller.activeInspectionToolNames();
				ctx.ui.notify([
					`SSH read-only inspection tools: ${active.length}/${controller.inspectionToolNames().length} active`,
					`Unrestricted write targets: ${controller.writeTargets().join(", ") || "none"} (ssh_exec ${pi.getActiveTools().includes("ssh_exec") ? "active" : "inactive"})`,
					`Session-approved targets: ${approved.length > 0 ? approved.join(", ") : "none"}`,
					`Available exact targets (approved or whitelisted): ${shownAvailable.length > 0 ? shownAvailable.join(", ") : "none"}${omittedAvailable > 0 ? ` … (${omittedAvailable} more omitted)` : ""}`,
				].join("\n"), "info");
				return;
			}
			if (value === "logout") {
				controller.clearApprovals({ emit: false });
				controller.clearCaches();
				controller.deactivateInspectionTools();
				syncWriteTool();
				persistState();
				updateStatus(controller, ctx);
				ctx.ui.notify("SSH session approvals and write grants cleared; SSH tools unloaded", "info");
				return;
			}
			if (!value) {
				if (!ctx.hasUI) {
					ctx.ui.notify("Usage: /sshro <target> | allow-write <target> | revoke-write <target> | status | logout", "info");
					return;
				}
				const choices = [...new Set([...whitelistedHosts(), ...suggestedTargets])].sort().slice(0, MAX_DISCOVERED_TARGETS);
				if (choices.length === 0) {
					ctx.ui.notify("No literal SSH aliases or whitelist targets were discovered. Use /sshro user@host.", "info");
					return;
				}
				const selected = await ctx.ui.select("Approve an exact SSH read-only target", choices);
				if (!selected) return;
				value = selected;
			}
			try {
				const target = controller.approveHumanInitiated(value);
				const activation = controller.activateInspectionTools();
				persistState();
				updateStatus(controller, ctx);
				ctx.ui.notify(`SSH read-only target approved: ${target}\n${activationSummary(activation)}`, activation.blocked.length > 0 ? "warning" : "info");
			} catch (err) {
				ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
			}
		},
	});

	pi.on("session_start", async (event, ctx) => {
		controller.clearCaches();
		controller.deactivateInspectionTools();
		lastPersistedSnapshot = undefined;
		if (event.reason === "reload") {
			const persisted = latestPersistedApprovalState(ctx);
			try {
				controller.restoreApprovals(persisted?.targets ?? []);
				controller.restoreWriteTargets(persisted?.writeTargets ?? []);
				if (persisted?.toolsActive) controller.activateInspectionTools();
				lastPersistedSnapshot = JSON.stringify(approvalSnapshot(controller));
			} catch {
				controller.clearApprovals({ emit: false });
				persistState();
				ctx.ui.notify("Ignored invalid persisted SSH read-only approval state", "warning");
			}
		} else {
			controller.clearApprovals({ emit: false });
			persistState();
		}

		syncWriteTool();
		const rejectedWhitelistEntries = whitelistConfig().rejected;
		if (rejectedWhitelistEntries > 0) {
			ctx.ui.notify(`${rejectedWhitelistEntries} invalid SSHRO_HOST_WHITELIST ${rejectedWhitelistEntries === 1 ? "entry was" : "entries were"} ignored`, "warning");
		}

		const raw = event.reason === "startup" ? pi.getFlag("ssh-ro") : undefined;
		if (typeof raw === "string" && raw.trim().length > 0) {
			try {
				const target = controller.approveHumanInitiated(raw);
				const activation = controller.activateInspectionTools();
				persistState();
				ctx.ui.notify(`SSH read-only target approved: ${target}\n${activationSummary(activation)}`, activation.blocked.length > 0 ? "warning" : "info");
			} catch (err) {
				ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
			}
		}
		const aliases = await discoverSshConfigAliases().catch(() => []);
		suggestedTargets = [...new Set([...whitelistedHosts(), ...aliases.slice(0, MAX_DISCOVERED_TARGETS)])].sort();
		updateStatus(controller, ctx);
	});

	pi.on("session_shutdown", (_event, ctx) => {
		controller.clearApprovals({ emit: false });
		controller.clearCaches();
		if (ctx.hasUI) ctx.ui.setStatus(SSHRO_STATUS_KEY, undefined);
	});

	pi.on("tool_call", (event) => {
		if (event.toolName !== "bash") return;
		const command = typeof (event.input as { command?: unknown }).command === "string" ? (event.input as { command: string }).command : "";
		const reason = bashSshBlockReason(command);
		if (reason) return { block: true, reason };
	});
}
