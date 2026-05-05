import { spawn } from "node:child_process";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { createFindTool, createGrepTool, createLsTool, createReadTool } from "@mariozechner/pi-coding-agent";
import { Text } from "@mariozechner/pi-tui";

type SshRoState =
	| { active: false; fatal?: undefined }
	| { active: true; target: string; remoteCwd: string; fatal: false }
	| { active: true; target: string; remoteCwd?: string; fatal: true; reason: string };

const TOOL_NAMES = ["sshro_read", "sshro_ls", "sshro_find", "sshro_grep"] as const;
const REQUIRED_REMOTE_COMMANDS = ["file", "find", "grep", "sed", "stat", "ls"];
const DEFAULT_LINE_LIMIT = 2000;
const DEFAULT_BYTE_LIMIT = 50 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const DENIED_DIR_NAMES = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".terraform", ".terraform.d", ".cloudflared", ".cloudflare", ".password-store"];
const DENIED_PATH_PARTS = ["/.config/gcloud", "/.config/gh", "/.gem/credentials", "/.cargo/credentials"];
const DENIED_FILE_NAMES = [".env", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials", "terraform.tfstate"];
const DENIED_FILE_SUFFIXES = [".pem", ".key", ".p12", ".pfx"];
const DENIED_FILE_PREFIXES = [".env.", "terraform.tfstate."];

let state: SshRoState = { active: false };
let toolsRegistered = false;

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

function findDenyExpression(): string {
	const dirPrunes = [...DENIED_DIR_NAMES, ".git", "node_modules"].map((name) => `-name ${shellQuote(name)}`).join(" -o ");
	const pathPrunes = DENIED_PATH_PARTS.map((part) => `-path ${shellQuote(`*${part}`)}`).join(" -o ");
	const allPrunes = [dirPrunes, pathPrunes].filter(Boolean).join(" -o ");
	return `\\( ${allPrunes} \\) -prune -o `;
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
			["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target, remoteCommand],
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
	const readParams = createReadTool(cwd).parameters;
	const lsParams = createLsTool(cwd).parameters;
	const findParams = createFindTool(cwd).parameters;
	const grepParams = createGrepTool(cwd).parameters;

	pi.registerTool({
		name: "sshro_read",
		label: "sshro_read",
		description: "Read a text file from the SSH Read-only Mode target. Supports path, offset, and limit. Binary/non-text files are refused.",
		promptSnippet: "sshro_read: Read a text file from the SSH Read-only Mode target with optional line offset/limit.",
		parameters: readParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
				const p = remotePath(params.path, remoteCwd);
				assertPathAllowed(p);
				const offset = Math.max(1, Math.floor(params.offset ?? 1));
				const limit = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.limit ?? DEFAULT_LINE_LIMIT)));
				const end = offset + limit - 1;
				const q = shellQuote(p);
				const script = `p=${q}; if [ ! -e "$p" ]; then echo "not found: $p" >&2; exit 2; fi; if [ ! -f "$p" ]; then echo "not a regular file: $p" >&2; exit 2; fi; if [ ! -r "$p" ]; then echo "not readable: $p" >&2; exit 2; fi; mt=$(file --mime-type -b "$p" 2>/dev/null || true); case "$mt" in text/*|inode/x-empty|application/json|application/xml|application/x-shellscript|application/x-perl|application/x-python|application/javascript|application/x-yaml) ;; *) echo "refusing non-text file ($mt): $p" >&2; exit 3;; esac; printf 'path: %s\\nmime: %s\\nlines: %s-%s\\n---\\n' "$p" "$mt" ${offset} ${end}; sed -n '${offset},${end}p' "$p"`;
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
				const combined = `${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}`;
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
				const limit = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.limit ?? 500)));
				const pathPattern = params.pattern.includes("/") && !params.pattern.startsWith("/") ? `*/${params.pattern}` : params.pattern;
				const pred = params.pattern.includes("/") ? `-path ${shellQuote(pathPattern)}` : `-name ${shellQuote(params.pattern)}`;
				assertPathAllowed(base);
				const shouldPrune = !base.includes("/.git") && !base.includes("/node_modules") && !denyReasonForPath(`${base}/placeholder`);
				const prune = shouldPrune ? findDenyExpression() : "";
				const fileDeny = findFileDenyPredicates();
				const script = `find ${shellQuote(base)} ${prune}${pred} ${fileDeny} -print 2>&1 | sed -n '1,${limit}p'`;
				const r = await sshExec(target, script, signal, 45_000);
				return textResult(truncateText(r.stdout + r.stderr, limit), r.code !== 0 && r.stdout.trim().length === 0);
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
		description: "Search remote files on the SSH Read-only Mode target. Recursive for directories, skips binary files, supports glob, ignoreCase, literal, context, and limit.",
		promptSnippet: "sshro_grep: Search text files on the SSH Read-only Mode target; recursive directory searches prune .git and node_modules by default.",
		parameters: grepParams,
		executionMode: "parallel",
		async execute(_id, params, signal) {
			try {
				const { target, remoteCwd } = requireHealthy();
				validatePathLike(params.pattern, "pattern");
				if (params.glob) validatePathLike(params.glob, "glob");
				const base = remotePath(params.path, remoteCwd);
				const limit = Math.max(1, Math.min(DEFAULT_LINE_LIMIT, Math.floor(params.limit ?? 500)));
				const opts = ["-nH", "-I"];
				if (params.ignoreCase) opts.push("-i");
				if (params.literal) opts.push("-F");
				if (params.context !== undefined) opts.push("-C", String(Math.max(0, Math.min(20, Math.floor(params.context)))));
				const globPred = params.glob ? ` -name ${shellQuote(params.glob)}` : "";
				assertPathAllowed(base);
				const shouldPrune = !base.includes("/.git") && !base.includes("/node_modules") && !denyReasonForPath(`${base}/placeholder`);
				const prune = shouldPrune ? findDenyExpression() : "";
				const fileDeny = findFileDenyPredicates();
				const script = `if [ -d ${shellQuote(base)} ]; then find ${shellQuote(base)} ${prune}-type f ${fileDeny}${globPred} -exec grep ${opts.join(" ")} -- ${shellQuote(params.pattern)} {} + 2>&1 | sed -n '1,${limit}p'; else grep ${opts.join(" ")} -- ${shellQuote(params.pattern)} ${shellQuote(base)} 2>&1 | sed -n '1,${limit}p'; fi`;
				const r = await sshExec(target, script, signal, 60_000);
				const output = r.stdout + r.stderr;
				return textResult(output.trim().length ? truncateText(output, limit) : "No matches");
			} catch (err) {
				return textResult(err instanceof Error ? err.message : String(err), true);
			}
		},
		renderCall(args, theme) {
			return new Text(`${theme.fg("toolTitle", theme.bold("sshro_grep"))} ${theme.fg("accent", args.pattern ?? "...")} ${theme.fg("muted", args.path ?? ".")}`, 0, 0);
		},
	});
}

function failClosed(pi: ExtensionAPI, ctx: ExtensionContext, target: string, reason: string): void {
	state = { active: true, target, fatal: true, reason };
	pi.setActiveTools([]);
	ctx.ui.setStatus("ssh-ro", ctx.ui.theme.fg("error", `SSH RO failed: ${target}`));
	ctx.ui.notify(`SSH Read-only Mode startup failed for ${target}: ${reason}`, "error");
}

export default function sshReadonlyExtension(pi: ExtensionAPI) {
	pi.registerFlag("ssh-ro", {
		type: "string",
		description: "Start SSH Read-only Mode against an SSH target, e.g. pi --ssh-ro user@server",
	});

	pi.on("session_start", async (_event, ctx) => {
		const raw = pi.getFlag("ssh-ro");
		if (typeof raw !== "string" || raw.length === 0) {
			state = { active: false };
			return;
		}

		try {
			const target = raw.trim();
			validateTarget(target);
			registerSshRoTools(pi);
			const remoteCwd = await startupCheck(target);
			state = { active: true, target, remoteCwd, fatal: false };
			pi.setActiveTools([...TOOL_NAMES]);
			ctx.ui.setStatus("ssh-ro", ctx.ui.theme.fg("accent", `SSH RO ${target}:${remoteCwd}`));
			ctx.ui.notify(`SSH Read-only Mode: ${target}:${remoteCwd}`, "info");
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
		systemPrompt += `\n\nSSH Read-only Mode is active for ${state.target}. Remote working directory: ${state.remoteCwd}. Paths are resolved on the remote host; relative paths resolve from that remote working directory. The sshro_read, sshro_ls, sshro_find, and sshro_grep tools operate on the remote host. Tilde expansion is not supported. The tools apply best-effort credential guardrails: common credential directories/files are blocked for direct access, and recursive sshro_find and sshro_grep prune .git, node_modules, and common credential paths.\n`;
		return { systemPrompt };
	});
}
