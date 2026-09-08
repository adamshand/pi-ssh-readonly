import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import { BoundedCapture, parseRemoteStderr, REMOTE_TIME_MARKER, type ParsedRemoteStderr } from "./ssh-output.ts";

export const DEFAULT_SSH_TIMEOUT_MS = 30_000;
export const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;

export type SshExecResult = ParsedRemoteStderr & {
	stdout: string;
	stdoutTruncated: boolean;
	stderrTruncated: boolean;
};

export type SshExecutor = (target: string, command: string, signal?: AbortSignal, timeoutMs?: number) => Promise<SshExecResult>;

type SshChild = ChildProcessByStdio<null, Readable, Readable>;
type SpawnSsh = (binary: string, args: readonly string[]) => SshChild;

export function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

export function buildSshArgs(target: string, command: string): string[] {
	// Force POSIX sh for fixed remote templates. The option terminator is defense
	// in depth; target validation independently rejects option-shaped values.
	const wrapped = `( ${command} ); __pi_sshro_rc=$?; printf '\n${REMOTE_TIME_MARKER}%s\n' "$(date -Is 2>/dev/null || date)" >&2; exit "$__pi_sshro_rc"`;
	const remoteCommand = `sh -c ${shellQuote(wrapped)}`;
	return [
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=10",
		"--",
		target,
		remoteCommand,
	];
}

function defaultSpawn(binary: string, args: readonly string[]): SshChild {
	return spawn(binary, [...args], { stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
}

export function createSshExecutor(options: { binary?: string; spawnSsh?: SpawnSsh } = {}): SshExecutor {
	const binary = options.binary ?? "ssh";
	const spawnSsh = options.spawnSsh ?? defaultSpawn;
	return (target, command, signal, timeoutMs = DEFAULT_SSH_TIMEOUT_MS) => new Promise((resolve, reject) => {
		if (signal?.aborted) {
			reject(new Error("SSH command aborted"));
			return;
		}

		let child: SshChild;
		try {
			child = spawnSsh(binary, buildSshArgs(target, command));
		} catch (error) {
			reject(error);
			return;
		}

		const stdout = new BoundedCapture(MAX_CAPTURE_BYTES);
		const stderr = new BoundedCapture(MAX_CAPTURE_BYTES);
		let settled = false;
		let timer: NodeJS.Timeout | undefined;
		const onAbort = () => rejectOnce(new Error("SSH command aborted"));
		const cleanup = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
		};
		const rejectOnce = (error: unknown) => {
			if (settled) return;
			settled = true;
			cleanup();
			// Own a process group for the default POSIX transport, so local SSH
			// helpers die too. Never wait for inherited pipes to close: even an
			// escaped descendant cannot hold this Promise past its deadline.
			try {
				if (!options.spawnSsh && process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL");
				else child.kill("SIGKILL");
			} catch { child.kill("SIGKILL"); }
			child.stdout.destroy();
			child.stderr.destroy();
			reject(error);
		};

		child.stdout.on("data", (data) => stdout.push(data));
		child.stderr.on("data", (data) => stderr.push(data));
		child.on("error", rejectOnce);
		child.stdout.on("error", rejectOnce);
		child.stderr.on("error", rejectOnce);
		timer = setTimeout(() => rejectOnce(new Error(`SSH command timed out after ${timeoutMs / 1000}s`)), timeoutMs);
		timer.unref?.();
		signal?.addEventListener("abort", onAbort, { once: true });
		if (signal?.aborted) onAbort();
		child.on("close", (code) => {
			if (settled) return;
			settled = true;
			cleanup();
			resolve({
				...parseRemoteStderr(stderr.toString(), code),
				stdout: stdout.toString(),
				stdoutTruncated: stdout.truncated,
				stderrTruncated: stderr.truncated,
			});
		});
	});
}

export const sshExec = createSshExecutor();

export function requireRemoteExecution(result: SshExecResult, operation: string): void {
	if (result.remoteTime !== undefined) return;
	const diagnostics = (result.stderr || result.stdout).trim() || "no diagnostics";
	throw new Error(`${operation} did not reach the remote command wrapper (SSH exit ${result.code ?? "unknown"}): ${diagnostics}`);
}

export function captureTruncationNote(result: SshExecResult): string {
	const streams = [result.stdoutTruncated ? "stdout" : undefined, result.stderrTruncated ? "stderr" : undefined].filter(Boolean);
	const capture = streams.length > 0 ? `\n\n[ssh-ro ${streams.join(" and ")} capture truncated at ${MAX_CAPTURE_BYTES} bytes per stream]` : "";
	const rows = result.remoteTruncation;
	return capture + (rows ? `\n\n[ssh-ro output truncated: showing ${rows.shown} of ${rows.total} lines]` : "");
}

export function requireCompleteCapture(result: SshExecResult, operation: string): void {
	if (result.stdoutTruncated || result.stderrTruncated) {
		throw new Error(`${operation} output exceeded the ${MAX_CAPTURE_BYTES}-byte per-stream capture limit`);
	}
}
