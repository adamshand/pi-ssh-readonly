import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import { BoundedCapture, parseRemoteStderr, REMOTE_TIME_MARKER } from "./ssh-output.ts";

export const DEFAULT_SSH_TIMEOUT_MS = 30_000;
export const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const KILL_GRACE_MS = 2_000;

export type SshExecResult = {
	stdout: string;
	stderr: string;
	code: number | null;
	remoteTime?: string;
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
	return spawn(binary, [...args], { stdio: ["ignore", "pipe", "pipe"] });
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
		let timedOut = false;
		let settled = false;
		let killTimer: NodeJS.Timeout | undefined;

		const terminate = () => {
			child.kill("SIGTERM");
			killTimer ??= setTimeout(() => child.kill("SIGKILL"), KILL_GRACE_MS);
			killTimer.unref?.();
		};
		const timer = setTimeout(() => {
			timedOut = true;
			terminate();
		}, timeoutMs);
		timer.unref?.();
		const onAbort = () => terminate();
		signal?.addEventListener("abort", onAbort, { once: true });

		const cleanup = () => {
			clearTimeout(timer);
			if (killTimer) clearTimeout(killTimer);
			signal?.removeEventListener("abort", onAbort);
		};
		const rejectOnce = (error: unknown) => {
			if (settled) return;
			settled = true;
			cleanup();
			reject(error);
		};

		child.stdout.on("data", (data) => stdout.push(data));
		child.stderr.on("data", (data) => stderr.push(data));
		child.on("error", rejectOnce);
		child.on("close", (code) => {
			if (settled) return;
			settled = true;
			cleanup();
			if (signal?.aborted) {
				reject(new Error("SSH command aborted"));
				return;
			}
			if (timedOut) {
				reject(new Error(`SSH command timed out after ${timeoutMs / 1000}s`));
				return;
			}
			const parsed = parseRemoteStderr(stderr.toString(), code);
			resolve({
				stdout: stdout.toString(),
				stderr: parsed.stderr,
				remoteTime: parsed.remoteTime,
				code: parsed.code,
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
	return streams.length > 0 ? `\n\n[ssh-ro ${streams.join(" and ")} capture truncated at ${MAX_CAPTURE_BYTES} bytes per stream]` : "";
}

export function requireCompleteCapture(result: SshExecResult, operation: string): void {
	if (result.stdoutTruncated || result.stderrTruncated) {
		throw new Error(`${operation} output exceeded the ${MAX_CAPTURE_BYTES}-byte per-stream capture limit`);
	}
}
