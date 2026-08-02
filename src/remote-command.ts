import {
	requireCompleteCapture,
	requireRemoteExecution,
	shellQuote,
	type SshExecutor,
} from "./ssh-transport.ts";

export type RemoteCommandCache = {
	getCachedRemoteCommand(key: string): { found: boolean; value: string | undefined };
	cacheRemoteCommand(key: string, value: string | undefined): void;
};

/** Resolve a fixed remote command, caching only completed remote lookups. */
export async function resolveRemoteCommandCached(
	cache: RemoteCommandCache,
	execute: SshExecutor,
	target: string,
	command: string,
	signal?: AbortSignal,
): Promise<string | undefined> {
	const key = `${target}\0${command}`;
	const cached = cache.getCachedRemoteCommand(key);
	if (cached.found) return cached.value;

	const result = await execute(target, `command -v ${shellQuote(command)} 2>/dev/null || true`, signal, 10_000);
	requireCompleteCapture(result, `command -v ${command}`);
	requireRemoteExecution(result, `command -v ${command}`);
	if (result.code !== 0) throw new Error(`command -v ${command} failed with exit ${result.code}`);

	const resolved = result.stdout.trim().split(/\r?\n/).find(Boolean);
	cache.cacheRemoteCommand(key, resolved);
	return resolved;
}
