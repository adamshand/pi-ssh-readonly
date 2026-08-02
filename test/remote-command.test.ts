import assert from "node:assert/strict";
import test from "node:test";
import { resolveRemoteCommandCached } from "../src/remote-command.ts";
import type { SshExecResult, SshExecutor } from "../src/ssh-transport.ts";

function result(overrides: Partial<SshExecResult>): SshExecResult {
	return {
		stdout: "",
		stderr: "",
		code: 0,
		remoteTime: "2026-08-02T00:00:00Z",
		stdoutTruncated: false,
		stderrTruncated: false,
		...overrides,
	};
}

function cacheHarness() {
	const values = new Map<string, string | undefined>();
	return {
		getCachedRemoteCommand: (key: string) => values.has(key)
			? { found: true, value: values.get(key) }
			: { found: false, value: undefined },
		cacheRemoteCommand: (key: string, value: string | undefined) => { values.set(key, value); },
	};
}

test("transport failures are not cached as missing remote commands", async () => {
	const cache = cacheHarness();
	let calls = 0;
	const execute: SshExecutor = async () => {
		calls++;
		return calls === 1
			? result({ code: 255, remoteTime: undefined, stderr: "connection refused" })
			: result({ stdout: "/usr/bin/cat\n" });
	};

	await assert.rejects(resolveRemoteCommandCached(cache, execute, "prod", "cat"), /did not reach the remote command wrapper/);
	assert.equal(await resolveRemoteCommandCached(cache, execute, "prod", "cat"), "/usr/bin/cat");
	assert.equal(await resolveRemoteCommandCached(cache, execute, "prod", "cat"), "/usr/bin/cat");
	assert.equal(calls, 2, "successful lookup should cache, transport failure should not");
});

test("completed command absence is cached", async () => {
	const cache = cacheHarness();
	let calls = 0;
	const execute: SshExecutor = async () => {
		calls++;
		return result({});
	};
	assert.equal(await resolveRemoteCommandCached(cache, execute, "prod", "missing"), undefined);
	assert.equal(await resolveRemoteCommandCached(cache, execute, "prod", "missing"), undefined);
	assert.equal(calls, 1);
});
