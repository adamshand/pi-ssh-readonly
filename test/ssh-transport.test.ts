import assert from "node:assert/strict";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { boundedReadFailed } from "../src/exit-policy.ts";
import { statusPreservingPipeline } from "../src/ssh-output.ts";
import { buildSshArgs, createSshExecutor, shellQuote } from "../src/ssh-transport.ts";

async function fakeSshBinary(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), "sshro-transport-"));
	const binary = join(dir, "fake-ssh.cjs");
	await writeFile(binary, `#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
if (process.env.FAKE_SSH_MODE === "transport-failure") {
  process.stderr.write("connection refused\\n");
  process.exit(255);
}
if (process.env.FAKE_SSH_MODE === "hang") setInterval(() => {}, 1000);
else {
  const command = process.argv.at(-1);
  const result = spawnSync("/bin/sh", ["-c", command], { stdio: "inherit" });
  process.exit(result.status ?? 1);
}
`);
	await chmod(binary, 0o755);
	return binary;
}

test("SSH argv terminates options before the exact target", () => {
	const args = buildSshArgs("user@prod", "printf ok");
	const delimiter = args.indexOf("--");
	assert.ok(delimiter >= 0);
	assert.equal(args[delimiter + 1], "user@prod");
	assert.match(args[delimiter + 2], /^sh -c /);
});

test("executor distinguishes transport failure from completed remote execution", async () => {
	const binary = await fakeSshBinary();
	const execute = createSshExecutor({ binary });
	const previous = process.env.FAKE_SSH_MODE;
	try {
		process.env.FAKE_SSH_MODE = "transport-failure";
		const failed = await execute("prod", "printf never");
		assert.equal(failed.code, 255);
		assert.equal(failed.remoteTime, undefined);
		assert.match(failed.stderr, /connection refused/);

		delete process.env.FAKE_SSH_MODE;
		const completed = await execute("prod", "printf ok");
		assert.equal(completed.code, 0);
		assert.equal(completed.stdout, "ok");
		assert.ok(completed.remoteTime);
	} finally {
		if (previous === undefined) delete process.env.FAKE_SSH_MODE;
		else process.env.FAKE_SSH_MODE = previous;
	}
});

test("intentional SIGPIPE from a bounded large-file read is accepted", async () => {
	const dir = await mkdtemp(join(tmpdir(), "sshro-large-read-"));
	const file = join(dir, "large.txt");
	await writeFile(file, "line\n".repeat(200_000));
	const execute = createSshExecutor({ binary: await fakeSshBinary() });
	const result = await execute("prod", statusPreservingPipeline(`cat -- ${shellQuote(file)}`, "head -n 10"));
	assert.equal(result.code, 141);
	assert.equal(boundedReadFailed(result.code), false);
	assert.equal(result.stdout, "line\n".repeat(10));
});

test("executor enforces timeout", async () => {
	const execute = createSshExecutor({ binary: await fakeSshBinary() });
	const previous = process.env.FAKE_SSH_MODE;
	try {
		process.env.FAKE_SSH_MODE = "hang";
		await assert.rejects(execute("prod", "printf never", undefined, 20), /timed out/);
	} finally {
		if (previous === undefined) delete process.env.FAKE_SSH_MODE;
		else process.env.FAKE_SSH_MODE = previous;
	}
});
