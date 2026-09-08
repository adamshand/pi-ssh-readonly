import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { boundedReadFailed } from "../src/exit-policy.ts";
import { boundedLineFilter, statusPreservingPipeline } from "../src/ssh-output.ts";
import { buildSshArgs, captureTruncationNote, createSshExecutor, shellQuote } from "../src/ssh-transport.ts";
import { localSshFixture } from "./helpers/local-ssh.ts";

test("SSH argv terminates options before the exact target", () => {
	const args = buildSshArgs("user@prod", "printf ok");
	const delimiter = args.indexOf("--");
	assert.ok(delimiter >= 0);
	assert.equal(args[delimiter + 1], "user@prod");
	assert.match(args[delimiter + 2], /^sh -c /);
});

test("executor distinguishes transport failure from completed remote execution", async (t) => {
	const unavailable = await localSshFixture("transport-failure");
	t.after(unavailable.close);
	const failed = await unavailable.execute("prod", "printf never");
	assert.equal(failed.code, 255);
	assert.equal(failed.remoteTime, undefined);
	assert.match(failed.stderr, /connection refused/);

	const connected = await localSshFixture();
	t.after(connected.close);
	const completed = await connected.execute("prod", "printf ok");
	assert.equal(completed.code, 0);
	assert.equal(completed.stdout, "ok");
	assert.ok(completed.remoteTime);
});

test("intentional SIGPIPE from a bounded large-file read is accepted", async (t) => {
	const fixture = await localSshFixture();
	t.after(fixture.close);
	const file = join(fixture.dir, "large.txt");
	await writeFile(file, "line\n".repeat(200_000));
	const result = await fixture.execute("prod", statusPreservingPipeline(`cat -- ${shellQuote(file)}`, "head -n 10"));
	assert.equal(result.code, 141);
	assert.equal(boundedReadFailed(result.code), false);
	assert.equal(result.stdout, "line\n".repeat(10));
});

test("quoted arbitrary scripts preserve heredocs, trailing comments, exit codes and remote metadata", async (t) => {
	const fixture = await localSshFixture();
	t.after(fixture.close);
	const script = "cat <<'EOF'\nquotes: ' and \" and $(not-executed)\nEOF\nexit 7\n# trailing comment";
	const result = await fixture.execute("staging", `sh -c ${shellQuote(script)}`);
	assert.equal(result.stdout, "quotes: ' and \" and $(not-executed)\n");
	assert.equal(result.code, 7);
	assert.ok(result.remoteTime);
});

test("intermediate filter failures are errors while grep no-match remains informative", async (t) => {
	const fixture = await localSshFixture();
	t.after(fixture.close);
	const failed = await fixture.execute("fixture", statusPreservingPipeline("printf 'example\\n'", [
		{ command: "grep -i -- '['", allowNoMatch: true }, "sed -n '1,10p'",
	]));
	assert.equal(failed.code, 2);
	const empty = await fixture.execute("fixture", statusPreservingPipeline("printf 'example\\n'", [
		{ command: "grep -i -- absent", allowNoMatch: true }, "sed -n '1,10p'",
	]));
	assert.equal(empty.code, 0);
	assert.equal(empty.stdout, "");
});

test("remote row limits disclose truncation without hiding late producer failure", async (t) => {
	const fixture = await localSshFixture();
	t.after(fixture.close);
	const result = await fixture.execute("fixture", statusPreservingPipeline("printf 'one\\ntwo\\nthree\\n'; (exit 7)", boundedLineFilter(2)));
	assert.equal(result.code, 7);
	assert.match(result.stdout, /^one\ntwo\n/);
	assert.match(captureTruncationNote(result), /truncated: showing 2 of 3 lines/);
	assert.equal(result.stderr, "");
	assert.doesNotMatch(result.stdout, /three/);
});

test("timeout and cancellation settle even when descendants retain output pipes", async () => {
	for (const cancel of [false, true]) {
		const execute = createSshExecutor({ spawnSsh: () => spawn(process.execPath, ["-e", `
require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(()=>{},1500)'], { stdio: 'inherit' });
setInterval(()=>{},1000);
`], { stdio: ["ignore", "pipe", "pipe"] }) });
		const controller = new AbortController();
		const timer = cancel ? setTimeout(() => controller.abort(), 200) : undefined;
		const start = Date.now();
		try {
			await assert.rejects(execute("unused", "unused", controller.signal, cancel ? 10000 : 200), cancel ? /aborted/ : /timed out/);
			assert.ok(Date.now() - start < 1000, "settlement must not wait for inherited pipes to close");
		} finally { clearTimeout(timer); }
	}
});

test("executor enforces timeout", async (t) => {
	const fixture = await localSshFixture("hang");
	t.after(fixture.close);
	await assert.rejects(fixture.execute("prod", "printf never", undefined, 20), /timed out/);
});
