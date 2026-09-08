import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { localSshFixture } from "./helpers/local-ssh.ts";
import { DENIED_PATH_PARTS } from "../src/path-policy.ts";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import sshReadonlyExtension from "../index.ts";
import type { SshExecResult, SshExecutor } from "../src/ssh-transport.ts";

const CONNECT = "sshro_connect";

type Handler = (event: any, context: any) => unknown | Promise<unknown>;

class FakePi {
	active = ["read", "another_extension_tool"];
	readonly tools = new Map<string, any>();
	readonly commands = new Map<string, any>();
	readonly flags = new Map<string, unknown>();
	readonly handlers = new Map<string, Handler[]>();
	readonly entries: any[];
	readonly notifications: Array<{ message: string; type: string }> = [];
	readonly statuses = new Map<string, string | undefined>();
	readonly blockedTools: Set<string>;
	confirmResult = true;
	selectResult: string | undefined;
	selectOptions: string[] = [];
	context: any;

	constructor(options: { entries?: any[]; blockedTools?: string[]; hasUI?: boolean } = {}) {
		this.entries = [...(options.entries ?? [])];
		this.blockedTools = new Set(options.blockedTools ?? []);
		this.context = {
			hasUI: options.hasUI ?? true,
			mode: options.hasUI === false ? "print" : "tui",
			ui: {
				theme: { fg: (_color: string, text: string) => text },
				confirm: async () => this.confirmResult,
				select: async (_title: string, options: string[]) => {
					this.selectOptions = [...options];
					return this.selectResult;
				},
				notify: (message: string, type = "info") => this.notifications.push({ message, type }),
				setStatus: (key: string, text: string | undefined) => this.statuses.set(key, text),
			},
			sessionManager: { getEntries: () => [...this.entries] },
		};
	}

	api(): ExtensionAPI {
		return this as unknown as ExtensionAPI;
	}

	registerTool(definition: any): void {
		this.tools.set(definition.name, definition);
		if (!this.active.includes(definition.name) && !this.blockedTools.has(definition.name)) this.active.push(definition.name);
	}

	registerCommand(name: string, options: any): void {
		this.commands.set(name, options);
	}

	registerFlag(name: string, _options: any): void {
		if (!this.flags.has(name)) this.flags.set(name, undefined);
	}

	getFlag(name: string): unknown {
		return this.flags.get(name);
	}

	getActiveTools(): string[] {
		return [...this.active];
	}

	setActiveTools(names: string[]): void {
		this.active = [...new Set(names.filter((name) => !this.blockedTools.has(name) && (this.tools.has(name) || ["read", "another_extension_tool"].includes(name))))];
	}

	getAllTools(): any[] {
		return [...this.tools.values()].map((tool) => ({ name: tool.name, description: tool.description, parameters: tool.parameters, sourceInfo: {} }));
	}

	appendEntry(customType: string, data: unknown): void {
		this.entries.push({ type: "custom", customType, data });
	}

	on(event: string, handler: Handler): void {
		const handlers = this.handlers.get(event) ?? [];
		handlers.push(handler);
		this.handlers.set(event, handlers);
	}

	async emit(event: string, payload: any): Promise<void> {
		for (const handler of this.handlers.get(event) ?? []) await handler(payload, this.context);
	}

	async runCommand(args: string): Promise<void> {
		await this.commands.get("sshro").handler(args, this.context);
	}

	async runTool(name: string, params: Record<string, unknown>): Promise<any> {
		return this.tools.get(name).execute("call-1", params, undefined, undefined, this.context);
	}
}

function inspectionNames(pi: FakePi): string[] {
	return [...pi.tools.keys()].filter((name) => name.startsWith("sshro_") && name !== CONNECT);
}

function sshResult(overrides: Partial<SshExecResult>): SshExecResult {
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

test("recursive grep enforces credential path policy below an allowed parent", async () => {
	const fixture = await localSshFixture();
	try {
		const files = [...DENIED_PATH_PARTS.map((path) => `${path.slice(1)}/private-data`), ".ssh/config", ".env", "app.env", ".npmrc"];
		const root = join(fixture.dir, "data");
		for (const file of [...files, "allowed.txt"]) {
			const path = join(root, file);
			await mkdir(dirname(path), { recursive: true });
			await writeFile(path, file === "allowed.txt" ? "MATCH public\n" : "MATCH PRIVATE_TEST_SECRET\n");
		}
		const pi = new FakePi();
		sshReadonlyExtension(pi.api(), { sshExecutor: fixture.execute });
		await pi.runCommand("fixture");
		const result = await pi.runTool("sshro_grep", { target: "fixture", path: root, pattern: "MATCH", literal: true });
		assert.match(result.content[0].text, /MATCH public/);
		assert.doesNotMatch(result.content[0].text, /PRIVATE_TEST_SECRET/);
		await writeFile(join(root, "allowed.txt"), "MATCH public\n".repeat(3));
		const limited = await pi.runTool("sshro_grep", { target: "fixture", path: root, pattern: "MATCH", literal: true, limit: 1 });
		assert.match(limited.content[0].text, /showing 1 of 3 lines/);
	} finally {
		await fixture.close();
	}
});

test("inspection operands cannot select command options or other hosts", async () => {
	let executions = 0;
	const pi = new FakePi();
	sshReadonlyExtension(pi.api(), { sshExecutor: async () => { executions++; return sshResult({}); } });
	await pi.runCommand("fixture");
	for (const [tool, params] of [
		["sshro_dig", { name: "-f/tmp/batch" }],
		["sshro_dig", { name: "+trace" }],
		["sshro_dig", { name: "@other-server" }],
		["sshro_dig", { name: "example.test", server: "@other-server" }],
		["sshro_systemctl", { action: "status", unit: "--host=root@other-server" }],
		["sshro_systemctl", { action: "show", unit: "-Hother-server" }],
		["sshro_docker_inspect", { object: "--format={{json .}}" }],
		["sshro_docker_stats", { container: "--no-stream=false" }],
	] as const) {
		await assert.rejects(pi.runTool(tool, { target: "fixture", ...params }), /option|operand|name|server|unit|object|container/);
	}
	assert.equal(executions, 0);
});

test("Docker inspect never exposes raw secrets when parsing or execution fails", async () => {
	for (const response of [
		sshResult({ stdout: '{"Config":{"Env":["PRIVATE_TEST_SECRET"]}} broken-json' }),
		sshResult({ stdout: '{"Config":{"Env":["PRIVATE_TEST_SECRET"]}}', stdoutTruncated: true }),
		sshResult({ code: 1, stdout: "PRIVATE_TEST_SECRET", stderr: "PRIVATE_TEST_SECRET" }),
	]) {
		const pi = new FakePi();
		sshReadonlyExtension(pi.api(), { sshExecutor: async () => response });
		await pi.runCommand("fixture");
		await assert.rejects(pi.runTool("sshro_docker_inspect", { target: "fixture", object: "app" }), (error: Error) => {
			assert.doesNotMatch(error.message, /PRIVATE_TEST_SECRET/);
			return true;
		});
	}
});

test("valid Docker inspect output retains useful metadata but redacts secrets", async () => {
	const pi = new FakePi();
	sshReadonlyExtension(pi.api(), { sshExecutor: async () => sshResult({ stdout: JSON.stringify([{
		Name: "app", Config: { Env: ["PRIVATE_ENV_SECRET"], Labels: { token: "PRIVATE_LABEL_SECRET", project: "public" } },
		GraphDriver: { Name: "overlay2", Data: { Secret: "PRIVATE_DRIVER_SECRET" } },
	}]) }) });
	await pi.runCommand("fixture");
	const result = await pi.runTool("sshro_docker_inspect", { target: "fixture", object: "app" });
	assert.match(result.content[0].text, /public/);
	assert.match(result.content[0].text, /\[redacted\]/);
	assert.match(result.content[0].text, /overlay2/);
	assert.doesNotMatch(result.content[0].text, /PRIVATE_/);
});

test("reload never falls back to older grants when the newest snapshot is malformed", async () => {
	for (const data of [null, { version: 2, targets: [] }, { version: 1, targets: [42], writeTargets: [] }, { version: 1, targets: [], writeTargets: [42] }, { version: 1, writeTargets: [] }]) {
		const pi = new FakePi({ entries: [
			{ type: "custom", customType: "sshro-approval-state", data: { version: 1, targets: ["old"], toolsActive: true, writeTargets: ["old"] } },
			{ type: "custom", customType: "sshro-approval-state", data },
		] });
		sshReadonlyExtension(pi.api());
		await pi.emit("session_start", { reason: "reload" });
		assert.ok(!pi.active.includes("ssh_exec"));
		assert.ok(!pi.active.includes("sshro_read"));
		await assert.rejects(pi.runTool("ssh_exec", { target: "old", command: "id" }), /No write grant/);
	}
});

test("all Docker output paths are bounded, including oversized rows and failures", async () => {
	for (const code of [0, 1]) {
		const pi = new FakePi();
		sshReadonlyExtension(pi.api(), { sshExecutor: async () => sshResult({ code, stdout: "ID COMMAND\nabc " + "x".repeat(100000) }) });
		await pi.runCommand("fixture");
		let text: string;
		try { text = (await pi.runTool("sshro_docker_ps", { target: "fixture" })).content[0].text; }
		catch (error) { text = (error as Error).message; }
		assert.ok(Buffer.byteLength(text) <= 51200);
		assert.match(text, /truncated/);
		assert.match(text, /ssh-ro: fixture/);
	}
});

test("ssh_exec renders its target and multiline command above the default output", () => {
	const pi = new FakePi();
	sshReadonlyExtension(pi.api());
	const tool = pi.tools.get("ssh_exec");
	const theme = { fg: (_color: string, text: string) => text, bold: (text: string) => text };
	const command = "cat <<'EOF'\nhello world\nEOF";
	const component = tool.renderCall({ target: "root@staging", command, timeout: 300 }, theme);
	const rendered = component.render(100).join("\n");
	assert.match(rendered, /ssh_exec root@staging · timeout 300s/);
	for (const line of command.split("\n")) assert.ok(rendered.includes(line));
	assert.ok(component.render(20).length > component.render(100).length);
	assert.doesNotThrow(() => tool.renderCall({}, theme).render(40));
	assert.equal(tool.renderResult, undefined, "keep Pi's default collapsible output renderer");
});

test("write grants are human-confirmed, exact-target, and independent of read-only approvals", async () => {
	const calls: any[] = [];
	const pi = new FakePi();
	sshReadonlyExtension(pi.api(), { sshExecutor: async (...args) => {
		calls.push(args);
		return sshResult({ stdout: "secret=unredacted\n" });
	} });
	await pi.emit("session_start", { reason: "startup" });
	await pi.runCommand("root@172.16.1.52");
	pi.context.ui.confirm = async () => { throw new Error("unexpected tool approval prompt"); };
	await assert.rejects(pi.runTool("ssh_exec", { target: "root@172.16.1.52", command: "id" }), /No write grant/);
	pi.context.ui.confirm = async () => false;
	await pi.runCommand("allow-write root@172.16.1.52");
	assert.ok(!pi.active.includes("ssh_exec"));
	pi.context.ui.confirm = async () => true;
	await pi.runCommand("allow-write root@172.16.1.52");
	assert.ok(pi.active.includes("ssh_exec"));
	assert.match(pi.statuses.get("sshro")!, /SSH WRITE: root@172.16.1.52/);
	const command = "cat > /root/.env <<'EOF'\nsecret=value\nEOF\n# trailing comment";
	const result = await pi.runTool("ssh_exec", { target: "root@172.16.1.52", command, timeout: 300 });
	assert.match(result.content[0].text, /secret=unredacted/);
	assert.equal(calls[0][0], "root@172.16.1.52");
	assert.match(calls[0][1], /^sh -c '/);
	assert.equal(calls[0][3], 300000);
	for (const target of ["172.16.1.52", "other@172.16.1.52", "root@production", "-oProxyCommand=bad"]) {
		await assert.rejects(pi.runTool("ssh_exec", { target, command: "id" }));
	}
	assert.equal(calls.length, 1);
	await assert.rejects(pi.runTool("sshro_read", { target: "root@172.16.1.52", path: "/root/.env" }), /blocked|denied/i);
	const guard = pi.handlers.get("tool_call")![0];
	assert.equal((await guard({ toolName: "bash", input: { command: "ssh root@172.16.1.52 id" } }, pi.context) as any).block, true);
	await pi.runCommand("status");
	assert.match(pi.notifications.at(-1)!.message, /Unrestricted write targets: root@172.16.1.52/);
	await pi.runCommand("revoke-write root@172.16.1.52");
	assert.ok(!pi.active.includes("ssh_exec"));
	await assert.rejects(pi.runTool("ssh_exec", { target: "root@172.16.1.52", command: "id" }), /No write grant/);
	assert.ok(pi.active.includes("read"));
});

test("write grants survive only reload and logout cannot be resurrected by reload", async () => {
	const first = new FakePi();
	sshReadonlyExtension(first.api());
	await first.emit("session_start", { reason: "startup" });
	await first.runCommand("allow-write root@staging");
	await first.emit("session_shutdown", { reason: "reload" });
	for (const reason of ["reload", "startup", "new", "resume", "fork"]) {
		const pi = new FakePi({ entries: first.entries });
		sshReadonlyExtension(pi.api());
		await pi.emit("session_start", { reason });
		assert.equal(pi.active.includes("ssh_exec"), reason === "reload");
		if (reason !== "reload") {
			await assert.rejects(pi.runTool("ssh_exec", { target: "root@staging", command: "id" }), /No write grant/);
		} else {
			await pi.runCommand("logout");
			await pi.emit("session_start", { reason: "reload" });
			assert.ok(!pi.active.includes("ssh_exec"));
			assert.equal(pi.statuses.get("sshro"), undefined);
		}
	}
});

test("write grants fail closed without UI, on invalid input, and across pending-confirmation resets", async () => {
	const pi = new FakePi({ hasUI: false });
	sshReadonlyExtension(pi.api());
	await pi.emit("session_start", { reason: "startup" });
	await pi.runCommand("allow-write root@staging");
	assert.match(pi.notifications.at(-1)!.message, /no UI/);
	pi.context.hasUI = true;
	for (const args of ["allow-write", "allow-write -oHostName=prod", "allow-write root@staging extra"]) {
		await pi.runCommand(args);
		assert.ok(!pi.active.includes("ssh_exec"));
	}
	let confirm!: (answer: boolean) => void;
	pi.context.ui.confirm = () => new Promise<boolean>((resolve) => { confirm = resolve; });
	const pending = pi.runCommand("allow-write root@staging");
	await pi.runCommand("logout");
	confirm(true);
	await pending;
	assert.ok(!pi.active.includes("ssh_exec"));
});

test("ssh_exec preserves failures, bounds output, passes cancellation, and respects tool policy", async () => {
	const pi = new FakePi({ blockedTools: ["ssh_exec"] });
	const signal = new AbortController().signal;
	let response = sshResult({ stdout: "x".repeat(100000), stdoutTruncated: true });
	sshReadonlyExtension(pi.api(), { sshExecutor: async (_target, _command, receivedSignal) => {
		assert.equal(receivedSignal, signal);
		return response;
	} });
	await pi.emit("session_start", { reason: "startup" });
	await pi.runCommand("allow-write root@staging");
	assert.ok(!pi.active.includes("ssh_exec"));
	assert.match(pi.notifications.at(-1)!.message, /blocked by Pi tool policy/);
	const execute = () => pi.tools.get("ssh_exec").execute("id", { target: "root@staging", command: "id" }, signal);
	const result = await execute();
	assert.ok(result.content[0].text.length < 53000);
	assert.match(result.content[0].text, /truncated/);
	response = sshResult({ code: 7, stderr: "failed" });
	await assert.rejects(execute(), /failed[\s\S]*exit: 7/);
	response = sshResult({ code: 255, remoteTime: undefined, stderr: "connection refused" });
	await assert.rejects(execute(), /connection refused/);
});

test("session startup leaves only sshro_connect active and preserves unrelated tools", async () => {
	const pi = new FakePi();
	sshReadonlyExtension(pi.api());
	assert.equal(inspectionNames(pi).length, 13);
	for (const name of inspectionNames(pi)) {
		assert.equal(pi.tools.get(name).promptSnippet, undefined);
		assert.equal(pi.tools.get(name).promptGuidelines, undefined);
	}
	await pi.emit("session_start", { reason: "startup" });
	assert.deepEqual(pi.active, ["read", "another_extension_tool", CONNECT]);
});

test("sshro_connect discovers a whitelist target and additively loads detailed tools", async () => {
	const previous = process.env.SSHRO_HOST_WHITELIST;
	process.env.SSHRO_HOST_WHITELIST = "prod";
	try {
		const pi = new FakePi({ hasUI: false });
		sshReadonlyExtension(pi.api());
		await pi.emit("session_start", { reason: "startup" });
		const result = await pi.runTool(CONNECT, {});
		assert.match(result.content[0].text, /target available: prod/);
		assert.match(result.content[0].text, /13 inspection tools loaded/);
		assert.ok(inspectionNames(pi).every((name) => pi.active.includes(name)));
		assert.ok(pi.active.includes("read"));
	} finally {
		if (previous === undefined) delete process.env.SSHRO_HOST_WHITELIST;
		else process.env.SSHRO_HOST_WHITELIST = previous;
	}
});

test("slash command exposes status and logout unloads tools", async () => {
	const pi = new FakePi();
	sshReadonlyExtension(pi.api());
	await pi.emit("session_start", { reason: "startup" });
	await pi.runCommand("user@prod");
	assert.ok(inspectionNames(pi).every((name) => pi.active.includes(name)));
	await pi.runCommand("status");
	assert.match(pi.notifications.at(-1)?.message ?? "", /user@prod/);
	await pi.runCommand("logout");
	assert.deepEqual(pi.active, ["read", "another_extension_tool", CONNECT]);
	assert.equal(pi.statuses.get("sshro"), undefined);
});

test("sshro_read handles a large bounded read through an injected SSH transport", async () => {
	const commands: string[] = [];
	const execute: SshExecutor = async (_target, command) => {
		commands.push(command);
		if (command.includes("command -v 'realpath'")) return sshResult({ stdout: "/usr/bin/realpath\n" });
		if (command.startsWith("'/usr/bin/realpath'")) return sshResult({ stdout: "/srv/app.log\n" });
		if (command.includes("command -v 'cat'")) return sshResult({ stdout: "/usr/bin/cat\n" });
		if (command.startsWith("sudo -n -l")) return sshResult({ code: 1, stdout: "not allowed\n" });
		if (command.includes("file --mime-type")) return sshResult({ code: 141, stdout: "text/plain\n" });
		if (command.startsWith("printf 'path:")) return sshResult({ code: 141, stdout: "path: /srv/app.log\nmime: text/plain\nlines: 1-2000\n---\nline\n" });
		throw new Error(`Unexpected remote command: ${command}`);
	};
	const pi = new FakePi();
	sshReadonlyExtension(pi.api(), { sshExecutor: execute });
	await pi.emit("session_start", { reason: "startup" });
	await pi.runCommand("prod");
	const result = await pi.runTool("sshro_read", { target: "prod", path: "/srv/app.log" });
	assert.match(result.content[0].text, /line/);
	assert.match(result.content[0].text, /ssh-ro: prod/);
	assert.ok(commands.some((command) => command.includes("file --mime-type")));
});

test("genuine tool validation failures are thrown without redundant state entries", async () => {
	const pi = new FakePi();
	sshReadonlyExtension(pi.api());
	await pi.emit("session_start", { reason: "startup" });
	await pi.runCommand("prod");
	const stateEntries = () => pi.entries.filter((entry) => entry.customType === "sshro-approval-state");
	const before = stateEntries().length;
	await assert.rejects(
		pi.runTool("sshro_read", { target: "prod", path: "~/.ssh/config" }),
		/~ expansion is not supported/,
	);
	assert.equal(stateEntries().length, before);
});

test("bare slash command offers discovered targets and completions without pre-approving them", async () => {
	const previous = process.env.SSHRO_HOST_WHITELIST;
	process.env.SSHRO_HOST_WHITELIST = "picker-target";
	try {
		const pi = new FakePi();
		sshReadonlyExtension(pi.api());
		await pi.emit("session_start", { reason: "startup" });
		assert.deepEqual(pi.active, ["read", "another_extension_tool", CONNECT]);
		pi.selectResult = "picker-target";
		await pi.runCommand("");
		assert.ok(pi.selectOptions.includes("picker-target"));
		assert.ok(inspectionNames(pi).every((name) => pi.active.includes(name)));
		const completions = pi.commands.get("sshro").getArgumentCompletions("st");
		assert.ok(completions.some((item: { value: string }) => item.value === "status"));
	} finally {
		if (previous === undefined) delete process.env.SSHRO_HOST_WHITELIST;
		else process.env.SSHRO_HOST_WHITELIST = previous;
	}
});

test("reload restores approval and activation while a true startup clears them", async () => {
	const first = new FakePi();
	sshReadonlyExtension(first.api());
	await first.emit("session_start", { reason: "startup" });
	await first.runCommand("prod");

	const reloaded = new FakePi({ entries: first.entries });
	sshReadonlyExtension(reloaded.api());
	await reloaded.emit("session_start", { reason: "reload" });
	assert.ok(inspectionNames(reloaded).every((name) => reloaded.active.includes(name)));
	await reloaded.runCommand("status");
	assert.match(reloaded.notifications.at(-1)?.message ?? "", /prod/);

	const restarted = new FakePi({ entries: first.entries });
	sshReadonlyExtension(restarted.api());
	await restarted.emit("session_start", { reason: "startup" });
	assert.deepEqual(restarted.active, ["read", "another_extension_tool", CONNECT]);
	await restarted.runCommand("status");
	assert.match(restarted.notifications.at(-1)?.message ?? "", /Session-approved targets: none/);
});

test("new, resume, and fork session reasons clear inherited approvals", async () => {
	const source = new FakePi();
	sshReadonlyExtension(source.api());
	await source.emit("session_start", { reason: "startup" });
	await source.runCommand("prod");

	for (const reason of ["new", "resume", "fork"]) {
		const replacement = new FakePi({ entries: source.entries });
		sshReadonlyExtension(replacement.api());
		await replacement.emit("session_start", { reason });
		assert.deepEqual(replacement.active, ["read", "another_extension_tool", CONNECT], reason);
		await replacement.runCommand("status");
		assert.match(replacement.notifications.at(-1)?.message ?? "", /Session-approved targets: none/, reason);
	}
});

test("startup flag activation and Pi tool-policy filtering are reported truthfully", async () => {
	const pi = new FakePi({ blockedTools: ["sshro_docker_inspect"] });
	pi.flags.set("ssh-ro", "prod");
	sshReadonlyExtension(pi.api());
	await pi.emit("session_start", { reason: "startup" });
	assert.ok(!pi.active.includes("sshro_docker_inspect"));
	assert.equal(pi.notifications.at(-1)?.type, "warning");
	assert.match(pi.notifications.at(-1)?.message ?? "", /blocked by Pi tool policy/);
});

test("startup flag is not reapplied after logout on reload or in replacement sessions", async () => {
	const first = new FakePi();
	first.flags.set("ssh-ro", "prod");
	sshReadonlyExtension(first.api());
	await first.emit("session_start", { reason: "startup" });
	await first.runCommand("logout");

	const reloaded = new FakePi({ entries: first.entries });
	reloaded.flags.set("ssh-ro", "prod");
	sshReadonlyExtension(reloaded.api());
	await reloaded.emit("session_start", { reason: "reload" });
	assert.deepEqual(reloaded.active, ["read", "another_extension_tool", CONNECT]);

	const replacement = new FakePi({ entries: first.entries });
	replacement.flags.set("ssh-ro", "prod");
	sshReadonlyExtension(replacement.api());
	await replacement.emit("session_start", { reason: "new" });
	assert.deepEqual(replacement.active, ["read", "another_extension_tool", CONNECT]);
});

test("invalid persisted approval snapshots fail closed", async () => {
	const pi = new FakePi({ entries: [{
		type: "custom",
		customType: "sshro-approval-state",
		data: { version: 1, targets: ["-oProxyCommand=bad"], toolsActive: true },
	}] });
	sshReadonlyExtension(pi.api());
	await pi.emit("session_start", { reason: "reload" });
	assert.deepEqual(pi.active, ["read", "another_extension_tool", CONNECT]);
	assert.equal(pi.notifications.at(-1)?.type, "warning");
});
