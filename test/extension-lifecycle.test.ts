import assert from "node:assert/strict";
import test from "node:test";
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
