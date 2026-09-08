import assert from "node:assert/strict";
import test from "node:test";
import { SshRoController } from "../src/sshro-controller.ts";

function harness(options: { whitelist?: string[]; blocked?: string[]; confirm?: () => Promise<boolean> } = {}) {
	let active = ["read", "sshro_connect"];
	let confirmCalls = 0;
	const controller = new SshRoController({
		pi: {
			getActiveTools: () => [...active],
			setActiveTools: (names) => {
				active = names.filter((name) => !(options.blocked ?? []).includes(name));
			},
		},
		whitelistedTargets: () => new Set(options.whitelist ?? []),
	});
	controller.setInspectionToolNames(["sshro_read", "sshro_ls"]);
	const context = {
		hasUI: true,
		ui: {
			confirm: async () => {
				confirmCalls++;
				return options.confirm ? options.confirm() : true;
			},
		},
	};
	return { controller, context, active: () => active, confirmCalls: () => confirmCalls };
}

test("whitelisted targets authorize without prompting", async () => {
	const h = harness({ whitelist: ["prod"] });
	assert.equal(await h.controller.authorize("prod", h.context), "prod");
	assert.equal(h.confirmCalls(), 0);
	assert.deepEqual(h.controller.availableTargets(), ["prod"]);
});

test("accepted exact-target approval is remembered and shared by concurrent requests", async () => {
	let release!: (approved: boolean) => void;
	const approval = new Promise<boolean>((resolve) => { release = resolve; });
	const h = harness({ confirm: () => approval });
	const first = h.controller.authorize("user@prod", h.context);
	const second = h.controller.authorize("user@prod", h.context);
	assert.equal(h.confirmCalls(), 1);
	release(true);
	assert.deepEqual(await Promise.all([first, second]), ["user@prod", "user@prod"]);
	assert.deepEqual(h.controller.approved(), ["user@prod"]);
});

test("clearing approvals invalidates an already pending confirmation", async () => {
	let release!: (approved: boolean) => void;
	const approval = new Promise<boolean>((resolve) => { release = resolve; });
	const h = harness({ confirm: () => approval });
	const pending = h.controller.authorize("prod", h.context);
	h.controller.clearApprovals();
	release(true);
	await assert.rejects(pending, /denied by the human/);
	assert.deepEqual(h.controller.approved(), []);
});

test("denied and non-interactive approval requests fail closed", async () => {
	const denied = harness({ confirm: async () => false });
	await assert.rejects(denied.controller.authorize("prod", denied.context), /denied by the human/);
	assert.deepEqual(denied.controller.approved(), []);

	const noUi = harness();
	await assert.rejects(noUi.controller.authorize("prod", { ...noUi.context, hasUI: false }), /no UI is available/);
	assert.equal(noUi.confirmCalls(), 0);
});

test("activation reports policy-blocked tools and preserves unrelated tools", () => {
	const h = harness({ blocked: ["sshro_ls"] });
	const report = h.controller.activateInspectionTools();
	assert.deepEqual(report.added, ["sshro_read"]);
	assert.deepEqual(report.active, ["sshro_read"]);
	assert.deepEqual(report.blocked, ["sshro_ls"]);
	assert.deepEqual(h.active(), ["read", "sshro_connect", "sshro_read"]);
});

test("approval restoration is atomic and cache clearing is explicit", () => {
	const h = harness();
	h.controller.restoreApprovals(["b", "a"]);
	assert.deepEqual(h.controller.approved(), ["a", "b"]);
	assert.throws(() => h.controller.restoreApprovals(["valid", "invalid:target"]), /SSH.*target/);
	assert.deepEqual(h.controller.approved(), ["a", "b"]);
	h.controller.cacheRemoteCommand("key", "/usr/bin/cat");
	h.controller.cacheSudoCheck("sudo", { allowed: true, reason: "ok" });
	h.controller.clearCaches();
	assert.deepEqual(h.controller.getCachedRemoteCommand("key"), { found: false, value: undefined });
	assert.equal(h.controller.getCachedSudoCheck("sudo"), undefined);
});
