import assert from "node:assert/strict";
import test from "node:test";
import {
	activateSshRoInspectionTools,
	deactivateSshRoInspectionTools,
	SSHRO_CONNECT_TOOL_NAME,
} from "../src/tool-activation.ts";

const INSPECTION_TOOL_NAMES = ["sshro_read", "sshro_ls", "sshro_grep", "sshro_docker_inspect"] as const;

function activationHarness(initial: string[]) {
	let active = [...initial];
	let setCalls = 0;
	return {
		pi: {
			getActiveTools: () => [...active],
			setActiveTools: (names: string[]) => {
				setCalls++;
				active = [...names];
			},
		},
		active: () => [...active],
		setCalls: () => setCalls,
	};
}

test("initial deactivation keeps sshro_connect and unrelated tools active", () => {
	const harness = activationHarness([
		"read",
		SSHRO_CONNECT_TOOL_NAME,
		...INSPECTION_TOOL_NAMES,
		"another_extension_tool",
	]);

	const removed = deactivateSshRoInspectionTools(harness.pi, INSPECTION_TOOL_NAMES);

	assert.deepEqual(removed, INSPECTION_TOOL_NAMES);
	assert.deepEqual(harness.active(), ["read", SSHRO_CONNECT_TOOL_NAME, "another_extension_tool"]);
	assert.equal(harness.setCalls(), 1);
});

test("activation additively loads every inspection tool without disturbing active tools", () => {
	const harness = activationHarness(["read", SSHRO_CONNECT_TOOL_NAME, "another_extension_tool"]);

	const added = activateSshRoInspectionTools(harness.pi, INSPECTION_TOOL_NAMES);

	assert.deepEqual(added, INSPECTION_TOOL_NAMES);
	assert.deepEqual(harness.active(), [
		"read",
		SSHRO_CONNECT_TOOL_NAME,
		"another_extension_tool",
		...INSPECTION_TOOL_NAMES,
	]);
	assert.equal(harness.setCalls(), 1);
});

test("activation reports only tools accepted by Pi active-tool policy", () => {
	let active = ["read", SSHRO_CONNECT_TOOL_NAME];
	const blocked: (typeof INSPECTION_TOOL_NAMES)[number] = "sshro_docker_inspect";
	const pi = {
		getActiveTools: () => [...active],
		setActiveTools: (names: string[]) => {
			active = names.filter((name) => name !== blocked);
		},
	};

	const added = activateSshRoInspectionTools(pi, INSPECTION_TOOL_NAMES);

	assert.ok(!added.includes(blocked));
	assert.ok(!active.includes(blocked));
	assert.deepEqual(added, INSPECTION_TOOL_NAMES.filter((name) => name !== blocked));
});

test("activation and deactivation are idempotent", () => {
	const harness = activationHarness(["read", SSHRO_CONNECT_TOOL_NAME]);

	activateSshRoInspectionTools(harness.pi, INSPECTION_TOOL_NAMES);
	assert.deepEqual(activateSshRoInspectionTools(harness.pi, INSPECTION_TOOL_NAMES), []);
	deactivateSshRoInspectionTools(harness.pi, INSPECTION_TOOL_NAMES);
	assert.deepEqual(deactivateSshRoInspectionTools(harness.pi, INSPECTION_TOOL_NAMES), []);
	assert.equal(harness.setCalls(), 2);
	assert.deepEqual(harness.active(), ["read", SSHRO_CONNECT_TOOL_NAME]);
});
