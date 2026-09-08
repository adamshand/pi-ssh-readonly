import assert from "node:assert/strict";
import test from "node:test";
import {
	BoundedCapture,
	parseRemoteStderr,
	REMOTE_STATUS_MARKER,
	REMOTE_TIME_MARKER,
	statusPreservingPipeline,
} from "../src/ssh-output.ts";

test("status-preserving pipelines emit a producer marker outside the filter", () => {
	const command = statusPreservingPipeline("systemctl status broken.service", "sed -n '1,20p'");
	assert.match(command, /systemctl status broken\.service/);
	assert.match(command, /sed -n/);
	assert.ok(command.includes(REMOTE_STATUS_MARKER));
	assert.match(command, />&2/);
});

test("producer failure overrides a successful outer pipeline status", () => {
	const parsed = parseRemoteStderr(`warning\n${REMOTE_STATUS_MARKER}7\n${REMOTE_TIME_MARKER}2026-08-02T00:00:00Z\n`, 0);
	assert.equal(parsed.code, 7);
	assert.equal(parsed.stderr, "warning");
	assert.equal(parsed.remoteTime, "2026-08-02T00:00:00Z");
});

test("outer SSH command failure takes precedence over producer status", () => {
	const parsed = parseRemoteStderr(`${REMOTE_STATUS_MARKER}0\n`, 127);
	assert.equal(parsed.code, 127);
});

test("bounded capture preserves exact small output", () => {
	const capture = new BoundedCapture(16, 4);
	capture.push("hello");
	capture.push(" world");
	assert.equal(capture.toString(), "hello world");
	assert.equal(capture.truncated, false);
});

test("bounded capture retains a final producer marker after oversized diagnostics", () => {
	const capture = new BoundedCapture(256, 128);
	capture.push("warning\n".repeat(200));
	capture.push(`\n${REMOTE_STATUS_MARKER}9\n`);
	const parsed = parseRemoteStderr(capture.toString(), 0);
	assert.equal(capture.truncated, true);
	assert.equal(parsed.code, 9);
});

test("bounded capture retains the beginning and tail", () => {
	const capture = new BoundedCapture(12, 4);
	capture.push("abcdefghij");
	capture.push("KLMNOP");
	assert.equal(capture.truncated, true);
	assert.equal(capture.toString(), "abcdefghMNOP");
	assert.equal(capture.toBuffer().length, 12);
});
