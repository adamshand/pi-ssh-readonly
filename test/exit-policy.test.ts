import assert from "node:assert/strict";
import test from "node:test";
import { boundedReadFailed, grepFailed, locateFailed, systemctlFailed } from "../src/exit-policy.ts";

test("intentional bounded-read SIGPIPE is successful but other producer failures are errors", () => {
	assert.equal(boundedReadFailed(0), false);
	assert.equal(boundedReadFailed(141), false);
	assert.equal(boundedReadFailed(1), true);
	assert.equal(boundedReadFailed(null), true);
});

test("expected empty search states remain successful", () => {
	assert.equal(grepFailed(1), false, "grep exit 1 means no matches");
	assert.equal(locateFailed(1, ""), false, "plocate exit 1 without diagnostics means no matches");
});

test("search execution failures are errors even with partial output", () => {
	assert.equal(grepFailed(2), true);
	assert.equal(locateFailed(1, "database unavailable"), true);
	assert.equal(locateFailed(127, "not found"), true);
});

test("systemctl inactive status is informative but other failures are errors", () => {
	assert.equal(systemctlFailed("status", 3), false);
	assert.equal(systemctlFailed("status", 4), true);
	assert.equal(systemctlFailed("show", 1), true);
});
