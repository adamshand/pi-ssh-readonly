import assert from "node:assert/strict";
import test from "node:test";
import { normalizeSshTarget, parseSshTargetList } from "../src/target-policy.ts";

test("normalizes exact SSH destinations", () => {
	assert.equal(normalizeSshTarget("  user@prod  "), "user@prod");
	assert.equal(normalizeSshTarget("prod-alias"), "prod-alias");
});

test("rejects option-shaped, whitespace, control, and path targets", () => {
	assert.throws(() => normalizeSshTarget("-oProxyCommand=touch /tmp/pwn"), /must not begin/);
	assert.throws(() => normalizeSshTarget("prod other"), /without whitespace/);
	assert.throws(() => normalizeSshTarget("prod\nother"), /control characters/);
	assert.throws(() => normalizeSshTarget("prod:/srv"), /target:\/path/);
});

test("whitelist parsing ignores invalid entries without exposing them", () => {
	const parsed = parseSshTargetList("prod, user@legacy, -F/tmp/config, has space");
	assert.deepEqual([...parsed.targets], ["prod", "user@legacy"]);
	assert.equal(parsed.rejected, 2);
});
