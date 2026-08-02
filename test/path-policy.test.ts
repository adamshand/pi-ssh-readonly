import assert from "node:assert/strict";
import test from "node:test";
import {
	canonicalPathForPolicy,
	denyReasonForPath,
	normalizeRemotePathForPolicy,
	remotePath,
} from "../src/path-policy.ts";

test("remote paths are normalized before policy checks", () => {
	assert.equal(normalizeRemotePathForPolicy("/var/log/../lib//app.log"), "/var/lib/app.log");
	assert.equal(normalizeRemotePathForPolicy("../../srv/app.log"), "../../srv/app.log");
	assert.equal(remotePath("logs/app.log", "/srv/app"), "/srv/app/logs/app.log");
	assert.match(denyReasonForPath("/home/alice/project/../.ssh/id_ed25519") ?? "", /blocked credential directory/);
});

test("credential paths use component boundaries and control characters fail closed", async () => {
	assert.match(denyReasonForPath("/srv/app/.env.production") ?? "", /credential-like/);
	assert.match(denyReasonForPath("/home/alice/.config/gh/hosts.yml") ?? "", /credential path/);
	assert.equal(denyReasonForPath("/home/alice/.config/ghoul/settings.json"), undefined);
	await assert.rejects(canonicalPathForPolicy("/srv/app/ok", async () => "/srv/app/bad\nname"), /control character/);
});

test("canonical path policy blocks an allowed-looking symlink into credentials", async () => {
	await assert.rejects(
		canonicalPathForPolicy("/srv/app/current-key", async () => "/home/alice/.ssh/id_ed25519"),
		/blocked credential directory/,
	);
});

test("canonical path policy returns an allowed canonical path", async () => {
	assert.equal(await canonicalPathForPolicy("/srv/app/current", async () => "/srv/releases/42"), "/srv/releases/42");
});
