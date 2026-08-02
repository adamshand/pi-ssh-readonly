import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { discoverSshConfigAliases } from "../src/ssh-config.ts";

test("discovers literal SSH aliases from config and bounded includes", async () => {
	const home = await mkdtemp(join(tmpdir(), "sshro-config-"));
	await mkdir(join(home, ".ssh", "config.d"), { recursive: true });
	await writeFile(join(home, ".ssh", "config"), [
		"Host prod *.wild !excluded",
		"  HostName prod.example",
		"Include config.d/*",
	].join("\n"));
	await writeFile(join(home, ".ssh", "config.d", "legacy"), "Host legacy admin@literal -F/tmp/evil\n");

	assert.deepEqual(await discoverSshConfigAliases(home), ["admin@literal", "legacy", "prod"]);
});

test("does not follow SSH config includes outside ~/.ssh", async () => {
	const home = await mkdtemp(join(tmpdir(), "sshro-config-"));
	await mkdir(join(home, ".ssh"), { recursive: true });
	const outside = join(home, "outside.conf");
	await writeFile(outside, "Host secret-outside\n");
	await writeFile(join(home, ".ssh", "config"), `Include ${outside}\nHost inside\n`);
	await symlink(outside, join(home, ".ssh", "linked.conf"));

	assert.deepEqual(await discoverSshConfigAliases(home), ["inside"]);
});
