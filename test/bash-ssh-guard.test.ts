import assert from "node:assert/strict";
import test from "node:test";
import { bashSshBlockReason } from "../src/bash-ssh-guard.ts";

const blockedCommands = [
	"ssh prod.example uptime",
	"/usr/bin/ssh prod.example uptime",
	"sudo ssh prod.example uptime",
	"exec sftp prod.example",
	"bash -lc 'ssh prod.example uptime'",
	"env RSYNC_RSH=ssh rsync ./dist prod.example:/srv/app",
];

for (const command of blockedCommands) {
	test(`blocks direct SSH access: ${command}`, () => {
		assert.ok(bashSshBlockReason(command));
	});
}

const allowedGitCommands = [
	"git clone git@github.com:example/private-repo.git",
	"git clone ssh://git@github.com/example/private-repo.git",
	"git fetch origin",
	"git pull --ff-only origin main",
	"git push origin main",
	"git ls-remote git@gitlab.com:example/private-repo.git",
	"GIT_SSH=ssh git fetch origin",
	"GIT_SSH_COMMAND='ssh -i /tmp/key' git fetch origin",
	"env GIT_SSH_COMMAND='ssh -o LogLevel=ERROR' git clone git@github.com:example/private-repo.git",
];

for (const command of allowedGitCommands) {
	test(`allows Git-over-SSH: ${command}`, () => {
		assert.equal(bashSshBlockReason(command), undefined);
	});
}

test("allows ordinary commands which mention an SSH URL", () => {
	assert.equal(bashSshBlockReason("printf '%s\\n' ssh://git@github.com/example/repo.git"), undefined);
});

test("the guard is deliberately not a subprocess sandbox", () => {
	assert.equal(
		bashSshBlockReason(`python3 -c 'import subprocess; subprocess.run(["/usr/bin/ssh", "prod.example", "uptime"])'`),
		undefined,
	);
});
