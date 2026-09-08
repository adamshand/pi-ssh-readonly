import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSshExecutor } from "../../src/ssh-transport.ts";

/** Execute generated remote scripts locally, with no network or privilege escalation. */
export async function localSshFixture(mode: "run" | "transport-failure" | "hang" = "run") {
	const dir = await mkdtemp(join(tmpdir(), "sshro-local-"));
	const scripts: Record<string, string> = {
		"fake-ssh": `#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const { dirname } = require('node:path');
if (${JSON.stringify(mode)} === 'transport-failure') {
 process.stderr.write('connection refused\\n');
 process.exit(255);
}
if (${JSON.stringify(mode)} === 'hang') { setInterval(() => {}, 1000); }
else {
const result = spawnSync('/bin/sh', ['-c', process.argv.at(-1)], {
 stdio: 'inherit', env: { ...process.env, PATH: dirname(process.argv[1]) + ':' + process.env.PATH }
});
process.exit(result.status ?? 1);
}
`,
		realpath: `#!/usr/bin/env node
try { console.log(require('node:fs').realpathSync(process.argv.at(-1))); }
catch { process.exit(1); }
`,
		sudo: "#!/bin/sh\necho 'not allowed' >&2\nexit 1\n",
	};
	for (const [name, script] of Object.entries(scripts)) {
		await writeFile(join(dir, name), script);
		await chmod(join(dir, name), 0o755);
	}
	return {
		dir,
		execute: createSshExecutor({ binary: join(dir, "fake-ssh") }),
		close: () => rm(dir, { recursive: true, force: true }),
	};
}
