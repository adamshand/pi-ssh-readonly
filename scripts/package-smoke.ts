import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// This intentionally uses the registry, but never publishes or contacts a model.
const root = resolve(import.meta.dirname, "..");
const temp = await mkdtemp(join(tmpdir(), "sshro-package-"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
try {
	const packed = JSON.parse(execFileSync(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", temp], { cwd: root, encoding: "utf8" }))[0];
	const paths = packed.files.map((file: { path: string }) => file.path) as string[];
	assert.ok(paths.includes("index.ts"));
	assert.ok(paths.includes("src/unrestricted-exec.ts"));
	assert.ok(paths.every((path) => /^(?:index\.ts|package\.json|README\.md|LICENSE|CONTEXT\.md|src\/|docs\/adr\/|docs\/architecture\.md)/.test(path)), "unexpected file in npm tarball");
	await writeFile(join(temp, "package.json"), JSON.stringify({ private: true, type: "module" }));
	execFileSync(npm, ["install", "--omit=dev", "--no-audit", "--no-fund", join(temp, packed.filename)], {
		cwd: temp, stdio: "pipe", timeout: 120000,
	});
	const packageDir = join(temp, "node_modules", "pi-ssh-readonly");
	const piDir = join(temp, "node_modules", "@earendil-works", "pi-coding-agent");
	const piManifest = JSON.parse(await readFile(join(piDir, "package.json"), "utf8"));
	const output = execFileSync(process.execPath, [join(piDir, piManifest.bin.pi), "--no-extensions", "-e", join(packageDir, "index.ts"), "--help"], {
		cwd: temp, encoding: "utf8", timeout: 30000,
		env: { ...process.env, PI_CODING_AGENT_DIR: join(temp, "agent"), PI_OFFLINE: "1" },
	});
	assert.match(output, /--ssh-ro/, "the installed extension must register its startup flag");
	console.log(`Packed-install smoke passed: ${packed.id}, ${paths.length} files, Pi ${piManifest.version}`);
} finally {
	await rm(temp, { recursive: true, force: true });
}
