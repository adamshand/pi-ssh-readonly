import { readFile, readdir, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { normalizeSshTarget } from "./target-policy.ts";

const MAX_CONFIG_FILES = 64;
const MAX_ALIASES = 1_000;
const MAX_CONFIG_BYTES = 256 * 1024;

function wildcardRegex(pattern: string): RegExp {
	const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
	return new RegExp(`^${escaped}$`);
}

function insideDirectory(path: string, root: string): boolean {
	const rel = relative(root, path);
	return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== "..");
}

async function expandInclude(pattern: string, baseDir: string, sshDir: string): Promise<string[]> {
	const expanded = pattern.startsWith("~/") ? join(homedir(), pattern.slice(2)) : isAbsolute(pattern) ? pattern : resolve(baseDir, pattern);
	if (!insideDirectory(expanded, sshDir) && !expanded.includes("*") && !expanded.includes("?")) return [];
	if (!expanded.includes("*") && !expanded.includes("?")) return insideDirectory(expanded, sshDir) ? [expanded] : [];
	const parent = dirname(expanded);
	if (!insideDirectory(parent, sshDir)) return [];
	try {
		const names = await readdir(parent);
		const match = wildcardRegex(basename(expanded));
		return names.filter((name) => match.test(name)).sort().map((name) => join(parent, name));
	} catch {
		return [];
	}
}

/** Discover literal Host aliases without invoking SSH or treating discovery as approval. */
export async function discoverSshConfigAliases(home = homedir()): Promise<string[]> {
	const sshDir = resolve(home, ".ssh");
	let canonicalSshDir: string;
	try {
		canonicalSshDir = await realpath(sshDir);
	} catch {
		return [];
	}
	const queue = [join(canonicalSshDir, "config")];
	const visited = new Set<string>();
	const aliases = new Set<string>();
	let bytesRead = 0;

	while (queue.length > 0 && visited.size < MAX_CONFIG_FILES && bytesRead < MAX_CONFIG_BYTES) {
		const candidate = queue.shift()!;
		let canonical: string;
		try {
			canonical = await realpath(candidate);
		} catch {
			continue;
		}
		if (!insideDirectory(canonical, canonicalSshDir) || visited.has(canonical)) continue;
		visited.add(canonical);
		let text: string;
		try {
			const info = await stat(canonical);
			if (!info.isFile() || info.size > MAX_CONFIG_BYTES - bytesRead) continue;
			text = await readFile(canonical, "utf8");
		} catch {
			continue;
		}
		bytesRead += Buffer.byteLength(text);
		if (bytesRead > MAX_CONFIG_BYTES) break;

		for (const rawLine of text.split(/\r?\n/)) {
			const line = rawLine.replace(/\s+#.*$/, "").trim();
			if (!line) continue;
			const [keyword, ...values] = line.split(/\s+/);
			if (/^host$/i.test(keyword)) {
				for (const value of values) {
					if (!value || /[*!?\[\]]/.test(value) || aliases.size >= MAX_ALIASES) continue;
					try {
						aliases.add(normalizeSshTarget(value));
					} catch {
						// Suggestions must be safe exact destinations; explicit invalid input
						// will receive the normal target validation error instead.
					}
				}
			} else if (/^include$/i.test(keyword)) {
				for (const value of values.map((item) => item.replace(/^['"]|['"]$/g, ""))) {
					queue.push(...await expandInclude(value, dirname(canonical), canonicalSshDir));
				}
			}
		}
	}

	return [...aliases].sort();
}
