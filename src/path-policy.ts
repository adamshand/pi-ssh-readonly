export const DENIED_DIR_NAMES = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".terraform", ".terraform.d", ".cloudflared", ".cloudflare", ".password-store"];
export const DENIED_PATH_PARTS = ["/.config/gcloud", "/.config/gh", "/.config/Bitwarden CLI", "/.config/Bitwarden", "/.config/bitwarden", "/.config/1Password", "/.config/op", "/.config/keepassxc", "/.config/KeePass", "/.config/keepass", "/.config/gopass", "/.config/chezmoi", "/.local/share/fish", "/.local/share/nano", "/.local/share/keepassxc", "/.local/share/gopass", "/.local/share/chezmoi", "/.gem/credentials", "/.cargo/credentials"];
export const DENIED_FILE_NAMES = [".env", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials", "terraform.tfstate", ".chezmoi.toml", ".chezmoi.yaml", ".chezmoi.json", ".chezmoiignore", ".bash_history", ".zsh_history", ".zhistory", ".fish_history", "fish_history", ".sh_history", ".ash_history", ".history", "search_history", ".mysql_history", ".psql_history", ".sqlite_history", ".python_history", ".node_repl_history", ".rediscli_history", ".lesshst", ".wget-hsts", "environ", "kcore"];
export const DENIED_FILE_SUFFIXES = [".env", ".pem", ".key", ".p12", ".pfx", "_history"];
export const DENIED_FILE_PREFIXES = [".env.", "terraform.tfstate."];

function hasControlChars(value: string): boolean {
	return /[\x00-\x1f\x7f]/.test(value);
}

export function validatePathLike(value: string, label: string): void {
	if (hasControlChars(value)) throw new Error(`${label} contains a newline or control character`);
	if (value === "~" || value.startsWith("~/")) throw new Error(`${label}: ~ expansion is not supported by SSH read-only tools`);
}

export function normalizeRemotePathForPolicy(path: string): string {
	const absolute = path.startsWith("/");
	const parts: string[] = [];
	for (const part of path.replace(/\/+/g, "/").split("/")) {
		if (!part || part === ".") continue;
		if (part === "..") {
			if (parts.length > 0 && parts[parts.length - 1] !== "..") parts.pop();
			else if (!absolute) parts.push(part);
			continue;
		}
		parts.push(part);
	}
	const normalized = `${absolute ? "/" : ""}${parts.join("/")}`;
	return normalized || (absolute ? "/" : ".");
}

export function remotePath(input: string | undefined, cwd: string): string {
	const path = input && input.length > 0 ? input : ".";
	validatePathLike(path, "path");
	if (path.startsWith("/")) return normalizeRemotePathForPolicy(path);
	if (path === ".") return normalizeRemotePathForPolicy(cwd);
	return normalizeRemotePathForPolicy(`${cwd.replace(/\/+$/, "")}/${path}`);
}

export function denyReasonForPath(path: string): string | undefined {
	const normalized = normalizeRemotePathForPolicy(path);
	const parts = normalized.split("/").filter(Boolean);
	const base = parts[parts.length - 1] ?? "";
	const deniedDir = parts.find((part) => DENIED_DIR_NAMES.includes(part));
	if (deniedDir) return `path is inside blocked credential directory ${deniedDir}`;
	const deniedPart = DENIED_PATH_PARTS.find((part) =>
		normalized === part.slice(1) || normalized.endsWith(part) || normalized.includes(`${part}/`),
	);
	if (deniedPart) return `path is inside blocked credential path ${deniedPart}`;
	if (DENIED_FILE_NAMES.includes(base)) return `blocked credential-like file ${base}`;
	const deniedPrefix = DENIED_FILE_PREFIXES.find((prefix) => base.startsWith(prefix));
	if (deniedPrefix) return `blocked credential-like file pattern ${deniedPrefix}*`;
	const deniedSuffix = DENIED_FILE_SUFFIXES.find((suffix) => base.endsWith(suffix));
	if (deniedSuffix) return `blocked credential-like file pattern *${deniedSuffix}`;
	return undefined;
}

export function assertPathAllowed(path: string): void {
	const reason = denyReasonForPath(path);
	if (reason) throw new Error(`SSH read-only tools block this path by default: ${reason}`);
}

export function joinRemotePath(parent: string, child: string): string {
	return normalizeRemotePathForPolicy(`${parent.replace(/\/+$/, "")}/${child}`);
}

/** Apply policy both before and after resolving symlinks. */
export async function canonicalPathForPolicy(path: string, resolveCanonical: (path: string) => Promise<string>): Promise<string> {
	assertPathAllowed(path);
	const canonical = await resolveCanonical(path);
	validatePathLike(canonical, "canonical path");
	assertPathAllowed(canonical);
	return canonical;
}
