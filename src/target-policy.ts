const MAX_TARGET_BYTES = 512;

function hasControlChars(value: string): boolean {
	return /[\x00-\x1f\x7f]/.test(value);
}

/** Validate and normalize one exact OpenSSH destination argument. */
export function normalizeSshTarget(raw: string): string {
	const target = raw.trim();
	if (!target) throw new Error("SSH target is empty");
	if (Buffer.byteLength(target) > MAX_TARGET_BYTES) throw new Error(`SSH target exceeds ${MAX_TARGET_BYTES} bytes`);
	if (hasControlChars(target)) throw new Error("SSH target contains control characters");
	if (target.startsWith("-")) throw new Error("SSH target must not begin with '-' or be an SSH option");
	if (/\s/.test(target)) throw new Error("SSH target must be one destination without whitespace");
	if (target.includes(":")) throw new Error("SSH read-only v1 accepts only an SSH target, not target:/path or IPv6 syntax");
	return target;
}

export type ParsedTargetList = {
	targets: Set<string>;
	rejected: number;
};

/** Parse an environment-provided exact-target list without exposing invalid values to prompts. */
export function parseSshTargetList(raw: string | undefined): ParsedTargetList {
	const targets = new Set<string>();
	let rejected = 0;
	for (const entry of (raw ?? "").split(",")) {
		if (!entry.trim()) continue;
		try {
			targets.add(normalizeSshTarget(entry));
		} catch {
			rejected++;
		}
	}
	return { targets, rejected };
}
