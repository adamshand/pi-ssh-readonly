import { randomBytes } from "node:crypto";

const MARKER_NONCE = randomBytes(12).toString("hex");
export const REMOTE_TIME_MARKER = `__PI_SSHRO_REMOTE_TIME_${MARKER_NONCE}__`;
export const REMOTE_STATUS_MARKER = `__PI_SSHRO_PRODUCER_STATUS_${MARKER_NONCE}__`;

export type ParsedRemoteStderr = {
	stderr: string;
	remoteTime?: string;
	code: number | null;
};

/** Keep a producer's status when a POSIX sh pipeline's final filter exits successfully. */
export function statusPreservingPipeline(command: string, filter: string): string {
	return `{ ${command}; __pi_sshro_producer_rc=$?; printf '\n${REMOTE_STATUS_MARKER}%s\n' "$__pi_sshro_producer_rc" >&2; } | ${filter}`;
}

export function parseRemoteStderr(stderr: string, outerCode: number | null): ParsedRemoteStderr {
	let remoteTime: string | undefined;
	let producerCode: number | undefined;
	const lines = stderr.split(/\r?\n/).filter((line) => {
		if (line.startsWith(REMOTE_TIME_MARKER)) {
			remoteTime = line.slice(REMOTE_TIME_MARKER.length).trim();
			return false;
		}
		if (line.startsWith(REMOTE_STATUS_MARKER)) {
			const parsed = Number(line.slice(REMOTE_STATUS_MARKER.length).trim());
			if (Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 255) producerCode = parsed;
			return false;
		}
		return true;
	});
	const code = outerCode !== 0 && outerCode !== null ? outerCode : producerCode ?? outerCode;
	return { stderr: lines.join("\n").trimEnd(), remoteTime, code };
}

/** Bounded process-stream capture that retains a tail for final status markers. */
export class BoundedCapture {
	readonly #maxBytes: number;
	readonly #tailBytes: number;
	readonly #headChunks: Buffer[] = [];
	#headBytes = 0;
	#tail = Buffer.alloc(0);
	#totalBytes = 0;

	constructor(maxBytes: number, tailBytes = Math.min(16 * 1024, Math.floor(maxBytes / 4))) {
		if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("maxBytes must be a positive integer");
		if (!Number.isSafeInteger(tailBytes) || tailBytes < 0 || tailBytes >= maxBytes) throw new Error("tailBytes must be >= 0 and less than maxBytes");
		this.#maxBytes = maxBytes;
		this.#tailBytes = tailBytes;
	}

	push(chunk: Buffer | Uint8Array | string): void {
		const buffer = typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk);
		this.#totalBytes += buffer.length;
		const headLimit = this.#maxBytes - this.#tailBytes;
		if (this.#headBytes < headLimit) {
			const take = Math.min(buffer.length, headLimit - this.#headBytes);
			if (take > 0) {
				this.#headChunks.push(buffer.subarray(0, take));
				this.#headBytes += take;
			}
		}
		if (this.#tailBytes > 0) {
			this.#tail = Buffer.concat([this.#tail, buffer]);
			if (this.#tail.length > this.#tailBytes) this.#tail = this.#tail.subarray(this.#tail.length - this.#tailBytes);
		}
	}

	get totalBytes(): number {
		return this.#totalBytes;
	}

	get truncated(): boolean {
		return this.#totalBytes > this.#maxBytes;
	}

	toBuffer(): Buffer {
		const head = Buffer.concat(this.#headChunks);
		if (this.truncated) return Buffer.concat([head, this.#tail]);
		const overlap = Math.max(0, head.length + this.#tail.length - this.#totalBytes);
		return Buffer.concat([head, this.#tail.subarray(overlap)]);
	}

	toString(): string {
		return this.toBuffer().toString("utf8");
	}
}
