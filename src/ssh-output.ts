import { randomBytes } from "node:crypto";

const MARKER_NONCE = randomBytes(12).toString("hex");
export const REMOTE_TIME_MARKER = `__PI_SSHRO_REMOTE_TIME_${MARKER_NONCE}__`;
export const REMOTE_STATUS_MARKER = `__PI_SSHRO_PRODUCER_STATUS_${MARKER_NONCE}__`;
export const REMOTE_FILTER_STATUS_MARKER = `__PI_SSHRO_FILTER_STATUS_${MARKER_NONCE}__`;
export const REMOTE_TRUNCATION_MARKER = `__PI_SSHRO_TRUNCATION_${MARKER_NONCE}__`;

export type ParsedRemoteStderr = {
	stderr: string;
	remoteTime?: string;
	remoteTruncation?: { shown: number; total: number };
	code: number | null;
};

export type PipelineFilter = string | { command: string; allowNoMatch?: boolean };

/** Each filter is a separate stage, never an opaque pipeline string. Carry
 * statuses out-of-band so a successful final stage cannot hide earlier errors. */
export function statusPreservingPipeline(command: string, filters: PipelineFilter | PipelineFilter[]): string {
	const stages = (Array.isArray(filters) ? filters : [filters]).map((filter) => {
		const stage = typeof filter === "string" ? { command: filter } : filter;
		const expected = stage.allowNoMatch ? '[ "$__pi_sshro_filter_rc" -eq 1 ] && __pi_sshro_filter_rc=0; ' : "";
		return `{ ${stage.command}; __pi_sshro_filter_rc=$?; ${expected}printf '\n${REMOTE_FILTER_STATUS_MARKER}%s\n' "$__pi_sshro_filter_rc" >&2; }`;
	});
	return [`{ ${command}; __pi_sshro_producer_rc=$?; printf '\n${REMOTE_STATUS_MARKER}%s\n' "$__pi_sshro_producer_rc" >&2; }`, ...stages].join(" | ");
}

/** Drain the producer (preserving its exit status), but disclose omitted rows. */
export function boundedLineFilter(limit: number): string {
	if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("line limit must be a positive safe integer");
	return `awk 'NR <= ${limit} { print } END { if (NR > ${limit}) printf "\\n${REMOTE_TRUNCATION_MARKER}${limit}/%d\\n", NR > "/dev/stderr" }'`;
}

export function parseRemoteStderr(stderr: string, outerCode: number | null): ParsedRemoteStderr {
	let remoteTime: string | undefined;
	let remoteTruncation: ParsedRemoteStderr["remoteTruncation"];
	let producerCode: number | undefined;
	const filterCodes: number[] = [];
	const lines = stderr.split(/\r?\n/).filter((line) => {
		if (line.startsWith(REMOTE_TIME_MARKER)) {
			remoteTime = line.slice(REMOTE_TIME_MARKER.length).trim();
			return false;
		}
		if (line.startsWith(REMOTE_TRUNCATION_MARKER)) {
			const match = /^(\d+)\/(\d+)$/.exec(line.slice(REMOTE_TRUNCATION_MARKER.length).trim());
			if (match) {
				const shown = Number(match[1]);
				const total = Number(match[2]);
				if (Number.isSafeInteger(shown) && Number.isSafeInteger(total) && shown > 0 && total > shown) remoteTruncation = { shown, total };
			}
			return false;
		}
		if (line.startsWith(REMOTE_FILTER_STATUS_MARKER)) {
			const parsed = Number(line.slice(REMOTE_FILTER_STATUS_MARKER.length).trim());
			if (Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 255) filterCodes.push(parsed);
			return false;
		}
		if (line.startsWith(REMOTE_STATUS_MARKER)) {
			const parsed = Number(line.slice(REMOTE_STATUS_MARKER.length).trim());
			if (Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 255) producerCode = parsed;
			return false;
		}
		return true;
	});
	// A real filter error outranks producer/no-match status; SIGPIPE is only
	// significant if no other stage failed. Transport failure outranks both.
	const statuses = [filterCodes.find((code) => code !== 0 && code !== 141), producerCode, ...filterCodes];
	const code = outerCode !== 0 ? outerCode : statuses.find((status) => status !== undefined && status !== 0) ?? 0;
	return { stderr: lines.join("\n").trimEnd(), remoteTime, remoteTruncation, code };
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
