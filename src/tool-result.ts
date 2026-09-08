import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, formatSize, truncateHead } from "@earendil-works/pi-coding-agent";

export function truncateText(text: string, maxLines = DEFAULT_MAX_LINES, maxBytes = DEFAULT_MAX_BYTES): string {
	const truncation = truncateHead(text, { maxLines, maxBytes });
	if (!truncation.truncated) return truncation.content;
	return `${truncation.content}\n\n[ssh-ro output truncated: ${truncation.outputLines}/${truncation.totalLines} lines, ${formatSize(truncation.outputBytes)}/${formatSize(truncation.totalBytes)}]`;
}

/** Last boundary before Pi sees output, including errors and metadata. Reserve
 * space for the truncation notice and keep a bounded target footer visible. */
export function boundedToolText(text: string): string {
	const check = truncateHead(text, { maxLines: DEFAULT_MAX_LINES, maxBytes: DEFAULT_MAX_BYTES });
	if (!check.truncated) return check.content;
	const footerMatch = /\n\n\[ssh(?:-ro| WRITE):[^\n]*\]$/.exec(text);
	const footer = footerMatch ? truncateHead(footerMatch[0], { maxBytes: 1024, maxLines: 3 }).content : "";
	const body = footerMatch ? text.slice(0, footerMatch.index) : text;
	return truncateText(body, DEFAULT_MAX_LINES - 6, DEFAULT_MAX_BYTES - Buffer.byteLength(footer) - 256) + footer;
}

export function textResult(text: string, failed = false) {
	const bounded = boundedToolText(text);
	if (failed) throw new Error(bounded);
	return { content: [{ type: "text" as const, text: bounded }], details: {} };
}

export function errorResult(err: unknown): never {
	const message = err instanceof Error ? err.message : String(err);
	const bounded = boundedToolText(message);
	throw err instanceof Error && bounded === message ? err : new Error(bounded);
}
