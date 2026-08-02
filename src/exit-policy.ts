export function boundedReadFailed(code: number | null): boolean {
	// A producer feeding head/tail may receive SIGPIPE after the requested bound
	// has been satisfied. Linux/POSIX shells conventionally report SIGPIPE as 141.
	return code !== 0 && code !== 141;
}

export function grepFailed(code: number | null): boolean {
	return code !== 0 && code !== 1;
}

export function locateFailed(code: number | null, stderr: string): boolean {
	return code !== 0 && !(code === 1 && stderr.trim().length === 0);
}

export function systemctlFailed(action: "failed" | "status" | "show" | "list", code: number | null): boolean {
	return code !== 0 && !(action === "status" && code === 3);
}
