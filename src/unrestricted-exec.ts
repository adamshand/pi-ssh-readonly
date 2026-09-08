import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import Type from "typebox";
import { captureTruncationNote, shellQuote, type SshExecutor } from "./ssh-transport.ts";
import type { SshRoController } from "./sshro-controller.ts";
import { errorResult, textResult } from "./tool-result.ts";

/** Register the deliberately unrestricted capability separately from inspection.
 * Tool activation is discoverability only; every execution checks the grant. */
export function registerUnrestrictedExec(pi: ExtensionAPI, controller: SshRoController, executeSsh: SshExecutor): () => void {
	pi.registerTool({
		name: "ssh_exec",
		label: "SSH unrestricted execution",
		description: "Execute arbitrary POSIX shell commands on an exact target granted write access by the human via /sshro allow-write. No read-only path restrictions or secret redaction. Unapproved targets fail without prompting. Non-interactive; commands start in the remote login directory. Output is bounded to 2,000 lines/50KB. Revocation, cancellation and timeout do not undo changes or guarantee remote processes stop.",
		parameters: Type.Object({
			target: Type.String({ description: "Exact target string granted by the human; aliases and other users are separate targets." }),
			command: Type.String({ minLength: 1, description: "Arbitrary remote POSIX shell script. Use heredocs to write files; no interactive stdin or TTY." }),
			timeout: Type.Optional(Type.Integer({ minimum: 1, maximum: 3600, description: "Timeout in seconds (default 120, maximum 3600)." })),
		}),
		executionMode: "sequential",
		async execute(_id, params, signal) {
			try {
				const target = controller.requireWriteTarget(params.target);
				if (!params.command.trim() || params.command.includes("\0")) throw new Error("command must be nonempty and contain no NUL bytes");
				const timeout = params.timeout ?? 120;
				if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600) throw new Error("timeout must be an integer from 1 to 3600 seconds");
				// A separate shell argument protects the status/time wrapper from
				// comments, heredocs and exit statements in the arbitrary script.
				const result = await executeSsh(target, `sh -c ${shellQuote(params.command)}`, signal, timeout * 1000);
				const output = result.stdout + (result.stderr ? `\n[stderr]\n${result.stderr}` : "") + captureTruncationNote(result);
				return textResult(`${output}\n\n[ssh WRITE: ${target} | exit: ${result.code ?? "unknown"}${result.remoteTime ? ` | remote time: ${result.remoteTime}` : ""}]`, result.code !== 0);
			} catch (err) { return errorResult(err); }
		},
		renderCall(args, theme) {
			const title = theme.fg("toolTitle", theme.bold("ssh_exec"));
			const target = theme.fg("accent", args.target ?? "...");
			const timeout = args.timeout === undefined ? "" : theme.fg("dim", ` · timeout ${args.timeout}s`);
			return new Text(`${title} ${target}${timeout}\n${theme.fg("muted", args.command ?? "...")}`, 0, 0);
		},
	});

	pi.on("before_agent_start", () => {
		const targets = controller.writeTargets();
		if (targets.length === 0) return;
		return { message: { customType: "sshro-write-access", content: `Current session unrestricted SSH grants (use ssh_exec with the exact target): ${targets.join(", ")}. All sshro_* tools remain read-only.`, display: false } };
	});

	return () => {
		const active = pi.getActiveTools().filter((name) => name !== "ssh_exec");
		if (controller.writeTargets().length > 0) active.push("ssh_exec");
		pi.setActiveTools(active);
	};
}
