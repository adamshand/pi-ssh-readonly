import { validatePathLike } from "./path-policy.ts";
import { shellQuote } from "./ssh-transport.ts";

/** Shell quoting and option boundaries are independent protections. */
export function validateOperand(value: string, label: string): void {
	validatePathLike(value, label);
	if (!value || value.startsWith("-")) throw new Error(`${label} must be a nonempty operand, not an option`);
}

export function validateDnsOperand(value: string, label: string): void {
	validateOperand(value, label);
	if (/^[+@]|\s/.test(value)) throw new Error(`${label} must be a DNS name/address, not an option or server selector`);
}

export function commandString(commandPath: string, args: string[]): string {
	return [commandPath, ...args].map(shellQuote).join(" ");
}

export function systemctlArgs(action: "failed" | "list" | "status" | "show", unit?: string): string[] {
	if (unit) validateOperand(unit, "unit");
	if ((action === "status" || action === "show") && !unit) throw new Error(`sshro_systemctl action '${action}' requires unit`);
	switch (action) {
		case "failed": return ["--no-pager", "--plain", "--failed"];
		case "list": return ["--no-pager", "--plain", "list-units", "--type=service", "--all"];
		case "status": return ["--no-pager", "status", "--", unit!];
		case "show": return ["--no-pager", "show", "--property=Id,Names,Description,LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainCode,ExecMainStatus,MainPID,FragmentPath,DropInPaths,Requires,Wants,After,Before,Restart,RestartUSec,StartLimitBurst,StartLimitIntervalUSec", "--", unit!];
		default: throw new Error("Unsupported systemctl action");
	}
}
