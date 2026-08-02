export const SSHRO_CONNECT_TOOL_NAME = "sshro_connect";

export type ToolActivationApi = {
	getActiveTools(): string[];
	setActiveTools(names: string[]): void;
};

export function activateSshRoInspectionTools(pi: ToolActivationApi, inspectionToolNames: readonly string[]): string[] {
	const active = pi.getActiveTools();
	const activeSet = new Set(active);
	const requested = inspectionToolNames.filter((name) => !activeSet.has(name));
	if (requested.length === 0) return [];
	pi.setActiveTools([...active, ...requested]);
	const activeAfter = new Set(pi.getActiveTools());
	return requested.filter((name) => activeAfter.has(name));
}

export function deactivateSshRoInspectionTools(pi: ToolActivationApi, inspectionToolNames: readonly string[]): string[] {
	const inspectionNames = new Set(inspectionToolNames);
	const active = pi.getActiveTools();
	const removed = active.filter((name) => inspectionNames.has(name));
	if (removed.length > 0) pi.setActiveTools(active.filter((name) => !inspectionNames.has(name)));
	return removed;
}
