import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { SshRoController } from "./sshro-controller.ts";

export const SSHRO_APPROVAL_STATE_ENTRY = "sshro-approval-state";
type PersistedApprovalState = { version: 1; targets: string[]; toolsActive: boolean; writeTargets: string[] };

export function approvalSnapshot(controller: SshRoController): PersistedApprovalState {
	return {
		version: 1,
		targets: controller.approved(),
		writeTargets: controller.writeTargets(),
		toolsActive: controller.inspectionToolsActive(),
	};
}

export function latestPersistedApprovalState(ctx: ExtensionContext): PersistedApprovalState | undefined {
	const entries = ctx.sessionManager.getEntries();
	for (let index = entries.length - 1; index >= 0; index--) {
		const entry = entries[index] as { type?: string; customType?: string; data?: unknown };
		if (entry.type !== "custom" || entry.customType !== SSHRO_APPROVAL_STATE_ENTRY) continue;
		// The newest entry is authoritative, including when it is invalid. Never
		// resurrect earlier grants after corruption or an unsupported version.
		if (!entry.data || typeof entry.data !== "object") return undefined;
		const data = entry.data as { version?: unknown; targets?: unknown; toolsActive?: unknown; writeTargets?: unknown };
		if (data.version !== undefined && data.version !== 1) return undefined;
		if (!Array.isArray(data.targets) || !data.targets.every((target) => typeof target === "string")) return undefined;
		const writeTargets = data.writeTargets === undefined ? [] : data.writeTargets;
		if (!Array.isArray(writeTargets) || !writeTargets.every((target) => typeof target === "string")) return undefined;
		return { version: 1, targets: data.targets, toolsActive: data.toolsActive === true, writeTargets };
	}
	return undefined;
}
