import {
	activateSshRoInspectionTools,
	deactivateSshRoInspectionTools,
	type ToolActivationApi,
} from "./tool-activation.ts";

export type ApprovalUiContext = {
	hasUI: boolean;
	ui: {
		confirm(title: string, message: string, options?: { signal?: AbortSignal }): Promise<boolean>;
	};
};

export type ActivationReport = {
	added: string[];
	active: string[];
	blocked: string[];
};

export type SudoCheck = { allowed: boolean; reason: string };

type SshRoControllerOptions = {
	pi: ToolActivationApi;
	whitelistedTargets: () => ReadonlySet<string>;
	validateTarget: (target: string) => void;
	onApprovalsChanged?: (targets: string[]) => void;
};

export class SshRoController {
	readonly #pi: ToolActivationApi;
	readonly #whitelistedTargets: () => ReadonlySet<string>;
	readonly #validateTarget: (target: string) => void;
	readonly #onApprovalsChanged?: (targets: string[]) => void;
	#inspectionToolNames: string[] = [];
	readonly #approvedTargets = new Set<string>();
	readonly #pendingTargetApprovals = new Map<string, Promise<boolean>>();
	#approvalGeneration = 0;
	readonly #remoteCommandCache = new Map<string, string | undefined>();
	readonly #sudoCheckCache = new Map<string, SudoCheck>();

	constructor(options: SshRoControllerOptions) {
		this.#pi = options.pi;
		this.#whitelistedTargets = options.whitelistedTargets;
		this.#validateTarget = options.validateTarget;
		this.#onApprovalsChanged = options.onApprovalsChanged;
	}

	setInspectionToolNames(names: readonly string[]): void {
		this.#inspectionToolNames = [...new Set(names)];
	}

	inspectionToolNames(): string[] {
		return [...this.#inspectionToolNames];
	}

	approved(): string[] {
		return [...this.#approvedTargets].sort();
	}

	availableTargets(): string[] {
		return [...new Set([...this.#whitelistedTargets(), ...this.#approvedTargets])].sort();
	}

	isApproved(target: string): boolean {
		return this.#whitelistedTargets().has(target) || this.#approvedTargets.has(target);
	}

	approveHumanInitiated(target: string): string {
		const trimmed = target.trim();
		this.#validateTarget(trimmed);
		const changed = !this.#approvedTargets.has(trimmed);
		this.#approvedTargets.add(trimmed);
		if (changed) this.#emitApprovals();
		return trimmed;
	}

	restoreApprovals(targets: readonly string[]): void {
		const validated = targets.map((raw) => {
			const target = raw.trim();
			this.#validateTarget(target);
			return target;
		});
		this.#approvedTargets.clear();
		for (const target of validated) this.#approvedTargets.add(target);
	}

	clearApprovals(options: { emit?: boolean } = {}): void {
		const changed = this.#approvedTargets.size > 0;
		this.#approvalGeneration++;
		this.#approvedTargets.clear();
		this.#pendingTargetApprovals.clear();
		if (options.emit !== false && changed) this.#emitApprovals();
	}

	clearCaches(): void {
		this.#remoteCommandCache.clear();
		this.#sudoCheckCache.clear();
	}

	async authorize(target: string, ctx: ApprovalUiContext, signal?: AbortSignal): Promise<string> {
		const trimmed = target.trim();
		this.#validateTarget(trimmed);
		if (this.isApproved(trimmed)) return trimmed;

		let approval = this.#pendingTargetApprovals.get(trimmed);
		if (!approval) {
			if (!ctx.hasUI) {
				throw new Error(`SSH read-only tool call to ${trimmed} requires human approval because it is not whitelisted, but no UI is available.`);
			}
			const generation = this.#approvalGeneration;
			let trackedApproval!: Promise<boolean>;
			trackedApproval = ctx.ui.confirm(
				"Approve SSH read-only tool access?",
				`The agent wants to enable read-only SSH inspection against:\n\n${trimmed}\n\nNo SSH connection is opened by approval. Approval is remembered for this Pi session only and matches this exact target string.`,
				{ signal },
			).then((approved) => {
				if (approved && generation === this.#approvalGeneration) {
					this.#approvedTargets.add(trimmed);
					this.#emitApprovals();
					return true;
				}
				return false;
			}).finally(() => {
				if (this.#pendingTargetApprovals.get(trimmed) === trackedApproval) {
					this.#pendingTargetApprovals.delete(trimmed);
				}
			});
			approval = trackedApproval;
			this.#pendingTargetApprovals.set(trimmed, approval);
		}

		if (!await approval) throw new Error(`SSH read-only tool access to ${trimmed} was denied by the human.`);
		return trimmed;
	}

	activateInspectionTools(): ActivationReport {
		const added = activateSshRoInspectionTools(this.#pi, this.#inspectionToolNames);
		const activeSet = new Set(this.#pi.getActiveTools());
		const active = this.#inspectionToolNames.filter((name) => activeSet.has(name));
		const blocked = this.#inspectionToolNames.filter((name) => !activeSet.has(name));
		return { added, active, blocked };
	}

	deactivateInspectionTools(): string[] {
		return deactivateSshRoInspectionTools(this.#pi, this.#inspectionToolNames);
	}

	activeInspectionToolNames(): string[] {
		const active = new Set(this.#pi.getActiveTools());
		return this.#inspectionToolNames.filter((name) => active.has(name));
	}

	inspectionToolsActive(): boolean {
		return this.activeInspectionToolNames().length > 0;
	}

	getCachedRemoteCommand(key: string): { found: boolean; value: string | undefined } {
		return this.#remoteCommandCache.has(key)
			? { found: true, value: this.#remoteCommandCache.get(key) }
			: { found: false, value: undefined };
	}

	cacheRemoteCommand(key: string, value: string | undefined): void {
		this.#remoteCommandCache.set(key, value);
	}

	getCachedSudoCheck(key: string): SudoCheck | undefined {
		return this.#sudoCheckCache.get(key);
	}

	cacheSudoCheck(key: string, value: SudoCheck): void {
		this.#sudoCheckCache.set(key, value);
	}

	#emitApprovals(): void {
		this.#onApprovalsChanged?.(this.approved());
	}
}
