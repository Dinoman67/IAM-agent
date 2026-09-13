import { AgentRunResponse } from '../../types';

/** Halts that need a human: notify + list in Review. Success stays silent. */
export const HALT_STOPS: ReadonlySet<string> = new Set([
  'security_block',
  'provider_mismatch',
  'privilege_expansion_blocked',
  'verification_failure_rolled_back',
  'rollback_failure',
  'unsupported_capability',
  'human_approval_required',
  'high_risk',
  'insufficient_evidence',
  'override_refused',
  'override_verification_failed',
]);

export const isHaltedRun = (stop?: string | null): boolean => !!stop && HALT_STOPS.has(stop);

export const KERNEL_INVARIANTS: string[] = [
  'NO_PRIVILEGE_EXPANSION',
  'NO_PROTECTED_PERMISSION_MUTATION',
  'NO_PROTECTED_RESOURCE_EXPOSURE',
  'NO_CROSS_PROVIDER_MUTATION',
  'NO_CROSS_TENANT_MUTATION',
  'NO_STALE_STATE_MUTATION',
  'NO_MUTATION_WITHOUT_EVIDENCE',
  'NO_MUTATION_WITHOUT_SIMULATION',
  'NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION',
  'NO_COMPLETION_WITHOUT_VERIFICATION',
  'NO_UNAPPROVED_HIGH_RISK',
];

export const KERNEL_CMDS: string[] = ['help', 'status', 'invariants', 'diff', 'allow', 'deny', 'escalate', 'ack'];

const STOP_RULES: Record<string, string> = {
  security_block: 'protected capability removal forbidden',
  provider_mismatch: 'cross-provider mutation forbidden',
  privilege_expansion_blocked: 'privilege expansion forbidden',
  unsupported_capability: 'unsupported provider operation',
  human_approval_required: 'human approval required',
  high_risk: 'sub-threshold confidence — human review required',
  insufficient_evidence: 'insufficient evidence for change',
  verification_failure_rolled_back: 'post-apply verification failed',
  rollback_failure: 'recovery failed',
  override_refused: 'override refused by gate',
  override_verification_failed: 'override verification failed',
};

export interface TierInfo {
  sensitive: boolean;
  rule: string;
}

/** Visual identity per halt kind — so different requests never look alike. */
export const KIND_META: Record<string, { label: string; chip: string; dot: string }> = {
  security_block: { label: 'Safety veto', chip: 'text-rose-300 border-rose-500/40 bg-rose-500/10', dot: 'bg-rose-400' },
  provider_mismatch: { label: 'Boundary block', chip: 'text-violet-300 border-violet-500/40 bg-violet-500/10', dot: 'bg-violet-400' },
  privilege_expansion_blocked: { label: 'Expansion blocked', chip: 'text-rose-300 border-rose-500/40 bg-rose-500/10', dot: 'bg-rose-400' },
  verification_failure_rolled_back: { label: 'Rolled back', chip: 'text-sky-300 border-sky-500/40 bg-sky-500/10', dot: 'bg-sky-400' },
  rollback_failure: { label: 'Recovery failed', chip: 'text-rose-300 border-rose-500/40 bg-rose-500/10', dot: 'bg-rose-400' },
  unsupported_capability: { label: 'Needs capability', chip: 'text-slate-300 border-white/20 bg-white/[0.04]', dot: 'bg-slate-400' },
  human_approval_required: { label: 'Needs approval', chip: 'text-amber-300 border-amber-500/40 bg-amber-500/10', dot: 'bg-amber-300' },
  high_risk: { label: 'Low-confidence hold', chip: 'text-amber-300 border-amber-500/40 bg-amber-500/10', dot: 'bg-amber-300' },
  insufficient_evidence: { label: 'Needs evidence', chip: 'text-amber-300 border-amber-500/40 bg-amber-500/10', dot: 'bg-amber-300' },
  override_refused: { label: 'Override refused', chip: 'text-rose-300 border-rose-500/40 bg-rose-500/10', dot: 'bg-rose-400' },
  override_verification_failed: { label: 'Override failed', chip: 'text-rose-300 border-rose-500/40 bg-rose-500/10', dot: 'bg-rose-400' },
};

export function kindOf(stop?: string | null): { label: string; chip: string; dot: string } {
  if (stop && KIND_META[stop]) return KIND_META[stop];
  const label = stop ? stop.replace(/_/g, ' ') : 'halted';
  return { label, chip: 'text-slate-300 border-white/20 bg-white/[0.04]', dot: 'bg-slate-400' };
}

export interface RecordedProposal {
  remove: string[];
  keep: string[];
  source: 'diff' | 'replan' | 'candidate' | 'attempted' | null;
}

/** What the simulation actually asked for. Halted pre-apply runs have no
 *  policy_diff — their proposal lives in replans[] / candidate_policy_changes[].
 *  Runs halted at the gate before proposing (e.g. safety-block) only leave the
 *  attempted mutation inside tool_called audit events — shown for transparency,
 *  never approvable. */
export function recordedProposal(run: AgentRunResponse | null): RecordedProposal {
  const diff = run?.policy_diff;
  if (diff && ((diff.removed?.length ?? 0) + (diff.kept?.length ?? 0) > 0)) {
    return { remove: diff.removed ?? [], keep: diff.kept ?? [], source: 'diff' };
  }
  const pick = (e: any): RecordedProposal | null => {
    if (!e) return null;
    const remove: string[] = e.remove_permissions ?? [];
    const keep: string[] = e.proposed_permissions ?? [];
    if (remove.length === 0 && keep.length === 0) return null;
    return { remove, keep, source: 'replan' };
  };
  const replans = run?.replans ?? [];
  const fromReplan = pick(replans[replans.length - 1]);
  if (fromReplan) return fromReplan;
  const cands = run?.candidate_policy_changes ?? [];
  const fromCand = pick(cands[cands.length - 1]);
  if (fromCand) return { ...fromCand, source: 'candidate' };
  // Last resort: the attempted mutation from the audit trail (display only).
  const attempted = attemptedChange(run);
  if (attempted.remove.length > 0) return { ...attempted, source: 'attempted' };
  return { remove: [], keep: [], source: null };
}

/** True only when the backend override endpoint could accept this run:
 *  a recorded candidate/replan proposal exists. Attempted-only mutations
 *  (gate halts with no proposal) are display-only by design. */
export function hasApprovableProposal(run: AgentRunResponse | null): boolean {
  const replans = run?.replans ?? [];
  const lastReplan = replans[replans.length - 1];
  if (lastReplan && ((lastReplan.remove_permissions?.length ?? 0) + (lastReplan.proposed_permissions?.length ?? 0) > 0)) return true;
  const cands = run?.candidate_policy_changes ?? [];
  const lastCand = cands[cands.length - 1];
  if (lastCand && ((lastCand.remove_permissions?.length ?? 0) + (lastCand.proposed_permissions?.length ?? 0) > 0)) return true;
  return false;
}

/** The mutation the agent attempted, recovered from tool_called audit events.
 *  Present even when the gate halted before any proposal was recorded. */
export function attemptedChange(run: AgentRunResponse | null): { remove: string[]; keep: string[] } {
  const events = run?.events ?? [];
  for (let i = events.length - 1; i >= 0; i--) {
    const e: any = events[i];
    if (e?.event_type === 'tool_called' && e?.tool === 'apply_policy_change' && e?.arguments) {
      const args = e.arguments;
      const remove: string[] = Array.isArray(args.remove_permissions) ? args.remove_permissions : [];
      const keep: string[] = Array.isArray(args.new_permissions)
        ? args.new_permissions
        : Array.isArray(args.keep_permissions)
          ? args.keep_permissions
          : [];
      if (remove.length > 0 || keep.length > 0) return { remove, keep };
    }
  }
  return { remove: [], keep: [] };
}

export interface KindNarrative {
  headline: string;
  whatHappened: string;
  whatNext: string;
}

/** Per-halt-kind story — the Review page never speaks generically. */
export const KIND_NARRATIVE: Record<string, KindNarrative> = {
  security_block: {
    headline: 'An unsafe change was stopped before anything was applied.',
    whatHappened: 'The agent proposed removing a protected administrative capability, and the kernel vetoed the mutation.',
    whatNext: 'Nothing changed. This kind cannot be approved in-product — run a least-privilege assessment instead.',
  },
  provider_mismatch: {
    headline: 'A cross-cloud mutation was intercepted.',
    whatHappened: 'A policy destined for one provider was aimed at another, and the kernel halted it at the boundary.',
    whatNext: 'Nothing changed. Re-run against the matching provider.',
  },
  privilege_expansion_blocked: {
    headline: 'A proposal that added permissions was blocked.',
    whatHappened: 'Least privilege only ever removes. The candidate granted new authority, so the kernel denied it.',
    whatNext: 'Nothing changed. Narrow the proposal to removals only.',
  },
  verification_failure_rolled_back: {
    headline: 'A bad policy was applied, caught, and automatically restored.',
    whatHappened: 'Post-apply verification failed, so the engine rolled back to the last good version and proved the restore.',
    whatNext: 'State is safe on the restored version. Inspect the failure, then re-run.',
  },
  rollback_failure: {
    headline: 'Recovery itself failed — this needs a human now.',
    whatHappened: 'Verification failed after apply, and the automated rollback could not be completed or confirmed.',
    whatNext: 'Do not re-run blindly. Inspect the run events, restore manually, then reassess.',
  },
  unsupported_capability: {
    headline: 'The provider cannot do what was asked — so nothing was faked.',
    whatHappened: 'A requested operation (such as native simulation) is unsupported, and the run halted rather than hallucinate a result.',
    whatNext: 'Use the labeled local-evaluation path, or run against a supporting provider.',
  },
  human_approval_required: {
    headline: 'A decision needs a person, so the run stopped here.',
    whatHappened: 'The proposal reached a gate that requires explicit human sign-off.',
    whatNext: 'Review the request below and approve or refuse it here.',
  },
  high_risk: {
    headline: 'A valid cleanup held for low confidence.',
    whatHappened: 'Simulation and evidence check out, but certainty sits below the autonomous threshold.',
    whatNext: 'Review the request below — approving applies it as a verified override run.',
  },
  insufficient_evidence: {
    headline: 'There was not enough proof to proceed.',
    whatHappened: 'The evidence gate found removals it could not justify from logs, dependencies, or simulation.',
    whatNext: 'Gather usage evidence or narrow the proposal, then re-run.',
  },
  override_refused: {
    headline: 'A break-glass approval was refused by the gate.',
    whatHappened: 'A human approved this halt, but the proposal violates load-bearing rules that no approval can waive.',
    whatNext: 'This kind cannot be approved in-product, by design.',
  },
  override_verification_failed: {
    headline: 'An approved override failed its own verification.',
    whatHappened: 'The override applied, but post-apply checks did not pass.',
    whatNext: 'Treat state as suspect. Inspect events, restore manually, then reassess.',
  },
};

const FALLBACK_NARRATIVE: KindNarrative = {
  headline: 'This run halted before completing.',
  whatHappened: 'The engine stopped safely rather than proceed.',
  whatNext: 'Inspect the run events, then re-run or escalate.',
};

export function narrativeOf(stop?: string | null): KindNarrative {
  if (stop && KIND_NARRATIVE[stop]) return KIND_NARRATIVE[stop];
  return FALLBACK_NARRATIVE;
}

/** Standard (auto, no human) vs Sensitive (human required) — display-only. */
export function getTier(
  run: AgentRunResponse | null,
  decision: string,
  blast: string,
): TierInfo {
  if (!run) return { sensitive: false, rule: '' };
  const stop = run.stop_reason ?? '';
  const blastHigh = blast === 'HIGH' || blast === 'CRITICAL';
  const gateDenied = decision !== '' && decision !== 'allow';
  const sensitive = gateDenied || blastHigh || STOP_RULES[stop] !== undefined;
  const rule =
    STOP_RULES[stop] ??
    (gateDenied ? `gate ${decision}` : blastHigh ? `blast radius ${blast}` : '');
  return { sensitive, rule };
}

/** Human-readable gate summary lines for a halted run. */
export function gateLines(run: AgentRunResponse): { decision: string; blast: string; codes: string[] } {
  const checks = [...run.events].reverse().filter((e) => e.event_type === 'security_check');
  const d: any = checks[0]?.details ?? run.security_decision ?? {};
  const codes: string[] = d.reason_codes ?? [];
  return {
    decision: String(d.decision ?? ''),
    blast: String(d.blast_radius ?? run.blast_radius ?? '—'),
    codes,
  };
}
