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
