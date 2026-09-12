import React from 'react';
import { SecurityGateResult } from '../../types';
import { CheckCircle2, Lock, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';

interface SecurityKernelPanelProps {
  decision?: SecurityGateResult;
  stopReason?: string;
}

export const SecurityKernelPanel: React.FC<SecurityKernelPanelProps> = ({ decision, stopReason }) => {
  const isBlocked =
    (decision && !decision.allowed) ||
    stopReason === 'security_block' ||
    stopReason === 'provider_mismatch' ||
    stopReason === 'privilege_expansion_blocked';

  const violated = decision?.violated_invariants || [];
  const reasonCodes = decision?.reason_codes || [];

  const checks = [
    {
      label: 'No privilege expansion detected',
      passed: !violated.some((v) => v.includes('PRIVILEGE_EXPANSION')) && !reasonCodes.some((r) => r.includes('privilege_expansion')),
      detail: 'Wildcards, actions, resource scopes, and conditions strictly bounded',
    },
    {
      label: 'Protected permissions preserved',
      passed: stopReason !== 'security_block' && !violated.some((v) => v.includes('PROTECTED_PERMISSION')),
      detail: 'Sensitive administrative capabilities (iam:CreateRole, etc.) protected from removal',
    },
    {
      label: 'Evidence sufficiency verified',
      passed: !violated.some((v) => v.includes('MUTATION_WITHOUT_EVIDENCE')),
      detail: 'Fail-closed on unobserved or unproven permissions',
    },
    {
      label: 'Counterfactual simulation passed',
      passed: !violated.some((v) => v.includes('MUTATION_WITHOUT_SIMULATION')),
      detail: 'Business workflows and downstream dependencies tested before change',
    },
    {
      label: 'Pre-apply regression test suite passed',
      passed: !violated.some((v) => v.includes('PRE_APPLY_VERIFICATION')),
      detail: 'Positive functional tests & negative security boundary tests passed',
    },
    {
      label: 'Fresh state optimistic concurrency check',
      passed: !violated.some((v) => v.includes('STALE_STATE')),
      detail: 'Active policy version matches baseline expected at proposal time',
    },
    {
      label: 'Provider tenant isolation validated',
      passed: stopReason !== 'provider_mismatch' && !violated.some((v) => v.includes('CROSS_PROVIDER')),
      detail: 'Mutations restricted to targeted cloud provider environment',
    },
  ];

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <div>
          <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-rose-400" />
            Deterministic Security Kernel Gate
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
            Authoritative Control Layer (Overrides AI Reasoner)
          </p>
        </div>

        <span
          className={`px-3 py-1 rounded text-xs font-mono font-bold uppercase border flex items-center gap-1.5 ${
            isBlocked
              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
              : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
          }`}
        >
          {isBlocked ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
          FINAL DECISION: {isBlocked ? 'BLOCKED' : 'PASS'}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 mt-3">
        {checks.map((chk, idx) => (
          <div
            key={idx}
            className={`p-2.5 rounded border flex items-start gap-2 text-xs transition-colors ${
              chk.passed
                ? 'bg-soc-surface/80 border-soc-border text-slate-200'
                : 'bg-rose-950/20 border-rose-500/40 text-rose-200'
            }`}
          >
            {chk.passed ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>
              <span className="font-medium font-sans block">{chk.label}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">{chk.detail}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-3.5 pt-2.5 border-t border-soc-border/60 flex items-center justify-between text-[11px] text-soc-muted">
        <span className="font-mono">Security Model Principle:</span>
        <span className="font-semibold text-rose-300 font-mono">
          AI proposes; deterministic security controls decide.
        </span>
      </div>
    </div>
  );
};
