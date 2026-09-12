import React from 'react';
import { AlertOctagon, ArrowRight, CheckCircle2, ShieldAlert, UserCheck } from 'lucide-react';

interface BlockedStateViewProps {
  stopReason?: string;
  reasonText?: string;
  invariants?: string[];
  requiredAction?: string;
}

export const BlockedStateView: React.FC<BlockedStateViewProps> = ({
  stopReason = 'security_block',
  reasonText = 'Security Kernel intercepted unauthorized attempt to mutate protected administrative capability.',
  invariants = ['INVARIANT_NO_PROTECTED_PERMISSION_MUTATION'],
  requiredAction = 'Human in-the-loop security administrator approval required for administrative permission changes.',
}) => {
  return (
    <div className="bg-rose-950/25 border-2 border-rose-500/50 rounded-lg p-5 my-4 glow-rose">
      <div className="flex items-center justify-between pb-3 border-b border-rose-500/30">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-rose-500/20 text-rose-300">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-rose-200 tracking-wide uppercase font-mono">
              Autonomous Action Blocked by Security Kernel
            </h3>
            <span className="text-[11px] text-rose-300/80 font-sans">
              Authoritative Security Invariant Preserved — Zero State Modified
            </span>
          </div>
        </div>

        <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
          SAFETY FEATURE ENFORCED
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 text-xs">
        <div className="p-3 rounded bg-soc-surface/80 border border-soc-border">
          <span className="text-[11px] text-soc-muted font-mono uppercase block">Security Trigger</span>
          <span className="font-semibold text-white mt-1 block font-mono">
            {stopReason.toUpperCase()}
          </span>
          <p className="text-[11px] text-slate-400 mt-1">{reasonText}</p>
        </div>

        <div className="p-3 rounded bg-soc-surface/80 border border-soc-border">
          <span className="text-[11px] text-soc-muted font-mono uppercase block">Violated Invariant</span>
          <span className="font-semibold text-rose-400 mt-1 block font-mono text-[11px]">
            {invariants.join(', ')}
          </span>
          <p className="text-[11px] text-slate-400 mt-1">
            Deterministic rule prohibits autonomous reduction of sensitive admin actions.
          </p>
        </div>

        <div className="p-3 rounded bg-soc-surface/80 border border-soc-border">
          <span className="text-[11px] text-soc-muted font-mono uppercase block">Required Safe Action</span>
          <span className="font-semibold text-amber-300 mt-1 block font-mono flex items-center gap-1">
            <UserCheck className="w-3.5 h-3.5" /> Human Approval
          </span>
          <p className="text-[11px] text-slate-400 mt-1">{requiredAction}</p>
        </div>
      </div>

      <div className="mt-3.5 pt-2.5 border-t border-rose-500/20 text-[11px] text-slate-300 font-sans">
        <strong>Important Architecture Note:</strong> This is a product safety feature, not an unexpected system failure.
        The Security Kernel is designed to fail closed whenever an invariant boundary is challenged.
      </div>
    </div>
  );
};
