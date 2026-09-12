import React from 'react';
import { AlertTriangle, ArrowRight, CheckCircle2, RotateCcw, ShieldCheck } from 'lucide-react';

interface RollbackStateViewProps {
  roleId?: string;
  restoredVersion?: string;
  violations?: string[];
}

export const RollbackStateView: React.FC<RollbackStateViewProps> = ({
  roleId = 'PaymentServiceRole',
  restoredVersion = 'v1',
  violations = ['Regression test failed: payment_checkout requires kms:Decrypt'],
}) => {
  return (
    <div className="bg-amber-950/25 border-2 border-amber-500/50 rounded-lg p-5 my-4 glow-amber">
      <div className="flex items-center justify-between pb-3 border-b border-amber-500/30">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-amber-500/20 text-amber-300">
            <RotateCcw className="w-5 h-5 animate-spin-slow" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-amber-200 tracking-wide uppercase font-mono">
              Automated Rollback Executed &amp; Verified
            </h3>
            <span className="text-[11px] text-amber-300/80 font-sans">
              Post-Apply Verification Failure Triggered Atomic Reversion
            </span>
          </div>
        </div>

        <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
          ROLLBACK SUCCESSFUL
        </span>
      </div>

      {/* Progression Steps */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5 mt-4 text-xs font-mono">
        <div className="p-2.5 rounded bg-soc-surface border border-soc-border">
          <span className="text-[10px] text-soc-muted uppercase block">1. CHANGE APPLIED</span>
          <span className="font-semibold text-slate-200 mt-1 block">Candidate Policy</span>
          <span className="text-[10px] text-slate-400">Mutated active role</span>
        </div>

        <div className="p-2.5 rounded bg-rose-950/40 border border-rose-500/40">
          <span className="text-[10px] text-rose-300 uppercase block">2. VERIFY FAILED</span>
          <span className="font-semibold text-rose-200 mt-1 block">Regression Caught</span>
          <span className="text-[10px] text-rose-300/80">Workflow failed</span>
        </div>

        <div className="p-2.5 rounded bg-amber-950/40 border border-amber-500/40">
          <span className="text-[10px] text-amber-300 uppercase block">3. ROLLBACK TRIGGER</span>
          <span className="font-semibold text-amber-200 mt-1 block">Atomic Revert</span>
          <span className="text-[10px] text-amber-300/80">Target: {restoredVersion}</span>
        </div>

        <div className="p-2.5 rounded bg-soc-surface border border-soc-border">
          <span className="text-[10px] text-soc-muted uppercase block">4. RESTORE VERSION</span>
          <span className="font-semibold text-slate-200 mt-1 block">Version {restoredVersion} Active</span>
          <span className="text-[10px] text-slate-400">Baseline restored</span>
        </div>

        <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-500/40">
          <span className="text-[10px] text-emerald-300 uppercase block">5. INDEPENDENT CHECK</span>
          <span className="font-semibold text-emerald-200 mt-1 block">Restore Confirmed</span>
          <span className="text-[10px] text-emerald-300/80">Zero state drift</span>
        </div>
      </div>

      <div className="mt-3.5 pt-2.5 border-t border-amber-500/20 text-xs text-slate-300 font-sans">
        <strong>Detected Violation:</strong>{' '}
        <span className="font-mono text-rose-300 text-[11px]">{violations.join('; ')}</span>
      </div>
    </div>
  );
};
