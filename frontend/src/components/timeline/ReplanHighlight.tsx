import React from 'react';
import { AlertTriangle, ArrowRight, CheckCircle2, Cpu, Key, RefreshCw } from 'lucide-react';

interface ReplanHighlightProps {
  failedWorkflow?: string;
  missingPermission?: string;
  retainedPermissions?: string[];
  reason?: string;
}

export const ReplanHighlight: React.FC<ReplanHighlightProps> = ({
  failedWorkflow = 'payment_checkout',
  missingPermission = 'kms:Decrypt',
  retainedPermissions = ['kms:Decrypt'],
  reason = 'Customer checkout records read from S3 bucket payment-transactions use SSE-KMS customer key.',
}) => {
  return (
    <div className="bg-gradient-to-r from-amber-950/20 via-soc-card to-emerald-950/20 border border-amber-500/40 rounded-lg p-4 my-4 glow-amber">
      <div className="flex items-center justify-between pb-2 border-b border-soc-border/60">
        <div className="flex items-center gap-2">
          <span className="p-1 rounded bg-amber-500/20 text-amber-300">
            <RefreshCw className="w-4 h-4 animate-spin-slow" />
          </span>
          <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">
            Autonomous Replanning Triggered
          </span>
        </div>
        <span className="text-[11px] font-mono text-slate-400 bg-soc-surface px-2 py-0.5 rounded border border-soc-border">
          Pre-Commit Adaptation
        </span>
      </div>

      <p className="text-xs text-slate-300 mt-2.5 leading-relaxed">
        The agent did not follow a rigid static script. When the initial counterfactual simulation
        failed because an unobserved permission was actually required by downstream architecture, the agent
        investigated hidden transitive couplings and adapted its policy proposal.
      </p>

      {/* Progression Flow */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 mt-3 text-xs font-mono">
        {/* Step 1: Simulation Failure */}
        <div className="p-2.5 rounded bg-rose-950/30 border border-rose-500/40 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-rose-400 font-semibold text-[11px]">
              <AlertTriangle className="w-3.5 h-3.5" /> 1. SIMULATION FAILED
            </div>
            <p className="text-[10px] text-rose-200/90 mt-1 font-sans">
              Workflow <span className="font-mono text-rose-300">{failedWorkflow}</span> broke without <span className="font-mono font-bold text-rose-300">{missingPermission}</span>.
            </p>
          </div>
        </div>

        {/* Step 2: Transitive Dependency Discovered */}
        <div className="p-2.5 rounded bg-amber-950/30 border border-amber-500/40 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-[11px]">
              <Key className="w-3.5 h-3.5" /> 2. NEW EVIDENCE
            </div>
            <p className="text-[10px] text-amber-200/90 mt-1 font-sans">
              Cryptographic Coupling: S3 bucket uses SSE-KMS customer key.
            </p>
          </div>
        </div>

        {/* Step 3: Agent Replan */}
        <div className="p-2.5 rounded bg-sky-950/30 border border-sky-500/40 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-sky-400 font-semibold text-[11px]">
              <Cpu className="w-3.5 h-3.5" /> 3. AGENT REPLANS
            </div>
            <p className="text-[10px] text-sky-200/90 mt-1 font-sans">
              Preserve <span className="font-mono text-sky-300 font-semibold">{retainedPermissions.join(', ')}</span>; continue cutting wildcards.
            </p>
          </div>
        </div>

        {/* Step 4: Re-Simulation Passed */}
        <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-500/40 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5" /> 4. SIMULATION PASSED
            </div>
            <p className="text-[10px] text-emerald-200/90 mt-1 font-sans">
              All business workflows verified with zero operational regression.
            </p>
          </div>
        </div>
      </div>

      <div className="mt-2.5 text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
        <ArrowRight className="w-3 h-3 text-amber-400 shrink-0" />
        <span className="truncate">Architectural Reason: {reason}</span>
      </div>
    </div>
  );
};
