import React from 'react';
import { SecurityGateResult } from '../../types';
import { AlertTriangle, CheckCircle2, HelpCircle, Shield, ShieldAlert, ShieldCheck } from 'lucide-react';

interface SecurityAssessmentCardProps {
  decision?: SecurityGateResult;
  riskLevel?: string;
  confidence?: number;
  blastRadius?: string;
  isBlocked?: boolean;
}

export const SecurityAssessmentCard: React.FC<SecurityAssessmentCardProps> = ({
  decision,
  riskLevel = 'medium',
  confidence = 0.94,
  blastRadius = 'LOW',
  isBlocked = false,
}) => {
  const isApproved = decision ? decision.allowed : !isBlocked;
  const decisionText = decision ? decision.decision.toUpperCase() : isBlocked ? 'BLOCKED' : 'APPROVED';

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-sky-400" />
          Security Boundary Assessment
        </h3>
        <span
          className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
            isApproved
              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
              : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
          }`}
        >
          {isApproved ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
          DECISION: {decisionText}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
        {/* Metric 1: Risk Level */}
        <div className="p-3 rounded bg-soc-surface border border-soc-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] text-soc-muted font-medium">
              <span>PRINCIPAL RISK</span>
              <span className="text-[10px] text-slate-500">Post-Assess</span>
            </div>
            <div className="text-lg font-bold font-mono text-amber-400 mt-1 uppercase">
              {riskLevel}
            </div>
          </div>
          <div className="text-[10px] text-slate-400 mt-2">
            Sensitive actions &amp; administrative privilege exposure
          </div>
        </div>

        {/* Metric 2: Confidence */}
        <div className="p-3 rounded bg-soc-surface border border-soc-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] text-soc-muted font-medium">
              <span>EVIDENCE CONFIDENCE</span>
              <span className="text-[10px] text-slate-500">Sufficiency</span>
            </div>
            <div className="text-lg font-bold font-mono text-sky-400 mt-1">
              {Math.round(confidence * 100)}%
            </div>
          </div>
          <div className="text-[10px] text-slate-400 mt-2">
            Workflow coverage &amp; dependency completeness (not safety probability)
          </div>
        </div>

        {/* Metric 3: Blast Radius */}
        <div className="p-3 rounded bg-soc-surface border border-soc-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] text-soc-muted font-medium">
              <span>BLAST RADIUS</span>
              <span className="text-[10px] text-slate-500">Impact</span>
            </div>
            <div
              className={`text-lg font-bold font-mono mt-1 uppercase ${
                blastRadius === 'LOW'
                  ? 'text-emerald-400'
                  : blastRadius === 'MEDIUM'
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {blastRadius}
            </div>
          </div>
          <div className="text-[10px] text-slate-400 mt-2">
            Downstream caller scope &amp; resource boundary containment
          </div>
        </div>

        {/* Metric 4: Security Decision */}
        <div
          className={`p-3 rounded border flex flex-col justify-between ${
            isApproved
              ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
          }`}
        >
          <div>
            <div className="flex items-center justify-between text-[11px] font-medium opacity-80">
              <span>SECURITY DECISION</span>
              <span className="text-[10px]">Kernel Gate</span>
            </div>
            <div className="text-lg font-bold font-mono mt-1">
              {decisionText}
            </div>
          </div>
          <div className="text-[10px] opacity-80 mt-2">
            {isApproved
              ? 'Deterministic invariants satisfied for automated apply'
              : 'Safety invariant triggered; autonomous mutation denied'}
          </div>
        </div>
      </div>
    </div>
  );
};
