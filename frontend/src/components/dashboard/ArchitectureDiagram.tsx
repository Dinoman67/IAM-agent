import React from 'react';
import { Cpu, Layers, Cloud, ShieldCheck, Lock } from 'lucide-react';

export const ArchitectureDiagram: React.FC = () => {
  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
          <Layers className="w-3.5 h-3.5 text-sky-400" />
          Autonomous Cross-Cloud Architecture
        </h3>
        <span className="text-[11px] font-mono text-soc-muted bg-soc-surface px-2 py-0.5 rounded border border-soc-border">
          Deterministic Control Boundary
        </span>
      </div>

      <div className="flex flex-col items-center gap-2 py-1 text-xs">
        {/* Tier 1: Autonomous Agent */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-sky-950/40 border border-sky-500/30 text-sky-200 font-mono shadow-sm">
          <Cpu className="w-3.5 h-3.5 text-sky-400" />
          <span className="font-medium">AUTONOMOUS AGENT</span>
          <span className="text-[10px] text-sky-400/80">(Dynamic Reasoner &amp; Planner)</span>
        </div>

        <div className="w-0.5 h-2.5 bg-soc-border" />

        {/* Tier 2: Common IAM Model */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900 border border-soc-border text-slate-200 font-mono">
          <Layers className="w-3.5 h-3.5 text-indigo-400" />
          <span className="font-medium">COMMON IAM IR MODEL</span>
          <span className="text-[10px] text-slate-400">(Provider-Neutral Semantic Representation)</span>
        </div>

        <div className="w-0.5 h-2.5 bg-soc-border" />

        {/* Tier 3: Multi-Cloud Adapters */}
        <div className="grid grid-cols-3 gap-2 w-full max-w-md">
          <div className="flex flex-col items-center justify-center p-2 rounded bg-soc-surface border border-emerald-500/30 text-center">
            <div className="flex items-center gap-1 text-emerald-300 font-mono font-medium text-[11px]">
              <Cloud className="w-3 h-3" /> AWS Adapter
            </div>
            <span className="text-[10px] text-emerald-400/80 mt-0.5 font-mono">Full Simulation</span>
          </div>

          <div className="flex flex-col items-center justify-center p-2 rounded bg-soc-surface border border-amber-500/30 text-center">
            <div className="flex items-center gap-1 text-amber-300 font-mono font-medium text-[11px]">
              <Cloud className="w-3 h-3" /> GCP Adapter
            </div>
            <span className="text-[10px] text-amber-400/80 mt-0.5 font-mono">Safe Escalation</span>
          </div>

          <div className="flex flex-col items-center justify-center p-2 rounded bg-soc-surface border border-purple-500/30 text-center">
            <div className="flex items-center gap-1 text-purple-300 font-mono font-medium text-[11px]">
              <Cloud className="w-3 h-3" /> Azure Adapter
            </div>
            <span className="text-[10px] text-purple-400/80 mt-0.5 font-mono">RBAC Assignment</span>
          </div>
        </div>

        <div className="w-0.5 h-2.5 bg-soc-border" />

        {/* Tier 4: Security Engine */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900 border border-soc-border text-slate-200 font-mono">
          <Lock className="w-3.5 h-3.5 text-amber-400" />
          <span className="font-medium">SIMULATION &amp; VERIFICATION ENGINE</span>
        </div>

        <div className="w-0.5 h-2.5 bg-soc-border" />

        {/* Tier 5: Security Kernel */}
        <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-md bg-rose-950/40 border border-rose-500/40 text-rose-200 font-mono shadow-sm">
          <ShieldCheck className="w-4 h-4 text-rose-400" />
          <span className="font-bold tracking-wide">DETERMINISTIC SECURITY KERNEL</span>
          <span className="text-[10px] text-rose-300/80">(Authoritative Gate)</span>
        </div>
      </div>

      <div className="mt-3 pt-2.5 border-t border-soc-border/60 flex items-center justify-between text-[11px] text-soc-muted">
        <span>Architectural Invariant:</span>
        <span className="font-mono text-sky-300 font-medium">AI proposes; deterministic security controls decide.</span>
      </div>
    </div>
  );
};
