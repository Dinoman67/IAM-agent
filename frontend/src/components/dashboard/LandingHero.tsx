import React from 'react';
import { Activity, ArrowRight, Play, Shield, ShieldCheck, Sparkles, Terminal } from 'lucide-react';

interface LandingHeroProps {
  onRunDemo: () => void;
  onViewArchitecture: () => void;
  isRunning?: boolean;
}

export const LandingHero: React.FC<LandingHeroProps> = ({ onRunDemo, onViewArchitecture, isRunning = false }) => {
  return (
    <div className="bg-gradient-to-r from-soc-card via-[#131D2E] to-soc-card border border-soc-border rounded-lg p-6 glow-subtle">
      <div className="max-w-4xl">
        <div className="flex items-center gap-2 mb-2">
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-sky-500/10 text-sky-400 border border-sky-500/30">
            <Shield className="w-3 h-3 text-sky-400" /> PS10 AUTONOMOUS CLOUD IAM
          </span>
          <span className="text-xs text-soc-muted font-mono">Closed-Loop Least-Privilege Engine</span>
        </div>

        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight leading-tight">
          Autonomous IAM Least-Privilege Remediation
        </h1>

        <p className="text-sm text-slate-300 mt-2 leading-relaxed">
          Traditional IAM security tools blindly strip unused permissions, breaking critical business workflows.
          <span className="text-white font-medium"> PS10 autonomously investigates permissions, counterfactually tests proposed changes, discovers hidden downstream dependencies, replans,</span> and submits proposals to a deterministic Security Kernel before enforcement.
        </p>

        {/* Core Differentiator Callouts */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-4 text-xs font-mono">
          <div className="p-2.5 rounded bg-soc-surface/80 border border-soc-border">
            <span className="text-sky-400 font-bold block">1. TEST BEFORE ENFORCE</span>
            <span className="text-slate-400 text-[11px] font-sans">
              Counterfactual simulation exposes broken dependencies before touching cloud state.
            </span>
          </div>

          <div className="p-2.5 rounded bg-soc-surface/80 border border-soc-border">
            <span className="text-amber-400 font-bold block">2. AUTONOMOUS REPLANNING</span>
            <span className="text-slate-400 text-[11px] font-sans">
              Adapts dynamically when unobserved permissions are required by downstream architecture.
            </span>
          </div>

          <div className="p-2.5 rounded bg-soc-surface/80 border border-soc-border">
            <span className="text-rose-400 font-bold block">3. DETERMINISTIC KERNEL</span>
            <span className="text-slate-400 text-[11px] font-sans">
              AI proposes mutations; independent invariant gates decide and enforce.
            </span>
          </div>
        </div>

        {/* CTAs */}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button
            type="button"
            onClick={onRunDemo}
            disabled={isRunning}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold text-sm transition-all shadow-lg shadow-sky-950/60 cursor-pointer disabled:opacity-50"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Running Killer Demo...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-sky-200" />
                <span>Run Guided Demo (PaymentServiceRole)</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={onViewArchitecture}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-soc-surface hover:bg-slate-800 text-slate-300 font-mono text-xs border border-soc-border transition-colors cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5 text-slate-400" />
            <span>Multi-Cloud Parity Matrix</span>
          </button>
        </div>
      </div>
    </div>
  );
};
