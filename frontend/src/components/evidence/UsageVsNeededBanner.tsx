import React from 'react';
import { AlertTriangle, Info, Shield } from 'lucide-react';

export const UsageVsNeededBanner: React.FC = () => {
  return (
    <div className="bg-sky-950/20 border border-sky-500/30 rounded-lg p-3.5 my-3 flex items-start gap-3">
      <div className="p-1.5 rounded bg-sky-500/20 text-sky-300 shrink-0 mt-0.5">
        <Info className="w-4 h-4" />
      </div>
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold text-sky-300 uppercase tracking-wide">
            Foundational Principle:
          </span>
          <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono text-xs font-bold border border-amber-500/30">
            NOT_OBSERVED ≠ PROVEN_UNNEEDED
          </span>
        </div>
        <p className="text-xs text-slate-300 mt-1 leading-relaxed">
          Standard IAM tools blindly truncate any permission with 0 log invocations, breaking disaster recovery,
          transitive cryptographic calls, and rare payment workflows. PS10 autonomously runs pre-commit counterfactual simulations
          and dependency graph analyses before any permission is removed.
        </p>
      </div>
    </div>
  );
};
