import React from 'react';
import { PolicyDiff, VerificationResult } from '../../types';
import { ArrowRight, CheckCircle2, FileCode, Lock, Shield, ShieldCheck } from 'lucide-react';
import { RawPolicyViewer } from './RawPolicyViewer';

interface PolicyDiffViewProps {
  diff?: PolicyDiff;
  roleId: string;
  verification?: VerificationResult;
}

export const PolicyDiffView: React.FC<PolicyDiffViewProps> = ({ diff, roleId, verification }) => {
  if (!diff) {
    return (
      <div className="bg-soc-card/70 border border-soc-border rounded-lg p-6 text-center text-xs text-soc-muted font-mono">
        Policy diff will be generated once remediation proposals are formulated and verified.
      </div>
    );
  }

  const removed = diff.removed || [];
  const kept = diff.kept || [];
  const added = diff.added || [];
  const isVerified = verification?.passed || false;

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-soc-border/60">
        <div>
          <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-sky-400" />
            IAM Policy Remediation Diff: {roleId}
          </h3>
          <span className="text-[11px] font-mono text-soc-muted">
            Version Transition: <strong className="text-slate-200">{diff.from_version}</strong> →{' '}
            <strong className="text-emerald-300">{diff.to_version || 'v2'}</strong> ({diff.provider.toUpperCase()})
          </span>
        </div>

        {/* Security Validation Status */}
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${
              isVerified
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            {isVerified ? 'VERIFIED LEAST PRIVILEGE' : 'SECURITY VALIDATED'}
          </span>
        </div>
      </div>

      {/* Semantic Summary Pill Row */}
      <div className="flex items-center gap-2 my-3 text-xs font-mono">
        <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30">
          -{removed.length} Removed
        </span>
        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
          +{kept.length} Preserved
        </span>
        {added.length > 0 && (
          <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/30">
            +{added.length} Scoped
          </span>
        )}
        <span className="ml-auto text-[11px] text-slate-400">
          {removed.length + kept.length} → {kept.length} permissions
        </span>
      </div>

      {/* Side-by-side Before and After Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2 font-mono text-xs">
        {/* Before Column */}
        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
          <div className="flex items-center justify-between pb-2 border-b border-soc-border/60 text-[11px] font-semibold text-slate-400 uppercase">
            <span>PRE-REMEDIATION POLICY ({diff.from_version})</span>
            <span>{removed.length + kept.length} Grants</span>
          </div>

          <div className="space-y-1.5 mt-2.5">
            {removed.map((perm) => (
              <div
                key={perm}
                className="p-1.5 rounded bg-rose-950/30 border border-rose-500/30 flex items-center justify-between gap-2 text-rose-200"
              >
                <span className="font-semibold">{perm}</span>
                <span className="text-[10px] uppercase font-bold text-rose-400 bg-rose-950 px-1.5 py-0.5 rounded border border-rose-800">
                  REMOVED
                </span>
              </div>
            ))}
            {kept.map((perm) => (
              <div
                key={perm}
                className="p-1.5 rounded bg-slate-800/80 border border-slate-700 flex items-center justify-between gap-2 text-slate-300"
              >
                <span>{perm}</span>
                <span className="text-[10px] text-slate-400">Baseline</span>
              </div>
            ))}
          </div>
        </div>

        {/* After Column */}
        <div className="p-3 rounded-lg bg-soc-surface border border-emerald-500/30">
          <div className="flex items-center justify-between pb-2 border-b border-soc-border/60 text-[11px] font-semibold text-emerald-400 uppercase">
            <span>LEAST-PRIVILEGE TARGET ({diff.to_version || 'v2'})</span>
            <span>{kept.length + added.length} Grants</span>
          </div>

          <div className="space-y-1.5 mt-2.5">
            {kept.map((perm) => {
              const isKms = perm === 'kms:Decrypt';
              return (
                <div
                  key={perm}
                  className={`p-1.5 rounded border flex items-center justify-between gap-2 ${
                    isKms
                      ? 'bg-amber-950/30 border-amber-500/40 text-amber-200'
                      : 'bg-emerald-950/30 border-emerald-500/30 text-emerald-200'
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    {isKms && <Lock className="w-3 h-3 text-amber-400" />}
                    <span className="font-semibold">{perm}</span>
                  </div>
                  <span
                    className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                      isKms
                        ? 'text-amber-300 bg-amber-950 border-amber-800'
                        : 'text-emerald-300 bg-emerald-950 border-emerald-800'
                    }`}
                  >
                    {isKms ? 'PRESERVED (COUPLING)' : 'PRESERVED'}
                  </span>
                </div>
              );
            })}

            {added.map((perm) => (
              <div
                key={perm}
                className="p-1.5 rounded bg-sky-950/30 border border-sky-500/30 flex items-center justify-between gap-2 text-sky-200"
              >
                <span className="font-semibold">{perm}</span>
                <span className="text-[10px] uppercase font-bold text-sky-400 bg-sky-950 px-1.5 py-0.5 rounded border border-sky-800">
                  ADDED (SCOPED)
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Semantic Justifications */}
      <div className="mt-4 pt-3 border-t border-soc-border/60 text-xs">
        <h4 className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-2">
          Deterministic Justifications:
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
          {Object.entries(diff.why_removed || {}).map(([p, reason]) => (
            <div key={p} className="p-2 rounded bg-soc-surface border border-soc-border">
              <span className="font-mono text-rose-300 font-semibold">{p}</span>:
              <p className="text-slate-400 mt-0.5">{reason}</p>
            </div>
          ))}
          {Object.entries(diff.why_kept || {}).map(([p, reason]) => (
            <div key={p} className="p-2 rounded bg-soc-surface border border-soc-border">
              <span className="font-mono text-emerald-300 font-semibold">{p}</span>:
              <p className="text-slate-400 mt-0.5">{reason}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Optional Raw JSON inspection */}
      <RawPolicyViewer diff={diff} />
    </div>
  );
};
