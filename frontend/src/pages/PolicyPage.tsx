import React from 'react';
import { AgentRunResponse } from '../types';

export const PolicyPage: React.FC<{ displayRun: AgentRunResponse | null }> = ({ displayRun }) => {
  const diff = displayRun?.policy_diff;

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8">
      <div className="text-[11px] font-mono tracking-[0.25em] text-slate-600">POLICY</div>
      <h1 className="mt-2 text-2xl font-bold text-white tracking-tight">
        {displayRun ? `Final policy · ${displayRun.role_id}` : 'Final policy'}
      </h1>

      {!diff ? (
        <div className="mt-10 text-center">
          <p className="text-sm text-slate-400">No policy produced yet.</p>
          <p className="mt-1 text-xs font-mono text-slate-600">Run an assessment first — its diff lands here.</p>
        </div>
      ) : (
        <>
          <p className="mt-1 text-sm text-slate-400">
            <span className="font-mono text-slate-200">{diff.from_version} → {diff.to_version ?? '…'}</span>
            {' '}· {diff.removed.length} removed · {diff.kept.length} kept
            {diff.added.length > 0 && <> · {diff.added.length} added</>}
          </p>

          {diff.removed.length > 0 && (
            <div className="mt-6 rounded-lg border border-white/10 bg-white/[0.02] p-4">
              <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">REMOVED</div>
              <ul className="mt-3 space-y-3">
                {diff.removed.map((p) => (
                  <li key={p}>
                    <code className="text-[13px] font-mono text-rose-300">− {p}</code>
                    <p className="mt-0.5 text-[13px] text-slate-400 leading-relaxed">
                      {diff.why_removed?.[p] ?? 'No recorded justification.'}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="mt-3 rounded-lg border border-white/10 bg-white/[0.02] p-4">
            <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">KEPT</div>
            <ul className="mt-3 space-y-3">
              {diff.kept.map((p) => (
                <li key={p}>
                  <code className="text-[13px] font-mono text-emerald-300">+ {p}</code>
                  <p className="mt-0.5 text-[13px] text-slate-400 leading-relaxed">
                    {diff.why_kept?.[p] ?? 'No recorded justification.'}
                  </p>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  );
};
