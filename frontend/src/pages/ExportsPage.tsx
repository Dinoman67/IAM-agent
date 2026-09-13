import React, { useEffect, useState } from 'react';
import { AgentRunResponse } from '../types';
import { getAuditBundle } from '../services/api';
import { DownloadRow } from '../components/run/DownloadRow';

export const ExportsPage: React.FC<{ displayRun: AgentRunResponse | null }> = ({ displayRun }) => {
  const [chain, setChain] = useState<string | null>(null);

  useEffect(() => {
    setChain(null);
    if (!displayRun) return;
    let cancelled = false;
    getAuditBundle(displayRun.run_id)
      .then((b) => {
        if (!cancelled) setChain(typeof b?.chain_sha256 === 'string' ? b.chain_sha256 : null);
      })
      .catch(() => {
        if (!cancelled) setChain(null);
      });
    return () => {
      cancelled = true;
    };
  }, [displayRun?.run_id]);

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8">
      <div className="text-[11px] font-mono tracking-[0.25em] text-slate-600">EXPORTS</div>
      <h1 className="mt-2 text-2xl font-bold text-white tracking-tight">Take it with you</h1>

      {!displayRun ? (
        <div className="mt-10 text-center">
          <p className="text-sm text-slate-400">Nothing to export yet.</p>
          <p className="mt-1 text-xs font-mono text-slate-600">Run an assessment first — its artifacts land here.</p>
        </div>
      ) : (
        <>
          <p className="mt-1 text-sm text-slate-400">
            Artifacts for run <span className="font-mono text-[13px] text-slate-200">{displayRun.run_id}</span>
            {displayRun.role_id && <> · <span className="font-mono text-[13px] text-slate-200">{displayRun.role_id}</span></>}.
          </p>
          <div className="mt-6 rounded-lg border border-white/10 bg-white/[0.02] p-4">
            <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">FILES</div>
            <div className="mt-3">
              <DownloadRow run={displayRun} />
            </div>
            <p className="mt-3 text-xs text-slate-500 leading-relaxed">
              <span className="font-mono text-slate-400">policy.json</span> — final least-privilege policy.
              {' '}<span className="font-mono text-slate-400">audit-bundle.json</span> — hash-chained evidence.
              {' '}<span className="font-mono text-slate-400">policy.tf</span> — Terraform HCL for review.
            </p>
            {chain && (
              <p className="mt-2 text-[11px] font-mono text-slate-600">
                ledger sha256: {chain.slice(0, 24)}…
              </p>
            )}
          </div>
        </>
      )}

      <div className="mt-3 rounded-lg border border-white/10 bg-white/[0.02] p-4">
        <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">FOR DEVELOPERS</div>
        <div className="mt-2 flex items-center gap-4 text-sm">
          <a href="/docs" target="_blank" rel="noreferrer" className="font-mono text-[13px] text-sky-300 hover:text-sky-200 transition-colors">
            API docs ↗
          </a>
          <a href="/health" target="_blank" rel="noreferrer" className="font-mono text-[13px] text-slate-400 hover:text-slate-200 transition-colors">
            health ↗
          </a>
        </div>
      </div>
    </div>
  );
};
