import React, { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { RunSummary } from '../types';
import { listRuns } from '../services/api';
import { kindOf } from '../components/kernel/model';

interface AuditPageProps {
  previewId?: string | null;
  onPreview: (runId: string) => void;
}

export const AuditPage: React.FC<AuditPageProps> = ({ previewId, onPreview }) => {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    listRuns()
      .then((r) => {
        if (!cancelled) setRuns(r.runs || []);
      })
      .catch((e: any) => {
        if (!cancelled) setError(e?.message ?? 'Failed to load runs');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8">
      <div className="text-[11px] font-mono tracking-[0.25em] text-slate-600">AUDIT</div>
      <h1 className="mt-2 text-2xl font-bold text-white tracking-tight">Run history</h1>

      {loading && (
        <div className="mt-10 text-center">
          <Loader2 className="w-5 h-5 text-sky-400 animate-spin mx-auto" />
          <p className="mt-2 text-xs font-mono text-slate-500">Loading ledger…</p>
        </div>
      )}
      {error && <p className="mt-8 text-center text-xs font-mono text-rose-400">{error}</p>}

      {!loading && !error && runs.length === 0 && (
        <div className="mt-10 text-center">
          <p className="text-sm text-slate-400">No runs recorded yet.</p>
          <p className="mt-1 text-xs font-mono text-slate-600">Run an assessment — it will be listed here.</p>
        </div>
      )}

      {!loading && !error && runs.length > 0 && (
        <div className="mt-6 rounded-lg border border-white/10 bg-white/[0.02] overflow-hidden">
          <ul className="divide-y divide-white/[0.06]">
            {runs.map((r) => (
              <li key={r.run_id}>
                <button
                  type="button"
                  onClick={() => onPreview(r.run_id)}
                  title="Preview this run"
                  className={`w-full text-left px-4 py-3 flex items-center gap-3 transition-colors cursor-pointer ${
                    previewId === r.run_id ? 'bg-sky-400/[0.07]' : 'hover:bg-white/[0.03]'
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      r.verified ? 'bg-emerald-400' : kindOf(r.stop_reason).dot
                    }`}
                  />
                  <span className="min-w-0">
                    <span className="block text-[13px] font-mono text-slate-200 truncate">{r.run_id}</span>
                    <span className="block text-[11px] font-mono text-slate-500 truncate">
                      {r.role_id} · {r.stop_reason ?? r.status} · {r.events_count} events
                    </span>
                  </span>
                  {r.verified && (
                    <span className="ml-auto text-[10px] font-mono text-emerald-300 shrink-0">verified</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
