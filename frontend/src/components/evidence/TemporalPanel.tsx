import React, { useEffect, useState } from 'react';
import { Clock } from 'lucide-react';
import { TemporalReport } from '../../types';
import { getTemporal } from '../../services/api';

const badge: Record<string, string> = {
  FREQUENT: 'bg-sky-500/10 text-sky-300 border-sky-500/30',
  RARE_BUT_CRITICAL: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  SEASONAL_CANDIDATE: 'bg-violet-500/10 text-violet-300 border-violet-500/30',
  DEAD: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
};

export const TemporalPanel: React.FC<{ roleId: string }> = ({ roleId }) => {
  const [report, setReport] = useState<TemporalReport | null>(null);

  useEffect(() => {
    let cancelled = false;
    getTemporal(roleId)
      .then((r) => !cancelled && setReport(r))
      .catch(() => !cancelled && setReport(null));
    return () => {
      cancelled = true;
    };
  }, [roleId]);

  if (!report) return <div className="text-xs font-mono text-slate-400">Loading temporal mining…</div>;

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5 pb-3 border-b border-soc-border/60">
        <Clock className="w-3.5 h-3.5 text-violet-300" />
        Temporal Mining — Rare but Critical ({report.window_days}d)
      </h3>
      <div className="mt-2 text-[11px] font-mono text-slate-300">
        Retain {report.retain.length} · Review {report.review.length} · Remove {report.remove.length}
      </div>
      <ul className="mt-2 space-y-1.5 max-h-44 overflow-auto">
        {report.findings.map((f) => (
          <li key={f.permission} className="text-[11px] font-mono px-2 py-1.5 rounded border border-soc-border bg-soc-surface">
            <span className="text-slate-100 font-bold">{f.permission}</span>{' '}
            <span className={`ml-1 px-1.5 py-0.5 rounded border text-[10px] ${badge[f.classification]}`}>
              {f.classification}
            </span>
            <div className="text-slate-400 mt-0.5">
              {f.uses_30d}/30d · {f.uses_365d}/365d {f.dependency_linked ? '· 🔗 dependency' : ''} → {f.recommendation} ({Math.round(f.confidence * 100)}%)
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};
