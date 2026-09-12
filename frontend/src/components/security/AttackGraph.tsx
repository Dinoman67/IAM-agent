import React, { useEffect, useState } from 'react';
import { ShieldAlert, Skull } from 'lucide-react';
import { AttackGraph } from '../../types';
import { getAttackGraph } from '../../services/api';

export const AttackGraphView: React.FC<{ roleId: string }> = ({ roleId }) => {
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAttackGraph(roleId)
      .then((g) => !cancelled && setGraph(g))
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [roleId]);

  if (error) return <div className="text-xs font-mono text-rose-300">Attack graph unavailable: {error}</div>;
  if (!graph) return <div className="text-xs font-mono text-slate-400">Loading attack paths…</div>;

  const color =
    graph.risk_level === 'CRITICAL'
      ? 'text-rose-400 border-rose-500/40 bg-rose-500/10'
      : graph.risk_level === 'HIGH'
      ? 'text-amber-300 border-amber-500/40 bg-amber-500/10'
      : 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10';

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
          <Skull className="w-3.5 h-3.5 text-rose-400" />
          Attack Path — “If this role is stolen?”
        </h3>
        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${color}`}>
          {graph.risk_level} · {graph.risk_score}
        </span>
      </div>
      <div className="mt-3 text-xs font-mono text-slate-300">
        Reachable: <strong>{graph.reachable_resources.length}</strong> · Protected:{' '}
        <strong className="text-rose-300">{graph.protected_reachable.length}</strong>
      </div>
      <ul className="mt-2 space-y-1.5 max-h-44 overflow-auto">
        {graph.paths.slice(0, 8).map((p, i) => (
          <li
            key={i}
            className={`text-[11px] font-mono px-2 py-1.5 rounded border ${
              p.reaches_protected
                ? 'border-rose-500/40 bg-rose-950/30 text-rose-200'
                : 'border-soc-border bg-soc-surface text-slate-300'
            }`}
          >
            <ShieldAlert className="w-3 h-3 inline mr-1.5 -mt-0.5" />
            {p.path.join(' → ')}
          </li>
        ))}
      </ul>
      {graph.paths.length > 8 && (
        <div className="text-[10px] font-mono text-slate-500 mt-1">+{graph.paths.length - 8} more paths</div>
      )}
    </div>
  );
};
