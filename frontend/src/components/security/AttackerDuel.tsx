import React, { useEffect, useState } from 'react';
import { Swords } from 'lucide-react';

interface DuelRound {
  policy: string;
  permissions: string[];
  reachable_protected: string[];
  reachable_count: number;
  risk_score: number;
  verdict: 'BREACHED' | 'HELD';
}

interface DuelResult {
  role_id: string;
  before: DuelRound;
  after: DuelRound;
  protected_saved: string[];
  headline: string;
}

async function postDuel(roleId: string, after?: string[]): Promise<DuelResult> {
  const res = await fetch('/api/duel', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: roleId, after_permissions: after ?? null }),
  });
  if (!res.ok) throw new Error(`Duel failed: ${res.statusText}`);
  return res.json();
}

const RoundCard: React.FC<{ round: DuelRound; label: string }> = ({ round, label }) => {
  const breached = round.verdict === 'BREACHED';
  return (
    <div
      className={`rounded-lg border p-3 ${
        breached ? 'border-rose-500/40 bg-rose-950/30' : 'border-emerald-500/40 bg-emerald-950/30'
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">{label}</span>
        <span
          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
            breached
              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
              : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
          }`}
        >
          {round.verdict}
        </span>
      </div>
      <div className="mt-1 font-mono text-lg font-bold text-white">
        {round.reachable_protected.length}
        <span className="ml-1 text-[11px] font-medium text-slate-400">protected reached</span>
      </div>
      <ul className="mt-2 space-y-1">
        {round.reachable_protected.length === 0 && (
          <li className="text-[11px] font-mono text-emerald-300">Attacker finds nothing worth stealing.</li>
        )}
        {round.reachable_protected.slice(0, 4).map((arn) => (
          <li key={arn} className="text-[11px] font-mono text-slate-300 truncate" title={arn}>
            → {arn}
          </li>
        ))}
      </ul>
    </div>
  );
};

export const AttackerDuel: React.FC<{ roleId: string; afterPermissions?: string[] }> = ({
  roleId,
  afterPermissions,
}) => {
  const [duel, setDuel] = useState<DuelResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    postDuel(roleId, afterPermissions)
      .then((d) => !cancelled && setDuel(d))
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [roleId, JSON.stringify(afterPermissions)]);

  if (error) return <div className="text-xs font-mono text-rose-300">Duel unavailable: {error}</div>;
  if (!duel) return <div className="text-xs font-mono text-slate-400">Staging red-team duel…</div>;

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5 pb-3 border-b border-soc-border/60">
        <Swords className="w-3.5 h-3.5 text-rose-400" />
        Red-team duel — same stolen credential, two policies
      </h3>
      <p className="mt-2 text-[11px] text-slate-300 leading-relaxed">{duel.headline}</p>
      <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3">
        <RoundCard round={duel.before} label="Old key card (v1)" />
        <RoundCard round={duel.after} label="New key card (remediated)" />
      </div>
    </div>
  );
};
