import React from 'react';
import { RunSummary } from '../../types';
import { CheckCircle2, Clock, History, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';

interface AuditHistoryTableProps {
  runs: RunSummary[];
  onSelectRun: (runId: string) => void;
  selectedRunId?: string;
}

export const AuditHistoryTable: React.FC<AuditHistoryTableProps> = ({ runs, onSelectRun, selectedRunId }) => {
  if (!runs || runs.length === 0) {
    return (
      <div className="bg-soc-card/70 border border-soc-border rounded-lg p-6 text-center text-xs text-soc-muted font-mono">
        No execution audit logs available yet. Trigger an IAM remediation run to populate audit history.
      </div>
    );
  }

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-5">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <div>
          <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
            <History className="w-3.5 h-3.5 text-sky-400" />
            Immutable Remediation Audit Ledger
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Cryptographic Hashes, Security Gates, and Forensic Telemetry
          </p>
        </div>

        <span className="text-[11px] font-mono text-soc-muted bg-soc-surface px-2 py-0.5 rounded border border-soc-border">
          {runs.length} Runs Recorded
        </span>
      </div>

      <div className="mt-3 overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse font-mono">
          <thead>
            <tr className="border-b border-soc-border text-soc-muted text-[11px]">
              <th className="py-2 px-2 font-medium">RUN ID</th>
              <th className="py-2 px-2 font-medium">PROVIDER</th>
              <th className="py-2 px-2 font-medium">PRINCIPAL</th>
              <th className="py-2 px-2 font-medium">STATUS</th>
              <th className="py-2 px-2 font-medium">RISK</th>
              <th className="py-2 px-2 font-medium">SECURITY</th>
              <th className="py-2 px-2 font-medium">VERIFIED</th>
              <th className="py-2 px-2 font-medium">RUNTIME</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border/40">
            {runs.map((r) => {
              const isSelected = selectedRunId === r.run_id;
              const isSuccess = r.status === 'completed';
              const isBlocked =
                r.stop_reason === 'security_block' ||
                r.stop_reason === 'provider_mismatch' ||
                r.stop_reason === 'privilege_expansion_blocked';
              const isRollback = r.stop_reason === 'verification_failure_rolled_back';

              return (
                <tr
                  key={r.run_id}
                  onClick={() => onSelectRun(r.run_id)}
                  className={`cursor-pointer transition-colors ${
                    isSelected ? 'bg-sky-950/40 border-l-2 border-sky-400' : 'hover:bg-soc-surface/60'
                  }`}
                >
                  <td className="py-2.5 px-2 text-sky-300 font-semibold">{r.run_id}</td>
                  <td className="py-2.5 px-2 uppercase text-slate-300">{r.provider}</td>
                  <td className="py-2.5 px-2 text-slate-200">{r.role_id}</td>
                  <td className="py-2.5 px-2">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] uppercase border ${
                        isSuccess
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : isBlocked
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                          : isRollback
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}
                    >
                      {r.stop_reason || r.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-2">
                    <span className="text-amber-400 uppercase font-semibold text-[11px]">{r.risk_level}</span>
                  </td>
                  <td className="py-2.5 px-2">
                    {isBlocked ? (
                      <span className="text-rose-400 flex items-center gap-1">
                        <ShieldAlert className="w-3.5 h-3.5" /> BLOCKED
                      </span>
                    ) : (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5" /> ALLOW
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-2">
                    {r.verified ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                      </span>
                    ) : (
                      <span className="text-slate-500 flex items-center gap-1">
                        <XCircle className="w-3.5 h-3.5" /> —
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-2 text-slate-400 text-[11px]">
                    {r.telemetry?.runtime_ms ? `${r.telemetry.runtime_ms}ms` : '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
