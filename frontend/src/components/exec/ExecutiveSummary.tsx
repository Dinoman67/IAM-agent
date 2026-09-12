import React, { useEffect, useState } from 'react';
import { BadgeCheck, Download, Link2 } from 'lucide-react';
import { ComplianceControl, getAuditBundle, getCompliance } from '../../services/api';

export const ExecutiveSummary: React.FC<{ roleId: string; runId?: string }> = ({ roleId, runId }) => {
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getCompliance(roleId).then((r) => !cancelled && setControls(r.controls)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [roleId]);

  const downloadBundle = async () => {
    if (!runId) return;
    const bundle = await getAuditBundle(runId);
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-bundle-${runId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyDemoLink = async () => {
    try {
      await navigator.clipboard.writeText(`${window.location.origin}${window.location.pathname}?demo=aws`);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  return (
    <div className="rounded-xl border border-soc-border bg-soc-card/70 p-4">
      <div className="flex flex-wrap items-center gap-2 justify-between">
        <div className="text-xs font-mono font-bold text-slate-200 uppercase">Executive summary · {roleId}</div>
        <div className="flex gap-2">
          {runId && (
            <button type="button" onClick={downloadBundle} className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded bg-soc-surface border border-soc-border hover:border-slate-500 text-[11px] font-mono text-slate-200 cursor-pointer">
              <Download className="w-3 h-3" /> Audit bundle
            </button>
          )}
          <button type="button" onClick={copyDemoLink} className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded bg-soc-surface border border-soc-border hover:border-slate-500 text-[11px] font-mono text-slate-200 cursor-pointer">
            <Link2 className="w-3 h-3" /> {copied ? 'Copied!' : 'Share demo link'}
          </button>
        </div>
      </div>
      <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
        {controls.map((c) => (
          <div key={`${c.framework}-${c.control_id}`} className="rounded-lg bg-slate-950/60 border border-soc-border p-2.5">
            <div className="flex items-center gap-1.5">
              <BadgeCheck className={`w-3.5 h-3.5 ${c.status === 'pass' ? 'text-emerald-400' : c.status === 'fail' ? 'text-rose-400' : 'text-amber-300'}`} />
              <span className="text-[10px] font-mono font-bold text-slate-300">{c.framework} {c.control_id}</span>
              <span className={`ml-auto text-[10px] font-mono font-bold uppercase ${c.status === 'pass' ? 'text-emerald-300' : c.status === 'fail' ? 'text-rose-300' : 'text-amber-300'}`}>{c.status}</span>
            </div>
            <div className="mt-1 text-[11px] text-slate-200 font-medium">{c.title}</div>
            <div className="text-[11px] text-slate-500">{c.plain_english}</div>
          </div>
        ))}
        {controls.length === 0 && <div className="text-[11px] font-mono text-slate-500">Loading compliance…</div>}
      </div>
    </div>
  );
};
