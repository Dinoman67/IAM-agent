import React, { useState } from 'react';
import { FileCode, GitPullRequest } from 'lucide-react';
import { exportTerraform } from '../../services/api';

export const TerraformExportCard: React.FC<{ roleId: string }> = ({ roleId }) => {
  const [hcl, setHcl] = useState<string>('');
  const [pr, setPr] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runExport = async () => {
    setLoading(true);
    setError(null);
    try {
      const out = await exportTerraform(roleId);
      setHcl(out.hcl);
      setPr(out.pr_body);
    } catch (e: any) {
      setError(e.message || 'Export failed');
    } finally {
      setLoading(false);
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // clipboard unavailable in some contexts
    }
  };

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
          <GitPullRequest className="w-3.5 h-3.5 text-emerald-300" />
          GitOps Export — Terraform PR Mode
        </h3>
        <button
          type="button"
          onClick={runExport}
          disabled={loading}
          className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-mono cursor-pointer"
        >
          {loading ? 'Generating…' : 'Generate TF + PR'}
        </button>
      </div>
      {error && <div className="text-xs font-mono text-rose-300 mt-2">{error}</div>}
      {!hcl && !error && (
        <div className="text-[11px] font-mono text-slate-400 mt-2">
          Proposes changes as a reviewable PR — never mutates live cloud directly.
        </div>
      )}
      {hcl && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-3">
          <div>
            <button
              type="button"
              onClick={() => copy(hcl)}
              className="text-[10px] font-mono text-sky-300 hover:text-sky-200 mb-1 inline-flex items-center gap-1 cursor-pointer"
            >
              <FileCode className="w-3 h-3" /> COPY HCL
            </button>
            <pre className="text-[10px] font-mono bg-slate-950 border border-soc-border rounded p-2 overflow-auto max-h-56 whitespace-pre-wrap text-slate-200">
              {hcl}
            </pre>
          </div>
          <div>
            <button
              type="button"
              onClick={() => copy(pr)}
              className="text-[10px] font-mono text-sky-300 hover:text-sky-200 mb-1 cursor-pointer"
            >
              COPY PR BODY
            </button>
            <pre className="text-[10px] font-mono bg-slate-950 border border-soc-border rounded p-2 overflow-auto max-h-56 whitespace-pre-wrap text-slate-300">
              {pr}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
