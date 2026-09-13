import React, { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { AgentRunResponse } from '../../types';
import { exportTerraform, getAuditBundle } from '../../services/api';

/** Shared take-home artifact downloads. Same row on verdict + Exports views. */
export const DownloadRow: React.FC<{ run: AgentRunResponse | null }> = ({ run }) => {
  const [dlBusy, setDlBusy] = useState<string | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);

  if (!run) return null;

  const saveBlob = (filename: string, text: string, mime: string) => {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const download = async (kind: 'policy' | 'audit' | 'terraform') => {
    if (dlBusy) return;
    setDlBusy(kind);
    setDlError(null);
    try {
      const roleId = run.role_id ?? 'role';
      if (kind === 'policy') {
        if (!run.policy_diff) throw new Error('No policy diff on this run.');
        saveBlob(`${roleId}-least-privilege-policy.json`, JSON.stringify(run.policy_diff, null, 2), 'application/json');
      } else if (kind === 'audit') {
        const bundle = await getAuditBundle(run.run_id);
        saveBlob(`audit-bundle-${run.run_id}.json`, JSON.stringify(bundle, null, 2), 'application/json');
      } else {
        // Export the REMEDIATED set from this run: each API call loads a fresh
        // environment, so omitting permissions would snapshot the broad baseline.
        const pd = run.policy_diff;
        const proposed = pd ? [...(pd.kept ?? []), ...(pd.added ?? [])] : undefined;
        const tf = await exportTerraform(roleId, proposed && proposed.length ? proposed : undefined);
        saveBlob(`${roleId}-least-privilege.tf`, tf.hcl, 'text/plain');
      }
    } catch (e: any) {
      setDlError(e?.message ?? 'Download failed');
    } finally {
      setDlBusy(null);
    }
  };

  const hasDiff = !!run.policy_diff;
  const items = [
    { kind: 'policy' as const, label: 'policy.json', enabled: hasDiff },
    { kind: 'audit' as const, label: 'audit-bundle.json', enabled: true },
    { kind: 'terraform' as const, label: 'policy.tf', enabled: true },
  ];

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap">
        {items.map(({ kind, label, enabled }) => (
          <button
            key={kind}
            type="button"
            disabled={!enabled || dlBusy !== null}
            onClick={() => download(kind)}
            title={enabled ? `Download ${label}` : 'Not available for this run outcome'}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-white/15 hover:border-sky-400/60 hover:text-sky-200 text-slate-300 text-[11px] font-mono transition-colors cursor-pointer disabled:opacity-35 disabled:cursor-not-allowed"
          >
            {dlBusy === kind ? <Loader2 className="w-3 h-3 animate-spin" /> : <span aria-hidden>↓</span>}
            {label}
          </button>
        ))}
      </div>
      {dlError && <p className="mt-2 text-[11px] font-mono text-rose-400">{dlError}</p>}
    </div>
  );
};
