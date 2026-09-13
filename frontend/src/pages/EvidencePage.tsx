import React from 'react';
import { AgentRunResponse, Role, ServiceDependency, Workflow } from '../types';

interface EvidencePageProps {
  roles: Role[];
  dependencies: ServiceDependency[];
  workflows: Workflow[];
  selectedRole: string;
  displayRun: AgentRunResponse | null;
}

const riskCls: Record<string, string> = {
  low: 'text-slate-400 border-white/10',
  medium: 'text-amber-200/90 border-amber-400/20',
  high: 'text-amber-300 border-amber-400/30',
  critical: 'text-rose-300 border-rose-500/30',
};

export const EvidencePage: React.FC<EvidencePageProps> = ({
  roles,
  dependencies,
  workflows,
  selectedRole,
  displayRun,
}) => {
  const role = roles.find((r) => r.id === selectedRole) ?? roles[0];
  const diff = displayRun?.policy_diff;
  const removedSet = new Set(diff?.removed ?? []);
  const keptSet = new Set(diff?.kept ?? []);
  const roleWorkflows = workflows.filter((w) => !role || w.role_id === role.id);

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8">
      <div className="text-[11px] font-mono tracking-[0.25em] text-slate-600">EVIDENCE</div>
      <h1 className="mt-2 text-2xl font-bold text-white tracking-tight">
        {role ? role.id : 'No role data'}
      </h1>
      {role && (
        <p className="mt-1 text-sm text-slate-400">{role.description || `${role.active_permissions.length} granted permissions, version ${role.current_version}.`}</p>
      )}

      {/* permissions ledger */}
      <div className="mt-6 rounded-lg border border-white/10 bg-white/[0.02] p-4">
        <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">GRANTED PERMISSIONS</div>
        {!role ? (
          <p className="mt-2 text-sm text-slate-500">Role data unavailable.</p>
        ) : (
          <ul className="mt-3 space-y-1.5">
            {(role.permissions_detail?.length ? role.permissions_detail : role.active_permissions.map((id) => ({ id, service: id.split('.')[0] ?? id, risk_level: 'medium' as const, description: '' }))).map((p) => (
              <li key={p.id} className="flex items-center gap-3 rounded-md border border-white/[0.07] px-3 py-2">
                <code className="text-xs font-mono text-slate-200">{p.id}</code>
                <span className={`ml-auto text-[10px] font-mono border rounded px-1.5 py-0.5 ${riskCls[p.risk_level] ?? riskCls.medium}`}>
                  {p.risk_level}
                </span>
                {diff && (
                  <span className={`text-[10px] font-mono ${removedSet.has(p.id) ? 'text-rose-300' : keptSet.has(p.id) ? 'text-emerald-300' : 'text-slate-600'}`}>
                    {removedSet.has(p.id) ? 'cut' : keptSet.has(p.id) ? 'kept' : '—'}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* dependencies */}
      {dependencies.length > 0 && (
        <div className="mt-3 rounded-lg border border-white/10 bg-white/[0.02] p-4">
          <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">HIDDEN DEPENDENCIES</div>
          <ul className="mt-3 space-y-2">
            {dependencies.map((d, i) => (
              <li key={i} className="text-[13px] text-slate-300 leading-relaxed">
                <span className="font-mono text-sky-300/90">{d.service} → {d.calls_service} → {d.downstream_dependency}</span>
                <span className="text-slate-500"> needs </span>
                <code className="font-mono text-amber-200/90 text-xs">{d.required_permission}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* workflows */}
      {roleWorkflows.length > 0 && (
        <div className="mt-3 rounded-lg border border-white/10 bg-white/[0.02] p-4">
          <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">PROTECTED WORKFLOWS</div>
          <ul className="mt-3 space-y-2">
            {roleWorkflows.map((w) => (
              <li key={w.id} className="text-[13px] text-slate-300">
                <span className="font-mono text-slate-100">{w.id}</span>
                <span className="text-slate-500"> — needs </span>
                <span className="font-mono text-xs text-slate-400">{w.required_permissions.join(', ')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!displayRun && (
        <p className="mt-4 text-center text-xs font-mono text-slate-600">
          Run an assessment to stamp cut / kept verdicts onto this ledger.
        </p>
      )}
    </div>
  );
};
