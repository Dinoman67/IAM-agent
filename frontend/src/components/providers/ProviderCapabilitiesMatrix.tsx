import React, { useState } from 'react';
import { ProviderCapabilities, ProviderName } from '../../types';
import { AlertTriangle, CheckCircle2, Cloud, HelpCircle, Info, Shield, XCircle } from 'lucide-react';

interface ProviderCapabilitiesMatrixProps {
  providers?: Record<ProviderName, ProviderCapabilities>;
}

export const ProviderCapabilitiesMatrix: React.FC<ProviderCapabilitiesMatrixProps> = ({ providers }) => {
  const [selectedProvider, setSelectedProvider] = useState<ProviderName>('aws');

  const providerData = providers?.[selectedProvider];

  const capabilityRows = [
    {
      capability: 'Principal & Role Inspection',
      key: 'supports_role_inspection',
      aws: true,
      gcp: true,
      azure: true,
      description: 'Fetch active permissions, versions, and identity attributes',
    },
    {
      capability: 'Common IR Translation',
      key: 'supports_policy_inspection',
      aws: true,
      gcp: true,
      azure: true,
      description: 'Normalize vendor-specific policy models to semantic statements',
    },
    {
      capability: 'Pre-Commit Counterfactual Simulation',
      key: 'supports_policy_simulation',
      aws: true,
      gcp: false,
      azure: false,
      description: 'Test workflow authorization before touching cloud state',
      note: 'GCP/Azure lack local simulators; requires safe escalation',
    },
    {
      capability: 'Provider-Aware Policy Validation',
      key: 'supports_policy_validation',
      aws: true,
      gcp: true,
      azure: true,
      description: 'Validate schema, statement syntax, and parameter bounds',
    },
    {
      capability: 'Atomic Policy Rollback',
      key: 'supports_rollback',
      aws: true,
      gcp: false,
      azure: false,
      description: 'Instant atomic reversion to previous policy version',
      note: 'GCP uses etag concurrency; Azure uses role deletion/recreation',
    },
    {
      capability: 'Deterministic Post-Apply Verification',
      key: 'supports_local_analysis',
      aws: true,
      gcp: true,
      azure: true,
      description: 'Independent verification layer evaluating runtime availability',
    },
    {
      capability: 'Transitive Coupling Discovery',
      key: 'supports_dependency_analysis',
      aws: true,
      gcp: false,
      azure: false,
      description: 'Detect downstream cryptographic couplings (e.g. SSE-KMS)',
    },
  ];

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-soc-border/60">
        <div>
          <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
            <Cloud className="w-3.5 h-3.5 text-sky-400" />
            Truthful Multi-Cloud Parity Matrix
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Realistic Vendor Capabilities &amp; Parity Boundaries (No Fake Support)
          </p>
        </div>

        {/* Cloud Provider Tabs */}
        <div className="flex items-center gap-1.5 bg-soc-surface p-1 rounded-md border border-soc-border">
          {(['aws', 'gcp', 'azure'] as ProviderName[]).map((prov) => (
            <button
              key={prov}
              type="button"
              onClick={() => setSelectedProvider(prov)}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors cursor-pointer ${
                selectedProvider === prov
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              {prov.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Selected Provider Alert */}
      {selectedProvider === 'gcp' && (
        <div className="bg-amber-950/25 border border-amber-500/40 rounded p-3 my-3 text-xs flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-slate-300">
            <strong className="text-amber-300 font-mono">GCP Parity Reality:</strong> Local simulation is
            unsupported in the GCP adapter. PS10 truthfully halts with{' '}
            <span className="font-mono text-amber-300">stop_reason: unsupported_capability</span> and safely
            escalates rather than faking execution.
          </div>
        </div>
      )}

      {selectedProvider === 'azure' && (
        <div className="bg-purple-950/25 border border-purple-500/40 rounded p-3 my-3 text-xs flex items-start gap-2.5">
          <Info className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
          <div className="text-slate-300">
            <strong className="text-purple-300 font-mono">Azure RBAC Architecture:</strong> Azure manages IAM via
            Role Assignments and Definitions without revision history. Atomic version rollback is not supported.
          </div>
        </div>
      )}

      {/* Capabilities Table */}
      <div className="mt-3 overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-soc-border text-soc-muted font-mono text-[11px]">
              <th className="py-2 px-2 font-medium">CAPABILITY</th>
              <th className="py-2 px-2 font-medium text-center">AWS</th>
              <th className="py-2 px-2 font-medium text-center">GCP</th>
              <th className="py-2 px-2 font-medium text-center">AZURE</th>
              <th className="py-2 px-2 font-medium">OPERATIONAL DESCRIPTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border/40 font-mono">
            {capabilityRows.map((row, idx) => (
              <tr key={idx} className="hover:bg-soc-surface/50">
                <td className="py-2.5 px-2 text-slate-200 font-sans font-medium">{row.capability}</td>
                <td className="py-2.5 px-2 text-center">
                  {row.aws ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                  ) : (
                    <XCircle className="w-4 h-4 text-slate-600 mx-auto" />
                  )}
                </td>
                <td className="py-2.5 px-2 text-center">
                  {row.gcp ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 mx-auto" />
                  )}
                </td>
                <td className="py-2.5 px-2 text-center">
                  {row.azure ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 mx-auto" />
                  )}
                </td>
                <td className="py-2.5 px-2 text-slate-400 font-sans text-[11px]">
                  {row.description}
                  {row.note && <div className="text-amber-400/80 mt-0.5 text-[10px] font-mono">{row.note}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
