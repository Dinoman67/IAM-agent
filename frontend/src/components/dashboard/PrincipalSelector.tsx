import React from 'react';
import { DemoScenario, ProviderName, Role } from '../../types';
import { Shield, Play, Sparkles, AlertCircle, Check, Server, Lock } from 'lucide-react';

interface PrincipalSelectorProps {
  roles: Role[];
  selectedRole: string;
  onSelectRole: (roleId: string) => void;
  selectedProvider: ProviderName;
  onSelectProvider: (provider: ProviderName) => void;
  selectedScenario: DemoScenario;
  onSelectScenario: (scenario: DemoScenario) => void;
  onStartRemediation: () => void;
  isRunning: boolean;
}

export const PrincipalSelector: React.FC<PrincipalSelectorProps> = ({
  roles,
  selectedRole,
  onSelectRole,
  selectedProvider,
  onSelectProvider,
  selectedScenario,
  onSelectScenario,
  onStartRemediation,
  isRunning,
}) => {
  const currentRoleObj = roles.find((r) => r.id === selectedRole) || roles[0];
  const activePerms = currentRoleObj?.active_permissions || [];

  const scenarios: Array<{
    id: DemoScenario;
    name: string;
    description: string;
    badge: string;
    badgeColor: string;
    icon: string;
  }> = [
    {
      id: 'aws',
      name: 'Killer Demo — AWS Cryptographic Dependency Discovery',
      description: 'Counterfactual simulation fails on SSE-KMS, discovers hidden coupling, autonomously replans & verifies.',
      badge: 'RECOMMENDED FOR JUDGES',
      badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      icon: '⭐',
    },
    {
      id: 'safety_block',
      name: 'Safety Block — Protected Administrative Invariant',
      description: 'Agent proposes mutating protected iam:CreateRole; Security Kernel vetoes mutation deterministically.',
      badge: 'SAFETY KERNEL VETO',
      badgeColor: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      icon: '🛡️',
    },
    {
      id: 'rollback',
      name: 'Automated Rollback — Post-Apply Verification Failure',
      description: 'Faulty change applied; post-apply verification detects regression and autonomously restores previous version.',
      badge: 'DEFENSE-IN-DEPTH',
      badgeColor: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      icon: '🔄',
    },
    {
      id: 'stale_state',
      name: 'Optimistic Concurrency — Stale State Recovery',
      description: 'Concurrent out-of-band policy modification detected before apply; agent adapts to refreshed baseline.',
      badge: 'CONCURRENCY GUARD',
      badgeColor: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
      icon: '⚡',
    },
    {
      id: 'unsupported_gcp',
      name: 'Unsupported Capability — Truthful GCP Adapter',
      description: 'Agent checks provider capabilities, identifies lack of local simulation, and escalates truthfully without fake data.',
      badge: 'PARITY AWARENESS',
      badgeColor: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
      icon: '🌐',
    },
    {
      id: 'provider_mismatch',
      name: 'Cross-Cloud Guard — Provider Mismatch Prevention',
      description: 'Cross-cloud mutation (Azure on AWS) is intercepted and rejected before modifying cloud infrastructure.',
      badge: 'TENANT ISOLATION',
      badgeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      icon: '🚫',
    },
  ];

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-5">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-soc-border/60">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-sky-500/10 text-sky-400 border border-sky-500/20">
              TARGET PRINCIPAL
            </span>
            <span className="text-xs text-soc-muted">Production Environment</span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight mt-1 flex items-center gap-2">
            <Server className="w-5 h-5 text-sky-400" />
            {currentRoleObj?.name || selectedRole}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">{currentRoleObj?.description}</p>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-3">
          <button
            onClick={onStartRemediation}
            disabled={isRunning}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-sm transition-all shadow-lg shadow-sky-950/50 hover:shadow-sky-600/25 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Remediating IAM...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white" />
                <span className="font-semibold">Run IAM Assessment</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Configuration Selectors */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
        {/* Provider Selector */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Cloud Provider
          </label>
          <div className="grid grid-cols-3 gap-2">
            {(['aws', 'gcp', 'azure'] as ProviderName[]).map((prov) => (
              <button
                key={prov}
                type="button"
                onClick={() => onSelectProvider(prov)}
                className={`py-1.5 px-2 rounded border text-xs font-mono font-medium transition-colors ${
                  selectedProvider === prov
                    ? 'bg-sky-500/20 border-sky-500 text-sky-200'
                    : 'bg-soc-surface border-soc-border text-soc-muted hover:border-slate-500'
                }`}
              >
                {prov.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Principal Selector */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            IAM Role / Principal
          </label>
          <select
            value={selectedRole}
            onChange={(e) => onSelectRole(e.target.value)}
            className="w-full bg-soc-surface border border-soc-border rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          >
            {roles.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name} ({r.id})
              </option>
            ))}
          </select>
        </div>

        {/* Posture Summary */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Current Risk Posture
          </label>
          <div className="flex items-center gap-2 bg-soc-surface border border-soc-border rounded px-3 py-1.5 text-xs">
            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
              MEDIUM RISK
            </span>
            <span className="text-soc-muted font-mono text-[11px]">
              {activePerms.length} Active Permissions
            </span>
            <span className="text-slate-500 font-mono text-[11px] ml-auto">
              ver: {currentRoleObj?.current_version || 'v1'}
            </span>
          </div>
        </div>
      </div>

      {/* Active Permissions Breakdown Preview */}
      <div className="mt-4 pt-3 border-t border-soc-border/40">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-400">Current Granted Permissions:</span>
          <span className="text-[11px] font-mono text-soc-muted">
            {activePerms.filter((p) => p.includes('*')).length} Wildcard Administrative Privileges
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {activePerms.map((perm) => {
            const isWildcard = perm.includes('*');
            return (
              <span
                key={perm}
                className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono ${
                  isWildcard
                    ? 'bg-rose-950/40 text-rose-300 border border-rose-500/30 font-medium'
                    : perm === 'kms:Decrypt'
                    ? 'bg-amber-950/40 text-amber-300 border border-amber-500/30 font-medium'
                    : 'bg-slate-800 text-slate-300 border border-slate-700'
                }`}
              >
                {isWildcard && <Lock className="w-2.5 h-2.5 mr-1 text-rose-400" />}
                {perm === 'kms:Decrypt' && <Lock className="w-2.5 h-2.5 mr-1 text-amber-400" />}
                {perm}
              </span>
            );
          })}
        </div>
      </div>

      {/* Demonstration Scenario Picker */}
      <div className="mt-4 pt-3 border-t border-soc-border/40">
        <label className="block text-xs font-semibold text-soc-highlight uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-sky-400" />
          Select Evaluation Scenario:
        </label>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {scenarios.map((sc) => {
            const isSelected = selectedScenario === sc.id;
            return (
              <div
                key={sc.id}
                onClick={() => onSelectScenario(sc.id)}
                className={`p-2.5 rounded-lg border cursor-pointer transition-all text-left flex flex-col justify-between ${
                  isSelected
                    ? 'bg-sky-950/30 border-sky-500 shadow-sm'
                    : 'bg-soc-surface/60 border-soc-border hover:border-slate-600'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-slate-100 flex items-center gap-1">
                      <span>{sc.icon}</span> {sc.name.split('—')[0]}
                    </span>
                    {isSelected && <Check className="w-3.5 h-3.5 text-sky-400 shrink-0" />}
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{sc.description}</p>
                </div>
                <div className="mt-2">
                  <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-mono border ${sc.badgeColor}`}>
                    {sc.badge}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
