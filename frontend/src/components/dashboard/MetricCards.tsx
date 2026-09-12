import React from 'react';
import { DashboardMetrics } from '../../types';
import { Shield, ShieldAlert, ShieldCheck, RotateCcw, AlertTriangle, Activity } from 'lucide-react';

interface MetricCardsProps {
  metrics?: DashboardMetrics;
  isLoading?: boolean;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ metrics, isLoading }) => {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-24 bg-soc-surface rounded-lg border border-soc-border animate-pulse" />
        ))}
      </div>
    );
  }

  const hasRuns = metrics && metrics.total_runs > 0;

  const cards = [
    {
      label: 'Remediation Runs',
      value: hasRuns ? metrics.total_runs : '0',
      subtext: hasRuns ? 'Autonomous executions' : 'No runs yet',
      icon: Activity,
      color: 'text-sky-400',
      borderColor: 'border-sky-500/20',
    },
    {
      label: 'Permissions Reduced',
      value: hasRuns ? metrics.permissions_reduced : '0',
      subtext: hasRuns ? 'Excessive privileges cut' : 'Awaiting assessment',
      icon: Shield,
      color: 'text-emerald-400',
      borderColor: 'border-emerald-500/20',
    },
    {
      label: 'Changes Verified',
      value: hasRuns ? metrics.changes_verified : '0',
      subtext: 'Post-apply verified',
      icon: ShieldCheck,
      color: 'text-emerald-400',
      borderColor: 'border-emerald-500/20',
    },
    {
      label: 'Changes Blocked',
      value: hasRuns ? metrics.changes_blocked : '0',
      subtext: 'Kernel safety vetoes',
      icon: ShieldAlert,
      color: 'text-rose-400',
      borderColor: 'border-rose-500/20',
    },
    {
      label: 'Rollbacks Executed',
      value: hasRuns ? metrics.rollbacks : '0',
      subtext: 'Defensive reversions',
      icon: RotateCcw,
      color: 'text-amber-400',
      borderColor: 'border-amber-500/20',
    },
    {
      label: 'Average Risk Tier',
      value: hasRuns ? metrics.average_risk : '—',
      subtext: 'Baseline risk posture',
      icon: AlertTriangle,
      color: 'text-soc-muted',
      borderColor: 'border-soc-border',
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`bg-soc-card/70 backdrop-blur-sm p-3.5 rounded-lg border ${card.borderColor} flex flex-col justify-between hover:border-slate-600 transition-colors`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-soc-muted tracking-tight">{card.label}</span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className="mt-2">
              <div className="text-2xl font-semibold tracking-tight text-white font-mono">{card.value}</div>
              <div className="text-[11px] text-slate-400 truncate mt-0.5">{card.subtext}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
