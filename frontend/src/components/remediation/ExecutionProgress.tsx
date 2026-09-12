import React from 'react';
import { Activity, AlertTriangle, CheckCircle2, Cpu, Eye, Layers, Lock, ShieldCheck } from 'lucide-react';

interface ExecutionProgressProps {
  currentPhase: string;
  hasReplanned?: boolean;
  isBlocked?: boolean;
  isRollback?: boolean;
  isCompleted?: boolean;
}

export const ExecutionProgress: React.FC<ExecutionProgressProps> = ({
  currentPhase,
  hasReplanned = false,
  isBlocked = false,
  isRollback = false,
  isCompleted = false,
}) => {
  const steps = [
    { id: 'OBSERVING', label: '1. OBSERVE', icon: Eye, desc: 'Inspect active role' },
    { id: 'ANALYZING', label: '2. ANALYZE', icon: Cpu, desc: 'Find unused grants' },
    { id: 'SIMULATING', label: '3. SIMULATE', icon: Activity, desc: 'Test business workflows' },
    { id: 'REPLANNING', label: '4. REPLAN', icon: Layers, desc: 'Adapt for dependencies' },
    { id: 'SECURITY', label: '5. KERNEL', icon: Lock, desc: 'Deterministic auth gate' },
    { id: 'VERIFYING', label: '6. VERIFY', icon: ShieldCheck, desc: 'Confirm availability' },
  ];

  const phaseOrder = ['OBSERVING', 'ANALYZING', 'SIMULATING', 'REPLANNING', 'APPLYING', 'VERIFYING', 'COMPLETED'];
  const currentIdx = phaseOrder.indexOf(currentPhase.toUpperCase());

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold text-soc-highlight uppercase tracking-wider">
          Closed-Loop Autonomous Remediation Progression
        </span>
        <span className="text-[11px] font-mono text-soc-muted">
          Current Phase:{' '}
          <strong className="text-white uppercase font-bold">
            {isBlocked ? 'SECURITY BLOCKED' : isRollback ? 'ROLLED BACK' : currentPhase}
          </strong>
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isCurrent = currentPhase.toUpperCase() === step.id;
          const isPassed = isCompleted || currentIdx > idx;

          let bgClass = 'bg-soc-surface border-soc-border text-slate-400';
          if (isBlocked && step.id === 'SECURITY') {
            bgClass = 'bg-rose-950/40 border-rose-500 text-rose-200';
          } else if (isCurrent) {
            bgClass = 'bg-sky-950/50 border-sky-500 text-sky-200 shadow-sm';
          } else if (isPassed) {
            bgClass = 'bg-soc-surface border-emerald-500/40 text-emerald-300';
          }

          return (
            <div key={step.id} className={`p-2.5 rounded-lg border flex flex-col justify-between transition-all ${bgClass}`}>
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold">{step.label}</span>
                {isPassed ? (
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                ) : isCurrent ? (
                  <div className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
                ) : (
                  <Icon className="w-3 h-3 opacity-60" />
                )}
              </div>
              <span className="text-[10px] text-slate-400 mt-1 font-sans truncate">{step.desc}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
