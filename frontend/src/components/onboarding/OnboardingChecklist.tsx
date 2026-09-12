import React from 'react';
import { CheckCircle2, Circle, X } from 'lucide-react';

export interface ChecklistState {
  ranDemo: boolean;
  viewedRun: boolean;
  visitedLearn: boolean;
}

export const OnboardingChecklist: React.FC<{
  state: ChecklistState;
  onRunDemo: () => void;
  onViewRun: () => void;
  onVisitLearn: () => void;
  onDismiss: () => void;
}> = ({ state, onRunDemo, onViewRun, onVisitLearn, onDismiss }) => {
  const steps = [
    { done: state.ranDemo, label: 'Run the 30-second killer demo', action: onRunDemo, cta: 'Run' },
    { done: state.viewedRun, label: 'See why kms:Decrypt was kept', action: onViewRun, cta: 'View' },
    { done: state.visitedLearn, label: 'Understand the genius (60s)', action: onVisitLearn, cta: 'Learn' },
  ];
  const done = steps.filter((s) => s.done).length;
  if (done === 3) return null;
  return (
    <div className="rounded-xl border border-sky-500/30 bg-sky-950/20 p-4">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono font-bold text-sky-200 uppercase">Getting started · {done}/3</div>
        <button type="button" onClick={onDismiss} className="text-slate-500 hover:text-slate-300 cursor-pointer" aria-label="Dismiss">
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
      <div className="mt-2 h-1.5 rounded bg-slate-800 overflow-hidden">
        <div className="h-full bg-sky-400 transition-all" style={{ width: `${(done / 3) * 100}%` }} />
      </div>
      <ul className="mt-3 space-y-2">
        {steps.map((s) => (
          <li key={s.label} className="flex items-center gap-2 text-xs">
            {s.done ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> : <Circle className="w-4 h-4 text-slate-500 shrink-0" />}
            <span className={s.done ? 'text-slate-500 line-through' : 'text-slate-200'}>{s.label}</span>
            {!s.done && (
              <button type="button" onClick={s.action} className="ml-auto text-[11px] font-mono text-sky-300 hover:underline cursor-pointer">{s.cta} →</button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
};
