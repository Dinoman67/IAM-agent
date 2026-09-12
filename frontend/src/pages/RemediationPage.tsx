import React from 'react';
import { AgentRunResponse } from '../types';
import { RemediationRunView } from '../components/remediation/RemediationRunView';
import { Activity, ArrowRight, Play, ShieldAlert, Sparkles } from 'lucide-react';

interface RemediationPageProps {
  currentRun: AgentRunResponse | null;
  onRestart: () => void;
  onStartAssessment: () => void;
  isRunning: boolean;
  error?: string | null;
}

export const RemediationPage: React.FC<RemediationPageProps> = ({
  currentRun,
  onRestart,
  onStartAssessment,
  isRunning,
  error,
}) => {
  if (error) {
    return (
      <div className="bg-rose-950/25 border border-rose-500/40 rounded-lg p-6 my-6 text-center max-w-2xl mx-auto">
        <ShieldAlert className="w-10 h-10 text-rose-400 mx-auto mb-2" />
        <h3 className="text-base font-bold text-white font-mono uppercase">Assessment Execution Error</h3>
        <p className="text-xs text-rose-300 mt-1 font-mono">{error}</p>
        <button
          type="button"
          onClick={onRestart}
          className="mt-4 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded font-mono text-xs cursor-pointer"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (isRunning && !currentRun) {
    return (
      <div className="bg-soc-card/70 border border-soc-border rounded-lg p-12 text-center max-w-lg mx-auto my-8">
        <div className="w-8 h-8 border-3 border-sky-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
          Initializing Autonomous Remediation Engine
        </h3>
        <p className="text-xs text-slate-400 mt-1">
          Investigating role permissions, loading dependency graphs, and preparing pre-commit simulations...
        </p>
      </div>
    );
  }

  if (!currentRun) {
    return (
      <div className="bg-soc-card/70 border border-soc-border rounded-lg p-12 text-center max-w-xl mx-auto my-8">
        <div className="p-3 bg-sky-500/10 rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-3 border border-sky-500/20">
          <Activity className="w-6 h-6 text-sky-400" />
        </div>
        <h3 className="text-base font-bold text-white font-mono">No Remediation Runs Active</h3>
        <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
          Start an IAM assessment or trigger the guided judge demonstration to observe the closed-loop
          investigate-simulate-replan-verify lifecycle in action.
        </p>
        <button
          type="button"
          onClick={onStartAssessment}
          className="mt-5 px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs font-mono inline-flex items-center gap-2 cursor-pointer shadow-lg shadow-sky-950"
        >
          <Sparkles className="w-4 h-4 text-sky-200" />
          <span>Launch Killer Demo Assessment</span>
        </button>
      </div>
    );
  }

  return (
    <RemediationRunView
      run={currentRun}
      onRestart={onRestart}
      isRunning={isRunning}
    />
  );
};
