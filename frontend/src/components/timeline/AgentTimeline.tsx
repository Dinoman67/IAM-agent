import React, { useState } from 'react';
import { AuditEvent } from '../../types';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Cpu,
  Eye,
  Key,
  Layers,
  Lock,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';

interface AgentTimelineProps {
  events: AuditEvent[];
  activeStep?: number;
}

export const AgentTimeline: React.FC<AgentTimelineProps> = ({ events, activeStep }) => {
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedEvents((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getEventBadge = (event: AuditEvent) => {
    const etype = event.event_type;
    const actor = event.actor;

    if (etype === 'goal_received') {
      return {
        label: 'GOAL',
        color: 'bg-sky-500/20 text-sky-300 border-sky-500/30',
        icon: Terminal,
      };
    }
    if (etype === 'tool_called' || (etype === 'tool_result' && event.tool === 'get_role')) {
      return {
        label: 'OBSERVE',
        color: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
        icon: Eye,
      };
    }
    if (etype === 'policy_candidate_generated' || etype === 'decide') {
      return {
        label: 'DECIDE',
        color: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
        icon: Cpu,
      };
    }
    if (etype === 'simulation_started') {
      return {
        label: 'SIMULATE',
        color: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
        icon: Activity,
      };
    }
    if (etype === 'simulation_failed') {
      return {
        label: 'SIM FAIL',
        color: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
        icon: AlertTriangle,
      };
    }
    if (etype === 'dependency_discovered') {
      return {
        label: 'COUPLING',
        color: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
        icon: Key,
      };
    }
    if (etype === 'replan_started' || etype === 'adapt') {
      return {
        label: 'REPLAN',
        color: 'bg-sky-500/20 text-sky-300 border-sky-500/30',
        icon: Layers,
      };
    }
    if (etype === 'security_check') {
      const dec = event.details?.decision || 'ALLOW';
      const isAllowed = dec.toUpperCase() === 'ALLOW';
      return {
        label: isAllowed ? 'KERNEL PASS' : 'KERNEL VETO',
        color: isAllowed
          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
          : 'bg-rose-500/20 text-rose-300 border-rose-500/30',
        icon: isAllowed ? ShieldCheck : ShieldAlert,
      };
    }
    if (etype === 'security_gate_denied' || etype === 'provider_mismatch') {
      return {
        label: 'BLOCKED',
        color: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
        icon: ShieldAlert,
      };
    }
    if (etype === 'policy_applied') {
      return {
        label: 'APPLY',
        color: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
        icon: Lock,
      };
    }
    if (etype === 'verification_started') {
      return {
        label: 'VERIFYING',
        color: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
        icon: Activity,
      };
    }
    if (etype === 'verification_passed') {
      return {
        label: 'VERIFIED',
        color: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
        icon: CheckCircle2,
      };
    }
    if (etype === 'verification_failed') {
      return {
        label: 'VERIFY FAIL',
        color: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
        icon: AlertTriangle,
      };
    }
    if (etype === 'rollback') {
      return {
        label: 'ROLLBACK',
        color: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
        icon: RotateCcw,
      };
    }
    if (etype === 'escalate') {
      return {
        label: 'ESCALATE',
        color: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
        icon: ShieldAlert,
      };
    }
    if (etype === 'final_outcome') {
      const st = event.details?.status || 'complete';
      return {
        label: st === 'success' ? 'SUCCESS' : 'HALTED',
        color: st === 'success'
          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
          : 'bg-slate-700 text-slate-300 border-slate-600',
        icon: st === 'success' ? CheckCircle2 : AlertTriangle,
      };
    }

    return {
      label: etype.toUpperCase().slice(0, 10),
      color: 'bg-slate-800 text-slate-300 border-slate-700',
      icon: Activity,
    };
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toISOString().substring(11, 19);
    } catch {
      return ts;
    }
  };

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-sky-400" />
          Live Agent Execution Trace ({events.length} Events)
        </h3>
        <span className="text-[11px] font-mono text-soc-muted">
          Authoritative Audit Trail
        </span>
      </div>

      <div className="mt-3 space-y-2 max-h-[480px] overflow-y-auto pr-1">
        {events.length === 0 ? (
          <div className="p-8 text-center text-xs text-soc-muted font-mono">
            No events recorded yet. Start an assessment to observe the autonomous execution trace.
          </div>
        ) : (
          events.map((evt, idx) => {
            const badge = getEventBadge(evt);
            const Icon = badge.icon;
            const isExpanded = expandedEvents[evt.event_id || idx];
            const isCurrent = activeStep !== undefined && activeStep === idx;

            return (
              <div
                key={evt.event_id || idx}
                className={`p-2.5 rounded-lg border transition-colors ${
                  isCurrent
                    ? 'bg-sky-950/40 border-sky-500'
                    : 'bg-soc-surface/70 border-soc-border hover:border-slate-600'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-start gap-2.5 min-w-0">
                    <span className="text-[11px] font-mono font-semibold text-slate-400 mt-0.5 w-6 text-right shrink-0">
                      {String(idx + 1).padStart(2, '0')}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 ${badge.color}`}
                    >
                      <Icon className="w-2.5 h-2.5" />
                      {badge.label}
                    </span>
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-slate-100 leading-snug break-words">
                        {evt.summary}
                      </div>
                      {evt.reason && (
                        <div className="text-[11px] text-slate-400 mt-0.5 truncate">
                          Reason: {evt.reason}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] font-mono text-slate-500 flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      {formatTimestamp(evt.timestamp)}
                    </span>
                    {(evt.details || evt.arguments || evt.result) && (
                      <button
                        type="button"
                        onClick={() => toggleExpand(evt.event_id || String(idx))}
                        className="text-slate-400 hover:text-white p-0.5 rounded"
                        title="Toggle technical details"
                      >
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Collapsible Technical Details / Raw Event */}
                {isExpanded && (
                  <div className="mt-2.5 pt-2 border-t border-soc-border/40 text-[11px] font-mono bg-black/40 p-2 rounded overflow-x-auto">
                    <div className="text-[10px] text-soc-muted mb-1 flex items-center justify-between">
                      <span>Actor: <strong className="text-sky-300">{evt.actor}</strong></span>
                      {evt.operation && <span>Op: <strong className="text-slate-300">{evt.operation}</strong></span>}
                    </div>
                    {evt.arguments && (
                      <div className="text-slate-300">
                        <span className="text-indigo-400">args:</span> {JSON.stringify(evt.arguments)}
                      </div>
                    )}
                    {evt.details && Object.keys(evt.details).length > 0 && (
                      <div className="text-slate-300 mt-1">
                        <span className="text-emerald-400">details:</span> {JSON.stringify(evt.details, null, 2)}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
