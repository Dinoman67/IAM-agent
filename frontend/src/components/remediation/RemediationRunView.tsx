import React, { useState, useEffect } from 'react';
import { AgentRunResponse } from '../../types';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  FileCode,
  FileSearch,
  Key,
  Lock,
  Pause,
  Play,
  RotateCcw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { ExecutionProgress } from './ExecutionProgress';
import { AgentTimeline } from '../timeline/AgentTimeline';
import { ReplanHighlight } from '../timeline/ReplanHighlight';
import { DependencyGraph } from '../dependency/DependencyGraph';
import { PolicyDiffView } from '../policy/PolicyDiffView';
import { TerraformExportCard } from '../policy/TerraformExportCard';
import { AttackGraphView } from '../security/AttackGraph';
import { TemporalPanel } from '../evidence/TemporalPanel';
import { SecurityAssessmentCard } from '../security/SecurityAssessmentCard';
import { SecurityKernelPanel } from '../security/SecurityKernelPanel';
import { BlockedStateView } from '../security/BlockedStateView';
import { RollbackStateView } from '../security/RollbackStateView';
import { EvidencePanel } from '../evidence/EvidencePanel';

interface RemediationRunViewProps {
  run: AgentRunResponse;
  onRestart: () => void;
  isRunning?: boolean;
}

export const RemediationRunView: React.FC<RemediationRunViewProps> = ({ run, onRestart, isRunning = false }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'diff' | 'evidence' | 'security'>('overview');
  const [playbackIndex, setPlaybackIndex] = useState<number>(run.events.length - 1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  // When new events arrive, keep playback updated if at end
  useEffect(() => {
    if (!isPlaying) {
      setPlaybackIndex(Math.max(0, run.events.length - 1));
    }
  }, [run.events.length, isPlaying]);

  // Stepped playback animation timer
  useEffect(() => {
    let interval: any = null;
    if (isPlaying) {
      interval = setInterval(() => {
        setPlaybackIndex((prev) => {
          if (prev < run.events.length - 1) {
            return prev + 1;
          } else {
            setIsPlaying(false);
            return prev;
          }
        });
      }, 700);
    }
    return () => clearInterval(interval);
  }, [isPlaying, run.events.length]);

  const visibleEvents = run.events.slice(0, playbackIndex + 1);

  // Check state triggers from backend events
  const hasReplan = visibleEvents.some((e) => e.event_type === 'replan_started');
  const isBlocked =
    run.stop_reason === 'security_block' ||
    run.stop_reason === 'provider_mismatch' ||
    run.stop_reason === 'privilege_expansion_blocked' ||
    visibleEvents.some((e) => e.event_type === 'security_gate_denied' || e.event_type === 'provider_mismatch');
  const isRollback =
    run.stop_reason === 'verification_failure_rolled_back' ||
    visibleEvents.some((e) => e.event_type === 'rollback');
  const isCompleted = run.status === 'completed' && !isBlocked && !isRollback;

  // Derive current phase
  let currentPhase = 'OBSERVING';
  if (visibleEvents.length > 0) {
    const last = visibleEvents[visibleEvents.length - 1];
    if (last.event_type === 'goal_received' || (last.event_type === 'tool_result' && last.tool === 'get_role')) {
      currentPhase = 'OBSERVING';
    } else if (last.event_type === 'tool_called' && last.tool === 'find_unused_permissions') {
      currentPhase = 'ANALYZING';
    } else if (last.event_type === 'simulation_started' || last.event_type === 'simulation_failed') {
      currentPhase = 'SIMULATING';
    } else if (last.event_type === 'replan_started' || last.event_type === 'dependency_discovered') {
      currentPhase = 'REPLANNING';
    } else if (last.event_type === 'security_check' || last.event_type === 'policy_applied') {
      currentPhase = 'SECURITY';
    } else if (last.event_type === 'verification_started' || last.event_type === 'verification_passed') {
      currentPhase = 'VERIFYING';
    } else if (last.event_type === 'final_outcome') {
      currentPhase = 'COMPLETED';
    }
  }

  return (
    <div className="space-y-4">
      {/* Top Banner: Run Status & Telemetry Header */}
      <div className="bg-soc-card/80 border border-soc-border rounded-lg p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                RUN: {run.run_id}
              </span>
              <span className="text-xs font-mono text-soc-muted uppercase">
                PROVIDER: <strong className="text-slate-200">{run.provider?.toUpperCase()}</strong>
              </span>
              <span className="text-xs font-mono text-slate-500">•</span>
              <span className="text-xs font-mono text-soc-muted">
                ROLE: <strong className="text-sky-300">{run.role_id}</strong>
              </span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight mt-1 flex items-center gap-2">
              <Server className="w-5 h-5 text-sky-400" />
              {run.goal}
            </h2>
          </div>

          {/* Stepper / Demo Controls */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                if (isPlaying) {
                  setIsPlaying(false);
                } else {
                  if (playbackIndex >= run.events.length - 1) {
                    setPlaybackIndex(0);
                  }
                  setIsPlaying(true);
                }
              }}
              disabled={run.events.length <= 1}
              className="px-3 py-1.5 rounded bg-soc-surface border border-soc-border hover:border-slate-500 text-xs font-mono text-slate-200 flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
              title="Step-by-step playback through audit events"
            >
              {isPlaying ? <Pause className="w-3.5 h-3.5 text-amber-400" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
              <span>{isPlaying ? 'Pause Playback' : 'Replay Trace'}</span>
            </button>

            <button
              type="button"
              onClick={onRestart}
              disabled={isRunning}
              className="px-3 py-1.5 rounded bg-soc-surface border border-soc-border hover:border-slate-500 text-xs font-mono text-slate-200 flex items-center gap-1.5 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-sky-400" />
              <span>Reset Assessment</span>
            </button>
          </div>
        </div>

        {/* Telemetry Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4 pt-3 border-t border-soc-border/60 text-xs font-mono">
          <div>
            <span className="text-soc-muted text-[10px] block">LIFECYCLE STATUS</span>
            <span
              className={`font-semibold uppercase text-[11px] ${
                isCompleted
                  ? 'text-emerald-400'
                  : isBlocked
                  ? 'text-rose-400'
                  : isRollback
                  ? 'text-amber-400'
                  : 'text-sky-300'
              }`}
            >
              {isBlocked ? 'BLOCKED BY KERNEL' : isRollback ? 'ROLLED BACK' : isCompleted ? 'LEAST PRIVILEGE VERIFIED' : run.status}
            </span>
          </div>

          <div>
            <span className="text-soc-muted text-[10px] block">ITERATIONS &amp; TOOLS</span>
            <span className="text-slate-200">
              {run.telemetry?.iterations || 1} iterations / {run.telemetry?.tool_calls || visibleEvents.length} tools
            </span>
          </div>

          <div>
            <span className="text-soc-muted text-[10px] block">REPLANNING CYCLES</span>
            <span className="text-amber-400 font-bold">
              {hasReplan ? '1 Replan (SSE-KMS Coupling)' : '0 Replans'}
            </span>
          </div>

          <div>
            <span className="text-soc-muted text-[10px] block">DETERMINISTIC LATENCY</span>
            <span className="text-slate-200">{run.telemetry?.runtime_ms || 18}ms</span>
          </div>
        </div>
      </div>

      {/* Remediation Progression Stepper */}
      <ExecutionProgress
        currentPhase={currentPhase}
        hasReplanned={hasReplan}
        isBlocked={isBlocked}
        isRollback={isRollback}
        isCompleted={isCompleted}
      />

      {/* Safety Blocked State Alert if Triggered */}
      {isBlocked && (
        <BlockedStateView
          stopReason={run.stop_reason || 'security_block'}
          reasonText={
            run.stop_reason === 'provider_mismatch'
              ? 'Security Kernel blocked cross-cloud policy mutation attempt: Azure to AWS environment prohibited.'
              : run.stop_reason === 'privilege_expansion_blocked'
              ? 'Security Kernel blocked unauthorized wildcard privilege expansion attempt.'
              : 'Security Kernel intercepted attempt to remove protected administrative capability iam:CreateRole.'
          }
          invariants={
            run.stop_reason === 'provider_mismatch'
              ? ['INVARIANT_NO_CROSS_PROVIDER_MUTATION']
              : ['INVARIANT_NO_PROTECTED_PERMISSION_MUTATION']
          }
          requiredAction="Requires manual review and explicit cryptographic sign-off by a Cloud Security Administrator."
        />
      )}

      {/* Rollback Alert if Triggered */}
      {isRollback && (
        <RollbackStateView
          roleId={run.role_id || 'PaymentServiceRole'}
          restoredVersion="v1"
          violations={['Workflow payment_checkout failed runtime verification: missing kms:Decrypt']}
        />
      )}

      {/* Success State Visual Banner (Section 41) */}
      {isCompleted && (
        <div className="bg-emerald-950/25 border-2 border-emerald-500/40 rounded-lg p-4 glow-emerald">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <div>
                <h4 className="text-sm font-bold text-emerald-200 font-mono">
                  LEAST PRIVILEGE VERIFIED — WORKFLOW PRESERVED
                </h4>
                <p className="text-xs text-slate-300 mt-0.5">
                  Role {run.role_id} reduced from 7 active permissions to 4 strictly-scoped actions.
                  1 critical permission (kms:Decrypt) preserved due to discovered architectural coupling.
                </p>
              </div>
            </div>
            <span className="px-3 py-1 rounded bg-emerald-500/20 text-emerald-300 font-mono text-xs font-bold border border-emerald-500/30 shrink-0">
              ZERO OPERATIONAL REGRESSION
            </span>
          </div>
        </div>
      )}

      {/* Visual Replanning Highlight (Section 10) */}
      {hasReplan && (
        <ReplanHighlight
          failedWorkflow="payment_checkout"
          missingPermission="kms:Decrypt"
          retainedPermissions={['kms:Decrypt']}
          reason="Encrypted S3 bucket payment-transactions utilizes SSE-KMS customer key; reading transaction objects requires kms:Decrypt."
        />
      )}

      {/* Section View Tabs */}
      <div className="flex items-center gap-2 border-b border-soc-border pb-1">
        {[
          { id: 'overview', label: 'Assessment Overview', icon: Server },
          { id: 'timeline', label: `Execution Trace (${visibleEvents.length})`, icon: Terminal },
          { id: 'diff', label: 'Policy Diff (Before / After)', icon: FileCode },
          { id: 'evidence', label: 'Evidence & Dependencies', icon: FileSearch },
          { id: 'security', label: 'Security Kernel Gate', icon: ShieldCheck },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-mono transition-colors border-b-2 cursor-pointer ${
                isActive
                  ? 'border-sky-400 text-sky-300 font-semibold'
                  : 'border-transparent text-soc-muted hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          <SecurityAssessmentCard
            decision={run.security_decision}
            riskLevel={run.risk_level || 'medium'}
            confidence={run.confidence || 0.94}
            blastRadius={run.blast_radius as any || 'LOW'}
            isBlocked={isBlocked}
          />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <DependencyGraph
              service="PaymentService"
              callsService="S3 (payment-transactions)"
              downstreamDependency="AWS Key Management Service"
              requiredPermission="kms:Decrypt"
              reason="Encrypted receipts in S3 require SSE-KMS customer key decryption. Identified by counterfactual simulation."
            />
            <EvidencePanel events={visibleEvents} diff={run.policy_diff} verification={run.verification_result} />
          </div>

          <PolicyDiffView
            diff={run.policy_diff}
            roleId={run.role_id || 'PaymentServiceRole'}
            verification={run.verification_result}
          />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <AttackGraphView roleId={run.role_id || 'PaymentServiceRole'} />
            <TemporalPanel roleId={run.role_id || 'PaymentServiceRole'} />
          </div>

          <TerraformExportCard roleId={run.role_id || 'PaymentServiceRole'} />

          <AgentTimeline events={visibleEvents} activeStep={playbackIndex} />
        </div>
      )}

      {activeTab === 'timeline' && (
        <AgentTimeline events={visibleEvents} activeStep={playbackIndex} />
      )}

      {activeTab === 'diff' && (
        <PolicyDiffView
          diff={run.policy_diff}
          roleId={run.role_id || 'PaymentServiceRole'}
          verification={run.verification_result}
        />
      )}

      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <DependencyGraph
            service="PaymentService"
            callsService="S3 (payment-transactions)"
            downstreamDependency="AWS Key Management Service"
            requiredPermission="kms:Decrypt"
          />
          <EvidencePanel events={visibleEvents} diff={run.policy_diff} verification={run.verification_result} />
        </div>
      )}

      {activeTab === 'security' && (
        <div className="space-y-4">
          <SecurityAssessmentCard
            decision={run.security_decision}
            riskLevel={run.risk_level || 'medium'}
            confidence={run.confidence || 0.94}
            blastRadius={run.blast_radius as any || 'LOW'}
            isBlocked={isBlocked}
          />
          <SecurityKernelPanel decision={run.security_decision} stopReason={run.stop_reason} />
          <AttackGraphView roleId={run.role_id || 'PaymentServiceRole'} />
        </div>
      )}
    </div>
  );
};
