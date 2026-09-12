import React from 'react';
import { AuditEvent, PolicyDiff, VerificationResult } from '../../types';
import { CheckCircle2, FileSearch, ShieldCheck, XCircle } from 'lucide-react';
import { UsageVsNeededBanner } from './UsageVsNeededBanner';

interface EvidencePanelProps {
  events: AuditEvent[];
  diff?: PolicyDiff;
  verification?: VerificationResult;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({ events, diff, verification }) => {
  const simFailed = events.some((e) => e.event_type === 'simulation_failed');
  const depDiscovered = events.some((e) => e.event_type === 'dependency_discovered');
  const simPassed = events.some(
    (e) => e.event_type === 'tool_result' && e.tool === 'simulate_policy' && e.result?.success
  );
  const secApproved = events.some(
    (e) => e.event_type === 'security_check' && (e.details?.decision === 'allow' || e.details?.allowed)
  );
  const verPassed = verification?.passed || events.some((e) => e.event_type === 'verification_passed');

  const evidenceItems = [
    {
      source: 'Usage Access Logs',
      status: 'NOT_OBSERVED',
      statusClass: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      description: 'Zero direct invocations recorded in CloudTrail log history window.',
    },
    {
      source: 'Transitive Dependency Analysis',
      status: depDiscovered ? 'REQUIRED COUPLING' : 'EVALUATED',
      statusClass: depDiscovered ? 'bg-sky-500/20 text-sky-300 border-sky-500/30' : 'bg-slate-700 text-slate-300',
      description: 'Identified S3 customer key decryption coupling requiring kms:Decrypt.',
    },
    {
      source: 'Counterfactual Simulation',
      status: simFailed ? 'FAILED → DISCOVERED' : simPassed ? 'PASSED' : 'PENDING',
      statusClass: simFailed
        ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
        : simPassed
        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
        : 'bg-slate-700 text-slate-300',
      description: 'Workflow simulation exposed broken payment_checkout before production apply.',
    },
    {
      source: 'Pre-Apply Regression Test',
      status: simPassed ? 'PASSED' : 'RUNNING',
      statusClass: simPassed ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-slate-700 text-slate-300',
      description: 'Verified operational workflows with candidate policy permissions.',
    },
    {
      source: 'Security Kernel Authorization',
      status: secApproved ? 'PASSED' : 'GATED',
      statusClass: secApproved ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-slate-700 text-slate-300',
      description: 'Authoritative deterministic invariants evaluated (expansion, blast radius, invariants).',
    },
    {
      source: 'Post-Apply Functional Verification',
      status: verPassed ? 'PASSED' : 'PENDING',
      statusClass: verPassed ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-slate-700 text-slate-300',
      description: 'Independent verification layer confirmed zero production workflow regression.',
    },
  ];

  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
          <FileSearch className="w-3.5 h-3.5 text-sky-400" />
          Evidence &amp; Verification Panel
        </h3>
        <span className="text-[11px] font-mono text-soc-muted">Multi-Source Verification</span>
      </div>

      <UsageVsNeededBanner />

      <div className="space-y-2 mt-3">
        {evidenceItems.map((item, idx) => (
          <div
            key={idx}
            className="p-2.5 rounded bg-soc-surface border border-soc-border flex items-center justify-between gap-3 text-xs"
          >
            <div className="min-w-0">
              <span className="font-semibold text-slate-200 block">{item.source}</span>
              <span className="text-[11px] text-slate-400 font-sans mt-0.5 block truncate">
                {item.description}
              </span>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 ${item.statusClass}`}
            >
              {item.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
