import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  Check,
  CheckCircle2,
  Loader2,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Undo2,
} from 'lucide-react';
import { AgentRunResponse, DemoScenario, Role } from '../types';
import { DownloadRow } from '../components/run/DownloadRow';

interface SimulationPageProps {
  roles: Role[];
  selectedRole: string;
  onSelectRole: (roleId: string) => void;
  selectedScenario: DemoScenario;
  onSelectScenario: (scenario: DemoScenario) => void;
  onRun: () => void;
  onBack: () => void;
  isRunning: boolean;
  currentRun: AgentRunResponse | null;
  error: string | null;
  systemHealthy: boolean;
}

const SCENARIOS: Array<{ id: DemoScenario; label: string }> = [
  { id: 'aws', label: 'Least-privilege fix' },
  { id: 'gcp', label: 'GCP · local eval' },
  { id: 'safety_block', label: 'Safety block' },
  { id: 'rollback', label: 'Rollback' },
  { id: 'stale_state', label: 'Stale state' },
  { id: 'provider_mismatch', label: 'Boundary guard' },
];

const STAGES = ['Observe', 'Analyze', 'Simulate', 'Replan', 'Verify'] as const;

/** Five-line first-timer explainers, one per scenario. Shown while idle, hidden on run. */
const SCENARIO_INFO: Record<DemoScenario, { title: string; lines: string[] }> = {
  aws: {
    title: 'Least-privilege fix',
    lines: [
      'The flagship demo: shrink an over-privileged AWS role without breaking it.',
      'It starts with 7 permissions, including 3 dangerous wildcards.',
      'The first simulation deliberately fails on a hidden S3 → KMS coupling.',
      'The agent discovers the coupling, replans, and re-tests clean.',
      'It ends verified: 7 → 4 permissions, zero regression.',
    ],
  },
  gcp: {
    title: 'GCP · local eval',
    lines: [
      'The same loop on a second cloud: a GCP service account with broad bindings.',
      'GCP has no native simulator, so this uses labeled local evaluation.',
      'The first evaluation fails on a hidden CMEK decryption coupling.',
      'The agent keeps the decrypter and cuts two dangerous grants.',
      'It ends verified: 6 → 4 bindings — same proof as AWS.',
    ],
  },
  safety_block: {
    title: 'Safety block',
    lines: [
      'An attack on the safety system itself: delete an admin capability.',
      'The agent proposes removing iam:CreateRole — the power to mint users.',
      'The Safety Kernel vetoes before anything is applied.',
      'Nothing changes. That refusal IS the result.',
      'Watch it once, then trust every other run on this page.',
    ],
  },
  rollback: {
    title: 'Rollback',
    lines: [
      'What if a bad change slips through? This demo applies one on purpose.',
      'A policy missing KMS decryption goes live.',
      'Independent verification catches the breakage immediately.',
      'The engine auto-rolls back to v1 and proves the restore.',
      'Failure contained, evidence kept, lesson logged.',
    ],
  },
  stale_state: {
    title: 'Stale state',
    lines: [
      'Two admins edit the same role at once — a classic cloud race.',
      'An out-of-band change moves the policy from v1 to v2 mid-run.',
      'The agent detects its baseline went stale.',
      'It refreshes, replans against v2, and applies v3.',
      'Optimistic concurrency handling, no drama.',
    ],
  },
  unsupported_gcp: {
    title: 'GCP parity check',
    lines: [
      'Asks GCP for native pre-commit simulation.',
      'The capability matrix answers honestly: not supported.',
      'The run escalates instead of hallucinating fake results.',
      'No state touched, limitation recorded in the audit trail.',
      'For the full GCP loop, pick “GCP · local eval”.',
    ],
  },
  provider_mismatch: {
    title: 'Boundary guard',
    lines: [
      'A cross-cloud contamination attempt: an Azure policy aimed at AWS.',
      'The Kernel compares the source and target providers.',
      'Mismatch detected — the mutation is denied deterministically.',
      'No state touched, full audit trail kept.',
      'Boundary enforcement you can demo in ten seconds.',
    ],
  },
};

/** One minimalist log line in the process box */
interface ProcLine {
  stage: number;
  text: string;
  tone: 'dim' | 'info' | 'warn' | 'good' | 'bad';
}

/** Fold the run's raw audit events into a short human-readable process log */
function buildProcLines(run: AgentRunResponse): ProcLine[] {
  const lines: ProcLine[] = [];
  for (const e of run.events) {
    const d: any = e.details ?? {};
    switch (e.event_type) {
      case 'goal_received':
        lines.push({ stage: 0, text: `Goal received — ${run.goal}`, tone: 'dim' });
        break;
      case 'tool_result':
        if (e.tool === 'get_role' || e.tool === 'inspect_role') {
          const perms: string[] = d.data?.active_permissions ?? [];
          lines.push({ stage: 0, text: `Observed ${perms.length} active permissions on ${run.role_id}`, tone: 'info' });
        } else if (e.tool === 'get_access_history') {
          const n: number = (d.data ?? []).length;
          lines.push({ stage: 0, text: `Audited ${n} CloudTrail log lines`, tone: 'info' });
        } else if (e.tool === 'find_unused_permissions') {
          const unused: string[] = d.data ?? [];
          lines.push({ stage: 1, text: `Flagged ${unused.length} unlogged candidates: ${unused.join(', ') || 'none'}`, tone: 'warn' });
        }
        break;
      case 'simulation_started':
        lines.push({ stage: 2, text: 'Simulating candidate policy against live workflows…', tone: 'info' });
        break;
      case 'simulation_failed':
        lines.push({ stage: 2, text: `SIM FAILED — ${d.failed_workflow} needs ${d.missing_permission}`, tone: 'bad' });
        break;
      case 'dependency_discovered': {
        const deps: any[] = d.dependencies ?? [];
        const chain = deps.map((x) => `${x.service} → ${x.calls_service} → ${x.downstream_dependency}`).join('; ');
        const need = deps[0]?.required_permission ? ` (needs ${deps[0].required_permission})` : '';
        lines.push({ stage: 3, text: `Hidden coupling found: ${chain}${need}`, tone: 'warn' });
        break;
      }
      case 'replan_started':
        lines.push({
          stage: 3,
          text: `Replanned — keeping ${(d.retained_dependencies ?? []).join(', ') || 'dependencies'}, cutting ${(d.remove_permissions ?? []).join(', ') || 'nothing'}`,
          tone: 'good',
        });
        break;
      case 'security_check':
        lines.push({
          stage: 4,
          text: `Safety Kernel: ${String(d.decision ?? '').toUpperCase()} (blast ${d.blast_radius ?? '—'})`,
          tone: d.decision === 'allow' ? 'good' : 'bad',
        });
        break;
      case 'security_gate_denied':
        lines.push({ stage: 4, text: `Kernel veto: ${(d.reason_codes ?? []).join(', ')}`, tone: 'bad' });
        break;
      case 'provider_mismatch':
        lines.push({ stage: 4, text: 'Cross-cloud mutation halted — provider boundary enforced', tone: 'bad' });
        break;
      case 'adapt':
        lines.push({ stage: 3, text: `Stale state detected — refreshed to ${d.refreshed_version ?? 'latest'}, replanning`, tone: 'warn' });
        break;
      case 'verification_started':
        lines.push({ stage: 4, text: 'Running independent post-apply verification…', tone: 'info' });
        break;
      case 'policy_applied':
        lines.push({ stage: 4, text: `Applied policy ${d.version_id ?? ''} to ${run.role_id}`, tone: 'good' });
        break;
      case 'verification_passed':
        lines.push({ stage: 4, text: 'Independent verification passed — zero regression', tone: 'good' });
        break;
      case 'verification_failed':
        lines.push({ stage: 4, text: 'Verification FAILED — rolling back', tone: 'bad' });
        break;
      case 'rollback':
        lines.push({ stage: 4, text: `Rolled back to ${d.restored_version ?? d.version_id ?? 'v1'} (verified)`, tone: 'warn' });
        break;
      case 'escalate':
        lines.push({ stage: 4, text: `Escalated safely (${run.stop_reason ?? 'human review needed'})`, tone: 'warn' });
        break;
      case 'final_outcome':
        lines.push({
          stage: 4,
          text: d.status === 'success' ? 'Least privilege verified ✓' : `Run ended: ${run.stop_reason ?? d.status}`,
          tone: d.status === 'success' ? 'good' : 'warn',
        });
        break;
      default:
        break;
    }
  }
  return lines.filter((l, i) => i === 0 || l.text !== lines[i - 1].text).slice(0, 16);
}

const toneCls: Record<ProcLine['tone'], string> = {
  dim: 'text-slate-500',
  info: 'text-slate-200',
  warn: 'text-amber-300',
  good: 'text-emerald-300',
  bad: 'text-rose-300',
};

function useRunFlags(run: AgentRunResponse | null) {
  const events = run?.events ?? [];
  const hasReplan = events.some((e) => e.event_type === 'replan_started');
  const isBlocked =
    run?.stop_reason === 'security_block' ||
    run?.stop_reason === 'provider_mismatch' ||
    run?.stop_reason === 'privilege_expansion_blocked' ||
    events.some((e) => e.event_type === 'security_gate_denied' || e.event_type === 'provider_mismatch');
  const isRollback =
    run?.stop_reason === 'verification_failure_rolled_back' ||
    events.some((e) => e.event_type === 'rollback');
  const isCompleted = run?.status === 'completed' && !isBlocked && !isRollback;
  return { hasReplan, isBlocked, isRollback, isCompleted };
}

const pickerCls =
  'w-full bg-black border border-white/20 hover:border-white/40 rounded-lg px-3 py-2.5 text-sm font-mono text-slate-200 cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 disabled:opacity-40';

const KERNEL_INVARIANTS = [
  'NO_PRIVILEGE_EXPANSION',
  'NO_PROTECTED_PERMISSION_MUTATION',
  'NO_PROTECTED_RESOURCE_EXPOSURE',
  'NO_CROSS_PROVIDER_MUTATION',
  'NO_CROSS_TENANT_MUTATION',
  'NO_STALE_STATE_MUTATION',
  'NO_MUTATION_WITHOUT_EVIDENCE',
  'NO_MUTATION_WITHOUT_SIMULATION',
  'NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION',
  'NO_COMPLETION_WITHOUT_VERIFICATION',
  'NO_UNAPPROVED_HIGH_RISK',
];

const KERNEL_CMDS = ['help', 'status', 'invariants', 'diff', 'allow', 'deny', 'escalate', 'ack'];

interface KernelVerdict {
  action: 'allow' | 'deny' | 'escalate' | 'ack';
  reason: string;
  raw: string;
}

interface KernelEntry {
  cmd: string;
  out: string[];
  tone: 'info' | 'good' | 'bad' | 'warn';
}

const STEP_MS = 650;

export const SimulationPage: React.FC<SimulationPageProps> = ({
  roles,
  selectedRole,
  onSelectRole,
  selectedScenario,
  onSelectScenario,
  onRun,
  onBack,
  isRunning,
  currentRun,
  error,
  systemHealthy,
}) => {
  // Curated process log for the current run + timed reveal (playback)
  const curated = useMemo(
    () => (currentRun ? buildProcLines(currentRun) : []),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [currentRun?.run_id],
  );
  const [reveal, setReveal] = useState(0);
  const [kernelLog, setKernelLog] = useState<KernelEntry[]>([]);
  const [kernelInput, setKernelInput] = useState('');
  const [kernelVerdict, setKernelVerdict] = useState<KernelVerdict | null>(null);
  const [evidencePerm, setEvidencePerm] = useState<string | null>(null);
  useEffect(() => {
    setReveal(0);
    setKernelLog([]);
    setKernelInput('');
    setKernelVerdict(null);
    setEvidencePerm(null);
    if (!currentRun) return;
    const t = setInterval(() => {
      setReveal((r) => {
        if (r >= curated.length) {
          clearInterval(t);
          return r;
        }
        return r + 1;
      });
    }, STEP_MS);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentRun?.run_id]);

  const playing = !!currentRun && reveal < curated.length;
  const revealed = curated.slice(0, reveal);

  // auto-scroll the live log as lines arrive
  const boxRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = boxRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [reveal]);

  // flow stages from revealed lines
  const maxStage = revealed.length ? Math.max(...revealed.map((l) => l.stage)) : -1;
  const stageState = (i: number): 'done' | 'active' | 'pending' => {
    if (!currentRun) return 'pending';
    if (!playing && !isRunning) return 'done';
    if (i < maxStage) return 'done';
    if (i === maxStage) return 'active';
    return 'pending';
  };

  const showProcess = !!currentRun;
  const showResultPre = !!currentRun && !playing && !isRunning;

  const { hasReplan, isBlocked, isRollback, isCompleted } = useRunFlags(showResultPre ? currentRun : null);
  const diff = currentRun?.policy_diff;
  const removed = diff?.removed ?? [];
  const kept = diff?.kept ?? [];

  // ---- Security Kernel console (visual reenactment of the real gate) ----
  // Always visible while a run exists; content goes standby → live gate.
  const events = currentRun?.events ?? [];
  const secChecks = events.filter((e) => e.event_type === 'security_check');
  const secCheck = secChecks[secChecks.length - 1];
  const secDetails: any = secCheck?.details ?? {};
  const kernelDecision: string = secDetails.decision ?? currentRun?.security_decision?.decision ?? '';
  const kernelBlast: string = secDetails.blast_radius ?? currentRun?.blast_radius ?? 'LOW';
  const kernelArrived = revealed.some((l) => l.stage >= 4) || showResultPre;
  const showKernel = !!currentRun;
  // ---- Autonomy tiers, derived purely from the finished payload ----
  // Standard: removal-only, gate allowed, blast LOW/MEDIUM → no human needed.
  // Sensitive: gate denied/escalated, HIGH blast, or a halting stop reason
  // → a human is required by design. Display-only; engine behavior unchanged.
  const STOP_RULES: Record<string, string> = {
    security_block: 'protected capability removal forbidden',
    provider_mismatch: 'cross-provider mutation forbidden',
    privilege_expansion_blocked: 'privilege expansion forbidden',
    unsupported_capability: 'unsupported provider operation',
    human_approval_required: 'human approval required',
    insufficient_evidence: 'insufficient evidence for change',
  };
  const stopReason = currentRun?.stop_reason ?? '';
  const blastHigh = kernelBlast === 'HIGH' || kernelBlast === 'CRITICAL';
  const gateDenied = kernelDecision !== '' && kernelDecision !== 'allow';
  const tierSensitive =
    !!currentRun && (gateDenied || blastHigh || STOP_RULES[stopReason] !== undefined);
  const tierRule =
    STOP_RULES[stopReason] ??
    (gateDenied ? `gate ${kernelDecision}` : blastHigh ? `blast radius ${kernelBlast}` : '');
  // The operator console is a sandbox: it records what-if entries only and
  // never gates the verdict — the backend run already completed on its own.
  const kernelGateActive = kernelDecision === 'allow' && removed.length > 0;

  const pushKernel = (cmd: string, out: string[], tone: KernelEntry['tone']) =>
    setKernelLog((log) => [...log, { cmd, out, tone }].slice(-30));

  const runKernelCmd = (raw: string) => {
    const text = raw.trim();
    if (!text) return;
    const verb = text.split(/\s+/)[0].toLowerCase();
    const reasonMatch = text.match(/--reason\s+"([^"]+)"|--reason\s+(.+)$/);
    const reason = (reasonMatch?.[1] ?? reasonMatch?.[2] ?? '').trim();

    if (verb === 'help') {
      pushKernel(text, ['commands: help · status · invariants · diff · allow · deny · escalate · ack', 'sandbox: allow | deny | escalate explore what-if outcomes · ack acknowledges the gate'], 'info');
      return;
    }
    if (verb === 'status') {
      pushKernel(text, [
        `gate: ${kernelDecision ? kernelDecision.toUpperCase() : '—'} · blast: ${kernelBlast}`,
        `role: ${currentRun?.role_id ?? '—'} · proposed removals: ${removed.join(', ') || 'none'}`,
      ], 'info');
      return;
    }
    if (verb === 'invariants') {
      pushKernel(text, KERNEL_INVARIANTS.map((v, i) => `${String(i + 1).padStart(2, '0')}. ${v}`), 'info');
      return;
    }
    if (verb === 'diff') {
      if (!removed.length && !kept.length) {
        pushKernel(text, ['no diff — nothing was applied on this run'], 'warn');
      } else {
        pushKernel(text, [
          ...removed.map((p) => `- ${p}`),
          ...kept.map((p) => `+ ${p} (kept)`),
        ], 'info');
      }
      return;
    }
    if (verb === 'allow') {
      if (!kernelGateActive) {
        pushKernel(text, [`gate decision is ${kernelDecision ? kernelDecision.toUpperCase() : 'unavailable'} — recorded as what-if only; try 'ack'`], 'warn');
        setKernelVerdict({ action: 'allow', reason, raw: text });
        return;
      }
      setKernelVerdict({ action: 'allow', reason, raw: text });
      pushKernel(text, [`what-if authorized${reason ? ` — ${reason}` : ''} (verdict above already released on its own)`], 'good');
      return;
    }
    if (verb === 'deny' || verb === 'escalate') {
      setKernelVerdict({ action: verb, reason, raw: text });
      pushKernel(text, [`what-if ${verb}${reason ? ` — ${reason}` : ''} — change would be held for human review (verdict above unchanged)`], 'warn');
      return;
    }
    if (verb === 'ack') {
      if (kernelGateActive) {
        pushKernel(text, ["nothing to acknowledge — gate awaits 'allow' or 'deny'"], 'warn');
        return;
      }
      setKernelVerdict({ action: 'ack', reason, raw: text });
      pushKernel(text, ['gate acknowledged — releasing run outcome'], 'info');
      return;
    }
    pushKernel(text, [`unknown command '${verb}' — try: ${KERNEL_CMDS.join(', ')}`], 'bad');
  };

  const submitKernel = () => {
    runKernelCmd(kernelInput);
    setKernelInput('');
  };

  // Verdict auto-releases when playback completes — the backend run already
  // finished alone. Sandbox entries never gate or reshape it.
  const showResult = showResultPre;
  const heldByOperator = kernelVerdict !== null && (kernelVerdict.action === 'deny' || kernelVerdict.action === 'escalate');

  return (
    <div className="relative min-h-[calc(100vh-4rem)]">
      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 py-5">
        {/* top row: back + status + run */}
        <div className="flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={onBack}
            className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-500 hover:text-slate-200 transition-colors cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 rounded"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Home
          </button>

          <div className="flex items-center gap-2.5">
            <span
              title={systemHealthy ? 'Backend reachable' : 'Backend unreachable'}
              className={`w-2 h-2 rounded-full ${systemHealthy ? 'bg-emerald-400' : 'bg-rose-500'}`}
            />
            <button
              type="button"
              onClick={onRun}
              disabled={isRunning}
              className="inline-flex items-center gap-1.5 px-5 py-2 rounded-md bg-sky-400 hover:bg-sky-300 disabled:opacity-50 disabled:hover:bg-sky-400 text-black text-sm font-semibold transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-200 focus-visible:ring-offset-2 focus-visible:ring-offset-black"
            >
              {isRunning || playing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {isRunning || playing ? 'Running…' : currentRun ? 'Run again' : 'Run demo simulation'}
            </button>
          </div>
        </div>

        {/* big visible selectors */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-mono tracking-[0.2em] text-slate-400">SERVICE ROLE</span>
            <select
              aria-label="Service role"
              value={selectedRole}
              onChange={(e) => onSelectRole(e.target.value)}
              disabled={isRunning || playing}
              className={pickerCls}
            >
              {(roles.length > 0 ? roles.map((r) => r.id) : ['PaymentServiceRole']).map((id) => (
                <option key={id} value={id} className="bg-black">
                  {id}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-mono tracking-[0.2em] text-slate-400">SCENARIO</span>
            <select
              aria-label="Scenario"
              value={selectedScenario}
              onChange={(e) => onSelectScenario(e.target.value as DemoScenario)}
              disabled={isRunning || playing}
              className={pickerCls}
            >
              {SCENARIOS.map((s) => (
                <option key={s.id} value={s.id} className="bg-black">
                  {s.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {/* slim error line */}
        {error && !currentRun && (
          <div className="mt-6 text-center text-xs font-mono text-rose-400 animate-rise-in">
            {error} — press Run to retry.
          </div>
        )}

        {/* IDLE: scenario explainer + ready */}
        {!currentRun && !isRunning && !error && (
          <div className="mt-10 animate-rise-in">
            <div className="max-w-xl mx-auto rounded-lg border border-white/10 bg-white/[0.02] p-6">
              <div className="text-[11px] font-mono tracking-[0.2em] text-slate-500">
                THIS SCENARIO
              </div>
              <div className="mt-1.5 text-xl font-bold text-white">
                {SCENARIO_INFO[selectedScenario].title}
              </div>
              <ol className="mt-4 space-y-2.5">
                {SCENARIO_INFO[selectedScenario].lines.map((line, i) => (
                  <li key={i} className="flex gap-3 text-[15px] text-slate-300 leading-relaxed">
                    <span className="font-mono text-xs text-sky-400/80 pt-1 shrink-0">{i + 1}</span>
                    {line}
                  </li>
                ))}
              </ol>
            </div>
            <div className="mt-8 text-center">
              <div className="text-[11px] font-mono tracking-[0.25em] text-slate-600">READY</div>
              <p className="mt-3 text-sm text-slate-400">
                Press <span className="text-slate-200">Run demo simulation</span> to watch it happen live.
              </p>
            </div>
          </div>
        )}

        {/* CONTACTING ENGINE */}
        {isRunning && !currentRun && (
          <div className="mt-20 text-center animate-rise-in">
            <Loader2 className="w-6 h-6 text-sky-400 animate-spin mx-auto" />
            <p className="mt-3 text-sm text-slate-400">Contacting assessment engine…</p>
          </div>
        )}

        {/* TWIN BOXES: flow + live log */}
        {showProcess && currentRun && (
          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-3 animate-rise-in">
            {/* LEFT: flow box */}
            <div className="rounded-lg border border-white/10 bg-white/[0.02] p-4">
              <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">FLOW</div>
              <ol className="mt-3 space-y-2">
                {STAGES.map((label, i) => {
                  const st = stageState(i);
                  return (
                    <li
                      key={label}
                      className={`flex items-center gap-3 rounded-md border px-4 py-3 transition-all ${
                        st === 'active'
                          ? 'border-sky-400/60 bg-sky-400/[0.07] shadow-[0_0_22px_rgba(56,189,248,0.35)]'
                          : st === 'done'
                          ? 'border-emerald-400/25 bg-emerald-400/[0.04]'
                          : 'border-white/[0.07] bg-transparent'
                      }`}
                    >
                      <span
                        className={`w-5 h-5 rounded-full flex items-center justify-center border text-[10px] font-mono shrink-0 ${
                          st === 'done'
                            ? 'border-emerald-400/60 text-emerald-300'
                            : st === 'active'
                            ? 'border-sky-400/70 text-sky-300'
                            : 'border-white/10 text-slate-600'
                        }`}
                      >
                        {st === 'done' ? (
                          <Check className="w-3 h-3" />
                        ) : st === 'active' ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          <span>{i + 1}</span>
                        )}
                      </span>
                      <span className={`text-[15px] ${st === 'pending' ? 'text-slate-600' : 'text-slate-100 font-medium'}`}>
                        {label}
                      </span>
                      {st === 'active' && (
                        <span className="ml-auto w-1.5 h-1.5 rounded-full bg-sky-400 pulse-dot" />
                      )}
                    </li>
                  );
                })}
              </ol>
            </div>

            {/* RIGHT: live step-by-step box */}
            <div className="rounded-lg border border-white/10 bg-white/[0.02] flex flex-col">
              <div className="flex items-center justify-between px-4 pt-3">
                <span className="text-[10px] font-mono tracking-[0.2em] text-slate-500">LIVE LOG</span>
                {playing ? (
                  <button
                    type="button"
                    onClick={() => setReveal(curated.length)}
                    className="text-[10px] font-mono text-slate-500 hover:text-slate-200 transition-colors cursor-pointer"
                  >
                    skip ↓
                  </button>
                ) : (
                  <span className="text-[10px] font-mono text-slate-600">
                    {revealed.length}/{curated.length}
                  </span>
                )}
              </div>
                <div ref={boxRef} className="px-4 py-2 pb-3 h-80 overflow-y-auto font-mono text-[13px] leading-7">
                {revealed.map((l, i) => (
                  <div key={`${currentRun.run_id}-${i}`} className={`${toneCls[l.tone]} animate-rise-in`}>
                    <span className="text-slate-600 select-none">› </span>
                    {l.text}
                  </div>
                ))}
                {playing && <span className="text-sky-300 animate-pulse">▍</span>}
              </div>
            </div>
          </div>
        )}

        {/* SECURITY KERNEL console — output box */}
        {showKernel && currentRun && (
          <div className="mt-3 max-w-3xl mx-auto rounded-lg border border-amber-400/25 bg-amber-400/[0.03] p-4 animate-rise-in">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-amber-300" />
              <span className="text-[10px] font-mono tracking-[0.2em] text-amber-200/80">SECURITY KERNEL</span>
              <span className="ml-auto text-[10px] font-mono text-slate-600">sandbox — step into the gate</span>
            </div>
            <div className="mt-2.5 font-mono text-xs leading-6">
              {!kernelArrived ? (
                <div className="text-slate-500">▸ Kernel standing by — gate opens at the Verify stage…</div>
              ) : secCheck ? (
                <>
                  <div className="text-slate-400">▸ Loading 11 deterministic invariants…</div>
                  <div className="text-slate-400">▸ Privilege-expansion check: <span className="text-emerald-300">PASS</span> (removal only)</div>
                  <div className="text-slate-400">▸ Blast radius: <span className="text-slate-200">{kernelBlast}</span></div>
                  <div className={kernelDecision === 'allow' ? 'text-emerald-300' : 'text-rose-300'}>
                    ▸ Decision: {kernelDecision.toUpperCase() || '—'}
                  </div>
                </>
              ) : (
                <div className="text-amber-200/90">
                  ▸ No mutation gate reached — run escalated ({currentRun.stop_reason ?? 'human review needed'})
                </div>
              )}

              {kernelArrived && kernelLog.map((entry, i) => (
                <div key={i} className="mt-1">
                  <div className="text-sky-300 select-none">› {entry.cmd}</div>
                  {entry.out.map((line, j) => (
                    <div
                      key={j}
                      className={
                        entry.tone === 'good' ? 'text-emerald-300'
                        : entry.tone === 'bad' ? 'text-rose-300'
                        : entry.tone === 'warn' ? 'text-amber-200/90'
                        : 'text-slate-400'
                      }
                    >
                      {line}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* KERNEL COMMANDS — separate, bigger input box below the kernel */}
        {showKernel && currentRun && kernelArrived && (
          <div className="mt-3 max-w-3xl mx-auto rounded-lg border border-white/15 bg-white/[0.03] p-5 animate-rise-in">
            <div className="text-[11px] font-mono tracking-[0.2em] text-slate-400">
              KERNEL COMMANDS — OPTIONAL SANDBOX PLAY
            </div>
            <div className="mt-3 flex items-center gap-3">
              <span className="text-lg text-sky-300 select-none">›</span>
              <input
                value={kernelInput}
                onChange={(e) => setKernelInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') submitKernel(); }}
                placeholder="try: help"
                autoFocus
                spellCheck={false}
                autoComplete="off"
                className="flex-1 min-w-0 bg-black/60 border border-white/20 focus:border-sky-400 rounded-md px-4 py-2.5 text-base text-slate-100 placeholder:text-slate-600 focus:outline-none"
              />
              <button
                type="button"
                onClick={submitKernel}
                className="text-sm font-mono px-4 py-2.5 rounded-md border border-white/20 hover:border-white/50 text-slate-200 hover:text-white transition-colors cursor-pointer shrink-0"
              >
                ↵ run
              </button>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {KERNEL_CMDS.map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => {
                    if (c === 'allow' || c === 'deny' || c === 'escalate') {
                      setKernelInput(`${c} `);
                    } else {
                      runKernelCmd(c);
                    }
                  }}
                  title={c === 'allow' || c === 'deny' || c === 'escalate' ? 'Fills the input — add --reason if you like, then ↵' : `Runs ${c}`}
                  className="text-xs font-mono px-2.5 py-1 rounded-md border border-white/15 hover:border-sky-400/60 hover:text-sky-200 text-slate-300 transition-colors cursor-pointer"
                >
                  {c}
                </button>
              ))}
            </div>
            <div className="mt-2 text-[11px] font-mono text-slate-600">
              what-if sandbox: allow · deny · escalate explore alternatives · ack acknowledges — verdict below is already final
            </div>
          </div>
        )}

        {/* FINAL OUTPUT — auto-releases when playback completes */}
        {showResult && currentRun && (
          <div key={currentRun.run_id} className="mt-8 max-w-xl mx-auto animate-rise-in">
            {/* autonomy tier: who (didn't) need to be involved */}
            <div className="flex justify-center">
              <div
                className={`inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-[11px] font-mono ${
                  tierSensitive
                    ? 'border-amber-400/40 bg-amber-400/[0.07] text-amber-200'
                    : 'border-emerald-400/40 bg-emerald-400/[0.07] text-emerald-200'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${tierSensitive ? 'bg-amber-300' : 'bg-emerald-300'}`} />
                {tierSensitive
                  ? `Track: Sensitive — human required${tierRule ? ` · ${tierRule}` : ''}`
                  : 'Track: Standard — auto-applied · human actions: 0'}
              </div>
            </div>
            {isCompleted && (
              <div className="text-center">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <h2 className="mt-3 text-2xl font-bold text-white tracking-tight">
                  Least privilege verified
                </h2>
                <p className="mt-2 text-sm text-slate-400">
                  {removed.length > 0 ? (
                    <>
                      {currentRun.role_id} went from{' '}
                      <span className="text-slate-200 font-mono">
                        {kept.length + removed.length} → {kept.length + (diff?.added?.length ?? 0)}
                      </span>{' '}
                      permissions, zero regression.
                    </>
                  ) : (
                    <>Assessment complete — zero regression.</>
                  )}
                </p>
              </div>
            )}

            {heldByOperator && (
              <div className="mt-6 rounded-lg border border-white/10 bg-white/[0.02] p-4 text-center">
                <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">SANDBOX WHAT-IF</div>
                <p className="mt-1.5 text-[13px] text-slate-400 leading-relaxed">
                  You entered <span className="font-mono text-amber-300">{kernelVerdict?.raw}</span>
                  {kernelVerdict?.reason && (
                    <> — <span className="text-slate-200">“{kernelVerdict.reason}”</span></>
                  )}. Had the gate decided that way, the change would be held for human
                  review instead of applied. The verdict below is the actual run outcome.
                </p>
              </div>
            )}

            {isBlocked && (
              <div className="text-center">
                <ShieldAlert className="w-8 h-8 text-rose-400 mx-auto" />
                <h2 className="mt-3 text-2xl font-bold text-white tracking-tight">Blocked by Safety Kernel</h2>
                <p className="mt-2 text-sm text-slate-400">
                  {currentRun.stop_reason === 'provider_mismatch'
                    ? 'Cross-cloud mutation refused — foreign policy can never land here.'
                    : 'Protected capability refused — no state was changed.'}
                </p>
              </div>
            )}

            {isRollback && (
              <div className="text-center">
                <Undo2 className="w-8 h-8 text-amber-300 mx-auto" />
                <h2 className="mt-3 text-2xl font-bold text-white tracking-tight">Rolled back safely</h2>
                <p className="mt-2 text-sm text-slate-400">
                  Verification failed after apply — policy restored to v1 and confirmed.
                </p>
              </div>
            )}

            {!isCompleted && !isBlocked && !isRollback && (
              <div className="text-center">
                <h2 className="mt-3 text-2xl font-bold text-white tracking-tight">
                  Run {currentRun.status}
                </h2>
                <p className="mt-2 text-sm text-slate-400">
                  {currentRun.final_result?.message ?? 'Escalated safely — no state was changed.'}
                </p>
              </div>
            )}

            {/* before / after — the actual run outcome */}
            {removed.length > 0 && isCompleted && (
              <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
                <div className="rounded-lg border border-white/10 p-4">
                  <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">
                    REMOVED
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {removed.map((p) => (
                      <button
                        key={p}
                        type="button"
                        title="Click for evidence"
                        onClick={() => setEvidencePerm((s) => (s === p ? null : p))}
                        className={`text-[11px] font-mono rounded px-1.5 py-0.5 border transition-colors cursor-pointer ${
                          evidencePerm === p
                            ? 'text-rose-200 bg-rose-500/20 border-rose-400/50'
                            : 'text-rose-300 bg-rose-500/10 border-rose-500/20 hover:border-rose-400/50'
                        }`}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="rounded-lg border border-white/10 p-4">
                  <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">
                    KEPT
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {kept.map((p) => (
                      <button
                        key={p}
                        type="button"
                        title="Click for evidence"
                        onClick={() => setEvidencePerm((s) => (s === p ? null : p))}
                        className={`text-[11px] font-mono rounded px-1.5 py-0.5 border transition-colors cursor-pointer ${
                          evidencePerm === p
                            ? 'text-emerald-200 bg-emerald-500/20 border-emerald-400/50'
                            : 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20 hover:border-emerald-400/50'
                        }`}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* per-change evidence — click any permission chip */}
            {evidencePerm && diff && (
              <div className="mt-3 rounded-lg border border-white/15 bg-white/[0.03] p-4 animate-rise-in">
                <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">
                  EVIDENCE · <span className="text-slate-200">{evidencePerm}</span>
                </div>
                <p className="mt-1.5 text-[13px] text-slate-300 leading-relaxed">
                  {diff.why_removed?.[evidencePerm] ?? diff.why_kept?.[evidencePerm] ?? 'No recorded justification.'}
                </p>
              </div>
            )}

            {(() => {
              const runEvents = currentRun?.events ?? [];
              const simFailEvt = runEvents.find((e) => e.event_type === 'simulation_failed');
              const simFailD: any = simFailEvt?.details ?? {};
              const depEvt = runEvents.find((e) => e.event_type === 'dependency_discovered');
              const depList: any[] = depEvt?.details?.dependencies ?? [];
              const dep0 = depList[0];
              const chain = dep0 ? `${dep0.service} → ${dep0.calls_service} → ${dep0.downstream_dependency}` : null;
              if (!hasReplan && !simFailEvt) return null;
              return (
                <p className="mt-5 text-center text-xs text-slate-400">
                  Simulation failed on <code className="font-mono text-amber-300">{simFailD.missing_permission ?? 'a hidden permission'}</code>
                  {chain && (<> — hidden <span className="font-mono">{chain}</span> coupling found</>)}
                  , plan adapted, re-simulation passed.
                </p>
              );
            })()}

            {kernelVerdict && (
              <p className={`mt-3 text-center text-[11px] font-mono ${kernelVerdict.action === 'allow' ? 'text-emerald-300/80' : 'text-amber-300/80'}`}>
                sandbox: {kernelVerdict.raw}{kernelVerdict.reason ? ` — “${kernelVerdict.reason}”` : ''} (exploration only — verdict above stands)
              </p>
            )}

            <div className="mt-5 text-center text-[11px] font-mono text-slate-600">
              {(currentRun.blast_radius ? `blast ${currentRun.blast_radius}` : 'blast LOW')
                + (currentRun.telemetry?.runtime_ms != null ? ` · ${currentRun.telemetry.runtime_ms}ms` : '')
                + ` · ${currentRun.run_id}`}
            </div>

            {/* take-home artifacts — real files from live endpoints */}
            <div className="mt-4 flex justify-center">
              <DownloadRow run={currentRun} />
            </div>

            <div className="mt-6 text-center">
              <button
                type="button"
                onClick={onRun}
                disabled={isRunning}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md border border-white/15 hover:border-white/40 text-slate-300 hover:text-white text-xs font-mono transition-colors cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-400"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Run again
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
