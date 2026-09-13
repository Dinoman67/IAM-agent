import React, { useEffect, useMemo, useState } from 'react';
import { Loader2, ShieldAlert, ShieldCheck } from 'lucide-react';
import { AgentRunResponse, RunSummary } from '../types';
import { getAgentRun, requestOverride } from '../services/api';
import { KERNEL_INVARIANTS, gateLines, getTier, isHaltedRun, kindOf, narrativeOf, recordedProposal } from '../components/kernel/model';
import { DownloadRow } from '../components/run/DownloadRow';

interface ReviewPageProps {
  summaries: RunSummary[];
  onReviewed: (runId: string) => void;
  onViewRun: (run: AgentRunResponse) => void;
}

interface Entry {
  cmd: string;
  out: string[];
  tone: 'info' | 'good' | 'bad' | 'warn';
}

const toneCls: Record<Entry['tone'], string> = {
  info: 'text-slate-400',
  good: 'text-emerald-300',
  bad: 'text-rose-300',
  warn: 'text-amber-200/90',
};

function haltedAt(run: AgentRunResponse | null): string {
  const ts = run?.events?.[0]?.timestamp;
  if (!ts) return '—';
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

export const ReviewPage: React.FC<ReviewPageProps> = ({ summaries, onReviewed, onViewRun }) => {
  // Single review: the latest halted run only. No queue, no history.
  const latestId = useMemo(() => {
    const halted = summaries.filter((r) => isHaltedRun(r.stop_reason));
    return halted[0]?.run_id ?? null;
  }, [summaries]);
  const [detail, setDetail] = useState<AgentRunResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastEntry, setLastEntry] = useState<Entry | null>(null);
  const [input, setInput] = useState('');
  const [approver, setApprover] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<AgentRunResponse | null>(null);

  useEffect(() => {
    if (!latestId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setOutcome(null);
    setLastEntry(null);
    getAgentRun(latestId)
      .then((run) => {
        if (cancelled) return;
        setDetail(run);
        onReviewed(latestId);
      })
      .catch((e: any) => {
        if (!cancelled) setError(e?.message ?? 'Failed to load run');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [latestId]);

  const push = (cmd: string, out: string[], tone: Entry['tone']) => setLastEntry({ cmd, out, tone });

  const gate = detail ? gateLines(detail) : { decision: '', blast: '—', codes: [] as string[] };
  const tier = getTier(detail, gate.decision, gate.blast);
  const kind = kindOf(detail?.stop_reason);
  const narrative = narrativeOf(detail?.stop_reason);
  const proposal = recordedProposal(detail);
  const removed: string[] = proposal.remove;
  const kept: string[] = proposal.keep;

  const doApprove = async (raw: string, by: string, why: string) => {
    if (!detail || busy) return;
    if (!by.trim() || !why.trim()) {
      push(raw, ['approver name and reason are both required — fill the fields above'], 'bad');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await requestOverride(detail.run_id, by.trim(), why.trim());
      if (res.stop_reason === 'override_refused') {
        push(raw, [`refused: ${(res.final_result?.details as any)?.reason_codes?.join?.(', ') ?? res.final_result?.message ?? 'unoverridable'}`], 'bad');
      } else {
        push(raw, [`override applied → ${res.policy_diff ? `v${(res.policy_diff.to_version ?? '').replace('v', '')}` : 'policy'} verified (${res.run_id})`], 'good');
      }
      setOutcome(res);
      onReviewed(detail.run_id);
    } catch (e: any) {
      push(raw, [e?.message ?? 'Override request failed'], 'bad');
    } finally {
      setBusy(false);
    }
  };

  function runCmdStandalone(raw: string) {
    const text = raw.trim();
    if (!text || !detail) return;
    const verb = text.split(/\s+/)[0].toLowerCase();
    if (verb === 'help') {
      push(text, ['commands: help · status · invariants · diff · allow · deny', 'allow executes a real override (needs approver + reason) · deny records refusal'], 'info');
    } else if (verb === 'status') {
      push(text, [
        `gate: ${gate.decision ? gate.decision.toUpperCase() : '—'} · blast: ${gate.blast}`,
        `role: ${detail.role_id ?? '—'} · stop: ${detail.stop_reason ?? '—'}`,
        ...(gate.codes.length ? [`codes: ${gate.codes.join(', ')}`] : []),
      ], 'info');
    } else if (verb === 'invariants') {
      push(text, KERNEL_INVARIANTS.map((v, i) => `${String(i + 1).padStart(2, '0')}. ${v}`), 'info');
    } else if (verb === 'diff') {
      if (!removed.length && !kept.length) push(text, ['no recorded proposal on this halt'], 'warn');
      else push(text, [...removed.map((p) => `- ${p}`), ...kept.map((p) => `+ ${p} (kept)`)], 'info');
    } else {
      push(text, [`unknown command '${verb}' — try: help, status, invariants, diff, allow, deny`], 'bad');
    }
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-xs font-mono tracking-[0.25em] text-slate-600">HUMAN REVIEW</div>
        <h1 className="mt-2 text-4xl font-bold text-white tracking-tight">Needs a human</h1>
        <p className="mt-2 text-base text-slate-400">
          Only halted runs appear here — successes never notify. Approvals execute a real
          override run; load-bearing denials refuse deterministically.
        </p>

        {!latestId ? (
          <div className="mt-10 text-center">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
            <p className="mt-3 text-sm text-slate-300">Queue empty — nothing needs you.</p>
            <p className="mt-1 text-xs font-mono text-slate-600">Blocked runs will raise a badge on this tab.</p>
          </div>
        ) : (
          <div className="mt-6 space-y-3">
            {loading && (
              <div className="rounded-lg border border-white/10 bg-white/[0.02] p-8 text-center">
                <Loader2 className="w-5 h-5 text-sky-400 animate-spin mx-auto" />
              </div>
            )}
            {error && <p className="text-xs font-mono text-rose-400">{error}</p>}
            {detail && !loading && (
              <>
                {/* run identity — which run is this, unmistakably */}
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                  <span className={`inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-xs font-mono font-bold ${kind.chip}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${kind.dot}`} />
                    {kind.label}
                  </span>
                  <span className="font-mono text-sm text-slate-200">{detail.run_id}</span>
                  <span className="font-mono text-sm text-slate-400">{detail.role_id ?? '—'}</span>
                  <span className="font-mono text-sm text-slate-500">{detail.provider?.toUpperCase() ?? ''}</span>
                  <span className="font-mono text-xs text-slate-500 ml-auto">halted {haltedAt(detail)}</span>
                </div>

                {/* what happened here, in this run's own words */}
                <div className="rounded-lg border border-white/10 bg-white/[0.02] p-6">
                  <div className="text-[11px] font-mono tracking-[0.2em] text-slate-500">
                    WHAT HAPPENED
                  </div>
                  <p className="mt-2 text-lg text-slate-100 leading-relaxed">{narrative.headline}</p>
                  <p className="mt-1.5 text-[15px] text-slate-400 leading-relaxed">{narrative.whatHappened}</p>
                  <p className="mt-1.5 text-[15px] text-slate-300 leading-relaxed">{narrative.whatNext}</p>
                </div>

                {/* the request — what the simulation asked for */}
                <div className="rounded-lg border border-white/10 bg-white/[0.02] p-6">
                  <div className="text-[11px] font-mono tracking-[0.2em] text-slate-500">
                    REQUEST
                  </div>
                  <p className="mt-2 text-lg text-slate-100 leading-relaxed">{detail.goal}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {removed.map((p) => (
                      <code key={p} className="text-xs font-mono text-rose-300 bg-rose-500/10 border border-rose-500/20 rounded px-2 py-0.5">
                        − {p}
                      </code>
                    ))}
                    {kept.map((p) => (
                      <code key={p} className="text-xs font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded px-2 py-0.5">
                        + {p}
                      </code>
                    ))}
                    {removed.length === 0 && kept.length === 0 && (
                      <span className="text-sm font-mono text-slate-500">no recorded proposal on this halt</span>
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-amber-400/25 bg-amber-400/[0.03] p-5">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-amber-300" />
                    <span className="text-[11px] font-mono tracking-[0.2em] text-amber-200/80">SECURITY KERNEL</span>
                    <span className={`ml-auto text-[11px] font-mono ${tier.sensitive ? 'text-amber-200' : 'text-emerald-200'}`}>
                      {tier.sensitive ? `sensitive${tier.rule ? ` · ${tier.rule}` : ''}` : 'standard'}
                    </span>
                  </div>
                  <div className="mt-2.5 font-mono text-sm leading-7">
                    <div className="text-slate-300">
                      ▸ Decision: <span className={gate.decision === 'allow' ? 'text-emerald-300' : 'text-rose-300'}>{gate.decision ? gate.decision.toUpperCase() : '—'}</span>
                      {' '}· blast <span className="text-slate-100">{gate.blast}</span>
                    </div>
                    {(removed.length > 0 || kept.length > 0) && (
                      <div className="text-slate-400">
                        ▸ Proposal: <span className="text-rose-300">−{removed.length}</span>
                        {' '}<span className="text-emerald-300">+{kept.length} kept</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-white/15 bg-white/[0.03] p-5">
                  <div className="text-[11px] font-mono tracking-[0.2em] text-slate-400">
                    KERNEL COMMANDS — DECISIONS EXECUTE HERE
                  </div>
                  <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] font-mono tracking-[0.15em] text-slate-500">APPROVER (REQUIRED)</span>
                      <input
                        value={approver}
                        onChange={(e) => setApprover(e.target.value)}
                        placeholder="your name"
                        autoComplete="off"
                        className="bg-black/60 border border-white/20 focus:border-sky-400 rounded-md px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none"
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] font-mono tracking-[0.15em] text-slate-500">REASON (REQUIRED)</span>
                      <input
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        placeholder="why is this safe to apply"
                        autoComplete="off"
                        className="bg-black/60 border border-white/20 focus:border-sky-400 rounded-md px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none"
                      />
                    </label>
                  </div>
                  <CommandInput
                    onSubmit={(t) => {
                      const v = t.trim().split(/\s+/)[0].toLowerCase();
                      if (v === 'allow') void doApprove(t, approver, reason);
                      else if (v === 'deny' || v === 'escalate') {
                        push(t, ['refusal recorded — run remains halted (no state changed)'], 'warn');
                        onReviewed(detail.run_id);
                      } else {
                        runCmdStandalone(t);
                      }
                    }}
                  />
                  <div className="mt-1.5 text-[11px] font-mono text-slate-600">
                    allow executes a real override run · deny records refusal · explorers never mutate
                  </div>
                  {lastEntry && (
                    <div className="mt-3 rounded-md border border-white/10 bg-black/40 p-4 animate-rise-in">
                      <div className="text-sky-300 font-mono text-sm select-none">› {lastEntry.cmd}</div>
                      {lastEntry.out.map((line, j) => (
                        <div key={j} className={`font-mono text-base leading-7 ${toneCls[lastEntry.tone]}`}>
                          {line}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {outcome && (
                  <div className="rounded-lg border border-white/10 bg-white/[0.02] p-5 animate-rise-in">
                    <div className="text-[11px] font-mono tracking-[0.2em] text-slate-500">OUTCOME</div>
                    {outcome.stop_reason === 'verified_success' ? (
                      <>
                        <p className="mt-2 text-base text-slate-200">
                          Override applied and verified —{' '}
                          <span className="font-mono text-[15px]">
                            {(outcome.policy_diff?.removed ?? []).length} removed
                          </span>{' '}
                          as <span className="font-mono text-[15px]">{outcome.run_id}</span>.
                        </p>
                        <div className="mt-3 flex items-center gap-3 flex-wrap">
                          <div className="flex-1 min-w-[12rem]">
                            <DownloadRow run={outcome} />
                          </div>
                          <button
                            type="button"
                            onClick={() => onViewRun(outcome)}
                            className="text-xs font-mono px-3 py-1.5 rounded-md border border-white/20 hover:border-white/50 text-slate-200 hover:text-white transition-colors cursor-pointer"
                          >
                            Open in Policy →
                          </button>
                        </div>
                      </>
                    ) : (
                      <p className="mt-2 text-base text-slate-300">
                        Override refused — {outcome.final_result?.message ?? outcome.stop_reason}.
                        Load-bearing denials cannot be approved in-product, by design.
                      </p>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

const CommandInput: React.FC<{ onSubmit: (text: string) => void }> = ({ onSubmit }) => {
  const [value, setValue] = useState('');
  return (
    <div className="mt-3">
      <div className="flex items-center gap-3">
        <span className="text-lg text-sky-300 select-none">›</span>
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              onSubmit(value);
              setValue('');
            }
          }}
          placeholder="try: help"
          spellCheck={false}
          autoComplete="off"
          className="flex-1 min-w-0 bg-black/60 border border-white/20 focus:border-sky-400 rounded-md px-4 py-2.5 text-base text-slate-100 placeholder:text-slate-600 focus:outline-none"
        />
        <button
          type="button"
          onClick={() => {
            onSubmit(value);
            setValue('');
          }}
          className="text-sm font-mono px-4 py-2.5 rounded-md border border-white/20 hover:border-white/50 text-slate-200 hover:text-white transition-colors cursor-pointer shrink-0"
        >
          ↵ run
        </button>
      </div>
      <div className="mt-2.5 flex flex-wrap gap-1.5">
        {['help', 'status', 'invariants', 'diff', 'allow', 'deny'].map((c) => (
          <button
            key={c}
            type="button"
            onClick={() => onSubmit(c)}
            className="text-xs font-mono px-2.5 py-1 rounded-md border border-white/15 hover:border-sky-400/60 hover:text-sky-200 text-slate-300 transition-colors cursor-pointer"
          >
            {c}
          </button>
        ))}
      </div>
    </div>
  );
};
