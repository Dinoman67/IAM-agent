import React, { useEffect, useMemo, useState } from 'react';
import { Loader2, ShieldAlert, ShieldCheck } from 'lucide-react';
import { AgentRunResponse, RunSummary } from '../types';
import { getAgentRun, requestOverride } from '../services/api';
import { KERNEL_CMDS, KERNEL_INVARIANTS, gateLines, getTier, isHaltedRun } from '../components/kernel/model';
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

export const ReviewPage: React.FC<ReviewPageProps> = ({ summaries, onReviewed, onViewRun }) => {
  const halted = useMemo(() => summaries.filter((r) => isHaltedRun(r.stop_reason)), [summaries]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AgentRunResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [log, setLog] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [approver, setApprover] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<AgentRunResponse | null>(null);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setOutcome(null);
    setLog([]);
    getAgentRun(selectedId)
      .then((run) => {
        if (cancelled) return;
        setDetail(run);
        onReviewed(selectedId);
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
  }, [selectedId]);

  useEffect(() => {
    if (!halted.some((r) => r.run_id === selectedId)) setSelectedId(halted[0]?.run_id ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [halted.length]);

  const push = (cmd: string, out: string[], tone: Entry['tone']) =>
    setLog((l) => [...l, { cmd, out, tone }].slice(-30));

  const gate = detail ? gateLines(detail) : { decision: '', blast: '—', codes: [] as string[] };
  const tier = getTier(detail, gate.decision, gate.blast);
  const diff = detail?.policy_diff;
  const removed: string[] = diff?.removed ?? [];
  const kept: string[] = diff?.kept ?? [];

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

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8">
      <div className="text-[11px] font-mono tracking-[0.25em] text-slate-600">HUMAN REVIEW</div>
      <h1 className="mt-2 text-2xl font-bold text-white tracking-tight">Runs awaiting a human</h1>
      <p className="mt-1 text-sm text-slate-400">
        Only halted runs appear here — successes never notify. Approvals execute a real
        override run; load-bearing denials refuse deterministically.
      </p>

      {halted.length === 0 ? (
        <div className="mt-10 text-center">
          <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
          <p className="mt-3 text-sm text-slate-300">Queue empty — nothing needs you.</p>
          <p className="mt-1 text-xs font-mono text-slate-600">Blocked runs will raise a badge on this tab.</p>
        </div>
      ) : (
        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3 items-start">
          {/* queue */}
          <div className="rounded-lg border border-white/10 bg-white/[0.02] overflow-hidden">
            <div className="px-3 py-2 text-[10px] font-mono tracking-[0.2em] text-slate-500">
              QUEUE ({halted.length})
            </div>
            <ul className="divide-y divide-white/[0.06]">
              {halted.map((r) => (
                <li key={r.run_id}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(r.run_id)}
                    className={`w-full text-left px-3 py-2.5 transition-colors cursor-pointer ${
                      selectedId === r.run_id ? 'bg-amber-400/[0.07]' : 'hover:bg-white/[0.03]'
                    }`}
                  >
                    <span className="block text-xs font-mono text-slate-200 truncate">{r.run_id}</span>
                    <span className="block text-[11px] font-mono text-slate-500 truncate">
                      {r.role_id} · {r.stop_reason}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* detail */}
          <div className="md:col-span-2 space-y-3">
            {loading && (
              <div className="rounded-lg border border-white/10 bg-white/[0.02] p-8 text-center">
                <Loader2 className="w-5 h-5 text-sky-400 animate-spin mx-auto" />
              </div>
            )}
            {error && <p className="text-xs font-mono text-rose-400">{error}</p>}
            {detail && !loading && (
              <>
                <div className="rounded-lg border border-amber-400/25 bg-amber-400/[0.03] p-4">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-amber-300" />
                    <span className="text-[10px] font-mono tracking-[0.2em] text-amber-200/80">SECURITY KERNEL</span>
                    <span className={`ml-auto text-[10px] font-mono ${tier.sensitive ? 'text-amber-200' : 'text-emerald-200'}`}>
                      {tier.sensitive ? `sensitive${tier.rule ? ` · ${tier.rule}` : ''}` : 'standard'}
                    </span>
                  </div>
                  <div className="mt-2.5 font-mono text-xs leading-6">
                    <div className="text-slate-400">
                      ▸ Decision: <span className={gate.decision === 'allow' ? 'text-emerald-300' : 'text-rose-300'}>{gate.decision ? gate.decision.toUpperCase() : '—'}</span>
                      {' '}· blast <span className="text-slate-200">{gate.blast}</span>
                    </div>
                    {gate.codes.length > 0 && (
                      <div className="text-slate-500 break-words">▸ {gate.codes.join(', ')}</div>
                    )}
                    {(removed.length > 0 || kept.length > 0) && (
                      <div className="text-slate-400">
                        ▸ Proposal: <span className="text-rose-300">−{removed.length}</span>
                        {' '}<span className="text-emerald-300">+{kept.length} kept</span>
                      </div>
                    )}
                    {log.map((e, i) => (
                      <div key={i} className="mt-1">
                        <div className="text-sky-300 select-none">› {e.cmd}</div>
                        {e.out.map((line, j) => (
                          <div
                            key={j}
                            className={
                              e.tone === 'good' ? 'text-emerald-300'
                              : e.tone === 'bad' ? 'text-rose-300'
                              : e.tone === 'warn' ? 'text-amber-200/90'
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
                      if (v === 'allow' || v === 'deny' || v === 'escalate') {
                        if (v === 'allow') void doApprove(t, approver, reason);
                        else {
                          push(t, ['refusal recorded — run remains halted (no state changed)'], 'warn');
                          onReviewed(detail.run_id);
                        }
                      } else {
                        runCmdStandalone(t);
                      }
                    }}
                  />
                  <div className="mt-1.5 text-[11px] font-mono text-slate-600">
                    allow executes a real override run · deny records refusal · explorers never mutate
                  </div>
                </div>

                {outcome && (
                  <div className="rounded-lg border border-white/10 bg-white/[0.02] p-4 animate-rise-in">
                    <div className="text-[10px] font-mono tracking-[0.2em] text-slate-500">OUTCOME</div>
                    {outcome.stop_reason === 'verified_success' ? (
                      <>
                        <p className="mt-2 text-sm text-slate-200">
                          Override applied and verified —{' '}
                          <span className="font-mono text-[13px]">
                            {(outcome.policy_diff?.removed ?? []).length} removed
                          </span>{' '}
                          as <span className="font-mono text-[13px]">{outcome.run_id}</span>.
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
                      <p className="mt-2 text-sm text-slate-300">
                        Override refused — {outcome.final_result?.message ?? outcome.stop_reason}.
                        Load-bearing denials cannot be approved in-product, by design.
                      </p>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );

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
            onClick={() => {
              if (c === 'allow' || c === 'deny') onSubmit(c);
              else onSubmit(c);
            }}
            className="text-xs font-mono px-2.5 py-1 rounded-md border border-white/15 hover:border-sky-400/60 hover:text-sky-200 text-slate-300 transition-colors cursor-pointer"
          >
            {c}
          </button>
        ))}
      </div>
    </div>
  );
};
