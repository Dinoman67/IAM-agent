import React from 'react';
import { ArrowRight, FlaskConical, GitPullRequest, Play, ShieldCheck, Skull } from 'lucide-react';

interface LandingPageProps {
  onLaunchDemo: () => void;
  onHowItWorks: () => void;
  onOpenConsole: () => void;
  isRunning: boolean;
}

// Stripe/Linear-inspired: confident headline, live product mock in hero, plain-English subhead.
export const LandingPage: React.FC<LandingPageProps> = ({ onLaunchDemo, onHowItWorks, onOpenConsole, isRunning }) => {
  return (
    <div className="space-y-10">
      {/* Announcement badge */}
      <div className="flex justify-center pt-2">
        <button
          type="button"
          onClick={onHowItWorks}
          className="group inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-sky-500/10 border border-sky-500/30 text-[11px] font-mono text-sky-300 hover:bg-sky-500/20 cursor-pointer"
        >
          <span className="px-1.5 py-0.5 rounded bg-sky-500 text-white text-[10px] font-bold">NEW</span>
          Attack-path graph + Terraform PR mode + temporal mining
          <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>

      {/* Hero */}
      <div className="text-center max-w-3xl mx-auto">
        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-white leading-[1.05]">
          Least privilege,
          <br />
          <span className="bg-gradient-to-r from-sky-400 via-indigo-400 to-emerald-400 bg-clip-text text-transparent">
            without breaking prod.
          </span>
        </h1>
        <p className="mt-4 text-sm sm:text-base text-slate-400 leading-relaxed max-w-2xl mx-auto">
          Most tools delete every permission with zero recent logs — then your annual disaster-recovery job explodes
          at 2am. This agent <strong className="text-slate-200">simulates every cut first</strong>, discovers hidden
          couplings like <code className="text-amber-300 font-mono">S3 → KMS</code>, and only applies what a
          deterministic Security Kernel approves.
        </p>
        <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
          <button
            type="button"
            onClick={onLaunchDemo}
            disabled={isRunning}
            className="w-full sm:w-auto px-6 py-3 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-60 text-white text-sm font-semibold inline-flex items-center justify-center gap-2 shadow-lg shadow-sky-950 cursor-pointer"
          >
            <Play className="w-4 h-4" />
            {isRunning ? 'Running demo…' : 'Watch it fix a role in 30 seconds'}
          </button>
          <button
            type="button"
            onClick={onHowItWorks}
            className="w-full sm:w-auto px-6 py-3 rounded-lg bg-soc-card border border-soc-border hover:border-slate-500 text-slate-200 text-sm font-mono cursor-pointer"
          >
            How it works (60s)
          </button>
        </div>
        <p className="mt-3 text-[11px] font-mono text-slate-500">
          No signup · deterministic offline demo · <button type="button" onClick={onOpenConsole} className="text-sky-400 hover:underline cursor-pointer">open the SOC console →</button>
        </p>
      </div>

      {/* Hero visual: live product mock (glassmorphism, Stripe-style glow) */}
      <div className="relative max-w-4xl mx-auto">
        <div className="absolute -inset-4 bg-gradient-to-r from-sky-500/20 via-indigo-500/20 to-emerald-500/20 blur-2xl rounded-3xl" />
        <div className="relative rounded-xl border border-soc-border bg-[#0D1420]/90 backdrop-blur p-5 shadow-2xl">
          <div className="flex items-center gap-1.5 pb-3 border-b border-soc-border/60">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400/70" />
            <span className="ml-2 text-[11px] font-mono text-slate-400">PaymentServiceRole — live remediation</span>
            <span className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">● KERNEL: ALLOW</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4 text-left">
            <div className="rounded-lg bg-slate-950/70 border border-soc-border p-3">
              <div className="text-[10px] font-mono text-slate-500 uppercase">Before → After</div>
              <div className="mt-1 font-mono text-lg text-white font-bold">7 → 4 <span className="text-xs text-emerald-400 font-medium">permissions</span></div>
              <div className="mt-2 space-y-1 text-[11px] font-mono">
                <div className="text-rose-300">− ec2:* · iam:* · dynamodb:*</div>
                <div className="text-emerald-300">+ kept kms:Decrypt (S3 SSE-KMS)</div>
              </div>
            </div>
            <div className="rounded-lg bg-slate-950/70 border border-soc-border p-3">
              <div className="text-[10px] font-mono text-slate-500 uppercase flex items-center gap-1"><Skull className="w-3 h-3" /> Attack paths</div>
              <div className="mt-1 font-mono text-lg text-white font-bold">6 → 3 <span className="text-xs text-amber-300 font-medium">blocked</span></div>
              <div className="mt-2 text-[11px] font-mono text-slate-400">Protected DB + admin user unreachable after fix.</div>
            </div>
            <div className="rounded-lg bg-slate-950/70 border border-soc-border p-3">
              <div className="text-[10px] font-mono text-slate-500 uppercase flex items-center gap-1"><GitPullRequest className="w-3 h-3" /> GitOps export</div>
              <div className="mt-1 font-mono text-lg text-white font-bold">TF + PR <span className="text-xs text-sky-300 font-medium">ready</span></div>
              <div className="mt-2 text-[11px] font-mono text-slate-400">Human merges. Rollback in one revert.</div>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] font-mono text-slate-400">
            <FlaskConical className="w-3.5 h-3.5 text-sky-400" />
            Sim 1 failed on <code className="text-amber-300">kms:Decrypt</code> → agent found the hidden coupling → replanned → Sim 2 passed.
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 ml-auto shrink-0" />
          </div>
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-4xl mx-auto text-center">
        {[
          ['7 → 4', 'permissions on demo role'],
          ['11', 'deterministic kernel invariants'],
          ['6 → 3', 'attack paths after fix'],
          ['109', 'backend tests passing'],
        ].map(([v, l]) => (
          <div key={l} className="rounded-lg bg-soc-card/60 border border-soc-border py-3 px-2">
            <div className="text-xl font-bold text-white font-mono">{v}</div>
            <div className="text-[11px] font-mono text-slate-500 mt-0.5">{l}</div>
          </div>
        ))}
      </div>

      {/* Dual track: new vs expert (Meta-style plain language + tech depth) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-4xl mx-auto">
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-5">
          <div className="text-[11px] font-mono font-bold text-emerald-300 uppercase">New to IAM? Start here</div>
          <h3 className="mt-1 text-lg font-bold text-white">Think hotel key cards.</h3>
          <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
            Your cloud role is a key card that opens 7 doors but you only use 4. Deleting the 5th door's access breaks
            the laundry room nobody logs — the encrypted backups. This agent <em>tests every door first</em>, keeps the
            laundry room, and hands you a safe new key card as a Terraform file.
          </p>
          <button type="button" onClick={onLaunchDemo} className="mt-3 text-xs font-mono text-emerald-300 hover:underline cursor-pointer">Run the 30-second demo →</button>
        </div>
        <div className="rounded-xl border border-sky-500/30 bg-sky-950/20 p-5">
          <div className="text-[11px] font-mono font-bold text-sky-300 uppercase">Cloud expert? The genius</div>
          <h3 className="mt-1 text-lg font-bold text-white">AI proposes. Deterministic controls decide.</h3>
          <p className="mt-1.5 text-xs text-slate-300 leading-relaxed font-mono">
            Counterfactual simulation → transitive SSE-KMS discovery → replan → 11-invariant kernel + 7-dim blast
            radius → atomic version + independent verifier → rollback on regression. Truthful GCP/Azure parity (escalate,
            never hallucinate).
          </p>
          <button type="button" onClick={onHowItWorks} className="mt-3 text-xs font-mono text-sky-300 hover:underline cursor-pointer">Read the technical deep-dive →</button>
        </div>
      </div>

      {/* How it works: 4 steps */}
      <div className="max-w-4xl mx-auto">
        <h2 className="text-center text-xl font-bold text-white">How it works</h2>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-4 gap-3">
          {[
            ['1 · Observe', 'Reads the role + CloudTrail logs. Finds unlogged permissions.'],
            ['2 · Simulate', 'Tests removal against real workflows. First try fails on kms:Decrypt.'],
            ['3 · Replan', 'Discovers S3→KMS coupling. Keeps it, cuts only true wildcards.'],
            ['4 · Verify', 'Kernel gates + verifier pass. Ships as Terraform PR with rollback.'],
          ].map(([t, d]) => (
            <div key={t} className="rounded-lg bg-soc-card/60 border border-soc-border p-3">
              <div className="text-xs font-mono font-bold text-sky-300">{t}</div>
              <div className="mt-1 text-[11px] text-slate-400 leading-relaxed">{d}</div>
            </div>
          ))}
        </div>
      </div>

      {/* FAQ (Linear/Stripe-style progressive disclosure) */}
      <div className="max-w-2xl mx-auto w-full">
        <h2 className="text-center text-xl font-bold text-white">Questions, answered</h2>
        <div className="mt-4 space-y-2">
          {[
            ['Will it break my infrequent jobs?', 'No — that is the entire point. The simulator catches hidden dependencies (like annual DR needing kms:Decrypt) before anything is applied. Unobserved ≠ unneeded.'],
            ['Does it touch my live cloud?', 'Not by default. It reads read-only and proposes a Terraform PR a human merges. Live mutation stays disabled unless you explicitly opt in.'],
            ['What if the AI is wrong?', 'The AI only proposes. Eleven deterministic kernel invariants + blast-radius scoring + an independent verifier decide. Wrong proposals get vetoed or rolled back.'],
            ['Does it work with GCP/Azure?', 'Yes — truthfully. Where a capability is unsupported (e.g. GCP pre-commit simulation) it escalates instead of hallucinating results.'],
            ['How do I prove this to auditors?', 'Every run exports a hash-chained audit bundle (Download button in the console) mapped to CIS, SOC 2, and PCI controls.'],
          ].map(([q, a]) => (
            <details key={q} className="group rounded-lg bg-soc-card/60 border border-soc-border open:border-sky-500/40">
              <summary className="cursor-pointer list-none px-4 py-3 text-xs font-semibold text-slate-200 flex items-center justify-between">
                {q}
                <span className="text-sky-400 group-open:rotate-45 transition-transform text-base leading-none">+</span>
              </summary>
              <div className="px-4 pb-3 text-[11px] text-slate-400 leading-relaxed">{a}</div>
            </details>
          ))}
        </div>
      </div>
    </div>
  );
};
