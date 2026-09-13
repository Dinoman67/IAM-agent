import React, { useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowRight } from 'lucide-react';
import { GalaxyBg } from '../components/decor/GalaxyBg';

interface LandingPageProps {
  onEnter: () => void;
}

/** Fade-and-rise reveal when a section scrolls into view. */
const Reveal: React.FC<{ children: React.ReactNode; delayMs?: number }> = ({ children, delayMs = 0 }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true);
          obs.disconnect();
        }
      },
      { threshold: 0.2 },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);
  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${delayMs}ms` }}
      className={`transition-all duration-700 ease-out ${
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
      }`}
    >
      {children}
    </div>
  );
};

const PROBLEM = [
  'Cloud roles collect master keys nobody remembers granting.',
  'Teams are afraid to remove them — something invisible might break at 2am.',
  'So every service keeps standing access to data, VMs, and user accounts.',
  'Attackers love this: one stolen key opens every door.',
  'And classic scanners just say “delete what is unused” — then checkout goes down.',
];

const SOLUTION = [
  'Prune rehearses every cut in a simulator before touching anything real.',
  'When rehearsal breaks, it hunts the hidden coupling — like files that silently need KMS decryption.',
  'It replans around the truth, re-tests, and only then asks a deterministic Safety Kernel.',
  'The Kernel approves or vetoes. You get a verified smaller policy — or a blocked attack.',
  'AWS and GCP. Same loop, same proof.',
];

const STEPS = [
  ['Observe', 'Lists every permission the role actually holds.'],
  ['Simulate', 'Rehearses removal against live workflows — and fails safely.'],
  ['Replan', 'Finds the hidden coupling and adapts the plan.'],
  ['Verify', 'Kernel gate plus independent checks. Zero regression.'],
];

export const LandingPage: React.FC<LandingPageProps> = ({ onEnter }) => {
  return (
    <div className="relative bg-black">
      <GalaxyBg />

      <div className="relative z-10">
        {/* HERO */}
        <section className="min-h-[calc(100vh-4rem)] flex flex-col items-center justify-center text-center px-6">
          <div className="text-[11px] font-mono tracking-[0.3em] text-sky-300/80">
            AUTONOMOUS CLOUD IAM
          </div>
          <h1 className="mt-4 text-6xl sm:text-8xl font-extrabold tracking-tight text-white leading-none">
            Prune<span className="text-sky-400">.</span>
          </h1>
          <p className="mt-5 text-sm sm:text-base text-slate-400 max-w-xl leading-relaxed">
            Cut cloud permissions without breaking production.
          </p>
          <div className="mt-9">
            <button
              type="button"
              onClick={onEnter}
              className="group inline-flex items-center gap-2 px-8 py-3.5 rounded-full bg-white text-black text-sm font-semibold hover:bg-slate-200 transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-black"
            >
              Go to simulation
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
            </button>
          </div>
          <div className="mt-14 flex flex-col items-center gap-2 text-slate-600">
            <span className="text-[10px] font-mono tracking-[0.25em]">SCROLL</span>
            <ArrowDown className="w-4 h-4 animate-bounce" />
          </div>
        </section>

        {/* PROBLEM */}
        <section className="min-h-[80vh] flex items-center justify-center px-6 py-20">
          <div className="max-w-xl w-full">
            <Reveal>
              <div className="text-xs font-mono tracking-[0.3em] text-rose-300/80">THE PROBLEM</div>
              <h2 className="mt-3 text-4xl sm:text-5xl font-bold text-white tracking-tight">
                Master keys everywhere.
              </h2>
            </Reveal>
            <ol className="mt-8 space-y-5">
              {PROBLEM.map((line, i) => (
                <Reveal key={i} delayMs={i * 60}>
                  <li className="flex gap-4 items-start">
                    <span className="font-mono text-base text-rose-300/70 pt-1 shrink-0">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span className="text-lg text-slate-200 leading-relaxed">{line}</span>
                  </li>
                </Reveal>
              ))}
            </ol>
          </div>
        </section>

        {/* SOLUTION */}
        <section className="min-h-[80vh] flex items-center justify-center px-6 py-20">
          <div className="max-w-xl w-full">
            <Reveal>
              <div className="text-xs font-mono tracking-[0.3em] text-emerald-300/80">THE SOLUTION</div>
              <h2 className="mt-3 text-4xl sm:text-5xl font-bold text-white tracking-tight">
                Rehearse first. Then cut.
              </h2>
            </Reveal>
            <ol className="mt-8 space-y-5">
              {SOLUTION.map((line, i) => (
                <Reveal key={i} delayMs={i * 60}>
                  <li className="flex gap-4 items-start">
                    <span className="font-mono text-base text-emerald-300/70 pt-1 shrink-0">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span className="text-lg text-slate-200 leading-relaxed">{line}</span>
                  </li>
                </Reveal>
              ))}
            </ol>
          </div>
        </section>

        {/* HOW IT RUNS */}
        <section className="min-h-[80vh] flex items-center justify-center px-6 py-20">
          <div className="max-w-3xl w-full text-center">
            <Reveal>
              <div className="text-xs font-mono tracking-[0.3em] text-sky-300/80">HOW IT RUNS</div>
              <h2 className="mt-3 text-4xl sm:text-5xl font-bold text-white tracking-tight">
                Four stages. Zero guesswork.
              </h2>
            </Reveal>
            <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-left">
              {STEPS.map(([t, d], i) => (
                <Reveal key={t} delayMs={i * 80}>
                  <div className="rounded-lg border border-white/10 bg-white/[0.02] p-5 h-full">
                    <div className="font-mono text-sm text-sky-300">0{i + 1}</div>
                    <div className="mt-1.5 text-base font-bold text-white">{t}</div>
                    <div className="mt-1.5 text-sm text-slate-300 leading-relaxed">{d}</div>
                  </div>
                </Reveal>
              ))}
            </div>
            <Reveal delayMs={200}>
              <div className="mt-12">
                <button
                  type="button"
                  onClick={onEnter}
                  className="group inline-flex items-center gap-2 px-8 py-3.5 rounded-full bg-white text-black text-sm font-semibold hover:bg-slate-200 transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-black"
                >
                  Watch it run live
                  <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
                </button>
                <p className="mt-3 text-[11px] font-mono text-slate-600">6 scenarios · 30 seconds · nothing breaks</p>
              </div>
            </Reveal>
          </div>
        </section>
      </div>
    </div>
  );
};
