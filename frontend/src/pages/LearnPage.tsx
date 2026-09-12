import React, { useState } from 'react';
import { BookOpen, Code2 } from 'lucide-react';
import { ArchitectureDiagram } from '../components/dashboard/ArchitectureDiagram';

const INVARIANTS = [
  ['NO_PRIVILEGE_EXPANSION', 'Zero action/wildcard/resource expansion permitted.'],
  ['NO_PROTECTED_PERMISSION_MUTATION', 'iam:* / iam:CreateRole cannot be pruned autonomously.'],
  ['NO_PROTECTED_RESOURCE_EXPOSURE', 'Sensitive tables & instances stay isolated.'],
  ['NO_CROSS_PROVIDER_MUTATION', 'Azure config can never land on AWS.'],
  ['NO_CROSS_TENANT_MUTATION', 'Tenant boundaries enforced.'],
  ['NO_STALE_STATE_MUTATION', 'Optimistic concurrency: refresh then replan.'],
  ['NO_MUTATION_WITHOUT_EVIDENCE', 'Logs, deps, or sims required.'],
  ['NO_MUTATION_WITHOUT_SIMULATION', 'Simulation mandatory where supported.'],
  ['NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION', 'Regression suite must pass.'],
  ['NO_COMPLETION_WITHOUT_VERIFICATION', 'No silent completion.'],
  ['NO_UNAPPROVED_HIGH_RISK', 'HIGH/CRITICAL needs a human.'],
];

export const LearnPage: React.FC<{ onLaunchDemo: () => void }> = ({ onLaunchDemo }) => {
  const [tab, setTab] = useState<'beginner' | 'expert'>('beginner');
  return (
    <div className="space-y-5 max-w-4xl mx-auto">
      <div className="text-center">
        <h1 className="text-2xl font-bold text-white">How it works</h1>
        <p className="text-xs font-mono text-slate-500 mt-1">One product, two explanations. Pick yours.</p>
        <div className="mt-3 inline-flex rounded-lg bg-soc-card border border-soc-border p-1 text-xs font-mono">
          <button
            type="button"
            onClick={() => setTab('beginner')}
            className={`px-4 py-1.5 rounded-md cursor-pointer ${tab === 'beginner' ? 'bg-sky-600 text-white' : 'text-slate-400'}`}
          >
            <BookOpen className="w-3.5 h-3.5 inline mr-1 -mt-0.5" /> I'm new
          </button>
          <button
            type="button"
            onClick={() => setTab('expert')}
            className={`px-4 py-1.5 rounded-md cursor-pointer ${tab === 'expert' ? 'bg-sky-600 text-white' : 'text-slate-400'}`}
          >
            <Code2 className="w-3.5 h-3.5 inline mr-1 -mt-0.5" /> I'm technical
          </button>
        </div>
      </div>

      {tab === 'beginner' ? (
        <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
          <div className="rounded-lg bg-soc-card/70 border border-soc-border p-4">
            <strong className="text-white">The problem, plainly:</strong> cloud permissions pile up because teams are
            scared removing one breaks something invisible — like the nightly backup that decrypts files. So roles keep
            master keys forever. Attackers love that.
          </div>
          <div className="rounded-lg bg-soc-card/70 border border-soc-border p-4">
            <strong className="text-white">What this does:</strong> 1) lists what the role can do, 2) rehearses removing
            things in a simulator (like a flight simulator for permissions), 3) when the rehearsal crashes it
            investigates and finds the hidden wiring, 4) keeps what's truly needed and removes the rest, 5) a strict
            safety checker (the Security Kernel) approves or vetoes, 6) everything ships as a reviewable file you can
            undo.
          </div>
          <div className="rounded-lg bg-emerald-950/20 border border-emerald-500/30 p-4 text-xs">
            Try it: hit <button type="button" onClick={onLaunchDemo} className="text-emerald-300 underline cursor-pointer">Run demo</button> and
            watch step 4 fail on <code className="font-mono">kms:Decrypt</code> — that's the genius moment.
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <ArchitectureDiagram />
          <div className="rounded-lg bg-soc-card/70 border border-soc-border p-4">
            <div className="text-xs font-mono font-bold text-sky-300 uppercase mb-2">11 kernel invariants (deterministic, LLM cannot override)</div>
            <ul className="space-y-1">
              {INVARIANTS.map(([k, v]) => (
                <li key={k} className="text-[11px] font-mono text-slate-300">
                  <code className="text-amber-300">{k}</code> <span className="text-slate-500">— {v}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-lg bg-slate-950 border border-soc-border p-4">
            <div className="text-xs font-mono text-slate-500 mb-1">API — trigger a run</div>
            <pre className="text-[11px] font-mono text-slate-200 overflow-auto">{`POST /api/agent/run
{"goal": "Make PaymentServiceRole least privilege...",
 "role_id": "PaymentServiceRole", "provider": "aws",
 "scenario": "aws", "use_mock": true}

GET /api/roles/PaymentServiceRole/attack-graph
GET /api/roles/PaymentServiceRole/temporal
POST /api/export/terraform  → HCL + PR body
GET /api/compliance/PaymentServiceRole  → CIS/SOC2/PCI
GET /api/audit/bundle/{run_id}  → hash-chained JSON`}</pre>
          </div>
        </div>
      )}
    </div>
  );
};
