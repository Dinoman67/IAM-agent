import React, { useState } from 'react';
import { X } from 'lucide-react';

const STEPS = [
  { title: 'The one-line genius', body: 'NOT OBSERVED ≠ PROVEN UNNEEDED. Deleting unused permissions breaks hidden jobs — so this agent rehearses every cut in a simulator first.' },
  { title: 'Watch it fail (on purpose)', body: 'Run the demo. Sim 1 removes kms:Decrypt and the checkout workflow crashes. That failure is the product finding gold.' },
  { title: 'The replan', body: 'The agent discovers PaymentService → S3 → KMS (encrypted receipts need decryption), keeps kms:Decrypt, cuts only true wildcards.' },
  { title: 'Trust, then verify', body: 'Security Kernel gates (11 invariants), verifier confirms, everything exports as a Terraform PR you can revert. Download the audit bundle as proof.' },
];

export const GuidedTour: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const [i, setI] = useState(0);
  if (!open) return null;
  const last = i === STEPS.length - 1;
  return (
    <div className="fixed bottom-4 right-4 z-[60] max-w-xs w-[calc(100vw-2rem)] rounded-xl border border-soc-border bg-[#0D1420] p-4 shadow-2xl">
      <div className="flex items-center justify-between">
        <div className="text-[11px] font-mono text-slate-500">GUIDED TOUR · {i + 1}/{STEPS.length}</div>
        <button type="button" onClick={onClose} className="text-slate-500 hover:text-slate-200 cursor-pointer" aria-label="Close tour"><X className="w-3.5 h-3.5" /></button>
      </div>
      <div className="mt-1 font-bold text-white text-sm">{STEPS[i].title}</div>
      <div className="mt-1 text-xs text-slate-400 leading-relaxed">{STEPS[i].body}</div>
      <div className="mt-3 flex gap-2">
        {i > 0 && (
          <button type="button" onClick={() => setI(i - 1)} className="px-3 py-1.5 rounded border border-soc-border text-xs font-mono text-slate-300 cursor-pointer">Back</button>
        )}
        <button
          type="button"
          onClick={() => (last ? onClose() : setI(i + 1))}
          className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono cursor-pointer"
        >
          {last ? 'Finish tour' : 'Next'}
        </button>
      </div>
    </div>
  );
};
