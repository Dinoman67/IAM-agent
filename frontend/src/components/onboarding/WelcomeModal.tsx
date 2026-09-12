import React from 'react';
import { Shield, Sparkles, X } from 'lucide-react';

export const WelcomeModal: React.FC<{
  open: boolean;
  onPick: (persona: 'new' | 'expert') => void;
  onClose: () => void;
}> = ({ open, onPick, onClose }) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative max-w-md w-full rounded-xl border border-soc-border bg-[#0D1420] p-6 shadow-2xl">
        <button type="button" onClick={onClose} className="absolute top-3 right-3 text-slate-500 hover:text-slate-200 cursor-pointer" aria-label="Close">
          <X className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2">
          <div className="p-2 rounded bg-sky-600/20 border border-sky-500/30"><Shield className="w-5 h-5 text-sky-400" /></div>
          <div>
            <div className="font-bold text-white text-sm">Welcome to IAM Mitigator</div>
            <div className="text-[11px] font-mono text-slate-500">30 seconds to your first “aha”.</div>
          </div>
        </div>
        <p className="mt-3 text-xs text-slate-400">Who are you? We'll tune the tour.</p>
        <div className="mt-3 grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => onPick('new')}
            className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 p-3 text-left hover:border-emerald-400 cursor-pointer"
          >
            <div className="text-xs font-bold text-emerald-200">I'm new to IAM</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Plain-English tour, no jargon.</div>
          </button>
          <button
            type="button"
            onClick={() => onPick('expert')}
            className="rounded-lg border border-sky-500/40 bg-sky-950/30 p-3 text-left hover:border-sky-400 cursor-pointer"
          >
            <div className="text-xs font-bold text-sky-200">I'm technical</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Kernel, APIs, attack paths.</div>
          </button>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="mt-3 w-full text-[11px] font-mono text-slate-500 hover:text-slate-300 cursor-pointer inline-flex items-center justify-center gap-1"
        >
          <Sparkles className="w-3 h-3" /> Skip — take me to the console
        </button>
      </div>
    </div>
  );
};
