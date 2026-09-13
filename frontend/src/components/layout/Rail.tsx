import React from 'react';
import { Activity, FileDown, FileText, History, Inbox, ShieldCheck } from 'lucide-react';

export type ShellView = 'run' | 'evidence' | 'policy' | 'exports' | 'audit' | 'review';

const ITEMS: Array<{ id: ShellView; label: string; icon: React.ReactNode }> = [
  { id: 'run', label: 'Run', icon: <Activity className="w-4 h-4" /> },
  { id: 'evidence', label: 'Evidence', icon: <FileText className="w-4 h-4" /> },
  { id: 'policy', label: 'Policy', icon: <ShieldCheck className="w-4 h-4" /> },
  { id: 'exports', label: 'Exports', icon: <FileDown className="w-4 h-4" /> },
  { id: 'audit', label: 'Audit', icon: <History className="w-4 h-4" /> },
  { id: 'review', label: 'Review', icon: <Inbox className="w-4 h-4" /> },
];

export const Rail: React.FC<{ view: ShellView; onSelect: (v: ShellView) => void; badge?: number }> = ({
  view,
  onSelect,
  badge = 0,
}) => (
  <nav aria-label="Console sections" className="sticky top-0 h-screen shrink-0 w-14 md:w-52 border-r border-white/10 bg-black flex flex-col py-5 px-2 md:px-3 gap-1">
    <div className="px-2 md:px-3 pb-4 hidden md:block">
      <div className="text-sm font-extrabold text-white tracking-tight">
        Prune<span className="text-sky-400">.</span>
      </div>
      <div className="text-[10px] font-mono text-slate-600 mt-0.5">CONSOLE</div>
    </div>
    <div className="pb-4 md:hidden flex justify-center">
      <span className="text-sm font-extrabold text-white">
        P<span className="text-sky-400">.</span>
      </span>
    </div>
    {ITEMS.map((item) => {
      const active = view === item.id;
      return (
        <button
          key={item.id}
          type="button"
          onClick={() => onSelect(item.id)}
          aria-current={active ? 'page' : undefined}
          className={`flex items-center gap-3 rounded-md px-2 md:px-3 py-2 text-sm transition-colors cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 ${
            active
              ? 'bg-sky-400/10 text-sky-200 shadow-[0_0_18px_rgba(56,189,248,0.25)]'
              : 'text-slate-500 hover:text-slate-200 hover:bg-white/[0.04]'
          }`}
        >
          <span className="shrink-0 relative">
            {item.icon}
            {item.id === 'review' && badge > 0 && (
              <span className="absolute -top-1.5 -right-2 min-w-[1rem] h-4 px-0.5 rounded-full bg-amber-400 text-black text-[10px] font-mono font-bold flex items-center justify-center animate-pulse">
                {badge > 9 ? '9+' : badge}
              </span>
            )}
          </span>
          <span className="hidden md:block font-mono text-[13px]">{item.label}</span>
        </button>
      );
    })}
  </nav>
);
