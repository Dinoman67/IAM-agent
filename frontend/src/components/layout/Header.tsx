import React from 'react';
import { Activity, Cloud, History, Layers, Shield, Sparkles } from 'lucide-react';

export type NavKey = 'landing' | 'dashboard' | 'remediation' | 'providers' | 'audit' | 'learn';

interface HeaderProps {
  systemHealthy: boolean;
  activeNav: NavKey;
  onSelectNav: (nav: NavKey) => void;
  onQuickDemo: () => void;
  isDemoRunning?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  systemHealthy,
  activeNav,
  onSelectNav,
  onQuickDemo,
  isDemoRunning = false,
}) => {
  return (
    <header className="border-b border-soc-border bg-[#0B0F17]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-4">
        {/* Logo & Product Principle */}
        <div className="flex items-center gap-3">
          <div
            onClick={() => onSelectNav('landing')}
            className="flex items-center gap-2 cursor-pointer"
          >
            <div className="p-1.5 rounded bg-sky-600/20 text-sky-400 border border-sky-500/30">
              <Shield className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <span className="font-bold text-sm tracking-tight text-white font-mono flex items-center gap-1.5">
                IAM MITIGATOR
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-sky-950 text-sky-400 border border-sky-800">
                  v3.0 SOC
                </span>
              </span>
            </div>
          </div>

          <div className="hidden md:block h-4 w-px bg-soc-border" />

          <div className="hidden md:block text-[11px] font-mono text-soc-muted">
            <span className="text-slate-400">Security Model:</span>{' '}
            <strong className="text-sky-300 font-semibold">AI proposes. Deterministic controls decide.</strong>
          </div>
        </div>

        {/* Navigation & Status */}
        <div className="flex items-center gap-3">
          <nav className="flex items-center gap-1 text-xs font-mono">
            <button
              type="button"
              onClick={() => onSelectNav('landing')}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                activeNav === 'landing'
                  ? 'bg-soc-card text-sky-300 border border-soc-border font-medium'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              Home
            </button>

            <button
              type="button"
              onClick={() => onSelectNav('dashboard')}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                activeNav === 'dashboard'
                  ? 'bg-soc-card text-sky-300 border border-soc-border font-medium'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              Dashboard
            </button>

            <button
              type="button"
              onClick={() => onSelectNav('learn')}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                activeNav === 'learn'
                  ? 'bg-soc-card text-sky-300 border border-soc-border font-medium'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              Learn
            </button>

            <button
              type="button"
              onClick={() => onSelectNav('remediation')}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                activeNav === 'remediation'
                  ? 'bg-soc-card text-sky-300 border border-soc-border font-medium'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              Remediation Run
            </button>

            <button
              type="button"
              onClick={() => onSelectNav('providers')}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                activeNav === 'providers'
                  ? 'bg-soc-card text-sky-300 border border-soc-border font-medium'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              Multi-Cloud
            </button>

            <button
              type="button"
              onClick={() => onSelectNav('audit')}
              className={`px-3 py-1.5 rounded transition-colors cursor-pointer ${
                activeNav === 'audit'
                  ? 'bg-soc-card text-sky-300 border border-soc-border font-medium'
                  : 'text-soc-muted hover:text-slate-200'
              }`}
            >
              Audit Trail
            </button>
          </nav>

          <div className="h-4 w-px bg-soc-border" />

          {/* Guided Demo Button */}
          <button
            type="button"
            onClick={onQuickDemo}
            disabled={isDemoRunning}
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded bg-sky-600/90 hover:bg-sky-500 text-white font-mono text-xs font-medium transition-all shadow-sm cursor-pointer disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5 text-sky-200" />
            <span>Judge Demo</span>
          </button>

          {/* System Health Indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-soc-surface border border-soc-border text-[11px] font-mono">
            <div
              className={`w-2 h-2 rounded-full ${
                systemHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
              }`}
            />
            <span className={systemHealthy ? 'text-emerald-300' : 'text-rose-400'}>
              {systemHealthy ? 'System Healthy' : 'Offline'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
