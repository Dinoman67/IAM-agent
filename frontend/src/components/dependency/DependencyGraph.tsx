import React from 'react';
import { ArrowRight, Database, Key, Lock, Server, ShieldCheck } from 'lucide-react';

interface DependencyGraphProps {
  service?: string;
  callsService?: string;
  downstreamDependency?: string;
  requiredPermission?: string;
  reason?: string;
}

export const DependencyGraph: React.FC<DependencyGraphProps> = ({
  service = 'PaymentService',
  callsService = 'S3 (Encrypted Storage)',
  downstreamDependency = 'AWS Key Management Service (KMS)',
  requiredPermission = 'kms:Decrypt',
  reason = 'Customer checkout records read from encrypted S3 bucket payment-transactions use SSE-KMS customer managed key arn:aws:kms:::key/payment-key.',
}) => {
  return (
    <div className="bg-soc-card/70 border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between pb-3 border-b border-soc-border/60">
        <h3 className="text-xs font-semibold text-soc-highlight uppercase tracking-wider flex items-center gap-1.5">
          <Key className="w-3.5 h-3.5 text-amber-400" />
          Transitive Dependency Coupling Graph
        </h3>
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30">
          <Lock className="w-3 h-3" /> REQUIRED DEPENDENCY
        </span>
      </div>

      <div className="mt-4 p-4 rounded-lg bg-soc-surface border border-soc-border/80">
        {/* Node Progression */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
          {/* Node 1: Originating Service */}
          <div className="w-full sm:w-1/4 p-3 rounded-md bg-slate-900 border border-slate-700 flex flex-col items-center text-center">
            <Server className="w-5 h-5 text-sky-400 mb-1.5" />
            <span className="font-mono font-bold text-white text-xs">{service}</span>
            <span className="text-[10px] text-slate-400 mt-0.5 font-sans">Payment Transactions</span>
          </div>

          <ArrowRight className="w-4 h-4 text-soc-muted shrink-0 rotate-90 sm:rotate-0" />

          {/* Node 2: Direct Service (Encrypted S3) */}
          <div className="w-full sm:w-1/4 p-3 rounded-md bg-slate-900 border border-slate-700 flex flex-col items-center text-center">
            <Database className="w-5 h-5 text-indigo-400 mb-1.5" />
            <span className="font-mono font-bold text-white text-xs">{callsService}</span>
            <span className="text-[10px] text-indigo-300/80 mt-0.5 font-sans">Reads Receipts (SSE-KMS)</span>
          </div>

          <ArrowRight className="w-4 h-4 text-amber-400 shrink-0 rotate-90 sm:rotate-0" />

          {/* Node 3: Transitive Key Management Service */}
          <div className="w-full sm:w-1/4 p-3 rounded-md bg-amber-950/30 border border-amber-500/40 flex flex-col items-center text-center">
            <Key className="w-5 h-5 text-amber-400 mb-1.5" />
            <span className="font-mono font-bold text-amber-200 text-xs">KMS Customer Key</span>
            <span className="text-[10px] text-amber-300/80 mt-0.5 font-sans">{downstreamDependency}</span>
          </div>

          <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0 rotate-90 sm:rotate-0" />

          {/* Node 4: Preserved Permission */}
          <div className="w-full sm:w-1/4 p-3 rounded-md bg-emerald-950/30 border border-emerald-500/40 flex flex-col items-center text-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400 mb-1.5" />
            <span className="font-mono font-bold text-emerald-300 text-xs">{requiredPermission}</span>
            <span className="text-[10px] text-emerald-400 mt-0.5 font-mono uppercase font-semibold">PRESERVED</span>
          </div>
        </div>

        {/* Technical Explanation */}
        <div className="mt-4 pt-3 border-t border-soc-border/60 text-xs text-slate-300 leading-relaxed font-sans">
          <strong className="text-amber-300 font-mono">Why this seemingly unused permission was preserved:</strong>
          <p className="mt-1 text-slate-400 text-[11px]">{reason}</p>
        </div>
      </div>
    </div>
  );
};
