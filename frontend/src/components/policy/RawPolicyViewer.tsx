import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Code } from 'lucide-react';

interface RawPolicyViewerProps {
  diff?: any;
  title?: string;
}

export const RawPolicyViewer: React.FC<RawPolicyViewerProps> = ({ diff, title = 'Technical Details & Raw IAM JSON' }) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="mt-4 pt-3 border-t border-soc-border/40">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-sky-300 font-mono transition-colors cursor-pointer"
      >
        <Code className="w-3.5 h-3.5" />
        {isOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        <span>{title}</span>
      </button>

      {isOpen && (
        <div className="mt-2 p-3 bg-black/60 rounded-md border border-soc-border font-mono text-[11px] text-slate-300 overflow-x-auto max-h-72">
          <pre>{JSON.stringify(diff, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};
