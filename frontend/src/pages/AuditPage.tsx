import React from 'react';
import { RunSummary } from '../types';
import { AuditHistoryTable } from '../components/audit/AuditHistoryTable';

interface AuditPageProps {
  runs: RunSummary[];
  onSelectRun: (runId: string) => void;
  selectedRunId?: string;
}

export const AuditPage: React.FC<AuditPageProps> = ({ runs, onSelectRun, selectedRunId }) => {
  return (
    <div className="space-y-5">
      <AuditHistoryTable runs={runs} onSelectRun={onSelectRun} selectedRunId={selectedRunId} />
    </div>
  );
};
