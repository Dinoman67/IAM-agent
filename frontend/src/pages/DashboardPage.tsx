import React from 'react';
import { DashboardMetrics, DemoScenario, ProviderName, Role, RunSummary } from '../types';
import { MetricCards } from '../components/dashboard/MetricCards';
import { LandingHero } from '../components/dashboard/LandingHero';
import { PrincipalSelector } from '../components/dashboard/PrincipalSelector';
import { ArchitectureDiagram } from '../components/dashboard/ArchitectureDiagram';
import { AuditHistoryTable } from '../components/audit/AuditHistoryTable';

interface DashboardPageProps {
  metrics?: DashboardMetrics;
  roles: Role[];
  selectedRole: string;
  onSelectRole: (roleId: string) => void;
  selectedProvider: ProviderName;
  onSelectProvider: (provider: ProviderName) => void;
  selectedScenario: DemoScenario;
  onSelectScenario: (scenario: DemoScenario) => void;
  onStartRemediation: () => void;
  onRunDemo: () => void;
  onViewArchitecture: () => void;
  isRunning: boolean;
  runs: RunSummary[];
  onSelectRun: (runId: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  metrics,
  roles,
  selectedRole,
  onSelectRole,
  selectedProvider,
  onSelectProvider,
  selectedScenario,
  onSelectScenario,
  onStartRemediation,
  onRunDemo,
  onViewArchitecture,
  isRunning,
  runs,
  onSelectRun,
}) => {
  return (
    <div className="space-y-5">
      {/* Landing / Entry Experience Hero */}
      <LandingHero
        onRunDemo={onRunDemo}
        onViewArchitecture={onViewArchitecture}
        isRunning={isRunning}
      />

      {/* SOC Summary Metrics */}
      <MetricCards metrics={metrics} />

      {/* Target Principal Selection & Assessment Setup */}
      <PrincipalSelector
        roles={roles}
        selectedRole={selectedRole}
        onSelectRole={onSelectRole}
        selectedProvider={selectedProvider}
        onSelectProvider={onSelectProvider}
        selectedScenario={selectedScenario}
        onSelectScenario={onSelectScenario}
        onStartRemediation={onStartRemediation}
        isRunning={isRunning}
      />

      {/* Architecture & Cross-Cloud Model */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2">
          <AuditHistoryTable runs={runs} onSelectRun={onSelectRun} />
        </div>
        <div>
          <ArchitectureDiagram />
        </div>
      </div>
    </div>
  );
};
