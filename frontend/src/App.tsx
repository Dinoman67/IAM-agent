import React, { useState, useEffect } from 'react';
import { AgentRunResponse, DemoScenario, Role } from './types';
import { checkHealth, getAgentRun, getPrincipals, triggerAgentRun } from './services/api';
import { LandingPage } from './pages/LandingPage';
import { SimulationPage } from './pages/SimulationPage';

type View = 'landing' | 'simulation';

export const App: React.FC = () => {
  const [view, setView] = useState<View>('landing');
  const [systemHealthy, setSystemHealthy] = useState<boolean>(true);

  const [roles, setRoles] = useState<Role[]>([]);
  const [selectedRole, setSelectedRole] = useState<string>('PaymentServiceRole');
  const [selectedScenario, setSelectedScenario] = useState<DemoScenario>('aws');

  const [currentRun, setCurrentRun] = useState<AgentRunResponse | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const health = await checkHealth();
        setSystemHealthy(health.status === 'ok');
      } catch {
        setSystemHealthy(false);
      }
      try {
        const principalsData = await getPrincipals();
        setRoles(principalsData.roles || []);
      } catch {
        // picker falls back to PaymentServiceRole
      }
    })();
    // NOTE: no autoplay — a run starts only when the Run button is pressed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep role/scenario coherent: GCP runs target the GCP service account.
  // Any selection change resets to idle — a run starts only via Run button.
  const handleSelectScenario = (s: DemoScenario) => {
    setSelectedScenario(s);
    if (s === 'gcp' && selectedRole === 'PaymentServiceRole') {
      setSelectedRole('BillingExportSA');
    } else if (s !== 'gcp' && selectedRole === 'BillingExportSA') {
      setSelectedRole('PaymentServiceRole');
    }
    setCurrentRun(null);
    setError(null);
  };

  const handleSelectRole = (r: string) => {
    setSelectedRole(r);
    setCurrentRun(null);
    setError(null);
  };

  const handleEnterSimulation = () => {
    setCurrentRun(null);
    setError(null);
    setView('simulation');
  };
  // Poll async runs until terminal (kept for API parity; default runs are sync)
  const pollAgentRun = async (runId: string, maxAttempts = 60): Promise<AgentRunResponse> => {
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const polled = await getAgentRun(runId);
      const terminal = ['completed', 'failed'].includes(polled.status);
      if (terminal || (polled.events && polled.events.length > 0 && polled.stop_reason)) {
        return polled;
      }
      if (terminal) return polled;
    }
    return getAgentRun(runId);
  };

  const handleStartRemediation = async (scenarioOverride?: DemoScenario) => {
    setIsRunning(true);
    setError(null);
    setCurrentRun(null);
    setView('simulation');

    const activeScenario = scenarioOverride || selectedScenario;
    const targetGoal =
      activeScenario === 'aws' || activeScenario === 'gcp'
        ? `Make ${selectedRole} least privilege without breaking required workflows.`
        : activeScenario === 'safety_block'
        ? `Attempt unsafe mutation of protected administrative permissions.`
        : activeScenario === 'rollback'
        ? `Demonstrate automated rollback on verification regression.`
        : activeScenario === 'stale_state'
        ? `Demonstrate optimistic concurrency handling on modified policy state.`
        : activeScenario === 'unsupported_gcp'
        ? `Audit and minimize GCP role permissions safely.`
        : `Attempt applying foreign Azure role assignment to AWS infrastructure.`;

    try {
      const runResponse = await triggerAgentRun({
        goal: targetGoal,
        role_id: selectedRole,
        provider: 'aws',
        scenario: activeScenario,
        use_mock: true, // Deterministic mock for instant, reliable demo
        async_run: false,
      });

      const finalRun =
        runResponse.status === 'observing' && runResponse.run_id
          ? await pollAgentRun(runResponse.run_id)
          : runResponse;

      setCurrentRun(finalRun);
    } catch (err: any) {
      setError(err.message || 'Remediation execution failed');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-slate-100 flex flex-col">
      <main className="flex-1 w-full">
        <div
          key={`${view}-${isRunning ? 'running' : currentRun?.run_id ?? 'idle'}`}
          className="animate-view-enter"
        >
          {view === 'landing' && <LandingPage onEnter={handleEnterSimulation} />}

          {view === 'simulation' && (
            <SimulationPage
              roles={roles}
              selectedRole={selectedRole}
              onSelectRole={handleSelectRole}
              selectedScenario={selectedScenario}
              onSelectScenario={handleSelectScenario}
              onRun={() => handleStartRemediation()}
              onBack={() => setView('landing')}
              isRunning={isRunning}
              currentRun={currentRun}
              error={error}
              systemHealthy={systemHealthy}
            />
          )}
        </div>
      </main>
    </div>
  );
};

export default App;
