import React, { useState, useEffect } from 'react';
import {
  AgentRunResponse,
  DashboardMetrics,
  DemoScenario,
  Principal,
  ProviderCapabilities,
  ProviderName,
  Role,
  RunSummary,
} from './types';
import {
  checkHealth,
  getAgentRun,
  getPrincipals,
  getProviders,
  listRuns,
  triggerAgentRun,
} from './services/api';
import { Header, NavKey } from './components/layout/Header';
import { DashboardPage } from './pages/DashboardPage';
import { LandingPage } from './pages/LandingPage';
import { LearnPage } from './pages/LearnPage';
import { RemediationPage } from './pages/RemediationPage';
import { CapabilitiesPage } from './pages/CapabilitiesPage';
import { AuditPage } from './pages/AuditPage';
import { WelcomeModal } from './components/onboarding/WelcomeModal';
import { OnboardingChecklist } from './components/onboarding/OnboardingChecklist';
import { GuidedTour } from './components/onboarding/GuidedTour';
import { ExecutiveSummary } from './components/exec/ExecutiveSummary';

const firstVisit = () => {
  try {
    return localStorage.getItem('iam_seen') !== '1';
  } catch {
    return true;
  }
};

export const App: React.FC = () => {
  const [systemHealthy, setSystemHealthy] = useState<boolean>(true);
  const [activeNav, setActiveNav] = useState<NavKey>(() => (firstVisit() ? 'landing' : 'dashboard'));
  const [welcomeOpen, setWelcomeOpen] = useState<boolean>(() => firstVisit());
  const [tourOpen, setTourOpen] = useState<boolean>(false);
  const [checklistDismissed, setChecklistDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem('iam_checklist_dismissed') === '1';
    } catch {
      return false;
    }
  });
  const [visitedLearn, setVisitedLearn] = useState<boolean>(false);

  const [roles, setRoles] = useState<Role[]>([]);
  const [providers, setProviders] = useState<Record<ProviderName, ProviderCapabilities> | undefined>();
  const [metrics, setMetrics] = useState<DashboardMetrics | undefined>();
  const [runs, setRuns] = useState<RunSummary[]>([]);

  const [selectedRole, setSelectedRole] = useState<string>('PaymentServiceRole');
  const [selectedProvider, setSelectedProvider] = useState<ProviderName>('aws');
  const [selectedScenario, setSelectedScenario] = useState<DemoScenario>('aws');

  const [currentRun, setCurrentRun] = useState<AgentRunResponse | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Initial load
  const loadInitialData = async () => {
    try {
      const health = await checkHealth();
      setSystemHealthy(health.status === 'ok');
    } catch {
      setSystemHealthy(false);
    }

    try {
      const [principalsData, providersData, runsData] = await Promise.all([
        getPrincipals(),
        getProviders(),
        listRuns(),
      ]);

      setRoles(principalsData.roles || []);
      setProviders(providersData.providers);
      setMetrics(runsData.metrics);
      setRuns(runsData.runs || []);

      if (runsData.runs && runsData.runs.length > 0 && !currentRun) {
        // Automatically fetch most recent run if available
        try {
          const latest = await getAgentRun(runsData.runs[0].run_id);
          setCurrentRun(latest);
        } catch {
          // ignore
        }
      }
    } catch (err: any) {
      console.error('Failed to load initial data:', err);
    }
  };

  useEffect(() => {
    loadInitialData();
    // Shareable demo link (?demo=aws autoplay) + guided tour (?tour=1)
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get('demo') === 'aws') {
        setSelectedScenario('aws');
        setSelectedRole('PaymentServiceRole');
        setSelectedProvider('aws');
        setTimeout(() => handleStartRemediation('aws'), 600);
      }
      if (params.get('tour') === '1') setTourOpen(true);
    } catch {
      // ignore
    }
  }, []);

  // Poll async runs until terminal (Fix #9: async_run previously never polled)
  const pollAgentRun = async (runId: string, maxAttempts = 60): Promise<AgentRunResponse> => {
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const polled = await getAgentRun(runId);
      const terminal = ['completed', 'failed'].includes(polled.status);
      if (terminal || (polled.events && polled.events.length > 0 && polled.stop_reason)) {
        return polled;
      }
      // Completed/failed without events yet still counts if stop_reason set
      if (terminal) return polled;
    }
    return getAgentRun(runId);
  };

  // Handler to trigger remediation run
  const handleStartRemediation = async (scenarioOverride?: DemoScenario, useAsync = false) => {
    setIsRunning(true);
    setError(null);

    const activeScenario = scenarioOverride || selectedScenario;
    const targetGoal =
      activeScenario === 'aws'
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
        provider: selectedProvider,
        scenario: activeScenario,
        use_mock: true, // Deterministic mock for instant, reliable judge demo
        async_run: useAsync,
      });

      // If backend returns a placeholder (async), poll until terminal
      const finalRun =
        runResponse.status === 'observing' && runResponse.run_id
          ? await pollAgentRun(runResponse.run_id)
          : runResponse;

      setCurrentRun(finalRun);
      setActiveNav('remediation');

      // Refresh runs list & metrics
      const updatedRuns = await listRuns();
      setMetrics(updatedRuns.metrics);
      setRuns(updatedRuns.runs || []);
    } catch (err: any) {
      setError(err.message || 'Remediation execution failed');
      setActiveNav('remediation');
    } finally {
      setIsRunning(false);
    }
  };

  const handleSelectNav = (nav: NavKey) => {
    setActiveNav(nav);
    if (nav === 'learn') setVisitedLearn(true);
    try {
      localStorage.setItem('iam_seen', '1');
    } catch {
      // ignore
    }
  };

  const handlePersona = (persona: 'new' | 'expert') => {
    setWelcomeOpen(false);
    try {
      localStorage.setItem('iam_seen', '1');
      localStorage.setItem('iam_persona', persona);
    } catch {
      // ignore
    }
    if (persona === 'new') setTourOpen(true);
    else handleSelectNav('learn');
  };

  const handleSelectRun = async (runId: string) => {
    try {
      const runData = await getAgentRun(runId);
      setCurrentRun(runData);
      setActiveNav('remediation');
    } catch (err: any) {
      console.error('Failed to fetch run:', err);
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col">
      {/* SOC Console Top Navigation */}
      <Header
        systemHealthy={systemHealthy}
        activeNav={activeNav}
        onSelectNav={handleSelectNav}
        onQuickDemo={() => {
          setSelectedScenario('aws');
          setSelectedRole('PaymentServiceRole');
          setSelectedProvider('aws');
          handleStartRemediation('aws');
        }}
        isDemoRunning={isRunning}
      />

      <WelcomeModal
        open={welcomeOpen}
        onPick={handlePersona}
        onClose={() => {
          setWelcomeOpen(false);
          try {
            localStorage.setItem('iam_seen', '1');
          } catch {
            // ignore
          }
        }}
      />
      <GuidedTour open={tourOpen} onClose={() => setTourOpen(false)} />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeNav === 'landing' && (
          <LandingPage
            onLaunchDemo={() => handleStartRemediation('aws')}
            onHowItWorks={() => handleSelectNav('learn')}
            onOpenConsole={() => handleSelectNav('dashboard')}
            isRunning={isRunning}
          />
        )}

        {activeNav === 'learn' && <LearnPage onLaunchDemo={() => handleStartRemediation('aws')} />}

        {activeNav === 'dashboard' && (
          <div className="space-y-5">
            {!checklistDismissed && (
              <OnboardingChecklist
                state={{ ranDemo: runs.length > 0 || !!currentRun, viewedRun: !!currentRun, visitedLearn }}
                onRunDemo={() => handleStartRemediation('aws')}
                onViewRun={() => currentRun && handleSelectNav('remediation')}
                onVisitLearn={() => handleSelectNav('learn')}
                onDismiss={() => {
                  setChecklistDismissed(true);
                  try {
                    localStorage.setItem('iam_checklist_dismissed', '1');
                  } catch {
                    // ignore
                  }
                }}
              />
            )}
            <ExecutiveSummary roleId={selectedRole} runId={currentRun?.run_id} />
            {runs.length === 0 && !currentRun && !isRunning ? (
              <div className="rounded-xl border border-dashed border-soc-border bg-soc-card/40 p-8 text-center">
                <div className="text-sm font-bold text-white">No runs yet — start with sample data</div>
                <p className="mt-1 text-xs text-slate-400 max-w-md mx-auto">
                  We've pre-loaded PaymentServiceRole (7 permissions, 1 hidden KMS coupling). Run the demo to see the
                  full investigate → simulate → replan → verify loop.
                </p>
                <button
                  type="button"
                  onClick={() => handleStartRemediation('aws')}
                  className="mt-4 px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold cursor-pointer"
                >
                  Run sample assessment
                </button>
                <button
                  type="button"
                  onClick={() => setTourOpen(true)}
                  className="ml-2 mt-4 px-5 py-2.5 rounded-lg border border-soc-border text-slate-300 text-xs font-mono cursor-pointer"
                >
                  Take the tour
                </button>
              </div>
            ) : null}
          <DashboardPage
            metrics={metrics}
            roles={roles}
            selectedRole={selectedRole}
            onSelectRole={setSelectedRole}
            selectedProvider={selectedProvider}
            onSelectProvider={setSelectedProvider}
            selectedScenario={selectedScenario}
            onSelectScenario={setSelectedScenario}
            onStartRemediation={() => handleStartRemediation()}
            onRunDemo={() => {
              setSelectedScenario('aws');
              setSelectedRole('PaymentServiceRole');
              setSelectedProvider('aws');
              handleStartRemediation('aws');
            }}
            onViewArchitecture={() => handleSelectNav('providers')}
            isRunning={isRunning}
            runs={runs}
            onSelectRun={handleSelectRun}
          />
          </div>
        )}

        {activeNav === 'remediation' && (
          <RemediationPage
            currentRun={currentRun}
            onRestart={() => handleStartRemediation()}
            onStartAssessment={() => handleStartRemediation('aws')}
            isRunning={isRunning}
            error={error}
          />
        )}

        {activeNav === 'providers' && (
          <CapabilitiesPage providers={providers} />
        )}

        {activeNav === 'audit' && (
          <AuditPage
            runs={runs}
            onSelectRun={handleSelectRun}
            selectedRunId={currentRun?.run_id}
          />
        )}
      </main>

      {/* Trust & Transparency Footer */}
      <footer className="border-t border-soc-border/60 bg-[#0B0F17] py-4 text-xs font-mono text-soc-muted">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="text-slate-300 font-semibold">PS10 IAM AGENT</span>
            <span className="text-slate-500">— Autonomous Cloud IAM Least-Privilege Mitigator</span>
          </div>

          <div className="text-center sm:text-right text-slate-400">
            <strong className="text-sky-300">AI proposes. Deterministic controls decide.</strong>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
