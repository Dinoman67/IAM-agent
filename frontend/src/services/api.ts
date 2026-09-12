import {
  AgentRunResponse,
  DashboardMetrics,
  DemoScenario,
  Principal,
  ProviderCapabilities,
  ProviderName,
  Role,
  RunSummary,
  ServiceDependency,
  Workflow,
} from '../types';

const API_BASE = '';

export interface PrincipalsResponse {
  principals: Principal[];
  roles: Role[];
  workflows: Workflow[];
  dependencies: ServiceDependency[];
  resources: any[];
}

export interface ProvidersResponse {
  providers: Record<ProviderName, ProviderCapabilities>;
}

export interface RunsResponse {
  metrics: DashboardMetrics;
  runs: RunSummary[];
}

export interface RunAgentPayload {
  goal: string;
  role_id: string;
  provider?: string;
  use_mock?: boolean;
  scenario?: DemoScenario;
  async_run?: boolean;
}

export async function checkHealth(): Promise<{ status: string; service: string; version: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function getProviders(): Promise<ProvidersResponse> {
  const res = await fetch(`${API_BASE}/api/providers`);
  if (!res.ok) {
    throw new Error(`Failed to fetch provider capabilities: ${res.statusText}`);
  }
  return res.json();
}

export async function getPrincipals(): Promise<PrincipalsResponse> {
  const res = await fetch(`${API_BASE}/api/principals`);
  if (!res.ok) {
    throw new Error(`Failed to fetch principals and roles: ${res.statusText}`);
  }
  return res.json();
}

export async function listRuns(): Promise<RunsResponse> {
  const res = await fetch(`${API_BASE}/api/runs`);
  if (!res.ok) {
    throw new Error(`Failed to fetch runs history: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerAgentRun(payload: RunAgentPayload): Promise<AgentRunResponse> {
  const res = await fetch(`${API_BASE}/api/agent/run`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      // ignore
    }
    throw new Error(`Remediation run failed (${res.status}): ${errorDetail}`);
  }

  return res.json();
}

export async function getAgentRun(runId: string): Promise<AgentRunResponse> {
  const res = await fetch(`${API_BASE}/api/agent/run/${encodeURIComponent(runId)}`);
  if (!res.ok) {
    throw new Error(`Run '${runId}' not found: ${res.statusText}`);
  }
  return res.json();
}
