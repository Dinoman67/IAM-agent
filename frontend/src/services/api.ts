import {
  AgentRunResponse,
  AttackGraph,
  DashboardMetrics,
  DemoScenario,
  Principal,
  ProviderCapabilities,
  ProviderName,
  Role,
  RunSummary,
  ServiceDependency,
  TemporalReport,
  TerraformExport,
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

export async function getAttackGraph(roleId: string): Promise<AttackGraph> {
  const res = await fetch(`${API_BASE}/api/roles/${encodeURIComponent(roleId)}/attack-graph`);
  if (!res.ok) throw new Error(`Attack graph failed: ${res.statusText}`);
  return res.json();
}

export async function getTemporal(roleId: string, windowDays = 365): Promise<TemporalReport> {
  const res = await fetch(
    `${API_BASE}/api/roles/${encodeURIComponent(roleId)}/temporal?window_days=${windowDays}`,
  );
  if (!res.ok) throw new Error(`Temporal analysis failed: ${res.statusText}`);
  return res.json();
}

export async function exportTerraform(roleId: string, permissions?: string[]): Promise<TerraformExport> {
  const res = await fetch(`${API_BASE}/api/export/terraform`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: roleId, permissions: permissions ?? null }),
  });
  if (!res.ok) throw new Error(`Terraform export failed: ${res.statusText}`);
  return res.json();
}

export async function getAWSLiveStatus(): Promise<{ live: boolean; reason?: string; region?: string }> {
  const res = await fetch(`${API_BASE}/api/aws/live-status`);
  if (!res.ok) throw new Error(`Live status failed: ${res.statusText}`);
  return res.json();
}

export interface ComplianceControl {
  framework: string;
  control_id: string;
  title: string;
  plain_english: string;
  status: 'pass' | 'fail' | 'review';
  evidence: string;
}

export async function getCompliance(roleId: string): Promise<{
  role_id: string;
  controls: ComplianceControl[];
  passing: number;
  failing: number;
  review: number;
}> {
  const res = await fetch(`${API_BASE}/api/compliance/${encodeURIComponent(roleId)}`);
  if (!res.ok) throw new Error(`Compliance failed: ${res.statusText}`);
  return res.json();
}

export async function getAuditBundle(runId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/audit/bundle/${encodeURIComponent(runId)}`);
  if (!res.ok) throw new Error(`Bundle failed: ${res.statusText}`);
  return res.json();
}
