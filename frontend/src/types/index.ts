export type ProviderName = 'aws' | 'gcp' | 'azure';

export type DemoScenario = 
  | 'aws' 
  | 'gcp'
  | 'lowconf'
  | 'safety_block' 
  | 'rollback' 
  | 'stale_state' 
  | 'unsupported_gcp' 
  | 'provider_mismatch';

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  relevant_ids: Record<string, string>;
  summary: string;
  details: Record<string, any>;
  run_id?: string;
  provider: string;
  operation?: string;
  step_number?: number;
  actor: 'agent' | 'security_kernel' | 'tool' | 'verifier' | 'controller' | 'simulator' | 'user';
  tool?: string;
  arguments?: Record<string, any>;
  result?: Record<string, any>;
  reason?: string;
  confidence?: number;
  evidence_refs: string[];
  old_state_hash?: string;
  final_state_hash?: string;
}

export interface PolicyDiff {
  role_id: string;
  from_version: string;
  to_version?: string;
  provider: string;
  removed: string[];
  kept: string[];
  added: string[];
  why_removed: Record<string, string>;
  why_kept: Record<string, string>;
  evidence?: Record<string, any>;
  provider_diff?: Record<string, any>;
  simulation_result?: Record<string, any>;
  verification_result?: Record<string, any>;
}

export interface SecurityGateResult {
  allowed: boolean;
  decision: 'allow' | 'deny' | 'escalate';
  reason: string;
  reason_codes: string[];
  required_approval: boolean;
  risk_level: string;
  confidence: number;
  blast_radius: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  violated_invariants: string[];
  required_verification: string[];
  escalation_reason?: string;
  details?: Record<string, any>;
}

export interface VerificationResult {
  passed: boolean;
  checks?: Record<string, boolean>;
  details: string[];
  violations?: string[];
  verification_type?: string;
}

export interface AgentRunResponse {
  run_id: string;
  status: 'observing' | 'analyzing' | 'proposing' | 'simulating' | 'replanning' | 'applying' | 'verifying' | 'completed' | 'failed';
  goal: string;
  provider?: string;
  role_id?: string;
  current_plan?: {
    objective: string;
    assumptions: string[];
    required_evidence: string[];
    verification_requirements: string[];
    risk_level: string;
    status: string;
    candidate_changes?: any[];
  };
  events: AuditEvent[];
  final_result?: {
    status: string;
    stop_reason?: string;
    message?: string;
    details?: any;
  };
  verification_result?: VerificationResult;
  policy_diff?: PolicyDiff;
  telemetry?: {
    runtime_ms?: number;
    iterations?: number;
    tool_calls?: number;
    replans?: number;
  };
  stop_reason?: string;
  security_decision?: SecurityGateResult;
  blast_radius?: string;
  confidence?: number;
  risk_level?: string;
}

export interface ProviderCapabilities {
  provider_name: string;
  supports_principal_inspection: boolean;
  supports_policy_inspection: boolean;
  supports_role_inspection: boolean;
  supports_binding_inspection: boolean;
  supports_policy_simulation: boolean;
  supports_policy_validation: boolean;
  supports_policy_preview: boolean;
  supports_resource_scoping: boolean;
  supports_conditions: boolean;
  supports_policy_versioning: boolean;
  supports_dry_run: boolean;
  supports_apply: boolean;
  supports_rollback: boolean;
  supports_local_analysis: boolean;
  supports_dependency_analysis: boolean;
  supported_policy_types: string[];
  metadata?: Record<string, any>;
}

export interface PermissionItem {
  id: string;
  service: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  current_version: string;
  active_permissions: string[];
  permissions_detail: PermissionItem[];
  policy_versions: Array<{
    version_id: string;
    permissions: string[];
    created_at: string;
    is_active: boolean;
    reason?: string;
  }>;
}

export interface Principal {
  id: string;
  name: string;
  type: string;
  roles: string[];
}

export interface ServiceDependency {
  service: string;
  calls_service: string;
  downstream_dependency: string;
  required_permission: string;
  reason: string;
}

export interface Workflow {
  id: string;
  name: string;
  description: string;
  role_id: string;
  required_permissions: string[];
  hidden_dependency_notes?: string;
}

export interface DashboardMetrics {
  total_runs: number;
  permissions_reduced: number;
  changes_verified: number;
  changes_blocked: number;
  rollbacks: number;
  average_risk: string;
}

export interface RunSummary {
  run_id: string;
  provider: string;
  role_id: string;
  goal: string;
  status: string;
  stop_reason?: string;
  events_count: number;
  verified: boolean;
  policy_diff?: PolicyDiff;
  telemetry?: Record<string, any>;
  risk_level: string;
  confidence: number;
  blast_radius: string;
  created_at?: string;
}

export interface AttackGraph {
  role_id: string;
  nodes: Array<{ id: string; kind: string; label: string; risk: string; protected: boolean }>;
  edges: Array<{ from_id: string; to_id: string; via: string }>;
  paths: Array<{ path: string[]; reaches_protected: boolean; severity: string }>;
  reachable_resources: string[];
  protected_reachable: string[];
  risk_score: number;
  risk_level: string;
  paths_blocked_by_proposal?: number;
}

export interface TemporalFinding {
  permission: string;
  uses_30d: number;
  uses_365d: number;
  days_since_last_use?: number | null;
  dependency_linked: boolean;
  classification: 'FREQUENT' | 'RARE_BUT_CRITICAL' | 'SEASONAL_CANDIDATE' | 'DEAD';
  recommendation: 'RETAIN' | 'REVIEW' | 'REMOVE';
  confidence: number;
  reason: string;
}

export interface TemporalReport {
  role_id: string;
  window_days: number;
  findings: TemporalFinding[];
  retain: string[];
  review: string[];
  remove: string[];
}

export interface TerraformExport {
  role_id: string;
  hcl: string;
  terraform_json: Record<string, any>;
  pr_body: string;
  removed: string[];
  retained: string[];
  blast: { level: string; score: number; factors: string[] };
  attack_paths_blocked: number;
  temporal: TemporalReport;
}
