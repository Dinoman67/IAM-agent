"""Pydantic schemas for the IAM Agent domain."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyVersion(BaseModel):
    """Represents a specific revision of an IAM policy attached to a role."""

    version_id: str = Field(..., description="Unique version identifier, e.g. 'v1', 'v2'")
    permissions: List[str] = Field(..., description="List of permissions granted in this version")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp when version was created"
    )
    is_active: bool = Field(default=True, description="Whether this version is currently active")
    reason: Optional[str] = Field(default=None, description="Reason for policy version creation or change")


class Role(BaseModel):
    """IAM Role definition including history of policy versions."""

    id: str = Field(..., description="Role ID or name, e.g. 'PaymentServiceRole'")
    name: str = Field(..., description="Human-readable role name")
    description: str = Field(default="", description="Role description and purpose")
    current_version: str = Field(default="v1", description="Current active policy version ID")
    policy_versions: List[PolicyVersion] = Field(default_factory=list, description="All policy versions")

    def active_permissions(self) -> List[str]:
        """Returns permissions of the currently active policy version."""
        for v in self.policy_versions:
            if v.version_id == self.current_version and v.is_active:
                return list(v.permissions)
        # Fallback to last active version
        for v in reversed(self.policy_versions):
            if v.is_active:
                return list(v.permissions)
        return []


class Principal(BaseModel):
    """IAM Principal (user, service, compute entity)."""

    id: str = Field(..., description="Principal ID")
    name: str = Field(..., description="Principal display name")
    type: str = Field(default="Service", description="Principal type, e.g. 'Service', 'User'")
    roles: List[str] = Field(default_factory=list, description="Roles bound to this principal")


class PermissionDefinition(BaseModel):
    """Catalog metadata for a permission action."""

    id: str = Field(..., description="Action name, e.g. 's3:GetObject'")
    service: str = Field(..., description="Cloud service prefix, e.g. 's3'")
    description: str = Field(default="", description="Description of the action")
    risk_level: str = Field(default="medium", description="Risk tier: 'low', 'medium', 'high', 'critical'")


class RoleBinding(BaseModel):
    """Association between a principal and a role."""

    principal_id: str
    role_id: str
    attached_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AccessLog(BaseModel):
    """Simulated CloudTrail / access log record."""

    id: str
    principal_id: str
    role_id: str
    action: str
    resource: str
    timestamp: str
    success: bool = True


class ServiceDefinition(BaseModel):
    """Service metadata."""

    id: str
    name: str
    owner: str = ""


class ServiceDependency(BaseModel):
    """Defines transitive or hidden downstream service dependencies."""

    service: str = Field(..., description="Service initiating request")
    calls_service: str = Field(..., description="Direct service called")
    downstream_dependency: str = Field(..., description="Hidden downstream dependency service")
    required_permission: str = Field(..., description="Permission required for the dependency to function")
    reason: str = Field(..., description="Technical explanation for the dependency")


class Resource(BaseModel):
    """Simulated cloud resource with protection level."""

    id: str
    arn: str
    type: str
    is_protected: bool = Field(default=False, description="Whether this resource contains sensitive data")
    required_permissions: List[str] = Field(default_factory=list)


class Workflow(BaseModel):
    """Business workflow that requires IAM permissions to succeed."""

    id: str = Field(..., description="Workflow ID, e.g. 'payment_checkout'")
    name: str
    description: str = ""
    role_id: str
    required_permissions: List[str] = Field(..., description="Direct and indirect permissions needed")
    hidden_dependency_notes: Optional[str] = None


class PolicyChangeProposal(BaseModel):
    """Structured proposal for modifying an IAM role's policy."""

    role_id: str
    remove_permissions: List[str]
    keep_permissions: List[str] = Field(default_factory=list)
    reason: str


class SimulationResult(BaseModel):
    """Structured result of policy simulation against required workflows."""

    success: bool
    failed_workflow: Optional[str] = None
    missing_permission: Optional[str] = None
    broken_dependency: Optional[str] = None
    evidence_id: str = Field(..., description="Unique evidence ID for traceability")
    details: str


class VerificationResult(BaseModel):
    """Structured result of the deterministic verification layer."""

    passed: bool
    checks: Dict[str, bool] = Field(default_factory=dict)
    details: List[str] = Field(default_factory=list)


class IAMEnvironmentData(BaseModel):
    """Complete root model for the simulated IAM environment."""

    principals: List[Principal] = Field(default_factory=list)
    roles: List[Role] = Field(default_factory=list)
    permissions: List[PermissionDefinition] = Field(default_factory=list)
    bindings: List[RoleBinding] = Field(default_factory=list)
    access_logs: List[AccessLog] = Field(default_factory=list)
    services: List[ServiceDefinition] = Field(default_factory=list)
    dependencies: List[ServiceDependency] = Field(default_factory=list)
    resources: List[Resource] = Field(default_factory=list)
    workflows: List[Workflow] = Field(default_factory=list)
    simulation_runs: List[Dict[str, Any]] = Field(default_factory=list)
