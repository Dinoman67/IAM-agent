"""Provider-neutral Common IAM Intermediate Representation (IR).

Enables provider-agnostic policy analysis, transformation, and reasoning
across AWS, GCP, and Azure without losing vendor-specific fidelity.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyEffect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class CommonPrincipal(BaseModel):
    """Provider-neutral identity representation."""

    id: str = Field(..., description="Unique principal identifier")
    name: str = Field(..., description="Human-readable name")
    type: str = Field(default="service", description="Identity type: service, user, group, role")
    provider: str = Field(default="aws", description="Origin provider")
    roles: List[str] = Field(default_factory=list, description="Bound role IDs")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CommonAction(BaseModel):
    """Provider-neutral action descriptor."""

    raw_action: str = Field(..., description="Raw action string, e.g. 's3:GetObject' or 'storage.objects.get'")
    service: str = Field(..., description="Service domain prefix, e.g. 's3' or 'storage'")
    operation: str = Field(default="", description="Specific verb or operation name")
    is_wildcard: bool = Field(default=False, description="True if action specifies full or partial wildcard")

    @classmethod
    def from_string(cls, action_str: str, provider: str = "aws") -> CommonAction:
        raw = action_str.strip()
        is_wildcard = "*" in raw
        if ":" in raw:
            svc, op = raw.split(":", 1)
        elif "." in raw:
            svc, op = raw.split(".", 1)
        else:
            svc, op = "global", raw
        return cls(raw_action=raw, service=svc, operation=op, is_wildcard=is_wildcard)


class CommonResource(BaseModel):
    """Provider-neutral resource specification."""

    arn_or_id: str = Field(..., description="Canonical resource ARN, URI, or pattern")
    service: str = Field(default="", description="Service owning resource")
    is_protected: bool = Field(default=False, description="Sensitive or high-privilege resource flag")
    scope: Optional[str] = Field(default=None, description="Account, project, or subscription boundary")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CommonCondition(BaseModel):
    """Provider-neutral conditional authorization clause."""

    operator: str = Field(..., description="Evaluation operator, e.g. 'StringEquals', 'NumericLessThan'")
    key: str = Field(..., description="Context key, e.g. 'aws:PrincipalArn', 'request.time'")
    values: List[str] = Field(default_factory=list, description="Target evaluation values")


class CommonStatement(BaseModel):
    """Canonical permission statement combining Effect, Actions, Resources, and Conditions."""

    sid: Optional[str] = Field(default=None, description="Statement identifier")
    effect: PolicyEffect = Field(default=PolicyEffect.ALLOW)
    actions: List[CommonAction] = Field(default_factory=list)
    resources: List[CommonResource] = Field(default_factory=list)
    conditions: List[CommonCondition] = Field(default_factory=list)


class CommonBinding(BaseModel):
    """Association of a principal to a policy or role within a scope."""

    principal_id: str
    role_or_policy_id: str
    scope: Optional[str] = None
    condition: Optional[CommonCondition] = None


class CommonPolicy(BaseModel):
    """Canonical representation of an IAM policy document."""

    id: str
    name: str
    provider: str = Field(default="aws")
    version: str = Field(default="v1")
    statements: List[CommonStatement] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def extract_permission_strings(self) -> List[str]:
        """Extracts all action strings declared in ALLOW statements."""
        perms: List[str] = []
        for stmt in self.statements:
            if stmt.effect == PolicyEffect.ALLOW:
                for a in stmt.actions:
                    if a.raw_action not in perms:
                        perms.append(a.raw_action)
        return perms

    @classmethod
    def from_permissions_list(
        cls,
        policy_id: str,
        name: str,
        permissions: List[str],
        version: str = "v1",
        provider: str = "aws",
    ) -> CommonPolicy:
        """Constructs a CommonPolicy from a list of action strings."""
        actions = [CommonAction.from_string(p, provider=provider) for p in permissions]
        statement = CommonStatement(
            sid="AllowRequestedActions",
            effect=PolicyEffect.ALLOW,
            actions=actions,
            resources=[CommonResource(arn_or_id="*")],
        )
        return cls(
            id=policy_id,
            name=name,
            provider=provider,
            version=version,
            statements=[statement],
        )
