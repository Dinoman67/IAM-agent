"""Configurable security policy governing permissions, protected resources, and autonomy gates."""

from __future__ import annotations

import fnmatch
from typing import List, Literal, Optional, Set
from pydantic import BaseModel, Field

AutonomyLevel = Literal["SAFE", "ASSISTED", "STRICT"]


class SecurityPolicyConfig(BaseModel):
    """Declarative, deterministic configuration for Security Kernel policies and gates.
    
    This configuration cannot be altered at runtime by the LLM.
    """

    # Protected wildcards and capabilities (retaining these in proposals requires escalation)
    protected_permissions: Set[str] = Field(
        default_factory=lambda: {
            "iam:*",
            "*",
            "sts:AssumeRole*",
            "iam:CreateUser",
            "iam:CreateRole",
            "iam:PutRolePolicy",
            "iam:AttachRolePolicy",
            "iam:DeleteRolePolicy",
            "iam:DeleteRole",
            "kms:ScheduleKeyDeletion",
            "cloudtrail:DeleteTrail",
            "cloudtrail:StopLogging",
        },
        description="Set of actions considered critical infrastructure or administrative capabilities",
    )

    # Specific administrative actions whose removal or modification requires explicit human escalation
    sensitive_administrative_actions: Set[str] = Field(
        default_factory=lambda: {
            "iam:createuser",
            "iam:createrole",
            "iam:putrolepolicy",
            "iam:attachrolepolicy",
            "iam:deleterolepolicy",
            "iam:deleterole",
            "kms:schedulekeydeletion",
            "cloudtrail:deletetrail",
            "cloudtrail:stoplogging",
        },
        description="Specific administrative capabilities that trigger escalation if removed or modified",
    )

    # Patterns or identifiers identifying protected cloud resources
    protected_resource_patterns: List[str] = Field(
        default_factory=lambda: [
            "*admin*",
            "*root*",
            "*master-key*",
            "*customer-pii*",
            "*audit-trail*",
            "*cloudtrail*",
            "*production-db*",
        ],
        description="Resource ARN/URI glob patterns deemed sensitive or protected",
    )

    # Sensitive operational areas
    protected_policy_areas: List[str] = Field(
        default_factory=lambda: [
            "identity_administration",
            "encryption_administration",
            "security_logging",
            "audit_infrastructure",
            "root_level_access",
            "production_critical_data",
        ],
        description="High-sensitivity domains subject to stricter blast radius and autonomy restrictions",
    )

    # Autonomy level gating
    autonomy_level: AutonomyLevel = Field(
        default="SAFE",
        description="Autonomous execution mode: 'SAFE' (standard), 'ASSISTED' (requires approval for medium+), 'STRICT' (autonomous only for low risk & 0.95+ conf)",
    )

    min_confidence_for_apply: float = Field(
        default=0.85, description="Minimum confidence score required for autonomous apply"
    )

    max_rollback_attempts: int = Field(
        default=1, description="Hard bound on automated rollback attempts before mandatory escalation"
    )

    max_failed_action_repeats: int = Field(
        default=2, description="Maximum repeated failures of an identical action before triggering loop escalation"
    )

    require_simulation: bool = Field(
        default=True, description="Enforce counterfactual simulation before apply when supported"
    )

    require_regression_tests: bool = Field(
        default=True, description="Enforce positive and negative policy regression test suite before apply"
    )

    def is_permission_protected(self, permission: str) -> bool:
        """Determines if an action is in or matched by the protected permissions set."""
        perm_lower = permission.lower().strip()
        for p in self.protected_permissions:
            p_lower = p.lower().strip()
            if p_lower == "*":
                if perm_lower == "*":
                    return True
            elif "*" in p_lower:
                if fnmatch.fnmatch(perm_lower, p_lower):
                    return True
            elif p_lower == perm_lower:
                return True
        return False

    def is_sensitive_action_removed(self, permission: str) -> bool:
        """Determines if a specific administrative action is being removed."""
        perm_lower = permission.lower().strip()
        return perm_lower in self.sensitive_administrative_actions

    def is_resource_protected(self, resource_arn_or_id: str) -> bool:
        """Determines if a resource identifier matches any protected resource pattern."""
        r_lower = resource_arn_or_id.lower().strip()
        for pat in self.protected_resource_patterns:
            if fnmatch.fnmatch(r_lower, pat.lower()):
                return True
        return False


DEFAULT_SECURITY_POLICY_CONFIG = SecurityPolicyConfig()

__all__ = [
    "AutonomyLevel",
    "SecurityPolicyConfig",
    "DEFAULT_SECURITY_POLICY_CONFIG",
]
