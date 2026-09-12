"""AWS / Simulated AWS provider adapter implementation."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.models.iam import CommonPolicy, CommonPrincipal
from backend.models.schemas import PolicyVersion, SimulationResult
from backend.providers.base import BaseProvider, ProviderValidationResult
from backend.providers.capabilities import AWS_CAPABILITIES, ProviderCapabilities
from backend.providers.common.errors import enforce_provider_match
from backend.security.analyzer import SecurityAnalyzer
from backend.security.diff import PolicyDiff, compute_policy_diff
from backend.security.validator import validate_aws_policy
from backend.security.verification import ComprehensiveVerificationResult, ExtendedPolicyVerifier


class AWSProviderAdapter(BaseProvider):
    """Adapter bridging simulated AWS IAMEnvironment to BaseProvider and Common IR."""

    def __init__(
        self,
        env: IAMEnvironment,
        capabilities: Optional[ProviderCapabilities] = None,
    ) -> None:
        self.env = env
        self._capabilities = capabilities or AWS_CAPABILITIES
        self.simulator = PolicySimulator(env)
        self.analyzer = SecurityAnalyzer(env)
        self.verifier = ExtendedPolicyVerifier(env, capabilities=self._capabilities)

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        principal = self.env.get_principal(principal_id)
        if not principal:
            return None
        return CommonPrincipal(
            id=principal.id,
            name=principal.name,
            type=principal.type.lower(),
            provider="aws",
            roles=principal.roles,
            provider_metadata={"arn": f"arn:aws:iam::123456789012:user/{principal.name}"},
        )

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        role_id = policy_id.replace("policy-", "").replace("Policy", "")
        role = self.env.get_role(role_id)
        if not role:
            return None
        active_perms = role.active_permissions()
        return CommonPolicy.from_permissions_list(
            policy_id=f"policy-{role.id}",
            name=f"{role.name}Policy",
            permissions=active_perms,
            version=role.current_version,
            provider="aws",
        )

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        bundles = self.analyzer.analyze_role(role_id)
        return {perm: b.model_dump() for perm, b in bundles.items()}

    def compute_policy_diff(
        self,
        role_id: str,
        from_version: str,
        original_permissions: List[str],
        new_permissions: List[str],
        to_version: Optional[str] = None,
        retained_dependencies: Optional[List[str]] = None,
    ) -> PolicyDiff:
        return compute_policy_diff(
            role_id=role_id,
            from_version=from_version,
            original_permissions=original_permissions,
            new_permissions=new_permissions,
            to_version=to_version,
            retained_dependencies=retained_dependencies,
            provider="aws",
        )

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        return self.simulator.simulate(role_id, proposed_permissions)

    def validate_change(self, target: Any) -> ProviderValidationResult:
        return validate_aws_policy(target)

    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> ComprehensiveVerificationResult:
        return self.verifier.verify_remediation(role_id, expected_permissions=expected_permissions, provider="aws")

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        return self.env.apply_policy_version(role_id, new_permissions, reason)

    def rollback_change(self, role_id: str, target_version: str = "v1") -> PolicyVersion:
        return self.env.rollback_policy(role_id, target_version)


class SimulatedAWSProvider(AWSProviderAdapter):
    """Explicit alias representing local deterministic simulated AWS provider."""
    pass


class RealAWSProvider(BaseProvider):
    """Production AWS connector stub with explicit disabled-by-default safeguards."""

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        self._capabilities = AWS_CAPABILITIES
        self._live_mutation_enabled = os.getenv("LIVE_MUTATION_ENABLED", "false").lower() in ("true", "1")

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        raise NotImplementedError("RealAWSProvider IAM lookup requires configured AWS credentials.")

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        raise NotImplementedError("RealAWSProvider policy lookup requires configured AWS credentials.")

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        raise NotImplementedError("RealAWSProvider permission analysis requires configured AWS credentials.")

    def compute_policy_diff(
        self,
        role_id: str,
        from_version: str,
        original_permissions: List[str],
        new_permissions: List[str],
        to_version: Optional[str] = None,
        retained_dependencies: Optional[List[str]] = None,
    ) -> PolicyDiff:
        return compute_policy_diff(
            role_id=role_id,
            from_version=from_version,
            original_permissions=original_permissions,
            new_permissions=new_permissions,
            to_version=to_version,
            retained_dependencies=retained_dependencies,
            provider="aws",
        )

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        raise NotImplementedError("RealAWSProvider live policy simulation requires AWS IAM Policy Simulator credentials.")

    def validate_change(self, target: Any) -> ProviderValidationResult:
        return validate_aws_policy(target)

    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> ComprehensiveVerificationResult:
        raise NotImplementedError("RealAWSProvider post-change verification requires AWS credentials.")

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        if not self._live_mutation_enabled:
            raise PermissionError(
                "Live AWS mutation is disabled by default in this environment. "
                "RealAWSProvider requires explicit LIVE_MUTATION_ENABLED=true."
            )
        raise NotImplementedError("Live AWS mutation is not enabled.")

    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        if not self._live_mutation_enabled:
            raise PermissionError("Live AWS rollback is disabled by default.")
        raise NotImplementedError("Live AWS rollback is not enabled.")


__all__ = [
    "AWSProviderAdapter",
    "SimulatedAWSProvider",
    "RealAWSProvider",
]
