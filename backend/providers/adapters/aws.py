"""AWS / Simulated AWS provider adapter implementation."""

from __future__ import annotations

from typing import List, Optional

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.models.iam import CommonPolicy, CommonPrincipal
from backend.models.schemas import PolicyVersion, SimulationResult
from backend.providers.base import BaseProvider
from backend.providers.capabilities import AWS_CAPABILITIES, ProviderCapabilities


class AWSProviderAdapter(BaseProvider):
    """Adapter bridging IAMEnvironment to BaseProvider and Common IR."""

    def __init__(
        self,
        env: IAMEnvironment,
        capabilities: Optional[ProviderCapabilities] = None,
    ) -> None:
        self.env = env
        self._capabilities = capabilities or AWS_CAPABILITIES
        self.simulator = PolicySimulator(env)

    @property
    def capabilities(self) -> ProviderCapabilities:
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
        )

    def inspect_role(self, role_id: str) -> Optional[CommonPolicy]:
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

    def simulate_policy(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        return self.simulator.simulate(role_id, proposed_permissions)

    def apply_policy(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        return self.env.apply_policy_version(role_id, new_permissions, reason)

    def rollback_policy(self, role_id: str, target_version: str = "v1") -> PolicyVersion:
        return self.env.rollback_policy(role_id, target_version)
