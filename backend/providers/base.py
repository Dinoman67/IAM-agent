"""Abstract base interface and protocol for cloud provider IAM adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from backend.models.iam import CommonPolicy, CommonPrincipal
from backend.models.schemas import PolicyVersion, SimulationResult
from backend.providers.capabilities import ProviderCapabilities
from backend.security.diff import PolicyDiff


class ProviderValidationResult(BaseModel):
    """Structured outcome of provider-specific policy validation."""

    is_valid: bool
    provider: str
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class IAMProvider(Protocol):
    """Canonical Protocol defining the contract for all cloud IAM providers."""

    def get_capabilities(self) -> ProviderCapabilities:
        """Returns machine-readable provider IAM capabilities."""
        ...

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        """Fetches principal metadata mapped to Common IR."""
        ...

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        """Fetches active policy/role mapped to Common IR."""
        ...

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        """Analyzes active permissions for a role, generating evidence bundles."""
        ...

    def compute_policy_diff(
        self,
        role_id: str,
        from_version: str,
        original_permissions: List[str],
        new_permissions: List[str],
        to_version: Optional[str] = None,
        retained_dependencies: Optional[List[str]] = None,
    ) -> PolicyDiff:
        """Computes provider-aware semantic and structural policy diff."""
        ...

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        """Runs pre-commit counterfactual simulation against business workflows."""
        ...

    def validate_change(self, target: Any) -> ProviderValidationResult:
        """Executes provider-specific syntax, boundary, and structural validation."""
        ...

    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> Any:
        """Executes provider-aware post-remediation verification."""
        ...

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        """Applies remediated policy, generating an immutable revision."""
        ...

    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        """Rolls back role policy to a designated revision."""
        ...


class BaseProvider(ABC):
    """Abstract base class implementing the IAMProvider contract with backward-compatible aliases."""

    @property
    def capabilities(self) -> ProviderCapabilities:
        """Backward-compatible property accessing provider capabilities."""
        return self.get_capabilities()

    @abstractmethod
    def get_capabilities(self) -> ProviderCapabilities:
        """Returns provider IAM capabilities."""
        pass

    @abstractmethod
    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        """Fetches principal metadata mapped to Common IR."""
        pass

    @abstractmethod
    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        """Fetches active role or policy mapped to Common IR."""
        pass

    def inspect_role(self, role_id: str) -> Optional[CommonPolicy]:
        """Backward-compatible alias for inspect_policy."""
        return self.inspect_policy(role_id)

    @abstractmethod
    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        """Analyzes active permissions for a role."""
        pass

    @abstractmethod
    def compute_policy_diff(
        self,
        role_id: str,
        from_version: str,
        original_permissions: List[str],
        new_permissions: List[str],
        to_version: Optional[str] = None,
        retained_dependencies: Optional[List[str]] = None,
    ) -> PolicyDiff:
        """Computes provider-aware policy diff."""
        pass

    @abstractmethod
    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        """Runs pre-commit counterfactual simulation against business workflows."""
        pass

    def simulate_policy(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        """Backward-compatible alias for simulate_change."""
        return self.simulate_change(role_id, proposed_permissions)

    @abstractmethod
    def validate_change(self, target: Any) -> ProviderValidationResult:
        """Executes provider-specific syntax, boundary, and structural validation."""
        pass

    @abstractmethod
    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> Any:
        """Executes provider-aware post-remediation verification."""
        pass

    @abstractmethod
    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        """Applies remediated policy, generating an immutable revision."""
        pass

    def apply_policy(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        """Backward-compatible alias for apply_change."""
        return self.apply_change(role_id, new_permissions, reason)

    @abstractmethod
    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        """Rolls back role policy to a designated revision."""
        pass

    def rollback_policy(self, role_id: str, target_version: str) -> PolicyVersion:
        """Backward-compatible alias for rollback_change."""
        return self.rollback_change(role_id, target_version)


__all__ = [
    "IAMProvider",
    "BaseProvider",
    "ProviderValidationResult",
]
