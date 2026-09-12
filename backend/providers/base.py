"""Abstract base interface for cloud provider IAM adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from backend.models.iam import CommonPolicy, CommonPrincipal
from backend.models.schemas import PolicyVersion, SimulationResult
from backend.providers.capabilities import ProviderCapabilities


class BaseProvider(ABC):
    """Abstract interface normalizing vendor IAM interactions into Common IR and semantics."""

    @property
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """Returns provider IAM capabilities."""
        pass

    @abstractmethod
    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        """Fetches principal metadata mapped to Common IR."""
        pass

    @abstractmethod
    def inspect_role(self, role_id: str) -> Optional[CommonPolicy]:
        """Fetches active role policy mapped to Common IR."""
        pass

    @abstractmethod
    def simulate_policy(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        """Runs pre-commit counterfactual simulation against business workflows."""
        pass

    @abstractmethod
    def apply_policy(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        """Applies remediated policy, generating an immutable revision."""
        pass

    @abstractmethod
    def rollback_policy(self, role_id: str, target_version: str) -> PolicyVersion:
        """Rolls back role policy to a designated revision."""
        pass
