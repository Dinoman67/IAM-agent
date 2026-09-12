"""Transitive service dependency graph and forensic investigation."""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from backend.environment.loader import IAMEnvironment
from backend.models.schemas import ServiceDependency


class DependencyChain(BaseModel):
    """Detailed trace explaining why a hidden permission is structurally required."""

    service: str
    intermediary: str
    target_service: str
    required_permission: str
    reason: str
    architecture_context: str = ""


class DependencyGraph:
    """Graph of direct and transitive service interactions and cryptographic couplings."""

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def find_dependencies_for_service(self, service_name: str) -> List[ServiceDependency]:
        """Returns direct and transitive dependencies registered for service."""
        return self.env.get_service_dependencies(service=service_name)

    def explain_missing_permission(
        self, service_name: str, missing_permission: str
    ) -> Optional[DependencyChain]:
        """Explains why a permission is needed even if not logged in application code."""
        deps = self.env.get_service_dependencies(service=service_name)
        for d in deps:
            if d.required_permission.lower() == missing_permission.lower():
                return DependencyChain(
                    service=d.service,
                    intermediary=d.calls_service,
                    target_service=d.downstream_dependency,
                    required_permission=d.required_permission,
                    reason=d.reason,
                    architecture_context=(
                        f"When {d.service} interacts with {d.calls_service}, server-side processes "
                        f"transitively invoke {d.downstream_dependency}, requiring '{d.required_permission}'."
                    ),
                )
        return None
