"""Environment data loader and stateful simulated IAM repository."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.models.schemas import (
    AccessLog,
    IAMEnvironmentData,
    PolicyVersion,
    Principal,
    Role,
    ServiceDependency,
)


class IAMEnvironment:
    """In-memory simulated IAM environment acting as the authorization reality."""

    def __init__(self, data: IAMEnvironmentData) -> None:
        self.data = data

    @classmethod
    def from_file(cls, path: str | Path) -> IAMEnvironment:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Environment data file not found at: {path}")
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return cls(IAMEnvironmentData.model_validate(raw))

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> IAMEnvironment:
        return cls(IAMEnvironmentData.model_validate(raw))

    def get_principal(self, principal_id: str) -> Optional[Principal]:
        for p in self.data.principals:
            if p.id == principal_id:
                return p
        return None

    def get_role(self, role_id: str) -> Optional[Role]:
        for r in self.data.roles:
            if r.id == role_id:
                return r
        return None

    def get_access_history(
        self, role_id: Optional[str] = None, principal_id: Optional[str] = None
    ) -> List[AccessLog]:
        logs = self.data.access_logs
        if role_id:
            logs = [log for log in logs if log.role_id == role_id]
        if principal_id:
            logs = [log for log in logs if log.principal_id == principal_id]
        return logs

    def list_permissions(self, role_id: str) -> List[str]:
        role = self.get_role(role_id)
        if not role:
            raise ValueError(f"Role '{role_id}' not found in environment.")
        return role.active_permissions()

    def find_unused_permissions(self, role_id: str) -> List[str]:
        """Compares active permissions with directly observed access logs.
        Returns permissions never observed in direct execution logs.
        """
        active = self.list_permissions(role_id)
        role_logs = self.get_access_history(role_id=role_id)
        used_actions = {log.action for log in role_logs if log.success}

        unused = [perm for perm in active if perm not in used_actions]
        return unused

    def get_service_dependencies(
        self, service: Optional[str] = None
    ) -> List[ServiceDependency]:
        deps = self.data.dependencies
        if service:
            deps = [d for d in deps if d.service.lower() == service.lower()]
        return deps

    def apply_policy_version(
        self, role_id: str, new_permissions: List[str], reason: str
    ) -> PolicyVersion:
        role = self.get_role(role_id)
        if not role:
            raise ValueError(f"Role '{role_id}' not found.")

        # Determine next version id
        ver_num = len(role.policy_versions) + 1
        new_version_id = f"v{ver_num}"

        # Deactivate previous versions
        for v in role.policy_versions:
            v.is_active = False

        new_version = PolicyVersion(
            version_id=new_version_id,
            permissions=new_permissions,
            is_active=True,
            reason=reason,
        )
        role.policy_versions.append(new_version)
        role.current_version = new_version_id
        return new_version

    def rollback_policy(self, role_id: str, target_version: str = "v1") -> PolicyVersion:
        role = self.get_role(role_id)
        if not role:
            raise ValueError(f"Role '{role_id}' not found.")

        target = None
        for v in role.policy_versions:
            if v.version_id == target_version:
                target = v
                break

        if not target:
            raise ValueError(f"Target version '{target_version}' not found for role '{role_id}'.")

        # Set all inactive and activate target
        for v in role.policy_versions:
            v.is_active = (v.version_id == target_version)

        role.current_version = target_version
        return target


def load_environment(path: Optional[str | Path] = None) -> IAMEnvironment:
    """Convenience helper to load environment from default or custom path."""
    if path is None:
        default_path = Path(__file__).resolve().parent.parent.parent / "data" / "environment.json"
        path = default_path
    return IAMEnvironment.from_file(path)
