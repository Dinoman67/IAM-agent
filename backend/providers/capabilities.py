"""Provider capabilities abstraction for multi-cloud parity awareness."""

from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class ProviderCapabilities(BaseModel):
    """Encapsulates cloud provider IAM feature capabilities."""

    provider_name: str = Field(..., description="Provider identifier, e.g. 'aws', 'gcp', 'azure'")
    supports_simulation: bool = Field(
        default=True, description="Whether provider supports pre-commit authorization simulation"
    )
    supports_policy_preview: bool = Field(
        default=True, description="Whether provider supports generating dry-run policy previews"
    )
    supports_policy_versioning: bool = Field(
        default=True, description="Whether native immutable policy revisions are maintained"
    )
    supports_conditions: bool = Field(
        default=True, description="Whether conditional statement blocks are evaluated"
    )
    supports_resource_scoping: bool = Field(
        default=True, description="Whether permissions can be scoped to specific resource ARNs"
    )
    supports_rollback: bool = Field(
        default=True, description="Whether instant atomic rollback to a previous version is available"
    )
    supported_policy_types: List[str] = Field(
        default_factory=lambda: ["identity_based", "resource_based"],
        description="Supported policy categories",
    )


# Standard profile templates
AWS_CAPABILITIES = ProviderCapabilities(
    provider_name="aws",
    supports_simulation=True,
    supports_policy_preview=True,
    supports_policy_versioning=True,
    supports_conditions=True,
    supports_resource_scoping=True,
    supports_rollback=True,
    supported_policy_types=["identity_based", "resource_based", "service_control"],
)

GCP_CAPABILITIES = ProviderCapabilities(
    provider_name="gcp",
    supports_simulation=False,  # GCP IAM requires security health analytics or dry-run testing
    supports_policy_preview=True,
    supports_policy_versioning=False,  # Etag based concurrency rather than version history
    supports_conditions=True,
    supports_resource_scoping=True,
    supports_rollback=False,  # Re-apply previous policy binding
    supported_policy_types=["role_binding", "conditional_binding"],
)

AZURE_CAPABILITIES = ProviderCapabilities(
    provider_name="azure",
    supports_simulation=False,
    supports_policy_preview=False,
    supports_policy_versioning=False,
    supports_conditions=True,
    supports_resource_scoping=True,
    supports_rollback=False,
    supported_policy_types=["rbac_role_assignment"],
)

RESTRICTED_MOCK_CAPABILITIES = ProviderCapabilities(
    provider_name="restricted_mock",
    supports_simulation=False,
    supports_policy_preview=False,
    supports_policy_versioning=False,
    supports_conditions=False,
    supports_resource_scoping=False,
    supports_rollback=False,
    supported_policy_types=["basic"],
)
