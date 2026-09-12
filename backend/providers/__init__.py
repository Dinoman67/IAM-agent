"""Cloud provider adapters, capability models, and abstractions."""

from backend.providers.base import BaseProvider, IAMProvider, ProviderValidationResult
from backend.providers.capabilities import (
    AWS_CAPABILITIES,
    AZURE_CAPABILITIES,
    GCP_CAPABILITIES,
    RESTRICTED_MOCK_CAPABILITIES,
    CapabilityStatus,
    ProviderCapabilities,
    negotiate_capability,
)
from backend.providers.common.errors import (
    ProviderMismatchError,
    UnsupportedCapabilityError,
    enforce_provider_match,
)

__all__ = [
    "IAMProvider",
    "BaseProvider",
    "ProviderValidationResult",
    "ProviderCapabilities",
    "CapabilityStatus",
    "negotiate_capability",
    "AWS_CAPABILITIES",
    "GCP_CAPABILITIES",
    "AZURE_CAPABILITIES",
    "RESTRICTED_MOCK_CAPABILITIES",
    "ProviderMismatchError",
    "UnsupportedCapabilityError",
    "enforce_provider_match",
]
