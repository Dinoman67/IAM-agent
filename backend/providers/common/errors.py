"""Common provider errors and boundary enforcement."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class ProviderMismatchError(ValueError):
    """Raised when an artifact from one cloud provider is routed to a different provider adapter."""

    def __init__(
        self,
        source_provider: str,
        target_provider: str,
        reason: str,
        recommended_action: Optional[str] = None,
    ) -> None:
        self.source_provider = source_provider
        self.target_provider = target_provider
        self.reason = reason
        self.recommended_action = recommended_action or (
            f"Route artifact to the '{source_provider}' adapter or explicitly translate into '{target_provider}' IR."
        )
        super().__init__(
            f"PROVIDER_MISMATCH: Cannot process {source_provider} artifact with {target_provider} adapter. "
            f"Reason: {reason}. Recommended action: {self.recommended_action}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": "PROVIDER_MISMATCH",
            "source_provider": self.source_provider,
            "target_provider": self.target_provider,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
        }


class UnsupportedCapabilityError(NotImplementedError):
    """Raised when an operation requested on a provider is not supported by that provider."""

    def __init__(
        self,
        provider: str,
        operation: str,
        reason: str,
        limitations: Optional[List[str]] = None,
    ) -> None:
        self.provider = provider
        self.operation = operation
        self.reason = reason
        self.limitations = limitations or []
        super().__init__(
            f"UNSUPPORTED_CAPABILITY [{provider}]: Operation '{operation}' is not supported. "
            f"Reason: {reason}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": "UNSUPPORTED_CAPABILITY",
            "provider": self.provider,
            "operation": self.operation,
            "supported": False,
            "reason": self.reason,
            "limitations": self.limitations,
        }


def enforce_provider_match(
    expected_provider: str,
    actual_provider: str,
    context: str = "operation",
) -> None:
    """Enforces provider match and prevents silent cross-cloud coercion."""
    if not actual_provider or not expected_provider:
        return
    exp = expected_provider.lower().strip()
    act = actual_provider.lower().strip()
    if exp != act:
        raise ProviderMismatchError(
            source_provider=act,
            target_provider=exp,
            reason=f"Mismatched provider during {context}: received '{act}', expected '{exp}'",
            recommended_action=f"Route artifact to '{act}' adapter or convert to '{exp}' schema explicitly.",
        )


__all__ = [
    "ProviderMismatchError",
    "UnsupportedCapabilityError",
    "enforce_provider_match",
]
