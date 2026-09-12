"""Provider-aware policy and role translation package."""

from backend.providers.translation.aws import (
    aws_policy_to_ir,
    ir_to_aws_policy,
)
from backend.providers.translation.gcp import (
    gcp_role_to_ir,
    ir_to_gcp_role,
    gcp_binding_to_ir,
    ir_to_gcp_binding,
    gcp_policy_to_ir,
    ir_to_gcp_policy,
)
from backend.providers.translation.azure import (
    azure_role_def_to_ir,
    ir_to_azure_role_def,
    azure_assignment_to_ir,
    ir_to_azure_assignment,
)

__all__ = [
    "aws_policy_to_ir",
    "ir_to_aws_policy",
    "gcp_role_to_ir",
    "ir_to_gcp_role",
    "gcp_binding_to_ir",
    "ir_to_gcp_binding",
    "gcp_policy_to_ir",
    "ir_to_gcp_policy",
    "azure_role_def_to_ir",
    "ir_to_azure_role_def",
    "azure_assignment_to_ir",
    "ir_to_azure_assignment",
]
