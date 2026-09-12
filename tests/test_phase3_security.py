"""Phase 3 Tests: Security Kernel Authority, Provider Mismatch Protection, and Negative Tests."""

import pytest

from backend.environment.loader import load_environment
from backend.models.iam import (
    CommonAction,
    CommonBinding,
    CommonPolicy,
    CommonResource,
    CommonStatement,
    PolicyEffect,
)
from backend.providers.adapters import AWSProviderAdapter, AzureProviderAdapter, GCPProviderAdapter
from backend.providers.capabilities import AWS_CAPABILITIES, AZURE_CAPABILITIES, GCP_CAPABILITIES
from backend.providers.common.errors import ProviderMismatchError, UnsupportedCapabilityError, enforce_provider_match
from backend.security.kernel import SecurityKernel
from backend.security.validator import (
    validate_aws_policy,
    validate_azure_assignment,
    validate_common_policy,
    validate_gcp_binding,
)


def test_security_kernel_blocks_provider_mismatch():
    """Security Kernel denies proposal if provider does not match the target environment."""
    env = load_environment()
    kernel = SecurityKernel(env, capabilities=AWS_CAPABILITIES)

    # Proposal marked with provider="azure" sent to AWS Security Kernel
    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "kms:Decrypt"],
        planned_policy_version="v1",
        confidence=0.95,
        simulation_result={"success": True},
        provider="azure",
    )

    assert gate_result.decision == "deny"
    assert any("provider_mismatch" in c for c in gate_result.reason_codes)
    assert gate_result.details["provider_mismatch"]["source_provider"] == "azure"
    assert gate_result.details["provider_mismatch"]["target_provider"] == "aws"


def test_security_kernel_blocks_unauthorized_privilege_expansion():
    """Security Kernel denies least-privilege candidate attempting to add new unneeded permissions."""
    env = load_environment()
    kernel = SecurityKernel(env, capabilities=AWS_CAPABILITIES)

    # Candidate proposing s3:GetObject + newly fabricated "iam:CreateUser" not in original role
    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "iam:CreateUser"],
        planned_policy_version="v1",
        confidence=0.95,
        simulation_result={"success": True},
        provider="aws",
    )

    assert gate_result.decision == "deny"
    assert any("unauthorized_privilege_expansion" in c for c in gate_result.reason_codes)
    assert "iam:CreateUser" in gate_result.details["privilege_expansion"]


def test_provider_mismatch_boundary_enforcement():
    """Verify enforce_provider_match raises structured ProviderMismatchError."""
    # Matching does not raise
    enforce_provider_match("aws", "aws")
    enforce_provider_match("GCP", "gcp")

    # Mismatch raises
    with pytest.raises(ProviderMismatchError) as exc:
        enforce_provider_match(expected_provider="azure", actual_provider="aws", context="policy_diff")

    err = exc.value.to_dict()
    assert err["error_code"] == "PROVIDER_MISMATCH"
    assert err["source_provider"] == "aws"
    assert err["target_provider"] == "azure"
    assert "policy_diff" in err["reason"]
    assert "recommended_action" in err


def test_negative_cross_provider_artifact_passing():
    """Negative tests asserting adapters and validators reject cross-cloud artifacts."""
    # 1. AWS policy document passed to Azure validator
    aws_policy_doc = {
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}]
    }
    azure_val_res = validate_azure_assignment(aws_policy_doc)
    assert azure_val_res.is_valid is False
    assert azure_val_res.details.get("provider_mismatch") is True

    # 2. Azure role definition passed to AWS validator
    azure_role_doc = {
        "properties": {
            "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-1",
            "assignableScopes": ["/"],
        }
    }
    aws_val_res = validate_aws_policy(azure_role_doc)
    assert aws_val_res.is_valid is False
    assert aws_val_res.details.get("provider_mismatch") is True

    # 3. GCP binding passed to AWS validator
    gcp_binding_doc = {
        "role": "roles/storage.objectViewer",
        "members": ["user:alice@example.com"],
    }
    aws_val_gcp = validate_aws_policy(gcp_binding_doc)
    assert aws_val_gcp.is_valid is False
    assert aws_val_gcp.details.get("provider_mismatch") is True


def test_negative_unsupported_operations_never_report_success():
    """Negative test asserting unsupported operations on GCP and Azure never report success."""
    gcp = GCPProviderAdapter()
    azure = AzureProviderAdapter()

    # GCP simulation
    with pytest.raises(UnsupportedCapabilityError) as exc_gcp:
        gcp.simulate_change("roles/viewer", ["storage.objects.get"])
    assert exc_gcp.value.to_dict()["supported"] is False

    # GCP rollback
    with pytest.raises(UnsupportedCapabilityError) as exc_gcp_rb:
        gcp.rollback_change("roles/viewer", "prev-etag")
    assert exc_gcp_rb.value.to_dict()["supported"] is False

    # Azure simulation
    with pytest.raises(UnsupportedCapabilityError) as exc_az:
        azure.simulate_change("Reader", ["Microsoft.Storage/read"])
    assert exc_az.value.to_dict()["supported"] is False

    # Azure rollback
    with pytest.raises(UnsupportedCapabilityError) as exc_az_rb:
        azure.rollback_change("Reader", "1.0")
    assert exc_az_rb.value.to_dict()["supported"] is False


def test_validator_detects_empty_and_malformed_policies():
    """Validator detects empty policies, missing actions, and invalid effects."""
    empty_policy = CommonPolicy(id="empty-1", name="Empty", provider="aws", statements=[])
    res_empty = validate_common_policy(empty_policy)
    assert res_empty.is_valid is False
    assert any("neither statements nor bindings" in e for e in res_empty.errors)

    no_actions_stmt = CommonStatement(effect=PolicyEffect.ALLOW, actions=[], resources=[CommonResource(arn_or_id="*")])
    bad_policy = CommonPolicy(id="bad-1", name="Bad", provider="aws", statements=[no_actions_stmt])
    res_bad = validate_common_policy(bad_policy)
    assert res_bad.is_valid is False
    assert any("defines no actions" in e for e in res_bad.errors)
