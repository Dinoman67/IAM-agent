"""Phase 3 Tests: Cloud Provider Adapters (AWS, GCP, Azure) and Capability Parity."""

import pytest

from backend.environment.loader import load_environment
from backend.models.iam import CommonBinding, CommonPolicy
from backend.providers.adapters import (
    AWSProviderAdapter,
    AzureProviderAdapter,
    GCPProviderAdapter,
    RealAWSProvider,
    RealAzureProvider,
    RealGCPProvider,
    SimulatedAWSProvider,
    SimulatedAzureProvider,
    SimulatedGCPProvider,
)
from backend.providers.capabilities import (
    AWS_CAPABILITIES,
    AZURE_CAPABILITIES,
    GCP_CAPABILITIES,
    negotiate_capability,
)
from backend.providers.common.errors import UnsupportedCapabilityError
from backend.security.validator import (
    validate_aws_policy,
    validate_azure_assignment,
    validate_gcp_binding,
)


def test_aws_provider_adapter_full_lifecycle():
    """Verify AWS provider adapter satisfies all functional IAMProvider methods."""
    env = load_environment()
    aws = AWSProviderAdapter(env)

    # 1. Capability inspection
    caps = aws.get_capabilities()
    assert caps.provider_name == "aws"
    assert caps.supports_policy_simulation is True
    assert caps.supports_rollback is True
    assert caps.supports_policy_versioning is True

    # 2. Principal inspection
    principal = aws.inspect_principal("principal-payment-svc")
    assert principal is not None
    assert principal.provider == "aws"
    assert principal.name == "PaymentServicePrincipal"

    # 3. Policy inspection
    policy = aws.inspect_policy("PaymentServiceRole")
    assert policy is not None
    assert policy.provider == "aws"
    assert "s3:GetObject" in policy.extract_permission_strings()

    # 4. Permission analysis
    analysis = aws.analyze_permissions("PaymentServiceRole")
    assert "s3:GetObject" in analysis
    assert "kms:Decrypt" in analysis

    # 5. Simulation (passing and failing)
    passing_sim = aws.simulate_change(
        "PaymentServiceRole",
        ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
    )
    assert passing_sim.success is True

    failing_sim = aws.simulate_change(
        "PaymentServiceRole",
        ["s3:GetObject", "s3:PutObject", "cloudwatch:PutMetricData"],
    )
    assert failing_sim.success is False
    assert failing_sim.missing_permission == "kms:Decrypt"

    # 6. Policy diff
    diff = aws.compute_policy_diff(
        role_id="PaymentServiceRole",
        from_version="v1",
        original_permissions=["s3:GetObject", "ec2:*"],
        new_permissions=["s3:GetObject"],
    )
    assert diff.provider == "aws"
    assert "ec2:*" in diff.removed
    assert "s3:GetObject" in diff.kept
    assert "AllowRequestedActions" in diff.provider_diff.get("statement_id", "")

    # 7. Validation
    val_res = aws.validate_change(policy)
    assert val_res.is_valid is True
    assert val_res.provider == "aws"

    # 8. Apply and Rollback
    new_version = aws.apply_change("PaymentServiceRole", ["s3:GetObject", "kms:Decrypt"], reason="Least privilege")
    assert new_version.version_id == "v2"

    rolled_back = aws.rollback_change("PaymentServiceRole", "v1")
    assert rolled_back.version_id == "v1"


def test_gcp_provider_adapter_truthful_capabilities_and_failures():
    """Verify GCP adapter exposes authentic capabilities and fails unsupported operations safely."""
    gcp = GCPProviderAdapter()

    # Capabilities
    caps = gcp.get_capabilities()
    assert caps.provider_name == "gcp"
    assert caps.supports_policy_simulation is False
    assert caps.supports_rollback is False
    assert caps.supports_policy_versioning is False

    # Machine-readable capability negotiation
    sim_status = gcp.get_capabilities().check_capability("simulate_change")
    assert sim_status.supported is False
    assert sim_status.risk == "unsupported"
    assert "Local GCP simulation is not implemented" in sim_status.reason

    rb_status = negotiate_capability(caps, "rollback_change")
    assert rb_status.supported is False
    assert "atomic policy rollback" in rb_status.reason

    # Unsupported simulation must raise structured UnsupportedCapabilityError
    with pytest.raises(UnsupportedCapabilityError) as exc_sim:
        gcp.simulate_change("roles/storage.objectViewer", ["storage.objects.get"])
    assert exc_sim.value.provider == "gcp"
    assert exc_sim.value.operation == "simulate_change"
    err_dict = exc_sim.value.to_dict()
    assert err_dict["error_code"] == "UNSUPPORTED_CAPABILITY"
    assert err_dict["supported"] is False

    # Unsupported rollback must raise structured UnsupportedCapabilityError
    with pytest.raises(UnsupportedCapabilityError) as exc_rb:
        gcp.rollback_change("roles/storage.objectViewer", "etag-prev")
    assert exc_rb.value.provider == "gcp"
    assert exc_rb.value.operation == "rollback_change"

    # Supported inspection and apply
    pol = gcp.inspect_policy("roles/storage.objectViewer")
    assert pol is not None
    assert pol.provider == "gcp"

    applied = gcp.apply_change("roles/storage.objectViewer", ["storage.objects.get"], reason="Restrict")
    assert applied.version_id == "etag-updated"


def test_azure_provider_adapter_truthful_capabilities_and_failures():
    """Verify Azure adapter exposes authentic capabilities and fails unsupported operations safely."""
    azure = AzureProviderAdapter()

    # Capabilities
    caps = azure.get_capabilities()
    assert caps.provider_name == "azure"
    assert caps.supports_policy_simulation is False
    assert caps.supports_rollback is False
    assert caps.supports_policy_preview is False

    # Negotiation
    sim_check = caps.check_capability("simulate_change")
    assert sim_check.supported is False
    assert "azure" in sim_check.reason.lower()

    # Unsupported simulation
    with pytest.raises(UnsupportedCapabilityError) as exc_sim:
        azure.simulate_change("Contributor", ["Microsoft.Storage/read"])
    assert exc_sim.value.provider == "azure"

    # Unsupported rollback
    with pytest.raises(UnsupportedCapabilityError) as exc_rb:
        azure.rollback_change("Contributor", "v1")
    assert exc_rb.value.provider == "azure"

    # Supported inspection and controlled apply
    pol = azure.inspect_policy("Contributor")
    assert pol is not None
    assert pol.provider == "azure"

    applied = azure.apply_change("Contributor", ["Microsoft.Storage/read"], reason="Restrict")
    assert applied.version_id == "rev-updated"


def test_real_cloud_providers_disabled_by_default():
    """Verify RealAWSProvider, RealGCPProvider, and RealAzureProvider protect against accidental live mutation."""
    real_aws = RealAWSProvider()
    with pytest.raises(PermissionError) as exc_aws:
        real_aws.apply_change("Role", ["s3:GetObject"], "Attempt live apply")
    assert "disabled by default" in str(exc_aws.value).lower()

    real_gcp = RealGCPProvider()
    with pytest.raises(PermissionError) as exc_gcp:
        real_gcp.apply_change("roles/test", ["storage.get"], "Attempt live apply")
    assert "disabled by default" in str(exc_gcp.value).lower()

    real_azure = RealAzureProvider()
    with pytest.raises(PermissionError) as exc_az:
        real_azure.apply_change("Contributor", ["Microsoft.Storage/read"], "Attempt live apply")
    assert "disabled by default" in str(exc_az.value).lower()


def test_provider_aware_syntax_validators():
    """Verify provider validators validate syntax and detect provider schema mismatches."""
    # AWS Validator with valid AWS policy
    aws_valid = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}],
    }
    assert validate_aws_policy(aws_valid).is_valid is True

    # AWS Validator with invalid action syntax (no colon and not '*')
    aws_invalid_action = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["invalidactionformat"], "Resource": ["*"]}],
    }
    res_inv = validate_aws_policy(aws_invalid_action)
    assert res_inv.is_valid is False
    assert any("must be '*' or 'service:Action'" in e for e in res_inv.errors)

    # GCP Validator with valid binding
    gcp_valid = {
        "role": "roles/storage.objectViewer",
        "members": ["user:bob@example.com", "serviceAccount:sa@proj.iam.gserviceaccount.com"],
    }
    assert validate_gcp_binding(gcp_valid).is_valid is True

    # GCP Validator with invalid unprefixed member
    gcp_invalid_member = {
        "role": "roles/storage.objectViewer",
        "members": ["unprefixed_alice@example.com"],
    }
    res_gcp_inv = validate_gcp_binding(gcp_invalid_member)
    assert res_gcp_inv.is_valid is False
    assert any("must be prefixed" in e for e in res_gcp_inv.errors)

    # Azure Validator with valid role assignment
    azure_valid = {
        "properties": {
            "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/def-1",
            "principalId": "sp-agent-guid",
            "scope": "/subscriptions/sub-1/resourceGroups/rg-1",
        }
    }
    assert validate_azure_assignment(azure_valid).is_valid is True

    # Azure Validator with invalid scope (missing leading slash)
    azure_invalid_scope = {
        "properties": {
            "roleDefinitionId": "def-1",
            "principalId": "sp-agent-guid",
            "scope": "subscriptions/sub-1",
        }
    }
    res_az_inv = validate_azure_assignment(azure_invalid_scope)
    assert res_az_inv.is_valid is False
    assert any("must start with leading slash" in e for e in res_az_inv.errors)
