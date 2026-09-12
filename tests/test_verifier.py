"""Tests for the deterministic policy verification layer."""

import pytest
from backend.environment.loader import load_environment
from backend.environment.verifier import PolicyVerifier


@pytest.fixture
def env():
    return load_environment()


@pytest.fixture
def verifier(env):
    return PolicyVerifier(env)


def test_initial_policy_fails_verification(verifier):
    """Initial v1 policy has broad wildcards and has not been mitigated."""
    result = verifier.verify("PaymentServiceRole")
    assert result.passed is False
    # In v1, protected resources (iam, ec2, dynamodb) are exposed
    assert result.checks["protected_resources_isolated"] is False
    # In v1, policy_applied is False because it's still version v1
    assert result.checks["policy_applied"] is False
    # Excess permissions have not been reduced
    assert result.checks["excess_permissions_reduced"] is False
    # Workflows pass in v1 because broad permissions cover everything
    assert result.checks["workflows_passed"] is True


def test_properly_mitigated_policy_passes_verification(env, verifier):
    """Applying the safe least-privilege policy allows verification to pass."""
    env.apply_policy_version(
        role_id="PaymentServiceRole",
        new_permissions=[
            "s3:GetObject",
            "s3:PutObject",
            "kms:Decrypt",
            "cloudwatch:PutMetricData",
        ],
        reason="Mitigated least-privilege configuration",
    )

    result = verifier.verify("PaymentServiceRole")
    assert result.passed is True
    assert result.checks["workflows_passed"] is True
    assert result.checks["protected_resources_isolated"] is True
    assert result.checks["policy_applied"] is True
    assert result.checks["excess_permissions_reduced"] is True


def test_broken_policy_fails_workflow_verification(env, verifier):
    """If a policy mistakenly strips kms:Decrypt, workflow verification fails."""
    env.apply_policy_version(
        role_id="PaymentServiceRole",
        new_permissions=[
            "s3:GetObject",
            "s3:PutObject",
            "cloudwatch:PutMetricData",
        ],
        reason="Faulty naive policy",
    )

    result = verifier.verify("PaymentServiceRole")
    assert result.passed is False
    assert result.checks["workflows_passed"] is False


def test_retained_wildcard_fails_protected_resources(env, verifier):
    """If excessive wildcard like ec2:* remains, isolation verification fails."""
    env.apply_policy_version(
        role_id="PaymentServiceRole",
        new_permissions=[
            "s3:GetObject",
            "s3:PutObject",
            "kms:Decrypt",
            "cloudwatch:PutMetricData",
            "ec2:*",
        ],
        reason="Incomplete mitigation leaving EC2 wildcard",
    )

    result = verifier.verify("PaymentServiceRole")
    assert result.passed is False
    assert result.checks["protected_resources_isolated"] is False
