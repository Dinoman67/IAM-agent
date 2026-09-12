"""Tests for the deterministic policy simulator."""

import pytest
from backend.environment.loader import load_environment
from backend.environment.simulator import PolicySimulator


@pytest.fixture
def env():
    return load_environment()


@pytest.fixture
def simulator(env):
    return PolicySimulator(env)


def test_action_allowed_matching():
    """Verify wildcard and exact permission matching."""
    perms = ["s3:GetObject", "ec2:*", "cloudwatch:PutMetricData"]
    assert PolicySimulator.is_action_allowed("s3:GetObject", perms) is True
    assert PolicySimulator.is_action_allowed("s3:PutObject", perms) is False
    assert PolicySimulator.is_action_allowed("ec2:DescribeInstances", perms) is True
    assert PolicySimulator.is_action_allowed("ec2:TerminateInstances", perms) is True
    assert PolicySimulator.is_action_allowed("iam:CreateUser", perms) is False


def test_simulation_failure_on_missing_kms(simulator):
    """Simulating policy that strips kms:Decrypt must fail with clear dependency evidence."""
    naive_permissions = [
        "s3:GetObject",
        "s3:PutObject",
        "cloudwatch:PutMetricData",
    ]

    result = simulator.simulate("PaymentServiceRole", naive_permissions)
    assert result.success is False
    assert result.failed_workflow == "payment_checkout"
    assert result.missing_permission == "kms:Decrypt"
    assert result.broken_dependency == "PaymentService -> S3 -> KMS"
    assert "Workflow 'payment_checkout' failed" in result.details
    assert result.evidence_id.startswith("sim-")


def test_simulation_success_with_dependency_preserved(simulator):
    """Simulating policy that retains kms:Decrypt while removing wildcards must pass."""
    safe_permissions = [
        "s3:GetObject",
        "s3:PutObject",
        "kms:Decrypt",
        "cloudwatch:PutMetricData",
    ]

    result = simulator.simulate("PaymentServiceRole", safe_permissions)
    assert result.success is True
    assert result.failed_workflow is None
    assert result.missing_permission is None
    assert "All workflows and dependencies satisfied" in result.details


def test_simulation_records_run_history(env, simulator):
    """Simulation runs should be recorded in environment data."""
    initial_count = len(env.data.simulation_runs)
    simulator.simulate("PaymentServiceRole", ["s3:GetObject"])
    assert len(env.data.simulation_runs) == initial_count + 1
