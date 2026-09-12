"""Tests for the 10 deterministic IAM tools and tool registry."""

import pytest
from backend.environment.loader import load_environment
from backend.tools.base import BaseTool, ToolResult
from backend.tools.iam_tools import (
    ApplyPolicyChangeTool,
    FindUnusedPermissionsTool,
    GetAccessHistoryTool,
    GetPrincipalTool,
    GetRoleTool,
    GetServiceDependenciesTool,
    ListPermissionsTool,
    RollbackPolicyTool,
    SimulatePolicyTool,
    VerifyRequiredAccessTool,
    create_default_tool_registry,
)


@pytest.fixture
def test_env():
    return load_environment()


@pytest.fixture
def registry(test_env):
    return create_default_tool_registry(test_env)


def test_registry_registration_and_listing(registry):
    tools = registry.list_tools()
    assert len(tools) == 10
    names = {t["name"] for t in tools}
    expected = {
        "get_principal",
        "get_role",
        "get_access_history",
        "list_permissions",
        "find_unused_permissions",
        "get_service_dependencies",
        "simulate_policy",
        "apply_policy_change",
        "verify_required_access",
        "rollback_policy",
    }
    assert expected.issubset(names)


def test_get_principal_success_and_failure(registry):
    res_ok = registry.execute("get_principal", {"principal_id": "principal-payment-svc"})
    assert res_ok.success is True
    assert res_ok.data["name"] == "PaymentServicePrincipal"

    res_fail = registry.execute("get_principal", {"principal_id": "non-existent"})
    assert res_fail.success is False
    assert "not found" in res_fail.error


def test_get_role_success_and_failure(registry):
    res_ok = registry.execute("get_role", {"role_id": "PaymentServiceRole"})
    assert res_ok.success is True
    assert res_ok.data["id"] == "PaymentServiceRole"
    assert len(res_ok.data["active_permissions"]) == 7

    res_fail = registry.execute("get_role", {"role_id": "UnknownRole"})
    assert res_fail.success is False


def test_get_access_history(registry):
    res = registry.execute("get_access_history", {"role_id": "PaymentServiceRole"})
    assert res.success is True
    assert len(res.data) > 0
    actions = {log["action"] for log in res.data}
    assert "s3:GetObject" in actions
    assert "kms:Decrypt" not in actions  # Direct access logs do not contain kms


def test_list_permissions(registry):
    res = registry.execute("list_permissions", {"role_id": "PaymentServiceRole"})
    assert res.success is True
    assert "s3:GetObject" in res.data
    assert "ec2:*" in res.data


def test_find_unused_permissions(registry):
    res = registry.execute("find_unused_permissions", {"role_id": "PaymentServiceRole"})
    assert res.success is True
    unused = res.data
    # Wildcards and unlogged KMS are identified
    assert "ec2:*" in unused
    assert "iam:*" in unused
    assert "dynamodb:*" in unused
    assert "kms:Decrypt" in unused


def test_get_service_dependencies(registry):
    res = registry.execute("get_service_dependencies", {"service": "PaymentService"})
    assert res.success is True
    deps = res.data
    assert len(deps) >= 1
    assert deps[0]["service"] == "PaymentService"
    assert deps[0]["downstream_dependency"] == "KMS"
    assert deps[0]["required_permission"] == "kms:Decrypt"


def test_simulate_policy(registry):
    # Fails when required permission missing
    res_fail = registry.execute(
        "simulate_policy",
        {
            "role_id": "PaymentServiceRole",
            "proposed_permissions": ["s3:GetObject", "s3:PutObject", "cloudwatch:PutMetricData"],
        },
    )
    assert res_fail.success is True
    assert res_fail.data["success"] is False
    assert res_fail.data["missing_permission"] == "kms:Decrypt"

    # Passes when all required permissions included
    res_pass = registry.execute(
        "simulate_policy",
        {
            "role_id": "PaymentServiceRole",
            "proposed_permissions": [
                "s3:GetObject",
                "s3:PutObject",
                "kms:Decrypt",
                "cloudwatch:PutMetricData",
            ],
        },
    )
    assert res_pass.success is True
    assert res_pass.data["success"] is True


def test_apply_policy_change_and_rollback(registry):
    # Apply new policy version
    res_apply = registry.execute(
        "apply_policy_change",
        {
            "role_id": "PaymentServiceRole",
            "remove_permissions": ["ec2:*", "iam:*", "dynamodb:*"],
            "reason": "Test mitigation",
        },
    )
    assert res_apply.success is True
    assert res_apply.data["version_id"] == "v2"

    # Check updated active permissions
    role_res = registry.execute("get_role", {"role_id": "PaymentServiceRole"})
    assert "ec2:*" not in role_res.data["active_permissions"]
    assert "kms:Decrypt" in role_res.data["active_permissions"]

    # Rollback to v1
    res_rb = registry.execute(
        "rollback_policy",
        {"role_id": "PaymentServiceRole", "target_version": "v1"},
    )
    assert res_rb.success is True
    assert res_rb.data["version_id"] == "v1"

    role_res_v1 = registry.execute("get_role", {"role_id": "PaymentServiceRole"})
    assert "ec2:*" in role_res_v1.data["active_permissions"]
    assert role_res_v1.data["current_version"] == "v1"
