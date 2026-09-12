"""Phase 3 Tests: Common IAM Intermediate Representation and Multi-Cloud Translators."""

import pytest

from backend.models.iam import (
    Action,
    Binding,
    CommonAction,
    CommonBinding,
    CommonCondition,
    CommonPolicy,
    CommonPrincipal,
    CommonResource,
    CommonStatement,
    Condition,
    Effect,
    Policy,
    PolicyEffect,
    Principal,
    Provider,
    Resource,
    Scope,
    Statement,
)
from backend.providers.common.errors import ProviderMismatchError
from backend.providers.translation import (
    aws_policy_to_ir,
    azure_assignment_to_ir,
    azure_role_def_to_ir,
    gcp_binding_to_ir,
    gcp_policy_to_ir,
    gcp_role_to_ir,
    ir_to_aws_policy,
    ir_to_azure_assignment,
    ir_to_azure_role_def,
    ir_to_gcp_binding,
    ir_to_gcp_policy,
    ir_to_gcp_role,
)


def test_common_iam_ir_canonical_aliases_and_models():
    """Verify all 10 canonical IAM concepts are instantiable and maintain provider fidelity."""
    principal = Principal(id="usr-1", name="Alice", type="user", provider="aws", provider_metadata={"dept": "sec"})
    action = Action.from_string("s3:GetObject", provider="aws")
    resource = Resource(arn_or_id="arn:aws:s3:::vault/*", is_protected=True, provider_metadata={"kms": "enabled"})
    condition = Condition(operator="StringEquals", key="aws:PrincipalArn", values=["arn:aws:iam::123:user/Alice"])
    scope = Scope(type="subscription", id="/subscriptions/sub-1")

    statement = Statement(
        sid="AllowVaultRead",
        effect=Effect.ALLOW,
        actions=[action],
        resources=[resource],
        conditions=[condition],
        principals=[principal],
        provider_metadata={"original_sid": "AllowVaultRead"},
    )
    binding = Binding(
        principal_id="serviceAccount:sa@proj.iam.gserviceaccount.com",
        role_or_policy_id="roles/storage.admin",
        scope="projects/proj-1",
        provider="gcp",
    )
    policy = Policy(
        id="policy-vault",
        name="VaultPolicy",
        provider=Provider.AWS.value,
        version="2012-10-17",
        statements=[statement],
        bindings=[binding],
        provider_metadata={"aws_version": "2012-10-17"},
    )

    assert policy.provider == "aws"
    assert len(policy.statements) == 1
    assert len(policy.bindings) == 1
    assert policy.extract_permission_strings() == ["s3:GetObject"]
    assert principal.provider_metadata["dept"] == "sec"


def test_aws_policy_translation_and_round_trip():
    """Verify AWS JSON -> IR -> AWS JSON round-trip preserves syntax, conditions, and statements."""
    aws_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SecureS3Access",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "kms:Decrypt"],
                "Resource": ["arn:aws:s3:::payment-bucket/*"],
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": ["arn:aws:iam::123456789012:role/PaymentRole"]
                    }
                },
            },
            {
                "Sid": "DenyWildcardEC2",
                "Effect": "Deny",
                "Action": "ec2:*",
                "Resource": "*",
            },
        ],
    }

    # 1. AWS JSON -> IR
    ir_policy = aws_policy_to_ir(aws_json, policy_id="policy-payment", name="PaymentPolicy")
    assert ir_policy.provider == "aws"
    assert ir_policy.version == "2012-10-17"
    assert len(ir_policy.statements) == 2

    stmt1 = ir_policy.statements[0]
    assert stmt1.sid == "SecureS3Access"
    assert stmt1.effect == PolicyEffect.ALLOW
    assert len(stmt1.actions) == 2
    assert [a.raw_action for a in stmt1.actions] == ["s3:GetObject", "kms:Decrypt"]
    assert len(stmt1.conditions) == 1
    assert stmt1.conditions[0].operator == "StringEquals"
    assert stmt1.conditions[0].key == "aws:PrincipalArn"

    stmt2 = ir_policy.statements[1]
    assert stmt2.sid == "DenyWildcardEC2"
    assert stmt2.effect == PolicyEffect.DENY
    assert stmt2.actions[0].raw_action == "ec2:*"
    assert stmt2.actions[0].is_wildcard is True

    # 2. IR -> AWS JSON
    exported_json = ir_to_aws_policy(ir_policy)
    assert exported_json["Version"] == "2012-10-17"
    assert len(exported_json["Statement"]) == 2

    exp_stmt1 = exported_json["Statement"][0]
    assert exp_stmt1["Effect"] == "Allow"
    assert exp_stmt1["Action"] == ["s3:GetObject", "kms:Decrypt"]
    assert exp_stmt1["Resource"] == "arn:aws:s3:::payment-bucket/*"
    assert exp_stmt1["Condition"]["StringEquals"]["aws:PrincipalArn"] == "arn:aws:iam::123456789012:role/PaymentRole"

    exp_stmt2 = exported_json["Statement"][1]
    assert exp_stmt2["Effect"] == "Deny"
    assert exp_stmt2["Action"] == "ec2:*"


def test_aws_wildcard_matching_semantics():
    """Verify non-naive wildcard matching for AWS actions (*, service:*, service:Action)."""
    wildcard_star = CommonAction.from_string("*")
    wildcard_s3 = CommonAction.from_string("s3:*")
    wildcard_ec2_desc = CommonAction.from_string("ec2:Describe*")
    exact_get = CommonAction.from_string("s3:GetObject")

    # Positive matches
    assert wildcard_star.matches("s3:GetObject") is True
    assert wildcard_star.matches("iam:CreateUser") is True
    assert wildcard_s3.matches("s3:GetObject") is True
    assert wildcard_s3.matches("s3:PutObject") is True
    assert wildcard_ec2_desc.matches("ec2:DescribeInstances") is True
    assert wildcard_ec2_desc.matches("ec2:DescribeVolumes") is True
    assert exact_get.matches("s3:GetObject") is True

    # Negative matches
    assert wildcard_s3.matches("ec2:DescribeInstances") is False
    assert wildcard_ec2_desc.matches("ec2:RunInstances") is False
    assert exact_get.matches("s3:PutObject") is False


def test_gcp_role_and_binding_translation_and_round_trip():
    """Verify GCP role and binding translation to/from Common IR."""
    gcp_role_data = {
        "name": "roles/storage.objectViewer",
        "title": "Storage Object Viewer",
        "description": "Read storage objects and metadata",
        "includedPermissions": ["storage.objects.get", "storage.objects.list"],
        "stage": "GA",
        "etag": "BwWA8z8QyTE=",
    }

    # GCP Role -> IR
    ir_role = gcp_role_to_ir(gcp_role_data)
    assert ir_role.provider == "gcp"
    assert ir_role.id == "roles/storage.objectViewer"
    assert ir_role.version == "BwWA8z8QyTE="
    assert ir_role.extract_permission_strings() == ["storage.objects.get", "storage.objects.list"]

    # IR -> GCP Role
    exported_role = ir_to_gcp_role(ir_role)
    assert exported_role["name"] == "roles/storage.objectViewer"
    assert exported_role["includedPermissions"] == ["storage.objects.get", "storage.objects.list"]
    assert exported_role["etag"] == "BwWA8z8QyTE="

    # GCP Bindings -> IR
    binding_dict = {
        "role": "roles/storage.objectViewer",
        "members": ["user:alice@example.com", "serviceAccount:sa@proj.iam.gserviceaccount.com"],
        "condition": {
            "title": "work_hours",
            "expression": "request.time.getHours() >= 9",
        },
    }
    ir_bindings = gcp_binding_to_ir(binding_dict, scope="projects/my-proj")
    assert len(ir_bindings) == 2
    assert ir_bindings[0].principal_id == "user:alice@example.com"
    assert ir_bindings[0].role_or_policy_id == "roles/storage.objectViewer"
    assert ir_bindings[0].scope == "projects/my-proj"
    assert ir_bindings[0].condition is not None
    assert ir_bindings[0].condition.values[0] == "request.time.getHours() >= 9"

    # IR -> GCP Bindings
    exported_bindings = ir_to_gcp_binding(ir_bindings)
    assert len(exported_bindings) == 1
    assert exported_bindings[0]["role"] == "roles/storage.objectViewer"
    assert "user:alice@example.com" in exported_bindings[0]["members"]
    assert "serviceAccount:sa@proj.iam.gserviceaccount.com" in exported_bindings[0]["members"]


def test_azure_role_def_and_assignment_translation_and_round_trip():
    """Verify Azure RBAC role definition and role assignment translation to/from Common IR."""
    azure_role_def = {
        "id": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/def-reader",
        "name": "def-reader",
        "properties": {
            "roleName": "Storage Reader",
            "description": "Allows read access to storage containers",
            "type": "CustomRole",
            "permissions": [
                {
                    "actions": [
                        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    ],
                    "notActions": [
                        "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
                    ],
                }
            ],
            "assignableScopes": ["/subscriptions/sub-123"],
        },
    }

    # Azure Role Def -> IR
    ir_role = azure_role_def_to_ir(azure_role_def)
    assert ir_role.provider == "azure"
    assert ir_role.name == "Storage Reader"
    assert len(ir_role.statements) == 2
    assert ir_role.statements[0].effect == PolicyEffect.ALLOW
    assert ir_role.statements[1].effect == PolicyEffect.DENY

    # IR -> Azure Role Def
    exported_def = ir_to_azure_role_def(ir_role)
    props = exported_def["properties"]
    assert props["roleName"] == "Storage Reader"
    assert len(props["permissions"][0]["actions"]) == 2
    assert props["permissions"][0]["notActions"] == ["Microsoft.Storage/storageAccounts/blobServices/containers/delete"]

    # Azure Assignment -> IR
    azure_assign = {
        "id": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/assign-1",
        "properties": {
            "roleDefinitionId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/def-reader",
            "principalId": "sp-agent-guid",
            "scope": "/subscriptions/sub-123/resourceGroups/rg-prod",
            "condition": "ActionMatches('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read')",
        },
    }
    ir_assign = azure_assignment_to_ir(azure_assign)
    assert ir_assign.provider == "azure"
    assert ir_assign.principal_id == "sp-agent-guid"
    assert ir_assign.scope == "/subscriptions/sub-123/resourceGroups/rg-prod"
    assert ir_assign.condition.values[0] == "ActionMatches('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read')"

    # IR -> Azure Assignment
    exported_assign = ir_to_azure_assignment(ir_assign)
    assert exported_assign["properties"]["principalId"] == "sp-agent-guid"
    assert exported_assign["properties"]["roleDefinitionId"] == "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/def-reader"


def test_translation_provider_mismatch_protection():
    """Verify translators reject artifacts belonging to mismatched providers without silent coercion."""
    gcp_dict = {"includedPermissions": ["storage.objects.get"], "bindings": []}
    azure_dict = {"properties": {"roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-1"}}
    aws_dict = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}

    # Passing GCP artifact to AWS translator
    with pytest.raises(ProviderMismatchError) as exc_gcp_to_aws:
        aws_policy_to_ir(gcp_dict)
    assert exc_gcp_to_aws.value.source_provider == "gcp"
    assert exc_gcp_to_aws.value.target_provider == "aws"

    # Passing Azure artifact to AWS translator
    with pytest.raises(ProviderMismatchError) as exc_az_to_aws:
        aws_policy_to_ir(azure_dict)
    assert exc_az_to_aws.value.source_provider == "azure"
    assert exc_az_to_aws.value.target_provider == "aws"

    # Passing AWS artifact to GCP translator
    with pytest.raises(ProviderMismatchError) as exc_aws_to_gcp:
        gcp_role_to_ir(aws_dict)
    assert exc_aws_to_gcp.value.source_provider == "aws"
    assert exc_aws_to_gcp.value.target_provider == "gcp"

    # Passing AWS artifact to Azure translator
    with pytest.raises(ProviderMismatchError) as exc_aws_to_az:
        azure_role_def_to_ir(aws_dict)
    assert exc_aws_to_az.value.source_provider == "aws"
    assert exc_aws_to_az.value.target_provider == "azure"
