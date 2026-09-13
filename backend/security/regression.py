"""Policy regression testing framework covering positive workflows and negative security tests."""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Literal, Optional, Sequence
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator


class PolicyRegressionTest(BaseModel):
    """Declarative specification of an operational or security regression test."""

    name: str = Field(..., description="Unique test name")
    description: str = Field(default="", description="Purpose of this regression check")
    test_type: Literal["positive", "negative"] = Field(
        default="positive",
        description="'positive' for legitimate workflow preservation, 'negative' for asserting forbidden access is blocked",
    )
    required_actions: List[str] = Field(
        default_factory=list, description="Action(s) evaluated in this test"
    )
    resource_arn: Optional[str] = Field(default=None, description="Optional target resource ARN")
    expected_allowed: bool = Field(
        default=True, description="True if actions must be allowed; False if actions must be denied"
    )
    role_id: Optional[str] = Field(default=None, description="Target role if scoped to specific identity")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")


class RegressionTestOutcome(BaseModel):
    """Execution result of a single regression test."""

    test_name: str
    test_type: Literal["positive", "negative"]
    passed: bool
    expected_allowed: bool
    actual_allowed: bool
    tested_actions: List[str]
    details: str


class RegressionTestSuiteResult(BaseModel):
    """Aggregate result of running a policy regression test suite."""

    passed: bool
    positive_passed: bool
    negative_passed: bool
    total_tests: int
    passed_count: int
    failed_count: int
    failed_tests: List[str] = Field(default_factory=list)
    outcomes: List[RegressionTestOutcome] = Field(default_factory=list)
    details: List[str] = Field(default_factory=list)


class RegressionTestSuite:
    """Deterministic regression test runner verifying policy safety and operational integrity."""

    def __init__(self, tests: Optional[List[PolicyRegressionTest]] = None) -> None:
        self.tests: List[PolicyRegressionTest] = list(tests or [])

    def add_test(self, test: PolicyRegressionTest) -> None:
        self.tests.append(test)

    def run(
        self,
        role_id: str,
        permissions: Sequence[str],
        env: Optional[IAMEnvironment] = None,
    ) -> RegressionTestSuiteResult:
        """Executes all positive and negative regression tests against a proposed or active permission set."""
        perms_list = list(permissions)
        outcomes: List[RegressionTestOutcome] = []
        failed_tests: List[str] = []
        details: List[str] = []

        pos_count = 0
        pos_passed = 0
        neg_count = 0
        neg_passed = 0

        for test in self.tests:
            # Skip if test is scoped to a different role
            if test.role_id and test.role_id != role_id:
                continue

            # Determine whether all required actions are allowed under permissions
            all_allowed = all(
                PolicySimulator.is_action_allowed(act, perms_list) for act in test.required_actions
            )

            test_passed = (all_allowed == test.expected_allowed)

            if test.test_type == "positive":
                pos_count += 1
                if test_passed:
                    pos_passed += 1
                    msg = f"Positive test '{test.name}': PASS (required workflow actions {test.required_actions} allowed)"
                else:
                    msg = f"Positive test '{test.name}': FAIL (workflow actions {test.required_actions} denied!)"
            else:
                neg_count += 1
                if test_passed:
                    neg_passed += 1
                    msg = f"Negative test '{test.name}': PASS (forbidden actions {test.required_actions} properly denied)"
                else:
                    msg = f"Negative test '{test.name}': FAIL (security invariant violated: forbidden actions {test.required_actions} allowed!)"

            outcome = RegressionTestOutcome(
                test_name=test.name,
                test_type=test.test_type,
                passed=test_passed,
                expected_allowed=test.expected_allowed,
                actual_allowed=all_allowed,
                tested_actions=test.required_actions,
                details=msg,
            )
            outcomes.append(outcome)
            details.append(msg)

            if not test_passed:
                failed_tests.append(test.name)

        all_positive_passed = (pos_passed == pos_count)
        all_negative_passed = (neg_passed == neg_count)
        overall_passed = len(failed_tests) == 0

        return RegressionTestSuiteResult(
            passed=overall_passed,
            positive_passed=all_positive_passed,
            negative_passed=all_negative_passed,
            total_tests=len(outcomes),
            passed_count=len(outcomes) - len(failed_tests),
            failed_count=len(failed_tests),
            failed_tests=failed_tests,
            outcomes=outcomes,
            details=details,
        )


def create_default_regression_suite(
    env: IAMEnvironment, role_id: Optional[str] = "PaymentServiceRole"
) -> RegressionTestSuite:
    """Builds a standardized suite of positive workflow tests and negative security regression tests."""
    suite = RegressionTestSuite()

    # 1. Positive Tests (Workflows from environment data)
    for wf in env.data.workflows:
        if role_id is None or wf.role_id == role_id:
            suite.add_test(
                PolicyRegressionTest(
                    name=f"workflow_{wf.id}",
                    description=wf.description or f"Operational workflow for {wf.role_id}",
                    test_type="positive",
                    required_actions=wf.required_permissions,
                    expected_allowed=True,
                    role_id=wf.role_id,
                    tags=["workflow", "operational"],
                )
            )

    # Positive test: S3 KMS encrypted object processing (AWS demo role only —
    # GCP roles use their own CMEK positive test below)
    if role_id in (None, "PaymentServiceRole"):
        suite.add_test(
            PolicyRegressionTest(
                name="payment_encrypted_object_access",
                description="Preserve transitive KMS SSE decryption when accessing transaction S3 bucket",
                test_type="positive",
                required_actions=["s3:GetObject", "kms:Decrypt"],
                expected_allowed=True,
                role_id=role_id,
                tags=["operational", "encryption", "dependency"],
            )
        )

    # 2. Negative Security Tests (Asserting forbidden behaviors remain blocked)
    # AWS-specific negatives only apply to the AWS demo role; GCP roles get
    # their own negatives below (generic workflow positives above already cover all roles).
    if role_id in (None, "PaymentServiceRole"):
        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_iam_administration",
                description="Ensure candidate cannot grant or retain administrative IAM permissions",
                test_type="negative",
                required_actions=["iam:CreateUser", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "privilege_escalation"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_global_wildcard",
                description="Ensure wildcard '*' is forbidden",
                test_type="negative",
                required_actions=["*"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "wildcard"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_sensitive_dynamodb_pii",
                description="Ensure access to sensitive customer PII database remains blocked",
                test_type="negative",
                required_actions=["dynamodb:*", "dynamodb:GetItem"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "protected_resource"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_sensitive_ec2_prod",
                description="Ensure access to sensitive production compute infrastructure remains blocked",
                test_type="negative",
                required_actions=["ec2:*", "ec2:TerminateInstances"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "protected_resource"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_kms_key_deletion",
                description="Ensure dangerous cryptographic key destruction permissions are blocked",
                test_type="negative",
                required_actions=["kms:ScheduleKeyDeletion", "kms:DeleteKey"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "cryptographic_safety"],
            )
        )

    # 3. GCP-specific tests (CMEK positive + dangerous-permission negatives)
    if role_id in (None, "BillingExportSA"):
        suite.add_test(
            PolicyRegressionTest(
                name="gcp_cmek_decryption_preserved",
                description="Preserve transitive Cloud KMS CMEK decryption when accessing export bucket",
                test_type="positive",
                required_actions=["storage.objects.get", "cloudkms.cryptoKeyDecrypter"],
                expected_allowed=True,
                role_id=role_id,
                tags=["operational", "encryption", "dependency"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_gcp_project_iam_admin",
                description="Ensure project-level IAM grant capability remains blocked",
                test_type="negative",
                required_actions=["resourcemanager.projects.setIamPolicy"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "privilege_escalation"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_gcp_compute_delete",
                description="Ensure production compute deletion remains blocked",
                test_type="negative",
                required_actions=["compute.instances.delete"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "protected_resource"],
            )
        )

        suite.add_test(
            PolicyRegressionTest(
                name="negative_deny_gcp_kms_destroy",
                description="Ensure cryptographic key destruction remains blocked",
                test_type="negative",
                required_actions=["cloudkms.cryptoKeyDestroy", "cloudkms.cryptoKeyVersions.destroy"],
                expected_allowed=False,
                role_id=role_id,
                tags=["security", "negative", "cryptographic_safety"],
            )
        )

    return suite


__all__ = [
    "PolicyRegressionTest",
    "RegressionTestOutcome",
    "RegressionTestSuiteResult",
    "RegressionTestSuite",
    "create_default_regression_suite",
]
