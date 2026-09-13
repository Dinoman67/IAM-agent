"""GCP local-evaluation path: seed integrity, CMEK fail/replan loop, kernel gate, recovery."""

from starlette.testclient import TestClient

from backend.agent.controller import AgentController
from backend.api.main import app
from backend.environment.loader import load_environment
from backend.providers.capabilities import GCP_CAPABILITIES
from backend.scenarios import (
    GCP_DEMO_ROLE_ID,
    GCP_PRUNED_PERMISSIONS,
    GCPRecoveryReasoner,
)
from backend.security.analyzer import SecurityAnalyzer
from backend.security.kernel import SecurityKernel
from backend.security.regression import create_default_regression_suite
from backend.tools.iam_tools import create_extended_tool_registry


def test_gcp_seed_integrity():
    env = load_environment()
    role = env.get_role(GCP_DEMO_ROLE_ID)
    assert role is not None
    assert len(role.active_permissions()) == 6
    unused = env.find_unused_permissions(GCP_DEMO_ROLE_ID)
    assert "cloudkms.cryptoKeyDecrypter" in unused  # hidden CMEK coupling: 0 logs
    assert "compute.instances.delete" in unused
    deps = env.get_service_dependencies(service="CheckoutService")
    assert len(deps) == 1
    assert deps[0].required_permission == "cloudkms.cryptoKeyDecrypter"
    wfs = [w for w in env.data.workflows if w.role_id == GCP_DEMO_ROLE_ID]
    assert len(wfs) == 1
    assert "cloudkms.cryptoKeyDecrypter" in wfs[0].required_permissions


def test_gcp_native_simulation_still_blocked():
    """Native simulate_* stays unsupported on GCP (truthful parity preserved)."""
    env = load_environment()
    reg = create_extended_tool_registry(env)
    res = reg.execute("simulate_policy", {"role_id": GCP_DEMO_ROLE_ID, "provider": "gcp"})
    assert res.success is False
    assert "UNSUPPORTED_CAPABILITY" in (res.error or "")


def test_gcp_local_evaluation_marks_output():
    env = load_environment()
    reg = create_extended_tool_registry(env)
    naive = ["storage.objects.get", "storage.objects.create", "logging.logEntries.create"]
    res = reg.execute(
        "evaluate_local_policy",
        {"role_id": GCP_DEMO_ROLE_ID, "proposed_permissions": naive, "provider": "gcp"},
    )
    assert res.success is True
    assert res.data["success"] is False  # CMEK decrypter missing
    assert res.data["missing_permission"] == "cloudkms.cryptoKeyDecrypter"
    assert res.data.get("local_evaluation") is True

    res2 = reg.execute(
        "evaluate_local_policy",
        {"role_id": GCP_DEMO_ROLE_ID, "proposed_permissions": list(GCP_PRUNED_PERMISSIONS), "provider": "gcp"},
    )
    assert res2.data["success"] is True


def test_gcp_capability_negotiation():
    assert GCP_CAPABILITIES.supports_policy_simulation is False  # native stays honest
    assert GCP_CAPABILITIES.supports_local_evaluation is True
    assert GCP_CAPABILITIES.supports_rollback is False
    assert GCP_CAPABILITIES.check_capability("evaluate_local_policy").supported is True
    assert GCP_CAPABILITIES.check_capability("simulate_policy").supported is False


def test_gcp_kernel_allows_pruned_set():
    env = load_environment()
    sim = {"success": True, "proposed_permissions": list(GCP_PRUNED_PERMISSIONS)}
    bundles = SecurityAnalyzer(env).analyze_role(GCP_DEMO_ROLE_ID, simulation_results=[sim])
    res = SecurityKernel(env, capabilities=GCP_CAPABILITIES).evaluate_proposal(
        role_id=GCP_DEMO_ROLE_ID,
        proposed_permissions=list(GCP_PRUNED_PERMISSIONS),
        planned_policy_version="v1",
        confidence=0.98,
        simulation_result=sim,
        provider="gcp",
        evidence_bundles=bundles,
    )
    assert res.decision == "allow"
    assert res.blast_radius == "LOW"
    assert res.reason_codes == []


def test_gcp_regression_suite_scoped():
    env = load_environment()
    gcp_suite = create_default_regression_suite(env, role_id=GCP_DEMO_ROLE_ID)
    names = [t.name for t in gcp_suite.tests]
    assert "payment_encrypted_object_access" not in names  # AWS test must not fire on GCP
    assert "gcp_cmek_decryption_preserved" in names
    ok = gcp_suite.run(role_id=GCP_DEMO_ROLE_ID, permissions=list(GCP_PRUNED_PERMISSIONS), env=env)
    assert ok.passed is True
    broad = list(GCP_PRUNED_PERMISSIONS) + ["compute.instances.delete", "resourcemanager.projects.setIamPolicy"]
    bad = gcp_suite.run(role_id=GCP_DEMO_ROLE_ID, permissions=broad, env=env)
    assert bad.passed is False
    # AWS suite unchanged
    aws_suite = create_default_regression_suite(env, role_id="PaymentServiceRole")
    assert "payment_encrypted_object_access" in [t.name for t in aws_suite.tests]


def test_gcp_closed_loop_verified():
    env = load_environment()
    from backend.scenarios import GCPDeterministicReasoner

    ctl = AgentController(
        reasoner=GCPDeterministicReasoner(),
        tool_registry=create_extended_tool_registry(env),
        environment=env,
        provider="gcp",
    )
    state = ctl.run(goal="t", role_id=GCP_DEMO_ROLE_ID, provider="gcp")
    assert state.current_phase == "COMPLETED"
    assert state.stop_reason == "verified_success"
    assert len(state.replans) == 1
    assert set(env.get_role(GCP_DEMO_ROLE_ID).active_permissions()) == set(GCP_PRUNED_PERMISSIONS)


def test_gcp_recovery_rebinds_and_verifies():
    env = load_environment()
    ctl = AgentController(
        reasoner=GCPRecoveryReasoner(),
        tool_registry=create_extended_tool_registry(env),
        environment=env,
        provider="gcp",
    )
    state = ctl.run(goal="t", role_id=GCP_DEMO_ROLE_ID, provider="gcp")
    assert state.current_phase == "COMPLETED"
    assert state.stop_reason == "verified_success"
    role = env.get_role(GCP_DEMO_ROLE_ID)
    assert role.current_version == "v3"  # v1 -> flawed v2 -> re-bound v3
    assert set(role.active_permissions()) == set(GCP_PRUNED_PERMISSIONS)


def test_api_gcp_scenario_verified():
    client = TestClient(app)
    res = client.post(
        "/api/agent/run",
        json={"scenario": "gcp", "role_id": "BillingExportSA", "provider": "gcp"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["stop_reason"] == "verified_success"
    assert data["provider"] == "gcp"
    assert set(data["policy_diff"]["kept"]) == set(GCP_PRUNED_PERMISSIONS)


def test_api_gcp_lists_new_role():
    client = TestClient(app)
    data = client.get("/api/principals").json()
    assert GCP_DEMO_ROLE_ID in [r["id"] for r in data["roles"]]
