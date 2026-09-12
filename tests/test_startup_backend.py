"""Startup-grade backend: fleet queue, policy-as-code, drift, ledger, AWS import, API key."""

from starlette.testclient import TestClient

from backend.api.main import app
from backend.environment.loader import load_environment


def test_fleet_endpoint_ranks_payment_role():
    client = TestClient(app)
    r = client.get("/api/fleet/risks")
    assert r.status_code == 200
    body = r.json()
    assert body["total_roles"] >= 1
    top = body["risks"][0]
    assert top["role_id"] == "PaymentServiceRole"
    assert top["risk_level"] in ("CRITICAL", "HIGH")
    assert "ec2:*" in top["wildcards"]


def test_policy_as_code_export():
    client = TestClient(app)
    r = client.get("/api/export/policy-as-code?format=all")
    assert r.status_code == 200
    assert "NO_PRIVILEGE_EXPANSION" in r.json()["rego"]
    assert "permit(" in r.json()["cedar"]
    assert client.get("/api/export/policy-as-code?format=rego").json().get("cedar") is None
    assert client.get("/api/export/policy-as-code?format=bogus").status_code == 400


def test_drift_detection():
    client = TestClient(app)
    # No drift
    r = client.post(
        "/api/watch/check",
        json={"role_id": "PaymentServiceRole", "baseline_permissions": load_environment().get_role("PaymentServiceRole").active_permissions()},
    )
    assert r.status_code == 200
    assert r.json()["drifted"] is False
    # Escalation drift
    r = client.post(
        "/api/watch/check",
        json={"role_id": "PaymentServiceRole", "baseline_permissions": ["s3:GetObject"], "current_permissions": ["s3:GetObject", "iam:*"]},
    )
    body = r.json()
    assert body["drifted"] is True
    assert body["severity"] == "CRITICAL"
    assert "iam:*" in body["escalations"]


def test_ledger_verify_roundtrip():
    client = TestClient(app)
    run = client.post(
        "/api/agent/run",
        json={"scenario": "aws", "role_id": "PaymentServiceRole", "use_mock": True},
    ).json()
    r = client.post("/api/audit/verify", json={"run_id": run["run_id"]})
    assert r.status_code == 200
    assert r.json()["valid"] is True
    assert r.json()["entries"] > 0
    assert client.post("/api/audit/verify", json={"run_id": "NOPE"}).status_code == 404


def test_ledger_tamper_detected():
    from backend.evidence.ledger import append_entry, verify_chain

    chain = []
    append_entry(chain, "a", {"x": 1})
    append_entry(chain, "b", {"x": 2})
    assert verify_chain(chain)["valid"] is True
    chain[0].data["x"] = 999
    assert verify_chain(chain)["valid"] is False


def test_aws_import_offline():
    client = TestClient(app)
    dump = {
        "RoleDetailList": [
            {
                "RoleName": "RealRole",
                "Arn": "arn:aws:iam::1:role/RealRole",
                "AttachedManagedPolicies": [],
                "RolePolicyList": [
                    {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "iam:*"]}]}}
                ],
            }
        ]
    }
    r = client.post("/api/import/aws-details", json={"payload": dump})
    assert r.status_code == 200
    assert r.json()["roles_analyzed"] == 1
    assert r.json()["top_risk"]["role_name"] == "RealRole"
    assert client.post("/api/import/aws-details", json={"payload": {}}).status_code == 400


def test_startup_tools_registered():
    from backend.tools.iam_tools import create_extended_tool_registry

    reg = create_extended_tool_registry(load_environment())
    assert reg.execute("fleet_risks", {}).success is True
    assert (
        reg.execute(
            "check_drift",
            {"role_id": "PaymentServiceRole", "baseline_permissions": ["s3:GetObject"]},
        ).success
        is True
    )


def test_api_key_guard(monkeypatch):
    import os

    monkeypatch.setenv("API_KEY", "secret123")
    client = TestClient(app)
    assert client.post("/api/agent/run", json={"scenario": "aws"}).status_code == 401
    r = client.post("/api/agent/run", json={"scenario": "aws", "use_mock": True}, headers={"x-api-key": "secret123"})
    assert r.status_code == 200
    assert client.get("/api/fleet/risks").status_code == 200  # reads stay open


def test_attacker_duel():
    from starlette.testclient import TestClient
    from backend.api.main import app

    client = TestClient(app)
    r = client.post(
        "/api/duel",
        json={
            "role_id": "PaymentServiceRole",
            "after_permissions": ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["before"]["verdict"] == "BREACHED"
    assert len(body["before"]["reachable_protected"]) >= 1
    assert body["after"]["verdict"] == "HELD"
    assert len(body["protected_saved"]) >= 1
    assert "OLD key card" in body["headline"]
    # Identical policies → honest no-duel message
    r2 = client.post("/api/duel", json={"role_id": "PaymentServiceRole"})
    assert "run remediation first" in r2.json()["headline"]
    assert client.post("/api/duel", json={"role_id": "NOPE"}).status_code == 404


def test_duel_tool_registered():
    from backend.tools.iam_tools import create_extended_tool_registry

    reg = create_extended_tool_registry(load_environment())
    res = reg.execute("run_attacker_duel", {"role_id": "PaymentServiceRole"})
    assert res.success is True
    assert res.data["before"]["verdict"] == "BREACHED"
