"""Hero features: AWS read-only, Terraform PR, attack graph, temporal mining."""

from starlette.testclient import TestClient

from backend.api.main import app
from backend.connectors.aws_readonly import AWSReadOnlyConnector
from backend.environment.loader import load_environment
from backend.export.terraform import build_pr_body, to_terraform_hcl, to_terraform_json
from backend.security.attack_graph import compute_attack_graph, paths_blocked
from backend.security.temporal import classify_permissions


def test_connector_offline_safe():
    status = AWSReadOnlyConnector().status()
    assert status["connector"] == "aws-read-only"
    assert "live" in status
    # Must never raise without creds
    probe = AWSReadOnlyConnector().inspect_role_live("PaymentServiceRole")
    assert "live" in probe


def test_cloudtrail_import(tmp_path):
    import json

    f = tmp_path / "trail.json"
    f.write_text(json.dumps({"Records": [{"eventName": "GetObject", "eventSource": "s3.amazonaws.com"}]}))
    out = AWSReadOnlyConnector.import_cloudtrail(f, role_id="PaymentServiceRole")
    assert out["count"] == 1
    assert out["logs"][0]["role_id"] == "PaymentServiceRole"


def test_terraform_export_shapes():
    hcl = to_terraform_hcl("PaymentServiceRole", ["s3:GetObject", "kms:Decrypt"])
    assert 'resource "aws_iam_role_policy"' in hcl
    assert "s3:GetObject" in hcl
    js = to_terraform_json("PaymentServiceRole", ["s3:GetObject"])
    assert "aws_iam_role_policy" in js["resource"]
    pr = build_pr_body("PaymentServiceRole", ["ec2:*"], ["s3:GetObject"])
    assert "Deterministic gates" in pr


def test_attack_graph_payment_role():
    env = load_environment()
    g = compute_attack_graph("PaymentServiceRole", env)
    assert g.role_id == "PaymentServiceRole"
    assert len(g.paths) > 0
    # Wildcards reach protected resources in demo data
    assert len(g.protected_reachable) >= 1
    assert g.risk_score > 0
    blocked = paths_blocked(g, ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"], env)
    assert blocked >= 1


def test_temporal_kms_is_rare_but_critical():
    env = load_environment()
    report = classify_permissions("PaymentServiceRole", env, window_days=365)
    by_perm = {f.permission: f for f in report.findings}
    # kms:Decrypt has 0 direct logs but is dependency-linked -> must RETAIN
    assert by_perm["kms:Decrypt"].classification == "RARE_BUT_CRITICAL"
    assert by_perm["kms:Decrypt"].recommendation == "RETAIN"
    assert "kms:Decrypt" in report.retain


def test_api_hero_endpoints():
    client = TestClient(app)
    assert client.get("/api/aws/live-status").status_code == 200
    r = client.get("/api/roles/PaymentServiceRole/attack-graph")
    assert r.status_code == 200
    assert r.json()["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    r = client.get("/api/roles/PaymentServiceRole/temporal")
    assert r.status_code == 200
    assert any(f["permission"] == "kms:Decrypt" for f in r.json()["findings"])
    r = client.post("/api/export/terraform", json={"role_id": "PaymentServiceRole"})
    assert r.status_code == 200
    body = r.json()
    assert "aws_iam_role_policy" in body["hcl"]
    assert "Deterministic gates" in body["pr_body"]
    assert client.get("/api/roles/NOPE/attack-graph").status_code == 404


def test_hero_tools_registered():
    from backend.tools.iam_tools import create_extended_tool_registry

    env = load_environment()
    reg = create_extended_tool_registry(env)
    names = {t["name"] for t in reg.list_tools()} if hasattr(reg, "list_tools") else set()
    # Fallback: execute directly
    assert reg.execute("get_attack_graph", {"role_id": "PaymentServiceRole"}).success is True
    assert reg.execute("analyze_temporal_usage", {"role_id": "PaymentServiceRole"}).success is True
    assert reg.execute("aws_live_status", {}).success is True
    assert reg.execute("export_terraform", {"role_id": "PaymentServiceRole"}).success is True
