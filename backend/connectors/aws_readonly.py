"""AWS read-only live connector — bridges simulation to reality without risk."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _try_boto3():
    try:
        import boto3  # type: ignore

        return boto3
    except Exception:
        return None


class AWSReadOnlyConnector:
    """Read-only AWS bridge. Never mutates. Falls back to local simulator.

    - If boto3 + credentials present: uses IAM Policy Simulator + live reads.
    - Else: returns {"live": False} and callers use deterministic simulator.
    """

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = os.getenv("AWS_REGION", region)
        self._boto3 = _try_boto3()

    def is_available(self) -> Dict[str, Any]:
        if self._boto3 is None:
            return {"live": False, "reason": "boto3 not installed (pip install boto3)"}
        if not (os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE") or os.getenv("AWS_ROLE_ARN")):
            return {"live": False, "reason": "no AWS credentials in environment"}
        return {"live": True, "region": self.region}

    def status(self) -> Dict[str, Any]:
        base = self.is_available()
        base.update(
            {
                "connector": "aws-read-only",
                "region": self.region,
                "mutation": "disabled (read-only; use Terraform PR mode to apply)",
                "capabilities": ["inspect-role", "simulate-principal-policy", "import-cloudtrail"],
            }
        )
        return base

    def inspect_role_live(self, role_name: str) -> Dict[str, Any]:
        """Best-effort live IAM GetRole. Returns live=False envelope when offline."""
        avail = self.is_available()
        if not avail["live"]:
            return {"live": False, "reason": avail["reason"], "role_name": role_name}
        try:
            iam = self._boto3.client("iam", region_name=self.region)
            role = iam.get_role(RoleName=role_name)["Role"]
            attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
            inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            return {
                "live": True,
                "role_name": role_name,
                "arn": role.get("Arn"),
                "attached_policies": [p["PolicyName"] for p in attached],
                "inline_policies": inline,
            }
        except Exception as ex:  # never crash the agent loop
            return {"live": False, "reason": f"live lookup failed: {ex}", "role_name": role_name}

    def simulate_live(
        self, role_arn: str, actions: List[str], resource: str = "*"
    ) -> Dict[str, Any]:
        """Try AWS IAM SimulatePrincipalPolicy; fall back envelope when offline."""
        avail = self.is_available()
        if not avail["live"]:
            return {"live": False, "reason": avail["reason"], "fallback": "local-simulator"}
        try:
            iam = self._boto3.client("iam", region_name=self.region)
            resp = iam.simulate_principal_policy(
                PolicySourceArn=role_arn, ActionNames=actions, ResourceArns=[resource]
            )
            evals = [
                {"action": e.get("EvalActionName"), "decision": e.get("EvalDecision")}
                for e in resp.get("EvaluationResults", [])
            ]
            return {"live": True, "evaluations": evals}
        except Exception as ex:
            return {"live": False, "reason": f"live simulation failed: {ex}", "fallback": "local-simulator"}

    @staticmethod
    def import_cloudtrail(path: str | Path, role_id: Optional[str] = None) -> Dict[str, Any]:
        """Import CloudTrail JSON-lines export into access-log-shaped records.

        Accepts either {Records:[...]} or one JSON object per line.
        Returns {"logs": [...], "count": N} with fields matching data/environment.json logs.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"CloudTrail file not found: {path}")
        raw_text = p.read_text(encoding="utf-8").strip()
        records: List[Dict[str, Any]] = []
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict) and "Records" in parsed:
                records = parsed["Records"]
            elif isinstance(parsed, list):
                records = parsed
            else:
                records = [parsed]
        except json.JSONDecodeError:
            for line in raw_text.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        logs: List[Dict[str, Any]] = []
        for i, r in enumerate(records):
            action = r.get("eventName") or r.get("action") or "unknown"
            # Normalize S3-style "GetObject" -> "s3:GetObject" when service known
            svc = (r.get("eventSource") or "").split(".")[0] or "aws"
            if ":" not in action and svc not in ("unknown", ""):
                action = f"{svc}:{action}"
            logs.append(
                {
                    "id": r.get("id") or f"imported-{i:04d}",
                    "principal_id": r.get("userIdentity", {}).get("arn", "imported") if isinstance(r.get("userIdentity"), dict) else r.get("principal_id", "imported"),
                    "role_id": role_id or r.get("role_id") or "PaymentServiceRole",
                    "action": action,
                    "resource": r.get("resources", [{}])[0].get("ARN", "*") if isinstance(r.get("resources"), list) and r.get("resources") else r.get("resource", "*"),
                    "timestamp": r.get("eventTime") or datetime.now(timezone.utc).isoformat(),
                    "success": r.get("errorCode", "") in ("", None),
                }
            )
        return {"logs": logs, "count": len(logs)}


__all__ = ["AWSReadOnlyConnector"]
