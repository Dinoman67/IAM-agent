"""Offline AWS import — parse `aws iam get-account-authorization-details` dumps.

No credentials needed: the user runs one AWS CLI command, uploads the JSON,
and the product analyzes their REAL roles with the same engines as the demo.
This is the demo-to-reality bridge investors ask for.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List


def _stmt_actions(stmt: Dict[str, Any]) -> List[str]:
    if stmt.get("Effect", "Allow") != "Allow":
        return []
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    return [str(a) for a in actions]


def summarize_account_details(payload: Dict[str, Any], max_roles: int = 50) -> Dict[str, Any]:
    """Summarize IAM dump into role cards with wildcard/escalation flags."""
    roles_out: List[Dict[str, Any]] = []
    user_details = payload.get("UserDetailList", payload.get("users", []))
    role_details = payload.get("RoleDetailList", payload.get("roles", []))
    policy_docs: Dict[str, Dict[str, Any]] = {}
    for p in payload.get("Policies", []):
        policy_docs[p.get("PolicyName", "")] = p.get("PolicyVersionList", [{}])[0].get("Document", {}) if p.get("PolicyVersionList") else {}

    for r in role_details[:max_roles]:
        name = r.get("RoleName") or r.get("RoleId") or "unknown"
        actions: List[str] = []
        for pol_name in r.get("AttachedManagedPolicies", []) or []:
            pname = pol_name.get("PolicyName", "") if isinstance(pol_name, dict) else str(pol_name)
            doc = policy_docs.get(pname, {})
            for stmt in doc.get("Statement", []) if isinstance(doc, dict) else []:
                actions.extend(_stmt_actions(stmt if isinstance(stmt, dict) else {}))
        for inline in r.get("RolePolicyList", []) or []:
            doc = inline.get("PolicyDocument", {}) if isinstance(inline, dict) else {}
            stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
            for stmt in stmts:
                actions.extend(_stmt_actions(stmt if isinstance(stmt, dict) else {}))
        wildcards = sorted({a for a in actions if "*" in a})
        admin = [a for a in actions if a.startswith("iam:") or a == "*"]
        score = min(100.0, len(wildcards) * 12.0 + len(admin) * 15.0 + len(set(actions)) * 0.5)
        roles_out.append(
            {
                "role_name": name,
                "arn": r.get("Arn", ""),
                "action_count": len(set(actions)),
                "wildcards": wildcards,
                "admin_grants": admin,
                "risk_score": round(score, 2),
                "risk_level": "CRITICAL" if score >= 75 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW")),
            }
        )
    roles_out.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "roles_analyzed": len(roles_out),
        "users_seen": len(user_details),
        "roles": roles_out,
        "top_risk": roles_out[0] if roles_out else None,
        "how_obtained": "aws iam get-account-authorization-details > details.json (read-only, offline)",
    }


__all__ = ["summarize_account_details"]
