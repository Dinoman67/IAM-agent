"""Tools and registry package for autonomous IAM remediation."""

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
from backend.tools.registry import ToolRegistry

__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolRegistry",
    "create_default_tool_registry",
    "GetPrincipalTool",
    "GetRoleTool",
    "GetAccessHistoryTool",
    "ListPermissionsTool",
    "FindUnusedPermissionsTool",
    "GetServiceDependenciesTool",
    "SimulatePolicyTool",
    "ApplyPolicyChangeTool",
    "VerifyRequiredAccessTool",
    "RollbackPolicyTool",
]
