"""Tool registry managing tool lifecycle, discovery, and dispatch."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from backend.tools.base import BaseTool, ToolResult


class ToolRegistry:
    """Central registry of executable tools accessible to the agent controller."""

    def __init__(self) -> None:
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Registers a tool instance by its unique name."""
        if tool.name in self._tools:
            raise ValueError(f"Tool with name '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        """Returns the registered tool or None if not found."""
        return self._tools.get(name)

    def execute(self, name: str, args: Dict[str, Any]) -> ToolResult:
        """Safely executes a registered tool with provided arguments."""
        tool = self.get(name)
        if not tool:
            return ToolResult(
                success=False,
                error=f"Tool '{name}' is not registered in ToolRegistry.",
                metadata={"registered_tools": list(self._tools.keys())},
            )
        return tool.run(**args)

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered tools."""
        descriptors = []
        for name, tool in self._tools.items():
            schema_json = tool.args_schema.model_json_schema()
            descriptors.append(
                {
                    "name": name,
                    "description": tool.description,
                    "parameters": schema_json,
                    "risk_classification": getattr(tool, "risk_classification", "read_only"),
                }
            )
        return descriptors
