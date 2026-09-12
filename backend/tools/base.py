"""Base tool contract and execution result models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type
from pydantic import BaseModel, ValidationError


class ToolResult(BaseModel):
    """Structured result returned by all tools."""

    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}


class BaseTool(ABC):
    """Abstract base class for all tools in the IAM Agent framework."""

    name: str
    description: str
    args_schema: Type[BaseModel]
    risk_classification: str = "read_only"  # "read_only", "simulation", "mutation", "critical"
    output_schema: Optional[Type[BaseModel]] = None

    def run(self, **kwargs: Any) -> ToolResult:
        """Validates arguments against args_schema and delegates to _execute."""
        try:
            validated = self.args_schema(**kwargs)
        except ValidationError as e:
            return ToolResult(
                success=False,
                data=None,
                error=f"Invalid arguments for tool '{self.name}': {e.errors()}",
                metadata={"validation_error": True},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                error=f"Argument parsing error for tool '{self.name}': {str(e)}",
            )

        try:
            return self._execute(validated)
        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                error=f"Execution error in tool '{self.name}': {str(e)}",
                metadata={"exception": type(e).__name__},
            )

    @abstractmethod
    def _execute(self, args: BaseModel) -> ToolResult:
        """Internal execution method implemented by specific tools."""
        pass
