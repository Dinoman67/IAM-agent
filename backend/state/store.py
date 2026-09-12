"""State storage abstraction and in-memory implementation."""

from __future__ import annotations

from typing import Dict, List, Optional, Protocol, runtime_checkable
from backend.state.models import AgentState


@runtime_checkable
class StateStore(Protocol):
    """Abstract persistence interface for agent execution states."""

    def save(self, state: AgentState) -> None:
        """Persist or update state."""
        ...

    def get(self, run_id: str) -> Optional[AgentState]:
        """Retrieve state by unique run_id."""
        ...

    def list_all(self) -> List[AgentState]:
        """List all stored agent states."""
        ...


class InMemoryStateStore:
    """In-memory state store implementation, swappable for SQLite/PostgreSQL."""

    def __init__(self) -> None:
        self._store: Dict[str, AgentState] = {}

    def save(self, state: AgentState) -> None:
        # Save a deep copy by serializing/deserializing via model_dump
        self._store[state.run_id] = AgentState.model_validate(state.model_dump())

    def get(self, run_id: str) -> Optional[AgentState]:
        state = self._store.get(run_id)
        if state is None:
            return None
        return AgentState.model_validate(state.model_dump())

    def list_all(self) -> List[AgentState]:
        return [AgentState.model_validate(s.model_dump()) for s in self._store.values()]
