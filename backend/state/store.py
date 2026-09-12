"""State storage abstractions and implementations (InMemory, JSON, and SQLite)."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
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
    """In-memory state store implementation for testing and ephemeral sessions."""

    def __init__(self) -> None:
        self._store: Dict[str, AgentState] = {}

    def save(self, state: AgentState) -> None:
        self._store[state.run_id] = AgentState.model_validate(state.model_dump())

    def get(self, run_id: str) -> Optional[AgentState]:
        state = self._store.get(run_id)
        if state is None:
            return None
        return AgentState.model_validate(state.model_dump())

    def list_all(self) -> List[AgentState]:
        return [AgentState.model_validate(s.model_dump()) for s in self._store.values()]


class JSONFileStateStore:
    """Persistent JSON file state store writing run artifacts to disk."""

    def __init__(self, directory: str | Path = "data/runs") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _file_for(self, run_id: str) -> Path:
        return self.directory / f"{run_id}.json"

    def save(self, state: AgentState) -> None:
        path = self._file_for(state.run_id)
        with open(path, "w", encoding="utf-8") as f:
            f.write(state.model_dump_json(indent=2))

    def get(self, run_id: str) -> Optional[AgentState]:
        path = self._file_for(run_id)
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return AgentState.model_validate(data)

    def list_all(self) -> List[AgentState]:
        states: List[AgentState] = []
        for path in self.directory.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                states.append(AgentState.model_validate(data))
            except Exception:
                continue
        return states


class SQLiteStateStore:
    """Persistent SQLite store recording full runs, plans, and events."""

    def __init__(self, db_path: str = "data/iam_runs.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_runs (
                    run_id TEXT PRIMARY KEY,
                    goal TEXT,
                    role_id TEXT,
                    phase TEXT,
                    payload TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def save(self, state: AgentState) -> None:
        data_json = state.model_dump_json()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO agent_runs (run_id, goal, role_id, phase, payload, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(run_id) DO UPDATE SET
                    phase = excluded.phase,
                    payload = excluded.payload,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (state.run_id, state.goal, state.current_role or "", state.current_phase, data_json),
            )
            conn.commit()

    def get(self, run_id: str) -> Optional[AgentState]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT payload FROM agent_runs WHERE run_id = ?", (run_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return AgentState.model_validate_json(row[0])

    def list_all(self) -> List[AgentState]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT payload FROM agent_runs ORDER BY updated_at DESC")
            rows = cursor.fetchall()
            return [AgentState.model_validate_json(r[0]) for r in rows]
