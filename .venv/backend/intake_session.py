"""intake_session.py — Thin session manager wrapping IntakeSpecAgent + LangGraph.

Three public operations:
  - await start_or_resume(run_id, user_goal, uploads, user_id)  → IntakeTurnResponse
  - await send_turn(run_id, user_message, user_id)              → IntakeTurnResponse
  - get_state(run_id)                                           → IntakeTurnResponse

Uses LangGraph MemorySaver (in-process) for the graph checkpointing and an
auxiliary JSON file per session for cross-restart persistence. The JSON only
stores the LangGraph state dict — not any secret or key material.

Security: does NOT weaken any provenance, approval, or evaluation gate inside
IntakeSpecAgent. The session manager is a pure orchestration layer.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path bootstrap (identical pattern to intake.py)
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from pydantic import BaseModel, ConfigDict, Field
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from agents.intake import (
    IntakeConfig,
    IntakeSpecAgent,
    LangChainMetaGateway,
    UsageLedger,
)
from storage import StorageConfig, StorageService


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------
class IntakeTurnResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    status: str
    assistant_message: str
    pending_questions: list[dict[str, Any]] = Field(default_factory=list)
    unresolved_blocking_ids: list[str] = Field(default_factory=list)
    spec_draft: dict[str, Any] | None = None
    spec: dict[str, Any] | None = None
    handoff: dict[str, Any] | None = None
    validation_errors: list[str] = Field(default_factory=list)
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Per-thread graph registry (one graph + saver per run_id)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_graphs: dict[str, Any] = {}       # run_id → compiled LangGraph
_savers: dict[str, MemorySaver] = {}  # run_id → its MemorySaver


def _build_graph(
    run_id: str,
    storage: StorageService,
    cfg: IntakeConfig,
) -> tuple[Any, MemorySaver]:
    ledger = UsageLedger(storage)
    ledger.init_tables_sync()
    # LangChainMetaGateway reads api_key/base_url from env via IntakeConfig.api_key_env / base_url
    gw = LangChainMetaGateway(config=cfg, ledger=ledger)
    agent = IntakeSpecAgent(config=cfg, storage=storage, gateway=gw, ledger=ledger)
    saver = MemorySaver()
    graph = agent.build_graph(checkpointer=saver)
    return graph, saver


# ---------------------------------------------------------------------------
# Session snapshot helpers (JSON persistence across restarts)
# ---------------------------------------------------------------------------
def _snapshot_path(sessions_dir: Path, run_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)
    return sessions_dir / f"{safe}.json"


def _save_snapshot(sessions_dir: Path, run_id: str, state: dict[str, Any]) -> None:
    try:
        path = _snapshot_path(sessions_dir, run_id)
        path.write_text(json.dumps(state, default=str), encoding="utf-8")
    except Exception:
        pass  # snapshot is best-effort; MemorySaver is the authoritative source


def _load_snapshot(sessions_dir: Path, run_id: str) -> dict[str, Any] | None:
    path = _snapshot_path(sessions_dir, run_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Response builder
# ---------------------------------------------------------------------------
def _build_response(run_id: str, state: dict[str, Any]) -> IntakeTurnResponse:
    st = state.get("status", "interviewing")
    pending_qs: list[dict[str, Any]] = state.get("pending_questions", []) or []

    terminal_bad = {
        "blocked_with_errors", "failed_model_unavailable",
        "blocked_insufficient_info", "cancelled", "rejected",
    }

    if st in terminal_bad:
        msg = state.get("error_message") or f"Session ended with status: {st}"
        if st == "failed_model_unavailable" and "MODEL_API_KEY" in msg:
            msg = (
                "The AI intake assistant needs a configured model key (MODEL_API_KEY) "
                "and is unavailable in offline demo mode. Your uploaded documents were "
                "received and verified. Please continue with the guided discovery "
                "questions on this page, then click "
                "\u201cPrepare & Submit Specification Blueprint\u201d to build and approve "
                "your specification manually \u2014 the factory pipeline works fully offline."
            )
    elif st == "handed_off":
        msg = "✅ Specification approved and handed off to the factory pipeline."
    elif st == "approved":
        msg = "✅ Specification approved. Preparing handoff package…"
    elif state.get("spec") and not pending_qs:
        msg = (
            "✅ I've completed your specification draft. "
            "Review it below and click **Approve Specification** to continue."
        )
    elif pending_qs:
        lines = []
        for i, q in enumerate(pending_qs):
            lines.append(f"**{i+1}.** {q.get('question', '')}")
            if q.get("suggested_default"):
                lines.append(f"   _(suggestion: {q['suggested_default']})_")
        msg = "\n".join(lines)
    elif state.get("validation_errors"):
        errs = "; ".join(state["validation_errors"][:5])
        msg = f"⚠️ Validation issues found: {errs}"
    else:
        msg = "Processing your information — please continue…"

    return IntakeTurnResponse(
        run_id=run_id,
        status=st,
        assistant_message=msg,
        pending_questions=pending_qs,
        unresolved_blocking_ids=state.get("unresolved_blocking_ids", []) or [],
        spec_draft=state.get("spec_draft"),
        spec=state.get("spec"),
        handoff=state.get("handoff"),
        validation_errors=state.get("validation_errors", []) or [],
        error_message=state.get("error_message"),
    )


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------
class IntakeSessionManager:
    """One instance shared across all requests (created during app lifespan)."""

    def __init__(self, data_root: Path) -> None:
        self._sessions_dir = data_root / "factory_storage" / "intake_sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

        self._storage = StorageService(StorageConfig(data_root / "factory_storage"))
        self._storage.initialize()

        self._cfg = IntakeConfig()
        # api_key and base_url are read by LangChainMetaGateway from env via IntakeConfig

    # ------------------------------------------------------------------
    def _get_or_create_graph(self, run_id: str) -> tuple[Any, MemorySaver]:
        with _lock:
            if run_id not in _graphs:
                g, s = _build_graph(run_id, self._storage, self._cfg)
                _graphs[run_id] = g
                _savers[run_id] = s
            return _graphs[run_id], _savers[run_id]

    @staticmethod
    def _thread_cfg(run_id: str, user_id: str = "user") -> dict[str, Any]:
        return {"configurable": {"thread_id": run_id, "authenticated_user_id": user_id}}

    # ------------------------------------------------------------------
    async def start_or_resume(
        self,
        run_id: str,
        user_goal: str,
        uploads: list[dict[str, Any]],
        user_id: str = "user",
    ) -> IntakeTurnResponse:
        graph, _ = self._get_or_create_graph(run_id)
        cfg = self._thread_cfg(run_id, user_id)

        # Check if graph already has state for this thread
        snapshot = graph.get_state(cfg)
        if snapshot and snapshot.values.get("status") not in (None, ""):
            return _build_response(run_id, dict(snapshot.values))

        # Try restoring from JSON snapshot (cross-restart persistence)
        saved = _load_snapshot(self._sessions_dir, run_id)
        if saved and saved.get("status") not in (None, ""):
            # Re-hydrate by updating graph state directly
            graph.update_state(cfg, saved)
            return _build_response(run_id, saved)

        # Fresh start
        init_transcript = [
            {
                "turn_id": "t1",
                "role": "user",
                "text": user_goal,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
        initial: dict[str, Any] = {
            "session_id": run_id,
            "authenticated_user_id": user_id,
            "transcript": init_transcript,
            "raw_uploads": uploads,
            "status": "profiling",
            "revision": 1,
            "round_count": 0,
            "empty_retry_count": 0,
            "repair_attempts": 0,
        }
        result = await graph.ainvoke(initial, config=cfg)
        result_dict = dict(result)
        if result_dict.get("status") not in ("failed_model_unavailable",):
            _save_snapshot(self._sessions_dir, run_id, result_dict)
        return _build_response(run_id, result_dict)

    # ------------------------------------------------------------------
    async def send_turn(
        self,
        run_id: str,
        user_message: str,
        user_id: str = "user",
    ) -> IntakeTurnResponse:
        graph, _ = self._get_or_create_graph(run_id)
        cfg = self._thread_cfg(run_id, user_id)

        # Resume the graph by providing the user reply as the interrupt value
        result = await graph.ainvoke(
            Command(resume={"text": user_message}),
            config=cfg,
        )
        result_dict = dict(result)
        if result_dict.get("status") not in ("failed_model_unavailable",):
            _save_snapshot(self._sessions_dir, run_id, result_dict)
        return _build_response(run_id, result_dict)

    # ------------------------------------------------------------------
    def get_state(self, run_id: str) -> IntakeTurnResponse:
        graph, _ = self._get_or_create_graph(run_id)
        cfg = self._thread_cfg(run_id)
        snapshot = graph.get_state(cfg)
        if snapshot and snapshot.values.get("status"):
            return _build_response(run_id, dict(snapshot.values))

        saved = _load_snapshot(self._sessions_dir, run_id)
        if saved:
            return _build_response(run_id, saved)

        return IntakeTurnResponse(
            run_id=run_id,
            status="not_started",
            assistant_message=(
                "No intake session found. Start an intake from Adaptation Home."
            ),
        )
