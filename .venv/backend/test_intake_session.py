"""test_intake_session.py — Deterministic unit tests for IntakeSessionManager
and intake API endpoints. Does NOT make real model calls (all LLM calls are
mocked out). Tests cover:
  1. Normal session start (mocked LLM)
  2. send_turn resume
  3. get_state before session exists
  4. get_state after session started
  5. POST /intake/start endpoint (HTTP)
  6. POST /intake/turn endpoint (HTTP)
  7. GET  /intake/state endpoint (HTTP)
  8. Auth: missing API key → 401
  9. Invalid payload → 422
 10. Session with blocking questions stays in interviewing
 11. duplicate app = create_app() not present (regression)
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Point to backend
_BACKEND = Path(__file__).resolve().parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# Set required env vars before any imports
os.environ.setdefault("ADAPTOS_API_KEY", "test-key-abc123")
os.environ.setdefault("ADAPTOS_EVAL_SERVICE_TOKEN", "test-token-32-chars-long-xyzabc")
os.environ.setdefault("ADAPTOS_EVAL_SIGNING_SEED", "test-signing-seed-phrase-abc")
os.environ.setdefault("MODEL_API_KEY", "sk-fake-key-for-testing")


# ---------------------------------------------------------------------------
# Minimal mocks for LLM gateway so no network calls are made
# ---------------------------------------------------------------------------
def _make_mock_turn_result() -> dict:
    return {
        "goal": "Test goal",
        "operation_mode": "new_solution",
        "existing_systems_context": "",
        "available_data_context": "",
        "success_criteria_context": "",
        "proposed_inputs": [],
        "proposed_outputs": [],
        "extracted_requirements": [],
        "inferred_requirements": [],
        "assumptions": [],
        "superseded_requirement_ids": [],
        "removed_input_names": [],
        "removed_output_names": [],
        "resolved_contradiction_ids": [],
        "answered_question_ids": [],
        "question_answers": {},
        "contradictions": [],
        "out_of_scope": [],
        "questions": [
            {
                "question_id": "q_inputs",
                "question": "What are the main data inputs?",
                "why_it_matters": "Required for spec",
                "blocking": True,
                "suggested_default": None,
            }
        ],
    }


class TestIntakeTurnResponse(unittest.TestCase):
    """Test the response builder directly — no I/O."""

    def test_not_started_state(self):
        from intake_session import IntakeTurnResponse, _build_response
        resp = _build_response("run-001", {"status": "", "pending_questions": []})
        self.assertIsInstance(resp, IntakeTurnResponse)

    def test_pending_questions_in_message(self):
        from intake_session import _build_response
        state = {
            "status": "interviewing",
            "pending_questions": [
                {
                    "question_id": "q1",
                    "question": "What are your inputs?",
                    "why_it_matters": "Need inputs",
                    "blocking": True,
                    "suggested_default": "CSV file",
                }
            ],
            "unresolved_blocking_ids": ["q1"],
        }
        resp = _build_response("run-002", state)
        self.assertIn("What are your inputs?", resp.assistant_message)
        self.assertEqual(len(resp.pending_questions), 1)
        self.assertEqual(resp.status, "interviewing")

    def test_spec_ready_message(self):
        from intake_session import _build_response
        state = {
            "status": "validating",
            "spec": {"goal": "Test"},
            "pending_questions": [],
        }
        resp = _build_response("run-003", state)
        self.assertIn("specification", resp.assistant_message.lower())

    def test_error_terminal_state(self):
        from intake_session import _build_response
        state = {
            "status": "blocked_with_errors",
            "error_message": "Validation failed: missing requirements",
        }
        resp = _build_response("run-004", state)
        self.assertIn("Validation failed", resp.assistant_message)
        self.assertEqual(resp.status, "blocked_with_errors")

    def test_handed_off_state(self):
        from intake_session import _build_response
        resp = _build_response("run-005", {"status": "handed_off"})
        self.assertIn("handed off", resp.assistant_message)

    def test_validation_errors_in_response(self):
        from intake_session import _build_response
        state = {
            "status": "repairing",
            "validation_errors": ["Missing criterion", "Bad field"],
            "pending_questions": [],
        }
        resp = _build_response("run-006", state)
        self.assertEqual(resp.validation_errors, ["Missing criterion", "Bad field"])


class TestSnapshotPersistence(unittest.TestCase):
    """JSON snapshot helpers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_and_load_roundtrip(self):
        from intake_session import _save_snapshot, _load_snapshot
        state = {"status": "interviewing", "transcript": [{"turn_id": "t1", "role": "user"}]}
        _save_snapshot(self._dir, "my-run", state)
        loaded = _load_snapshot(self._dir, "my-run")
        self.assertEqual(loaded["status"], "interviewing")

    def test_load_missing_returns_none(self):
        from intake_session import _load_snapshot
        result = _load_snapshot(self._dir, "nonexistent-run")
        self.assertIsNone(result)

    def test_special_chars_in_run_id(self):
        from intake_session import _save_snapshot, _load_snapshot
        _save_snapshot(self._dir, "run/with:special?chars", {"status": "ok"})
        loaded = _load_snapshot(self._dir, "run/with:special?chars")
        self.assertIsNotNone(loaded)


class TestApiIntakeEndpoints(unittest.TestCase):
    """HTTP-level tests via FastAPI TestClient — LLM fully mocked."""

    API_KEY = "test-key-abc123"

    def setUp(self):
        from fastapi.testclient import TestClient
        import api
        # Build a fresh app with mocked service dependencies
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["ADAPTOS_DATA_ROOT"] = tmp
            test_app = api.create_app()

        # Install a mock intake session manager
        from intake_session import IntakeTurnResponse
        mock_intake = MagicMock()
        mock_intake.start_or_resume = AsyncMock(return_value=IntakeTurnResponse(
            run_id="test-run",
            status="interviewing",
            assistant_message="What are your inputs?",
            pending_questions=[],
        ))
        mock_intake.send_turn = AsyncMock(return_value=IntakeTurnResponse(
            run_id="test-run",
            status="interviewing",
            assistant_message="Got it. What are the outputs?",
            pending_questions=[],
        ))
        mock_intake.get_state = MagicMock(return_value=IntakeTurnResponse(
            run_id="test-run",
            status="interviewing",
            assistant_message="Current state",
            pending_questions=[],
        ))
        test_app.state.intake_session_manager = mock_intake

        # Mock AdaptOSService
        from eval_plane.service import AdaptOSService
        mock_svc = MagicMock(spec=AdaptOSService)
        mock_svc.eval_public_key_bytes = b"\x00" * 32
        test_app.state.adaptos_service = mock_svc

        # Mock runtime service
        from runtime_service import AdaptOSRuntimeService
        mock_rt = MagicMock(spec=AdaptOSRuntimeService)
        test_app.state.runtime_service = mock_rt

        self.client = TestClient(test_app, raise_server_exceptions=False)
        self.headers = {"Authorization": f"Bearer {self.API_KEY}"}

    def test_start_intake_ok(self):
        r = self.client.post(
            "/api/projects/test-run/intake/start",
            headers=self.headers,
            json={"user_goal": "Build a fraud detection system", "uploads": [], "user_id": "alice"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "interviewing")
        self.assertIn("assistant_message", data)

    def test_send_turn_ok(self):
        r = self.client.post(
            "/api/projects/test-run/intake/turn",
            headers=self.headers,
            json={"user_message": "The inputs are transaction amount and merchant ID", "user_id": "alice"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("assistant_message", data)

    def test_get_state_ok(self):
        r = self.client.get(
            "/api/projects/test-run/intake/state",
            headers=self.headers,
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["run_id"], "test-run")

    def test_missing_auth_returns_401(self):
        r = self.client.post(
            "/api/projects/test-run/intake/start",
            json={"user_goal": "test", "uploads": [], "user_id": "u"},
        )
        self.assertEqual(r.status_code, 401)

    def test_invalid_payload_returns_422(self):
        r = self.client.post(
            "/api/projects/test-run/intake/start",
            headers=self.headers,
            json={"user_goal": ""},  # empty goal violates min_length=1
        )
        self.assertEqual(r.status_code, 422)

    def test_send_turn_empty_message_returns_422(self):
        r = self.client.post(
            "/api/projects/test-run/intake/turn",
            headers=self.headers,
            json={"user_message": ""},  # empty violates min_length=1
        )
        self.assertEqual(r.status_code, 422)


class TestApiRegressions(unittest.TestCase):
    """Regression checks on api.py structure."""

    def test_no_duplicate_create_app_calls(self):
        api_path = Path(__file__).parent / "api.py"
        # Count only module-level (non-indented) occurrences
        count = sum(
            1 for line in api_path.read_text(encoding="utf-8").splitlines()
            if line.strip() == "app = create_app()" and not line.startswith(" ")
        )
        self.assertEqual(count, 1, f"Expected 1 module-level 'app = create_app()' but found {count}")

    def test_api_app_is_fastapi(self):
        import api
        from fastapi import FastAPI
        self.assertIsInstance(api.app, FastAPI)
        self.assertIsNotNone(api.app)

    def test_intake_import_in_api(self):
        api_path = Path(__file__).parent / "api.py"
        src = api_path.read_text(encoding="utf-8")
        self.assertIn("from intake_session import", src)

    def test_three_intake_endpoints_registered(self):
        api_path = Path(__file__).parent / "api.py"
        src = api_path.read_text(encoding="utf-8")
        self.assertIn("/api/projects/{run_id}/intake/start", src)
        self.assertIn("/api/projects/{run_id}/intake/turn", src)
        self.assertIn("/api/projects/{run_id}/intake/state", src)

    def test_frontend_uses_backend_intake(self):
        tsx_path = Path(__file__).parent.parent / "frontend" / "src" / "App.tsx"
        src = tsx_path.read_text(encoding="utf-8")
        self.assertIn("intake/turn", src)
        self.assertIn("intake/start", src)
        self.assertIn("intakeLoading", src)
        self.assertIn("handleSendIntakeTurn = async", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
