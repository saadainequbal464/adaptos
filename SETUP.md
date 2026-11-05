# AdaptOS — Autonomous AI Adaptation Factory

AdaptOS takes a natural-language requirement + knowledge documents and produces an independently-verified AI application: intake → specification approval → architecture → build (planner/codegen/sandbox) → bounded repair → protected evaluation (sealed held-out cases, Ed25519-signed verdicts) → ready-gated delivery → provisioned runtime chatbot.

## Layout
- `.venv/backend/` — FastAPI API (`api.py`), factory orchestrator (`graph.py`), agents (`agents/`), core runtime (`runtime.py`), operational runtime backend (`runtime_service.py`), schemas/storage/sandbox
- `.venv/eval_plane/` — service layer (`service.py`) + protected evaluation plane (`evaluator.py`)
- `.venv/frontend/` — React + Vite UI (9-stage journey, Your Adapted AI chatbot)

## Prerequisites
- Python 3.14 in `.venv` (with fastapi, uvicorn, httpx, pydantic, pydantic-settings, langchain-core, langchain-openai, langgraph, openai, cryptography installed)
- Node.js (for the frontend)
- A Muse/OpenAI-compatible model key

## Environment (backend)
```
ADAPTOS_API_KEY=<http bearer key for /api/*>
ADAPTOS_EVAL_SERVICE_TOKEN=<>=16 chars>
ADAPTOS_EVAL_SIGNING_SEED=<any phrase, hashed to the signing key>
AGNOS_PROCESS_ROLE=factory
ADAPTOS_DATA_ROOT=<data dir>
MODEL_API_KEY=<Muse model key>
META_BASE_URL=<provider base URL, default https://api.meta.ai/v1>
ADAPTOS_NODE_TIMEOUT_SECONDS=300
ADAPTOS_OFFLINE_DEMO=1   # optional: deterministic factory fixtures (reliable READY demo); omit for fully-live LLM pipeline
```

## Run
```
# backend (or just run start_backend_8000.cmd)
.venv\Scripts\python.exe .venv\backend\api.py --host 127.0.0.1 --port 8000

# frontend
cd .venv\frontend && npm install && npm run dev   # http://localhost:5173
```
Session Bearer key for the UI: value of `ADAPTOS_API_KEY`.

## Self-tests
```
.venv\Scripts\python.exe .venv\backend\runtime.py --self-test
.venv\Scripts\python.exe .venv\backend\runtime_service.py --self-test
.venv\Scripts\python.exe .venv\backend\sandbox.py --self-test
.venv\Scripts\python.exe .venv\eval_plane\service.py --self-test
.venv\Scripts\python.exe .venv\backend\api.py --self-test
```

## Security invariants (do not weaken)
Docker sandbox fails closed; Ed25519 verdict verification; ready-gated delivery; protected eval plane role isolation; sealed held-out data never reaches the factory; Bearer auth on all `/api/*` routes.
