@echo off

REM AdaptOS backend launcher - port 8000 (live Muse intake + chat, verified factory)

cd /d "C:\Users\Lenovo\Desktop\agnos ai"



for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1



set "ADAPTOS_API_KEY=demo-key-123"

set "ADAPTOS_EVAL_SERVICE_TOKEN=demo-eval-service-token-32b"

set "ADAPTOS_EVAL_SIGNING_SEED=demo-eval-signing-seed-2026"

set "AGNOS_PROCESS_ROLE=factory"

set "ADAPTOS_DATA_ROOT=C:\Users\Lenovo\Desktop\agnos ai\.venv\data\adaptos_8000"

REM Fully online: intake, planner, codegen, eval-designer, repair and chat

REM all run through the LIVE Muse model key below.

REM Intake agent + Your Adapted AI chat run LIVE via the Muse key below.
REM Factory test-case generation uses deterministic fixtures (ADAPTOS_OFFLINE_DEMO=1)
REM so the build-verify-deliver demo is reliable. Remove this line for full-online.
set "ADAPTOS_OFFLINE_DEMO=1"
set "MODEL_API_KEY=LLM_1132022235881333_UUub0xkX2BR_AxRXGYuUgJ0_jlw"

set "ADAPTOS_NODE_TIMEOUT_SECONDS=300"



echo Starting AdaptOS backend on http://127.0.0.1:8000 ...

".venv\Scripts\python.exe" ".venv\backend\api.py" --host 127.0.0.1 --port 8000

pause

