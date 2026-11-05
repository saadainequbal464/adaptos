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






set "ADAPTOS_OFFLINE_DEMO=1"

REM MODEL_API_KEY must be set in your environment before running this script.
REM It is intentionally NOT stored in this file (it was leaked in git history; rotate it).
if "%MODEL_API_KEY%"=="" set "MODEL_API_KEY=%MODEL_API_KEY%"



set "ADAPTOS_NODE_TIMEOUT_SECONDS=300"







echo Starting AdaptOS backend on http://127.0.0.1:8000 ...



".venv\Scripts\python.exe" ".venv\backend\api.py" --host 127.0.0.1 --port 8000



pause



