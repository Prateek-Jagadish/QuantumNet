@echo off
echo QuantumNet Standalone Launcher

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 goto NoPython

:: Check for Node.js
node --version >nul 2>&1
if errorlevel 1 goto NoNode

echo [INFO] Environment checks passed.

:: Setup Backend
echo.
echo [INFO] Setting up Backend...
if not exist "backend" goto NoBackendDir
cd backend

if not exist "venv" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate

echo [INFO] Installing backend dependencies...
pip install -r requirements.txt >nul 2>&1
if errorlevel 1 goto InstallFailed

:: Setup Frontend
echo.
echo [INFO] Setting up Frontend...
cd ..
if not exist "frontend" goto NoFrontendDir
cd frontend

if not exist "node_modules" (
    echo [INFO] Installing frontend dependencies...
    call npm install >nul 2>&1
    if errorlevel 1 goto FrontendInstallFailed
)

:: Start Application
echo.
echo [INFO] Starting QuantumNet...
echo [INFO] Backend running on http://localhost:8000
echo [INFO] Frontend running on http://localhost:5173

:: Start Backend in background
start "QuantumNet Backend" cmd /k "cd ..\backend && venv\Scripts\activate && python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

:: Start Frontend
echo [INFO] Starting Frontend...
call npm run dev
goto End

:NoPython
echo [ERROR] Python is not installed or not in PATH.
pause
exit /b 1

:NoNode
echo [ERROR] Node.js is not installed or not in PATH.
pause
exit /b 1

:NoBackendDir
echo [ERROR] backend directory not found!
pause
exit /b 1

:NoFrontendDir
echo [ERROR] frontend directory not found!
pause
exit /b 1

:InstallFailed
echo [ERROR] Failed to install backend dependencies.
pause
exit /b 1

:FrontendInstallFailed
echo [ERROR] Failed to install frontend dependencies.
pause
exit /b 1

:End
pause
