@echo off
echo ===================================================
echo QuantumNet Cleanup Tool
echo ===================================================
echo This will remove virtual environments, node_modules, and temporary files.
echo Use this before zipping the project to move to another laptop.
echo.
pause

echo [INFO] Cleaning Backend...
cd backend
if exist "venv" (
    echo Removing venv...
    rmdir /s /q venv
)
if exist "qnenv" (
    echo Removing qnenv...
    rmdir /s /q qnenv
)
if exist "__pycache__" (
    echo Removing __pycache__...
    rmdir /s /q __pycache__
)
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"

echo [INFO] Cleaning Frontend...
cd ..\frontend
if exist "node_modules" (
    echo Removing node_modules...
    rmdir /s /q node_modules
)
if exist "dist" (
    echo Removing dist...
    rmdir /s /q dist
)

echo.
echo [INFO] Cleanup Complete!
pause
