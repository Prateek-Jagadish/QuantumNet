@echo off
echo Starting QuantumNet Enhanced in Production Mode...

REM Set production environment variables
set FLASK_ENV=production
set FLASK_DEBUG=False
set PYTHONPATH=%CD%

REM Start the application
echo Starting QuantumNet Enhanced...
echo.
echo ========================================
echo   QuantumNet Enhanced - Production Mode
echo ========================================
echo.
echo Application URL: http://localhost:5000
echo Admin Panel: http://localhost:5000/security
echo BB84 Demo: http://localhost:5000/bb84-demo
echo.
echo Press Ctrl+C to stop the application
echo.

python app.py

pause
