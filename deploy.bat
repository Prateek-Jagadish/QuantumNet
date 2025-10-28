@echo off
REM QuantumNet Production Deployment Script for Windows
REM This script sets up QuantumNet for production deployment

echo 🚀 Starting QuantumNet Production Deployment...

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Create environment file if it doesn't exist
if not exist .env (
    echo 📝 Creating environment file...
    (
        echo # QuantumNet Production Environment Variables
        echo SECRET_KEY=your-secret-key-here
        echo POSTGRES_PASSWORD=your-postgres-password-here
        echo FLASK_ENV=production
        echo DEBUG=False
    ) > .env
    echo ✅ Environment file created. Please edit .env with your secure keys.
)

REM Create necessary directories
echo 📁 Creating necessary directories...
if not exist data mkdir data
if not exist models mkdir models
if not exist static\uploads mkdir static\uploads
if not exist ssl mkdir ssl

REM Generate SSL certificates (self-signed for development)
if not exist ssl\cert.pem (
    echo 🔐 Generating SSL certificates...
    echo You need to generate SSL certificates manually or use a certificate authority.
    echo For development, you can use self-signed certificates.
    echo Please place your certificates in the ssl\ directory as cert.pem and key.pem
)

REM Create database initialization script
echo 🗄️ Creating database initialization script...
(
    echo -- QuantumNet Database Initialization
    echo CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    echo.
    echo -- Create indexes for better performance
    echo CREATE INDEX IF NOT EXISTS idx_users_username ON users^(username^);
    echo CREATE INDEX IF NOT EXISTS idx_users_email ON users^(email^);
    echo CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages^(sender_id^);
    echo CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages^(recipient_id^);
    echo CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages^(created_at^);
    echo CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events^(user_id^);
    echo CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events^(created_at^);
    echo CREATE INDEX IF NOT EXISTS idx_file_shares_sender ON file_shares^(sender_id^);
    echo CREATE INDEX IF NOT EXISTS idx_file_shares_recipient ON file_shares^(recipient_id^);
) > init.sql

REM Build and start services
echo 🔨 Building Docker images...
docker-compose build

echo 🚀 Starting QuantumNet services...
docker-compose up -d

REM Wait for services to be ready
echo ⏳ Waiting for services to start...
timeout /t 30 /nobreak >nul

REM Check if services are running
echo 🔍 Checking service status...
docker-compose ps

REM Test the application
echo 🧪 Testing application...
curl -f http://localhost:5000/ >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ QuantumNet is running successfully!
    echo.
    echo 🌐 Access your application at:
    echo    HTTP:  http://localhost:5000
    echo    HTTPS: https://localhost:443
    echo.
    echo 📊 Monitor your application:
    echo    docker-compose logs -f web
    echo    docker-compose logs -f db
    echo    docker-compose logs -f redis
    echo.
    echo 🛑 To stop the application:
    echo    docker-compose down
    echo.
    echo 🔄 To restart the application:
    echo    docker-compose restart
) else (
    echo ❌ Application failed to start. Check logs with: docker-compose logs
    pause
    exit /b 1
)

echo 🎉 QuantumNet deployment completed successfully!
pause
