#!/bin/bash

# QuantumNet Production Deployment Script
# This script sets up QuantumNet for production deployment

set -e

echo "🚀 Starting QuantumNet Production Deployment..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating environment file..."
    cat > .env << EOF
# QuantumNet Production Environment Variables
SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
FLASK_ENV=production
DEBUG=False
EOF
    echo "✅ Environment file created with secure random keys"
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p data models static/uploads ssl

# Generate SSL certificates (self-signed for development)
if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
    echo "🔐 Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    echo "✅ SSL certificates generated"
fi

# Create database initialization script
echo "🗄️ Creating database initialization script..."
cat > init.sql << EOF
-- QuantumNet Database Initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_file_shares_sender ON file_shares(sender_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_recipient ON file_shares(recipient_id);

-- Create full-text search indexes
CREATE INDEX IF NOT EXISTS idx_messages_content_fts ON messages USING gin(to_tsvector('english', content));
CREATE INDEX IF NOT EXISTS idx_security_events_description_fts ON security_events USING gin(to_tsvector('english', description));
EOF

# Build and start services
echo "🔨 Building Docker images..."
docker-compose build

echo "🚀 Starting QuantumNet services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check if services are running
echo "🔍 Checking service status..."
docker-compose ps

# Test the application
echo "🧪 Testing application..."
if curl -f http://localhost:5000/ > /dev/null 2>&1; then
    echo "✅ QuantumNet is running successfully!"
    echo ""
    echo "🌐 Access your application at:"
    echo "   HTTP:  http://localhost:5000"
    echo "   HTTPS: https://localhost:443"
    echo ""
    echo "📊 Monitor your application:"
    echo "   docker-compose logs -f web"
    echo "   docker-compose logs -f db"
    echo "   docker-compose logs -f redis"
    echo ""
    echo "🛑 To stop the application:"
    echo "   docker-compose down"
    echo ""
    echo "🔄 To restart the application:"
    echo "   docker-compose restart"
else
    echo "❌ Application failed to start. Check logs with: docker-compose logs"
    exit 1
fi

echo "🎉 QuantumNet deployment completed successfully!"
