#!/bin/bash
# QuantumNet Installation Script

set -e

echo "🚀 Installing QuantumNet..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8+ is required. Current version: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data/keys
mkdir -p models
mkdir -p logs
mkdir -p tests

# Set permissions
echo "🔐 Setting permissions..."
chmod +x run.py
chmod +x install.sh

# Initialize database
echo "🗄️ Initializing database..."
python -c "
import sys
sys.path.append('src')
from src.server.database import DatabaseManager
db = DatabaseManager('data/quantumnet.db')
print('Database initialized successfully!')
"

# Train ML model
echo "🧠 Training ML model..."
python -c "
import sys
sys.path.append('src')
from src.ml.model_manager import ModelManager
mm = ModelManager(models_dir='models', data_dir='data')
result = mm.train_model(samples_per_class=100)
if result['success']:
    print('ML model trained successfully!')
else:
    print('ML model training failed:', result['error'])
"

echo "✅ QuantumNet installation completed!"
echo ""
echo "To start the application:"
echo "  source venv/bin/activate"
echo "  python run.py"
echo ""
echo "To run tests:"
echo "  pytest tests/ -v"
echo ""
echo "To run in development mode:"
echo "  FLASK_ENV=development python run.py"
