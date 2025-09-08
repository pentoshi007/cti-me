#!/bin/bash

echo "🔄 Debugging CTI Dashboard Setup..."

cd backend

# Clean up any existing venv
rm -rf venv 2>/dev/null

# Create fresh virtual environment
echo "📦 Creating fresh Python virtual environment..."
python3 -m venv venv

# Activate and install
echo "🔌 Activating virtual environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create .env
cp .env.example .env

echo "🧪 Testing Flask import in virtual environment..."
source venv/bin/activate && python -c "import flask; print('✅ Flask imported successfully in venv')"

echo "🚀 Starting Flask app in virtual environment..."
source venv/bin/activate && python app.py