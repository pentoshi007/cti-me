#!/bin/bash

echo "🔧 Setting up CTI Dashboard Backend..."

# Change to backend directory
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    echo "✅ Created .env file from example"
fi

# Test import
echo "🧪 Testing Flask import..."
python3 -c "import flask; print('✅ Flask imported successfully')"

# Start the application
echo "🚀 Starting Flask application..."
python3 app.py