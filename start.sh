#!/bin/bash

# CTI Dashboard Quick Start Script
echo "🚀 Starting CTI Dashboard..."

# Check if Python and Node.js are installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check Python version (should be 3.9+)
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.9"
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" &> /dev/null; then
    echo "❌ Python 3.9+ is required, but found Python $PYTHON_VERSION"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi

# Function to start backend
start_backend() {
    echo "🔧 Setting up backend..."
    cd backend
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo "📦 Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    echo "📦 Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install Python dependencies. Please check the error messages above."
        exit 1
    fi
    
    # Check if .env exists
    if [ ! -f ".env" ]; then
        echo "⚠️  .env file not found. Please copy .env.example to .env and configure your settings."
        cp .env.example .env
        echo "✅ Created .env file from example. Please update it with your API keys."
    fi
    
    # Start backend server
    echo "🚀 Starting Flask backend on http://localhost:5001"
    python app.py &
    BACKEND_PID=$!
    
    cd ..
}

# Function to start frontend
start_frontend() {
    echo "🔧 Setting up frontend..."
    cd frontend
    
    # Install dependencies
    if [ ! -d "node_modules" ]; then
        echo "📦 Installing Node.js dependencies..."
        npm install
        
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install Node.js dependencies. Please check the error messages above."
            exit 1
        fi
    fi
    
    # Start frontend server
    echo "🚀 Starting React frontend on http://localhost:3000"
    npm run dev &
    FRONTEND_PID=$!
    
    cd ..
}

# Function to cleanup on exit
cleanup() {
    echo "🛑 Shutting down servers..."
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    exit 0
}

# Trap Ctrl+C and call cleanup
trap cleanup INT

# Start services
start_backend
sleep 3  # Wait for backend to start
start_frontend

echo ""
echo "✅ CTI Dashboard is starting up!"
echo ""
echo "🌐 Frontend: http://localhost:3000"
echo "🔧 Backend API: http://localhost:5001"
echo "📚 API Docs: http://localhost:5001/docs/"
echo ""
echo "🔑 Default credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "📝 To stop the servers, press Ctrl+C"
echo ""

# Wait for both processes
wait
