"""
Vercel serverless function entry point for CTI Dashboard API
"""
import sys
import os

# Add the parent directory to the Python path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

# Create the Flask application instance
app = create_app()

# Export for Vercel
if __name__ == "__main__":
    app.run()
