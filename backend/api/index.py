"""
Vercel serverless function entry point for CTI Dashboard API
"""
import sys
import os
import logging

# Add the parent directory to the Python path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging for serverless
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_serverless_app():
    """Create Flask app optimized for serverless environment"""
    try:
        from flask import Flask
        from flask_cors import CORS
        from flask_restx import Api
        from flask_jwt_extended import JWTManager
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        from config import Config
        from database import MongoDB
        from auth.routes import auth_ns
        from iocs.routes import iocs_ns
        from lookup.routes import lookup_ns
        from tags.routes import tags_ns
        from metrics.routes import metrics_ns
        from exports.routes import exports_ns
        from admin.routes import admin_ns
        
        # Create Flask app
        app = Flask(__name__)
        app.config.from_object(Config)
        
        # Initialize CORS
        CORS(app, resources={
            r"/api/*": {
                "origins": Config.CORS_ORIGINS,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"]
            }
        })
        
        # Initialize JWT
        jwt = JWTManager(app)
        
        # Initialize rate limiter (simplified for serverless)
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["1000 per hour"],
            storage_uri="memory://"  # Use memory storage for serverless
        )
        
        # Initialize database
        MongoDB.initialize()
        
        # Create API instance
        api = Api(
            app,
            version='1.0',
            title='CTI Dashboard API',
            description='Cyber Threat Intelligence Dashboard API',
            doc='/docs/',
            prefix='/api'
        )
        
        # Register namespaces
        api.add_namespace(auth_ns, path='/auth')
        api.add_namespace(iocs_ns, path='/iocs')
        api.add_namespace(lookup_ns, path='/lookup')
        api.add_namespace(tags_ns, path='/tags')
        api.add_namespace(metrics_ns, path='/metrics')
        api.add_namespace(exports_ns, path='/exports')
        api.add_namespace(admin_ns, path='/admin')
        
        # Health check endpoint
        @app.route('/')
        @app.route('/health')
        def health_check():
            return {
                'status': 'healthy',
                'timestamp': str(datetime.utcnow()),
                'environment': 'serverless'
            }
        
        logger.info("Serverless Flask app created successfully")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create serverless app: {e}")
        raise

# Create the Flask application instance
try:
    from datetime import datetime
    app = create_serverless_app()
    logger.info("CTI Dashboard serverless function initialized")
except Exception as e:
    logger.error(f"Failed to initialize serverless function: {e}")
    # Create a minimal error app
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return {"error": f"Failed to initialize: {str(e)}"}, 500
