"""
Vercel serverless function entry point for CTI Dashboard API
"""
import sys
import os
import logging
import traceback

# Add the parent directory to the Python path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging for serverless
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test imports early to catch import errors
try:
    logger.info("Testing imports...")
    from flask import Flask, jsonify
    from flask_cors import CORS
    from flask_restx import Api
    logger.info("Basic Flask imports successful")
    
    from config import Config
    logger.info("Config import successful")
    
    from database import MongoDB
    logger.info("Database import successful")
    
    logger.info("All imports successful")
except Exception as e:
    logger.error(f"Import error: {e}")
    logger.error(f"Import traceback: {traceback.format_exc()}")

def create_serverless_app():
    """Create Flask app optimized for serverless environment"""
    try:
        logger.info("Starting serverless app creation...")
        
        # Import Flask components
        from flask_jwt_extended import JWTManager
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        # Import route namespaces
        from auth.routes import auth_ns
        from iocs.routes import iocs_ns
        from lookup.routes import lookup_ns
        from tags.routes import tags_ns
        from metrics.routes import metrics_ns
        from exports.routes import exports_ns
        from admin.routes import admin_ns
        
        logger.info("All route imports successful")
        
        # Create Flask app
        logger.info("Creating Flask app instance...")
        app = Flask(__name__)
        app.config.from_object(Config)
        
        logger.info("Initializing CORS...")
        # Initialize CORS
        CORS(app, resources={
            r"/api/*": {
                "origins": Config.CORS_ORIGINS,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"]
            }
        })
        
        # Initialize JWT
        logger.info("Initializing JWT...")
        jwt = JWTManager(app)
        
        # Initialize rate limiter (simplified for serverless)
        logger.info("Initializing rate limiter...")
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["1000 per hour"],
            storage_uri="memory://"  # Use memory storage for serverless
        )
        
        # Initialize database
        logger.info("Initializing database connection...")
        MongoDB.initialize()
        
        # Create API instance
        logger.info("Creating API instance...")
        api = Api(
            app,
            version='1.0',
            title='CTI Dashboard API',
            description='Cyber Threat Intelligence Dashboard API',
            doc='/docs/',
            prefix='/api'
        )
        
        # Register namespaces
        logger.info("Registering API namespaces...")
        api.add_namespace(auth_ns, path='/auth')
        api.add_namespace(iocs_ns, path='/iocs')
        api.add_namespace(lookup_ns, path='/lookup')
        api.add_namespace(tags_ns, path='/tags')
        api.add_namespace(metrics_ns, path='/metrics')
        api.add_namespace(exports_ns, path='/exports')
        api.add_namespace(admin_ns, path='/admin')
        
        # Health check endpoint
        logger.info("Creating health check endpoints...")
        @app.route('/')
        @app.route('/health')
        def health_check():
            from datetime import datetime
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

# Global variables for error handling
init_error_msg = None
error_traceback = None

# Create the Flask application instance
try:
    from datetime import datetime
    app = create_serverless_app()
    logger.info("CTI Dashboard serverless function initialized successfully")
except Exception as e:
    init_error_msg = str(e)
    logger.error(f"Failed to initialize serverless function: {e}")
    import traceback
    error_traceback = traceback.format_exc()
    logger.error(f"Full traceback: {error_traceback}")
    
    # Create a minimal error app that shows the actual error
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    @app.route('/health')
    def error():
        return jsonify({
            "error": "Failed to initialize CTI Dashboard",
            "message": init_error_msg or "Unknown initialization error",
            "status": "error",
            "environment": "serverless"
        }), 500
    
    @app.route('/debug')
    def debug():
        return jsonify({
            "error": init_error_msg or "Unknown initialization error",
            "traceback": error_traceback or "No traceback available",
            "environment_vars": {
                "FLASK_ENV": os.environ.get("FLASK_ENV", "not set"),
                "MONGO_URI": "***set***" if os.environ.get("MONGO_URI") else "not set",
                "FLASK_SECRET_KEY": "***set***" if os.environ.get("FLASK_SECRET_KEY") else "not set"
            }
        })
