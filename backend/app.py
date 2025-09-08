"""
Cyber Threat Intelligence (CTI) Dashboard - Flask Backend
Main application entry point
"""
import os
import logging
import json
from datetime import datetime, timedelta
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit

from config import Config
from database import MongoDB
from auth.routes import auth_bp
from iocs.routes import iocs_bp
from lookup.routes import lookup_bp
from tags.routes import tags_bp
from metrics.routes import metrics_bp
from exports.routes import exports_bp
from admin.routes import admin_bp
from ingestion.urlhaus_fetcher import URLHausFetcher
from auth.models import User

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cti_dashboard.log')
    ]
)
logger = logging.getLogger(__name__)


def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Configure CORS with enhanced settings for dashboard
    CORS(app, 
         origins=app.config['CORS_ORIGINS'],
         supports_credentials=True, 
         allow_headers=['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
         max_age=600  # Cache preflight for 10 minutes
    )
    
    # Configure app logging
    app.logger.setLevel(logging.INFO)
    
    try:
        # Initialize JWT
        jwt = JWTManager(app)
        
        # JWT Error Handlers
        @jwt.expired_token_loader
        def expired_token_callback(jwt_header, jwt_payload):
            logger.warning(f"Expired token accessed. Header: {jwt_header}, Payload: {jwt_payload}")
            return {'message': 'Token has expired'}, 401
        
        @jwt.invalid_token_loader
        def invalid_token_callback(error):
            if "Only refresh tokens are allowed" in str(error):
                logger.warning(f"Wrong token type used for refresh: {error}")
                return {'message': 'Wrong token type. Use refresh token for refresh endpoint, not access token.'}, 422
            logger.error(f"Invalid token error: {error}")
            return {'message': f'Invalid token: {str(error)}'}, 422
        
        @jwt.unauthorized_loader
        def missing_token_callback(error):
            logger.warning(f"Missing token error: {error}")
            return {'message': 'Authorization token required'}, 401
        
        @jwt.needs_fresh_token_loader
        def token_not_fresh_callback(jwt_header, jwt_payload):
            logger.warning("Fresh token required but non-fresh token provided")
            return {'message': 'Fresh token required'}, 401
        
        @jwt.revoked_token_loader
        def revoked_token_callback(jwt_header, jwt_payload):
            logger.warning("Revoked token accessed")
            return {'message': 'Token has been revoked'}, 401
        
        @jwt.decode_key_loader
        def decode_key_callback(jwt_header, jwt_payload):
            return app.config['JWT_SECRET_KEY']
        
        # Handle specific JWT errors
        from flask_jwt_extended.exceptions import WrongTokenError
        
        @app.errorhandler(WrongTokenError)
        def handle_wrong_token_error(error):
            logger.warning(f"Wrong token type used: {error}")
            return {'message': 'Wrong token type. Use refresh token for refresh endpoint, not access token.'}, 422
        
        # Initialize rate limiter with more generous limits for dashboard usage
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["10000 per day", "500 per hour", "100 per minute"]
        )
        limiter.init_app(app)
        
        # Initialize MongoDB
        logger.info("Initializing MongoDB connection...")
        MongoDB.initialize(app)

        # Register blueprints
        logger.info("Registering API blueprints...")
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(iocs_bp, url_prefix='/api/iocs')
        app.register_blueprint(lookup_bp, url_prefix='/api/lookup')
        app.register_blueprint(tags_bp, url_prefix='/api/tags')
        app.register_blueprint(metrics_bp, url_prefix='/api/metrics')
        app.register_blueprint(exports_bp, url_prefix='/api/exports')
        app.register_blueprint(admin_bp, url_prefix='/api/admin')

        # Health check endpoint
        @app.route('/api/health')
        def health_check():
            return {'status': 'healthy', 'service': 'cti-dashboard'}
        
        # Ensure a default admin exists on startup
        try:
            logger.info("Creating default admin user...")
            User.create_default_admin()
        except Exception as e:
            logger.error(f"Error creating default admin user: {e}")
        
        # Setup scheduler for background tasks
        if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
            logger.info("Setting up background scheduler...")
            scheduler = BackgroundScheduler(timezone=app.config['SCHEDULER_TIMEZONE'])
            
            # URLHaus ingestion every 30 minutes
            urlhaus_fetcher = URLHausFetcher()
            scheduler.add_job(
                func=urlhaus_fetcher.fetch_and_ingest,
                trigger=IntervalTrigger(minutes=30),
                id='urlhaus_ingestion',
                name='URLHaus Feed Ingestion',
                replace_existing=True
            )
            
            scheduler.start()
            logger.info("Background scheduler started")
            
            # Shut down the scheduler when exiting the app
            atexit.register(lambda: scheduler.shutdown())
        
        logger.info("CTI Dashboard application initialized successfully")
        return app
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise


if __name__ == '__main__':
    try:
        app = create_app()
        port = int(os.environ.get('PORT', 8080))
        logger.info(f"Starting CTI Dashboard server on 0.0.0.0:{port}")
        app.run(debug=False, host='0.0.0.0', port=port)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
