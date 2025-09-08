"""
Authentication API routes
"""
from datetime import datetime, timedelta
from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt
)

from auth.models import User
from utils.decorators import require_permission, get_current_user

auth_bp = Blueprint('auth', __name__)

# No model definitions needed for standard Flask routes


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'viewer').lower()
        
    # Validation
    if not username or len(username) < 3 or len(username) > 50:
        return jsonify({'error': 'Username must be 3-50 characters long'}), 400

    if not email or '@' not in email:
        return jsonify({'error': 'Valid email address required'}), 400

    if not password or len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400

    # Validate role
    if role not in ['admin', 'analyst', 'viewer']:
        role = 'viewer'  # Default to viewer for invalid roles

    # Only admins can create admin users
    if role == 'admin':
        current_user = get_current_user()
        if not current_user or not current_user.has_permission('admin'):
            role = 'viewer'  # Downgrade to viewer if not admin

    # Check if user already exists
    if User.find_by_username(username):
        return jsonify({'error': 'Username already exists'}), 409

    if User.find_by_email(email):
        return jsonify({'error': 'Email already registered'}), 409

    # Create new user
    try:
        user = User(
            username=username,
            email=email,
            role=role
        )
        user.set_password(password)
        user.save()

        # Update last login
        user.last_login = datetime.utcnow()
        user.save()

        # Create tokens
        access_token = create_access_token(identity=str(user._id))
        refresh_token = create_refresh_token(identity=str(user._id))

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        })

    except Exception as e:
        return jsonify({'error': f'User registration failed: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT tokens"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.find_by_username(username)
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Update last login
    user.last_login = datetime.utcnow()
    user.save()
    
    # Create tokens
    access_token = create_access_token(identity=str(user._id))
    refresh_token = create_refresh_token(identity=str(user._id))
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    })


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Refresh token endpoint called")
        
        # Get current user from refresh token
        current_user_id = get_jwt_identity()
        logger.info(f"Extracted user ID from refresh token: {current_user_id}")
        
        if not current_user_id:
            logger.error("No user ID found in refresh token")
            return jsonify({'error': 'Invalid refresh token - no user identity'}), 401
        
        user = User.find_by_id(current_user_id)
        if not user:
            logger.error(f"User not found for ID: {current_user_id}")
            return jsonify({'error': 'User not found'}), 401
        
        logger.info(f"Creating new tokens for user: {user.username}")
        
        # Create new access token
        access_token = create_access_token(identity=current_user_id)
        # Also create a new refresh token to extend session
        refresh_token = create_refresh_token(identity=current_user_id)
        
        logger.info("Token refresh successful")
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Token refresh failed with exception: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Token refresh failed: {str(e)}'}), 422

