"""
Authentication API routes
"""
from datetime import datetime, timedelta
from flask import request
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt
)

from auth.models import User
from utils.decorators import require_permission, get_current_user

auth_ns = Namespace('auth', description='Authentication operations')

# API Models
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})

register_model = auth_ns.model('Register', {
    'username': fields.String(required=True, description='Username (3-50 characters)'),
    'email': fields.String(required=True, description='Valid email address'),
    'password': fields.String(required=True, description='Password (minimum 8 characters)'),
    'role': fields.String(description='User role (admin only)', enum=['admin', 'analyst', 'viewer'])
})

token_response = auth_ns.model('TokenResponse', {
    'access_token': fields.String(description='JWT access token'),
    'refresh_token': fields.String(description='JWT refresh token'),
    'user': fields.Raw(description='User information')
})

refresh_model = auth_ns.model('RefreshToken', {
    'refresh_token': fields.String(required=True, description='Refresh token')
})

user_model = auth_ns.model('User', {
    'id': fields.String(description='User ID'),
    'username': fields.String(description='Username'),
    'email': fields.String(description='Email'),
    'role': fields.String(description='User role'),
    'permissions': fields.List(fields.String, description='User permissions'),
    'created_at': fields.String(description='Creation timestamp'),
    'last_login': fields.String(description='Last login timestamp')
})

password_reset_request_model = auth_ns.model('PasswordResetRequest', {
    'email': fields.String(required=True, description='Email address for password reset')
})

password_reset_model = auth_ns.model('PasswordReset', {
    'email': fields.String(required=True, description='Email address'),
    'reset_code': fields.String(required=True, description='6-digit reset code'),
    'new_password': fields.String(required=True, description='New password')
})

change_password_model = auth_ns.model('ChangePassword', {
    'current_password': fields.String(required=True, description='Current password'),
    'new_password': fields.String(required=True, description='New password')
})


@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model)
    @auth_ns.marshal_with(token_response)
    def post(self):
        """Register a new user"""
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'viewer').lower()
        
        # Validation
        if not username or len(username) < 3 or len(username) > 50:
            auth_ns.abort(400, 'Username must be 3-50 characters long')
        
        if not email or '@' not in email:
            auth_ns.abort(400, 'Valid email address required')
        
        if not password or len(password) < 8:
            auth_ns.abort(400, 'Password must be at least 8 characters long')
        
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
            auth_ns.abort(409, 'Username already exists')
        
        if User.find_by_email(email):
            auth_ns.abort(409, 'Email already registered')
        
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
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user.to_dict()
            }
            
        except Exception as e:
            auth_ns.abort(500, f'User registration failed: {str(e)}')


@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.marshal_with(token_response)
    def post(self):
        """Authenticate user and return JWT tokens"""
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            auth_ns.abort(400, 'Username and password required')
        
        user = User.find_by_username(username)
        if not user or not user.check_password(password):
            auth_ns.abort(401, 'Invalid credentials')
        
        # Update last login
        user.last_login = datetime.utcnow()
        user.save()
        
        # Create tokens
        access_token = create_access_token(identity=str(user._id))
        refresh_token = create_refresh_token(identity=str(user._id))
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }


@auth_ns.route('/refresh')
class RefreshToken(Resource):
    @jwt_required(refresh=True)
    @auth_ns.marshal_with(token_response)
    def post(self):
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
                auth_ns.abort(401, 'Invalid refresh token - no user identity')
            
            user = User.find_by_id(current_user_id)
            if not user:
                logger.error(f"User not found for ID: {current_user_id}")
                auth_ns.abort(401, 'User not found')
            
            logger.info(f"Creating new tokens for user: {user.username}")
            
            # Create new access token
            access_token = create_access_token(identity=current_user_id)
            # Also create a new refresh token to extend session
            refresh_token = create_refresh_token(identity=current_user_id)
            
            logger.info("Token refresh successful")
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user.to_dict()
            }
            
        except Exception as e:
            logger.error(f"Token refresh failed with exception: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            auth_ns.abort(422, f'Token refresh failed: {str(e)}')


@auth_ns.route('/refresh-debug')
class RefreshTokenDebug(Resource):
    def post(self):
        """Debug refresh token issues by manually checking the token"""
        import logging
        from flask_jwt_extended import decode_token
        logger = logging.getLogger(__name__)
        
        try:
            # Get the Authorization header
            auth_header = request.headers.get('Authorization', '')
            logger.info(f"Authorization header: {auth_header[:50]}...")
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return {'error': 'Missing or invalid Authorization header'}, 400
            
            token = auth_header.split(' ')[1]
            logger.info(f"Extracted token: {token[:20]}...")
            
            # Try to decode the token manually
            try:
                decoded_token = decode_token(token)
                logger.info(f"Decoded token: {decoded_token}")
                
                # Check if it's a refresh token
                if decoded_token.get('type') != 'refresh':
                    return {'error': 'Token is not a refresh token'}, 400
                
                user_id = decoded_token.get('sub')
                if not user_id:
                    return {'error': 'No user ID in token'}, 400
                
                # Check if user exists
                user = User.find_by_id(user_id)
                if not user:
                    return {'error': f'User not found: {user_id}'}, 404
                
                return {
                    'status': 'success',
                    'user_id': user_id,
                    'username': user.username,
                    'token_type': decoded_token.get('type'),
                    'token_exp': decoded_token.get('exp')
                }
                
            except Exception as decode_error:
                logger.error(f"Token decode error: {decode_error}")
                return {'error': f'Token decode failed: {str(decode_error)}'}, 422
                
        except Exception as e:
            logger.error(f"Debug refresh failed: {e}")
            return {'error': f'Debug failed: {str(e)}'}, 500


@auth_ns.route('/change-password')
class ChangePassword(Resource):
    @jwt_required()
    @auth_ns.expect(auth_ns.model('ChangePassword', {
        'current_password': fields.String(required=True, description='Current password'),
        'new_password': fields.String(required=True, description='New password'),
    }))
    def post(self):
        """Change user password"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            current_user_id = get_jwt_identity()
            user = User.find_by_id(current_user_id)
            
            if not user:
                auth_ns.abort(404, 'User not found')
            
            data = request.get_json()
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            
            if not current_password or not new_password:
                auth_ns.abort(400, 'Current password and new password are required')
            
            # Verify current password
            if not user.check_password(current_password):
                auth_ns.abort(400, 'Current password is incorrect')
            
            # Validate new password
            if len(new_password) < 8:
                auth_ns.abort(400, 'New password must be at least 8 characters long')
            
            # Update password
            user.set_password(new_password)
            user.save()
            
            logger.info(f"Password changed successfully for user: {user.username}")
            
            return {
                'message': 'Password changed successfully',
                'success': True
            }, 200
            
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            auth_ns.abort(500, f'Password change failed: {str(e)}')


@auth_ns.route('/me')
class UserProfile(Resource):
    @jwt_required()
    @auth_ns.marshal_with(user_model)
    def get(self):
        """Get current user profile"""
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user:
            auth_ns.abort(401, 'User not found')
        
        return user.to_dict()


@auth_ns.route('/logout')
class Logout(Resource):
    @jwt_required()
    def post(self):
        """Logout user (client should discard tokens)"""
        # In a production app, you might want to blacklist the token
        return {'message': 'Successfully logged out'}


@auth_ns.route('/password-reset/request')
class PasswordResetRequest(Resource):
    @auth_ns.expect(password_reset_request_model)
    def post(self):
        """Request password reset"""
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            auth_ns.abort(400, 'Email is required')
        
        user = User.find_by_email(email)
        if not user:
            # Don't reveal if email exists or not for security
            return {'message': 'If this email is registered, you will receive a reset code.'}
        
        # Generate 6-digit reset code
        import random
        reset_code = f"{random.randint(100000, 999999)}"
        
        # Store reset code in user record (expires in 15 minutes)
        from database import MongoDB
        users = MongoDB.get_collection('users')
        users.update_one(
            {'_id': user._id},
            {
                '$set': {
                    'reset_code': reset_code,
                    'reset_code_expires': datetime.utcnow() + timedelta(minutes=15)
                }
            }
        )
        
        # In a real app, you would send this via email
        # For demo purposes, we'll return it in the response
        print(f"Password reset code for {email}: {reset_code}")
        
        return {
            'message': 'If this email is registered, you will receive a reset code.',
            'demo_reset_code': reset_code  # Remove this in production
        }


@auth_ns.route('/password-reset/verify')
class PasswordResetVerify(Resource):
    @auth_ns.expect(password_reset_model)
    def post(self):
        """Reset password with code"""
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        reset_code = data.get('reset_code', '').strip()
        new_password = data.get('new_password', '')
        
        if not email or not reset_code or not new_password:
            auth_ns.abort(400, 'Email, reset code, and new password are required')
        
        if len(new_password) < 8:
            auth_ns.abort(400, 'New password must be at least 8 characters long')
        
        user = User.find_by_email(email)
        if not user:
            auth_ns.abort(400, 'Invalid reset request')
        
        # Get user data with reset code info
        from database import MongoDB
        users = MongoDB.get_collection('users')
        user_data = users.find_one({'_id': user._id})
        
        if not user_data or not user_data.get('reset_code'):
            auth_ns.abort(400, 'Invalid or expired reset code')
        
        # Check if code matches and hasn't expired
        if (user_data['reset_code'] != reset_code or 
            user_data.get('reset_code_expires', datetime.min) < datetime.utcnow()):
            auth_ns.abort(400, 'Invalid or expired reset code')
        
        # Reset password and clear reset code
        user.set_password(new_password)
        users.update_one(
            {'_id': user._id},
            {
                '$set': {'password_hash': user.password_hash},
                '$unset': {'reset_code': '', 'reset_code_expires': ''}
            }
        )
        
        return {'message': 'Password reset successfully'}


@auth_ns.route('/change-password')
class ChangePassword(Resource):
    @jwt_required()
    @auth_ns.expect(change_password_model)
    def post(self):
        """Change password for authenticated user"""
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user:
            auth_ns.abort(401, 'User not found')
        
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            auth_ns.abort(400, 'Current password and new password are required')
        
        if len(new_password) < 8:
            auth_ns.abort(400, 'New password must be at least 8 characters long')
        
        # Verify current password
        if not user.check_password(current_password):
            auth_ns.abort(400, 'Current password is incorrect')
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        return {'message': 'Password changed successfully'}


# Initialize default admin user when module loads
def init_default_users():
    """Initialize default users if database is empty"""
    try:
        User.create_default_admin()
    except Exception as e:
        print(f"Error creating default admin user: {e}")

# Call initialization
init_default_users()
