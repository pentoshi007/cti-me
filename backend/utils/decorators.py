"""
Utility decorators for authentication and authorization
"""
from functools import wraps
from flask import abort
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from auth.models import User


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure a valid JWT is present for protected routes
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            if not current_user_id:
                abort(401, 'Authentication required')
            
            user = User.find_by_id(current_user_id)
            if not user:
                abort(401, 'User not found')
            
            if not user.has_permission(permission):
                abort(403, f'Permission denied: {permission} required')
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_current_user():
    """Get current authenticated user"""
    try:
        # Allow requests without JWT (public endpoints)
        verify_jwt_in_request(optional=True)
        current_user_id = get_jwt_identity()
    except Exception:
        current_user_id = None

    if current_user_id:
        return User.find_by_id(current_user_id)
    return None
