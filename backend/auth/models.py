"""
User authentication models and utilities
"""
from datetime import datetime
from typing import Dict, List, Optional
from werkzeug.security import check_password_hash, generate_password_hash
from database import MongoDB


class User:
    """User model for authentication and authorization"""
    
    ROLES = {
        'admin': ['read', 'write', 'tag', 'export', 'lookup', 'admin'],
        'analyst': ['read', 'tag', 'export', 'lookup'],
        'viewer': ['read', 'tag', 'lookup']  # Added 'tag' permission for viewers when logged in
    }
    
    def __init__(self, username: str, email: str, role: str = 'viewer', 
                 password_hash: str = None, created_at: datetime = None, 
                 last_login: datetime = None, _id: str = None):
        self.username = username
        self.email = email
        self.role = role
        self.password_hash = password_hash
        self.created_at = created_at or datetime.utcnow()
        self.last_login = last_login
        self._id = _id
    
    def set_password(self, password: str):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Check if provided password is correct"""
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        return permission in self.ROLES.get(self.role, [])
    
    def get_permissions(self) -> List[str]:
        """Get all permissions for user role"""
        return self.ROLES.get(self.role, [])
    
    def to_dict(self) -> Dict:
        """Convert user to dictionary (without password hash)"""
        return {
            'id': str(self._id) if self._id else None,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'permissions': self.get_permissions(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """Create user from dictionary"""
        return cls(
            username=data['username'],
            email=data['email'],
            role=data.get('role', 'viewer'),
            password_hash=data.get('password_hash'),
            created_at=data.get('created_at'),
            last_login=data.get('last_login'),
            _id=data.get('_id')
        )
    
    def save(self) -> str:
        """Save user to database"""
        users = MongoDB.get_collection('users')
        user_data = {
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'password_hash': self.password_hash,
            'created_at': self.created_at,
            'last_login': self.last_login
        }
        
        if self._id:
            users.update_one({'_id': self._id}, {'$set': user_data})
            return str(self._id)
        else:
            result = users.insert_one(user_data)
            self._id = result.inserted_id
            return str(self._id)
    
    @classmethod
    def find_by_username(cls, username: str) -> Optional['User']:
        """Find user by username"""
        users = MongoDB.get_collection('users')
        user_data = users.find_one({'username': username})
        if user_data:
            return cls.from_dict(user_data)
        return None
    
    @classmethod
    def find_by_email(cls, email: str) -> Optional['User']:
        """Find user by email"""
        users = MongoDB.get_collection('users')
        user_data = users.find_one({'email': email.lower()})
        if user_data:
            return cls.from_dict(user_data)
        return None
    
    @classmethod
    def find_by_id(cls, user_id: str) -> Optional['User']:
        """Find user by ID"""
        from bson import ObjectId
        users = MongoDB.get_collection('users')
        try:
            user_data = users.find_one({'_id': ObjectId(user_id)})
            if user_data:
                return cls.from_dict(user_data)
        except:
            pass
        return None
    
    @classmethod
    def create_default_admin(cls):
        """Create default admin user if none exists"""
        users = MongoDB.get_collection('users')
        if users.count_documents({}) == 0:
            admin = cls(
                username='admin',
                email='admin@cti-dashboard.local',
                role='admin'
            )
            admin.set_password('admin123')  # Change this in production
            admin.save()
            print("Default admin user created: admin/admin123")
            return admin
        return None
