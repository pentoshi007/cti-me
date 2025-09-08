"""
Lookup models and utilities
"""
from datetime import datetime
from typing import Dict, Optional
from bson import ObjectId
from database import MongoDB


class Lookup:
    """Lookup request model"""
    
    STATUSES = ['pending', 'done', 'error']
    
    def __init__(self, indicator: Dict, user_id: str, status: str = 'pending',
                 started_at: datetime = None, finished_at: datetime = None,
                 result_indicator_id: str = None, error: str = None,
                 _id: str = None):
        self.indicator = indicator  # {'type': str, 'value': str}
        self.user_id = user_id
        self.status = status
        self.started_at = started_at or datetime.utcnow()
        self.finished_at = finished_at
        self.result_indicator_id = result_indicator_id
        self.error = error
        self._id = _id
    
    def to_dict(self) -> Dict:
        """Convert lookup to dictionary"""
        return {
            'id': str(self._id) if self._id else None,
            'indicator': self.indicator,
            'user_id': self.user_id,
            'status': self.status,
            'started_at': self.started_at.isoformat() if isinstance(self.started_at, datetime) else self.started_at,
            'finished_at': self.finished_at.isoformat() if isinstance(self.finished_at, datetime) else self.finished_at,
            'result_indicator_id': self.result_indicator_id,
            'error': self.error
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Lookup':
        """Create lookup from dictionary"""
        # Handle datetime parsing
        def parse_datetime(dt_str):
            if isinstance(dt_str, datetime):
                return dt_str
            elif isinstance(dt_str, str):
                try:
                    return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    return None
            return dt_str
        
        return cls(
            indicator=data['indicator'],
            user_id=data['user_id'],
            status=data.get('status', 'pending'),
            started_at=parse_datetime(data.get('started_at')),
            finished_at=parse_datetime(data.get('finished_at')),
            result_indicator_id=data.get('result_indicator_id'),
            error=data.get('error'),
            _id=data.get('_id')
        )
    
    def save(self) -> str:
        """Save lookup to database"""
        lookups = MongoDB.get_collection('lookups')
        
        lookup_data = {
            'indicator': self.indicator,
            'user_id': self.user_id,
            'status': self.status,
            'started_at': self.started_at,
            'finished_at': self.finished_at,
            'result_indicator_id': self.result_indicator_id,
            'error': self.error,
            'created_at': datetime.utcnow()  # For TTL index
        }
        
        if self._id:
            lookups.update_one({'_id': self._id}, {'$set': lookup_data})
            return str(self._id)
        else:
            result = lookups.insert_one(lookup_data)
            self._id = result.inserted_id
            return str(self._id)
    
    @classmethod
    def find_by_id(cls, lookup_id: str) -> Optional['Lookup']:
        """Find lookup by ID"""
        lookups = MongoDB.get_collection('lookups')
        try:
            lookup_data = lookups.find_one({'_id': ObjectId(lookup_id)})
            if lookup_data:
                return cls.from_dict(lookup_data)
        except:
            pass
        return None
    
    def mark_done(self, result_indicator_id: str = None):
        """Mark lookup as completed"""
        self.status = 'done'
        self.finished_at = datetime.utcnow()
        self.result_indicator_id = result_indicator_id
        self.save()
    
    def mark_error(self, error: str):
        """Mark lookup as failed"""
        self.status = 'error'
        self.finished_at = datetime.utcnow()
        self.error = error
        self.save()
