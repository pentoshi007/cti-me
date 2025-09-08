"""
Tag models and utilities
"""
from datetime import datetime
from typing import Dict, List, Optional
from bson import ObjectId
from database import MongoDB


class Tag:
    """Tag model for categorizing IOCs"""
    
    def __init__(self, name: str, color: str = None, description: str = None,
                 created_by: str = None, created_at: datetime = None, _id: str = None):
        self.name = name.lower().strip()
        self.color = color or '#6B7280'  # Default gray color
        self.description = description
        self.created_by = created_by
        self.created_at = created_at or datetime.utcnow()
        self._id = _id
    
    def to_dict(self) -> Dict:
        """Convert tag to dictionary"""
        return {
            'id': str(self._id) if self._id else None,
            'name': self.name,
            'color': self.color,
            'description': self.description,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Tag':
        """Create tag from dictionary"""
        return cls(
            name=data['name'],
            color=data.get('color'),
            description=data.get('description'),
            created_by=data.get('created_by'),
            created_at=data.get('created_at'),
            _id=data.get('_id')
        )
    
    def save(self) -> str:
        """Save tag to database"""
        tags = MongoDB.get_collection('tags')
        
        tag_data = {
            'name': self.name,
            'color': self.color,
            'description': self.description,
            'created_by': self.created_by,
            'created_at': self.created_at
        }
        
        if self._id:
            tags.update_one({'_id': self._id}, {'$set': tag_data})
            return str(self._id)
        else:
            result = tags.insert_one(tag_data)
            self._id = result.inserted_id
            return str(self._id)
    
    @classmethod
    def find_by_id(cls, tag_id: str) -> Optional['Tag']:
        """Find tag by ID"""
        tags = MongoDB.get_collection('tags')
        try:
            tag_data = tags.find_one({'_id': ObjectId(tag_id)})
            if tag_data:
                return cls.from_dict(tag_data)
        except:
            pass
        return None
    
    @classmethod
    def find_by_name(cls, name: str) -> Optional['Tag']:
        """Find tag by name"""
        tags = MongoDB.get_collection('tags')
        tag_data = tags.find_one({'name': name.lower().strip()})
        if tag_data:
            return cls.from_dict(tag_data)
        return None
    
    @classmethod
    def list_all(cls, sort_by: str = 'name') -> List['Tag']:
        """List all tags"""
        tags = MongoDB.get_collection('tags')
        
        sort_direction = 1  # ascending
        if sort_by == 'created_at':
            sort_direction = -1  # descending for dates
        
        cursor = tags.find().sort(sort_by, sort_direction)
        return [cls.from_dict(doc) for doc in cursor]
    
    @classmethod
    def search(cls, query: str = None) -> List['Tag']:
        """Search tags by name or description"""
        tags = MongoDB.get_collection('tags')
        
        if query:
            search_query = {
                '$or': [
                    {'name': {'$regex': query, '$options': 'i'}},
                    {'description': {'$regex': query, '$options': 'i'}}
                ]
            }
            cursor = tags.find(search_query).sort('name', 1)
        else:
            cursor = tags.find().sort('name', 1)
        
        return [cls.from_dict(doc) for doc in cursor]
    
    def delete(self) -> bool:
        """Delete tag from database"""
        if not self._id:
            return False
        
        tags = MongoDB.get_collection('tags')
        result = tags.delete_one({'_id': self._id})
        return result.deleted_count > 0
    
    @classmethod
    def get_tag_usage_stats(cls) -> Dict[str, int]:
        """Get statistics about tag usage across IOCs"""
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        
        # Aggregate tag usage
        pipeline = [
            {'$unwind': '$tags'},
            {'$group': {'_id': '$tags', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        
        result = indicators.aggregate(pipeline)
        return {doc['_id']: doc['count'] for doc in result}
