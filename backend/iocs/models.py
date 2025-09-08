"""
IOC (Indicator of Compromise) models and utilities
"""
from datetime import datetime
from typing import Dict, List, Optional, Any
from bson import ObjectId
from database import MongoDB
import re


class IOC:
    """Indicator of Compromise model"""
    
    IOC_TYPES = ['ip', 'domain', 'url', 'sha256', 'md5', 'sha1']
    SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
    
    def __init__(self, ioc_type: str, value: str, sources: List[Dict] = None,
                 score: int = 0, severity: str = 'info', vt: Dict = None,
                 abuseipdb: Dict = None, tags: List[str] = None,
                 first_seen: datetime = None, last_seen: datetime = None,
                 created_at: datetime = None, updated_at: datetime = None,
                 _id: str = None):
        self.type = ioc_type.lower()
        self.value = value
        self.sources = sources or []
        self.score = score
        self.severity = severity
        self.vt = vt or {}
        self.abuseipdb = abuseipdb or {}
        self.tags = tags or []
        self.first_seen = first_seen or datetime.utcnow()
        self.last_seen = last_seen or datetime.utcnow()
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
        self._id = _id
    
    @staticmethod
    def detect_type(value: str) -> str:
        """Auto-detect IOC type from value"""
        # Remove whitespace
        value = value.strip()
        
        # IP address pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, value):
            return 'ip'
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'sha256'
        
        # URL pattern
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # Domain pattern (simple check)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, value) and '.' in value:
            return 'domain'
        
        return 'unknown'
    
    def calculate_score(self) -> int:
        """Calculate threat score (0-100) based on various factors"""
        score = 0
        
        # Base score from number of sources
        source_score = min(len(self.sources) * 10, 30)
        score += source_score
        
        # Recency score (more recent = higher score)
        if self.last_seen:
            hours_ago = (datetime.utcnow() - self.last_seen).total_seconds() / 3600
            if hours_ago < 24:
                score += 20
            elif hours_ago < 168:  # 1 week
                score += 15
            elif hours_ago < 720:  # 30 days
                score += 10
        
        # VirusTotal score
        if self.vt.get('positives') and self.vt.get('total'):
            vt_ratio = self.vt['positives'] / self.vt['total']
            score += int(vt_ratio * 30)
        
        # AbuseIPDB score (for IPs) - Enhanced scoring
        if self.type == 'ip' and self.abuseipdb and isinstance(self.abuseipdb, dict):
            abuse_confidence = self.abuseipdb.get('abuse_confidence', 0)
            if abuse_confidence >= 90:
                score += 20
            elif abuse_confidence >= 75:
                score += 15
            elif abuse_confidence >= 50:
                score += 10
            elif abuse_confidence >= 25:
                score += 5
            elif abuse_confidence > 0:
                score += 2
        
        return min(score, 100)
    
    def update_severity(self):
        """Update severity based on score"""
        if self.score >= 85:
            self.severity = 'critical'
        elif self.score >= 70:
            self.severity = 'high'
        elif self.score >= 50:
            self.severity = 'medium'
        elif self.score >= 25:
            self.severity = 'low'
        else:
            self.severity = 'info'
    
    def add_source(self, source_name: str, reference: str = None):
        """Add a source to the IOC"""
        now = datetime.utcnow()
        now_iso = now.isoformat()
        
        # Check if source already exists
        for source in self.sources:
            if source['name'] == source_name:
                source['last_seen'] = now_iso
                return
        
        # Add new source
        self.sources.append({
            'name': source_name,
            'first_seen': now_iso,
            'last_seen': now_iso,
            'ref': reference
        })
        self.last_seen = now
    
    def add_tag(self, tag: str):
        """Add a tag to the IOC"""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str):
        """Remove a tag from the IOC"""
        if tag in self.tags:
            self.tags.remove(tag)
    
    def to_dict(self) -> Dict:
        """Convert IOC to dictionary"""
        def safe_datetime_to_string(dt):
            """Safely convert datetime to ISO string"""
            if isinstance(dt, datetime):
                return dt.isoformat()
            elif isinstance(dt, str):
                return dt
            else:
                return str(dt) if dt is not None else None
        
        def deep_serialize_datetime(obj):
            """Recursively serialize datetime objects in nested structures"""
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {key: deep_serialize_datetime(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [deep_serialize_datetime(item) for item in obj]
            else:
                return obj
        
        # Process sources to ensure datetime fields are serializable
        safe_sources = []
        for source in self.sources:
            safe_source = {}
            for key, value in source.items():
                if key in ['first_seen', 'last_seen'] and isinstance(value, datetime):
                    safe_source[key] = value.isoformat()
                else:
                    safe_source[key] = value
            safe_sources.append(safe_source)
        
        return {
            'id': str(self._id) if self._id else None,
            'type': self.type,
            'value': self.value,
            'sources': safe_sources,
            'score': self.score,
            'severity': self.severity,
            'vt': deep_serialize_datetime(self.vt),
            'abuseipdb': deep_serialize_datetime(self.abuseipdb),
            'tags': self.tags,
            'first_seen': safe_datetime_to_string(self.first_seen),
            'last_seen': safe_datetime_to_string(self.last_seen),
            'created_at': safe_datetime_to_string(self.created_at),
            'updated_at': safe_datetime_to_string(self.updated_at)
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'IOC':
        """Create IOC from dictionary"""
        # Handle datetime parsing
        def parse_datetime(dt_str):
            if isinstance(dt_str, datetime):
                return dt_str
            elif isinstance(dt_str, str):
                try:
                    return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    return datetime.utcnow()
            return dt_str
        
        return cls(
            ioc_type=data['type'],
            value=data['value'],
            sources=data.get('sources', []),
            score=data.get('score', 0),
            severity=data.get('severity', 'info'),
            vt=data.get('vt', {}),
            abuseipdb=data.get('abuseipdb', {}),
            tags=data.get('tags', []),
            first_seen=parse_datetime(data.get('first_seen')),
            last_seen=parse_datetime(data.get('last_seen')),
            created_at=parse_datetime(data.get('created_at')),
            updated_at=parse_datetime(data.get('updated_at')),
            _id=data.get('_id')
        )
    
    def save(self) -> str:
        """Save IOC to database (upsert by type and value)"""
        indicators = MongoDB.get_collection('indicators')
        
        # Update timestamps
        self.updated_at = datetime.utcnow()
        if not self._id:
            self.created_at = datetime.utcnow()
        
        # Recalculate score and severity
        self.score = self.calculate_score()
        self.update_severity()
        
        ioc_data = {
            'type': self.type,
            'value': self.value,
            'sources': self.sources,
            'score': self.score,
            'severity': self.severity,
            'vt': self.vt,
            'abuseipdb': self.abuseipdb,
            'tags': self.tags,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
        
        # Upsert by type and value
        result = indicators.update_one(
            {'type': self.type, 'value': self.value},
            {'$set': ioc_data},
            upsert=True
        )
        
        if result.upserted_id:
            self._id = result.upserted_id
        elif not self._id:
            # Find the existing document
            doc = indicators.find_one({'type': self.type, 'value': self.value})
            if doc:
                self._id = doc['_id']
        
        return str(self._id)
    
    @classmethod
    def find_by_id(cls, ioc_id: str) -> Optional['IOC']:
        """Find IOC by ID"""
        indicators = MongoDB.get_collection('indicators')
        try:
            ioc_data = indicators.find_one({'_id': ObjectId(ioc_id)})
            if ioc_data:
                return cls.from_dict(ioc_data)
        except:
            pass
        return None
    
    @classmethod
    def find_by_value(cls, ioc_type: str, value: str) -> Optional['IOC']:
        """Find IOC by type and value"""
        indicators = MongoDB.get_collection('indicators')
        ioc_data = indicators.find_one({'type': ioc_type, 'value': value})
        if ioc_data:
            return cls.from_dict(ioc_data)
        return None
    
    @classmethod
    def search(cls, query: Dict = None, sort: List = None, skip: int = 0, 
               limit: int = 50) -> tuple[List['IOC'], int]:
        """Search IOCs with pagination"""
        indicators = MongoDB.get_collection('indicators')
        
        if query is None:
            query = {}
        
        if sort is None:
            sort = [('last_seen', -1)]
        
        # Get total count
        total = indicators.count_documents(query)
        
        # Get results
        cursor = indicators.find(query).sort(sort).skip(skip).limit(limit)
        iocs = [cls.from_dict(doc) for doc in cursor]
        
        return iocs, total
