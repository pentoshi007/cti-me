"""
Export models and utilities
"""
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional
from bson import ObjectId
from database import MongoDB
from config import Config


class Export:
    """Export request model"""
    
    FORMATS = ['csv']
    STATUSES = ['pending', 'processing', 'completed', 'error']
    
    def __init__(self, export_format: str, query: Dict, created_by: str,
                 status: str = 'pending', file_url: str = None,
                 row_count: int = None, error: str = None,
                 created_at: datetime = None, finished_at: datetime = None,
                 _id: str = None):
        self.format = export_format
        self.query = query
        self.created_by = created_by
        self.status = status
        self.file_url = file_url
        self.row_count = row_count
        self.error = error
        self.created_at = created_at or datetime.utcnow()
        self.finished_at = finished_at
        self._id = _id
    
    def to_dict(self) -> Dict:
        """Convert export to dictionary"""
        return {
            'id': str(self._id) if self._id else None,
            'format': self.format,
            'query': self.query,
            'created_by': self.created_by,
            'status': self.status,
            'file_url': self.file_url,
            'row_count': self.row_count,
            'error': self.error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'finished_at': self.finished_at.isoformat() if self.finished_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Export':
        """Create export from dictionary"""
        return cls(
            export_format=data['format'],
            query=data['query'],
            created_by=data['created_by'],
            status=data.get('status', 'pending'),
            file_url=data.get('file_url'),
            row_count=data.get('row_count'),
            error=data.get('error'),
            created_at=data.get('created_at'),
            finished_at=data.get('finished_at'),
            _id=data.get('_id')
        )
    
    def save(self) -> str:
        """Save export to database"""
        exports = MongoDB.get_collection('exports')
        
        export_data = {
            'format': self.format,
            'query': self.query,
            'created_by': self.created_by,
            'status': self.status,
            'file_url': self.file_url,
            'row_count': self.row_count,
            'error': self.error,
            'created_at': self.created_at,
            'finished_at': self.finished_at
        }
        
        if self._id:
            exports.update_one({'_id': self._id}, {'$set': export_data})
            return str(self._id)
        else:
            result = exports.insert_one(export_data)
            self._id = result.inserted_id
            return str(self._id)
    
    @classmethod
    def find_by_id(cls, export_id: str) -> Optional['Export']:
        """Find export by ID"""
        exports = MongoDB.get_collection('exports')
        try:
            export_data = exports.find_one({'_id': ObjectId(export_id)})
            if export_data:
                return cls.from_dict(export_data)
        except:
            pass
        return None
    
    def mark_processing(self):
        """Mark export as processing"""
        self.status = 'processing'
        self.save()
    
    def mark_completed(self, file_url: str, row_count: int):
        """Mark export as completed"""
        self.status = 'completed'
        self.file_url = file_url
        self.row_count = row_count
        self.finished_at = datetime.utcnow()
        self.save()
    
    def mark_error(self, error: str):
        """Mark export as failed"""
        self.status = 'error'
        self.error = error
        self.finished_at = datetime.utcnow()
        self.save()
    
    def generate_csv(self) -> str:
        """Generate CSV file from IOC query"""
        from iocs.models import IOC
        
        # Ensure export directory exists
        os.makedirs(Config.EXPORT_DIR, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"iocs_export_{timestamp}_{self._id}.csv"
        filepath = os.path.join(Config.EXPORT_DIR, filename)
        
        try:
            self.mark_processing()
            
            # Execute query
            iocs, total = IOC.search(query=self.query, limit=100000)  # Large limit for export
            
            # Write CSV
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'id', 'type', 'value', 'severity', 'score', 'tags',
                    'first_seen', 'last_seen', 'sources', 'vt_positives',
                    'vt_total', 'abuseipdb_score', 'created_at', 'updated_at'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for ioc in iocs:
                    # Prepare row data
                    row = {
                        'id': str(ioc._id),
                        'type': ioc.type,
                        'value': ioc.value,
                        'severity': ioc.severity,
                        'score': ioc.score,
                        'tags': ','.join(ioc.tags),
                        'first_seen': ioc.first_seen.isoformat() if ioc.first_seen else '',
                        'last_seen': ioc.last_seen.isoformat() if ioc.last_seen else '',
                        'sources': ','.join([s['name'] for s in ioc.sources]),
                        'vt_positives': ioc.vt.get('positives', ''),
                        'vt_total': ioc.vt.get('total', ''),
                        'abuseipdb_score': ioc.abuseipdb.get('abuseConfidenceScore', ''),
                        'created_at': ioc.created_at.isoformat() if ioc.created_at else '',
                        'updated_at': ioc.updated_at.isoformat() if ioc.updated_at else ''
                    }
                    writer.writerow(row)
            
            # Return relative file path
            file_url = f"/api/exports/{self._id}/download"
            self.mark_completed(file_url, len(iocs))
            
            return filepath
            
        except Exception as e:
            self.mark_error(str(e))
            raise e
