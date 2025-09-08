"""
IOC API routes
"""
from datetime import datetime
from flask import request
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import jwt_required
from bson import ObjectId

from iocs.models import IOC
from utils.decorators import require_permission, get_current_user

iocs_ns = Namespace('iocs', description='IOC operations')

# API Models
ioc_model = iocs_ns.model('IOC', {
    'id': fields.String(description='IOC ID'),
    'type': fields.String(description='IOC type', enum=['ip', 'domain', 'url', 'sha256', 'md5', 'sha1']),
    'value': fields.String(description='IOC value'),
    'sources': fields.List(fields.Raw, description='Sources that reported this IOC'),
    'score': fields.Integer(description='Threat score (0-100)'),
    'severity': fields.String(description='Severity level', enum=['info', 'low', 'medium', 'high', 'critical']),
    'vt': fields.Raw(description='VirusTotal data'),
    'abuseipdb': fields.Raw(description='AbuseIPDB data'),
    'tags': fields.List(fields.String, description='Tags'),
    'first_seen': fields.String(description='First seen timestamp'),
    'last_seen': fields.String(description='Last seen timestamp'),
    'created_at': fields.String(description='Creation timestamp'),
    'updated_at': fields.String(description='Update timestamp')
})

ioc_list_model = iocs_ns.model('IOCList', {
    'iocs': fields.List(fields.Nested(ioc_model)),
    'total': fields.Integer(description='Total number of IOCs'),
    'page': fields.Integer(description='Current page'),
    'pages': fields.Integer(description='Total pages'),
    'per_page': fields.Integer(description='Items per page')
})

ioc_create_model = iocs_ns.model('IOCCreate', {
    'type': fields.String(required=True, description='IOC type'),
    'value': fields.String(required=True, description='IOC value'),
    'tags': fields.List(fields.String, description='Initial tags')
})

tag_operation_model = iocs_ns.model('TagOperation', {
    'action': fields.String(required=True, enum=['add', 'remove'], description='Tag operation'),
    'tag': fields.String(required=True, description='Tag name')
})


@iocs_ns.route('')
class IOCList(Resource):
    @iocs_ns.marshal_with(ioc_list_model)
    @iocs_ns.doc(params={
        'q': 'Search query',
        'type': 'IOC type filter',
        'severity': 'Severity filter',
        'tags': 'Comma-separated tags',
        'from': 'Start date (YYYY-MM-DD)',
        'to': 'End date (YYYY-MM-DD)',
        'sort': 'Sort field (last_seen, score, created_at)',
        'order': 'Sort order (asc, desc)',
        'page': 'Page number (default: 1)',
        'per_page': 'Items per page (default: 50, max: 100)'
    })
    def get(self):
        """Get list of IOCs with filtering and pagination"""
        # Parse query parameters
        q = request.args.get('q', '').strip()
        ioc_type = request.args.get('type', '').strip()
        severity = request.args.get('severity', '').strip()
        tags = request.args.get('tags', '').strip()
        from_date = request.args.get('from', '').strip()
        to_date = request.args.get('to', '').strip()
        sort_param = request.args.get('sort', 'last_seen')
        sort_order = request.args.get('order', 'desc')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        
        # Handle sort parameter with colon notation (e.g., "created_at:desc")
        if ':' in sort_param:
            sort_field, sort_order = sort_param.split(':', 1)
        else:
            sort_field = sort_param
        
        # Build query
        query = {}
        
        if q:
            query['value'] = {'$regex': q, '$options': 'i'}
        
        if ioc_type and ioc_type in IOC.IOC_TYPES:
            query['type'] = ioc_type
        
        if severity and severity in IOC.SEVERITIES:
            query['severity'] = severity
        
        if tags:
            tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]
            if tag_list:
                query['tags'] = {'$in': tag_list}
        
        # Date range filter
        date_filter = {}
        if from_date:
            try:
                date_filter['$gte'] = datetime.fromisoformat(from_date)
            except ValueError:
                pass
        
        if to_date:
            try:
                date_filter['$lte'] = datetime.fromisoformat(to_date)
            except ValueError:
                pass
        
        if date_filter:
            query['last_seen'] = date_filter
        
        # Build sort
        sort_direction = -1 if sort_order == 'desc' else 1
        sort = [(sort_field, sort_direction)]
        
        # Calculate pagination
        skip = (page - 1) * per_page
        
        # Execute search
        iocs, total = IOC.search(query=query, sort=sort, skip=skip, limit=per_page)
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return {
            'iocs': [ioc.to_dict() for ioc in iocs],
            'total': total,
            'page': page,
            'pages': pages,
            'per_page': per_page
        }
    
    @jwt_required()
    @require_permission('write')
    @iocs_ns.expect(ioc_create_model)
    @iocs_ns.marshal_with(ioc_model)
    def post(self):
        """Create a new IOC"""
        data = request.get_json()
        
        ioc_type = data.get('type', '').lower()
        value = data.get('value', '').strip()
        tags = data.get('tags', [])
        
        if not value:
            iocs_ns.abort(400, 'IOC value is required')
        
        # Auto-detect type if not provided or invalid
        if not ioc_type or ioc_type not in IOC.IOC_TYPES:
            ioc_type = IOC.detect_type(value)
            if ioc_type == 'unknown':
                iocs_ns.abort(400, 'Invalid IOC type or value')
        
        # Check if IOC already exists
        existing_ioc = IOC.find_by_value(ioc_type, value)
        if existing_ioc:
            # Add manual source
            existing_ioc.add_source('manual', f'Added by user')
            for tag in tags:
                existing_ioc.add_tag(tag)
            existing_ioc.save()
            return existing_ioc.to_dict()
        
        # Create new IOC
        ioc = IOC(ioc_type=ioc_type, value=value, tags=tags)
        ioc.add_source('manual', f'Added by user')
        ioc.save()
        
        return ioc.to_dict()


@iocs_ns.route('/<string:ioc_id>')
class IOCDetail(Resource):
    @iocs_ns.marshal_with(ioc_model)
    def get(self, ioc_id):
        """Get IOC by ID"""
        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            iocs_ns.abort(404, 'IOC not found')
        
        return ioc.to_dict()
    
    @jwt_required()
    @require_permission('tag')
    @iocs_ns.expect(tag_operation_model)
    @iocs_ns.marshal_with(ioc_model)
    def patch(self, ioc_id):
        """Apply or remove tags from IOC"""
        data = request.get_json()
        action = data.get('action')
        tag = data.get('tag', '').strip()
        
        if not tag:
            iocs_ns.abort(400, 'Tag name is required')
        
        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            iocs_ns.abort(404, 'IOC not found')
        
        if action == 'add':
            ioc.add_tag(tag)
        elif action == 'remove':
            ioc.remove_tag(tag)
        else:
            iocs_ns.abort(400, 'Invalid action. Use "add" or "remove"')
        
        ioc.save()
        return ioc.to_dict()


@iocs_ns.route('/bulk/tags')
class BulkTagOperation(Resource):
    @jwt_required()
    @require_permission('tag')
    def post(self):
        """Apply or remove tags from multiple IOCs"""
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        action = data.get('action')
        tag = data.get('tag', '').strip()
        
        if not ioc_ids or not tag:
            iocs_ns.abort(400, 'IOC IDs and tag name are required')
        
        if action not in ['add', 'remove']:
            iocs_ns.abort(400, 'Invalid action. Use "add" or "remove"')
        
        updated_count = 0
        for ioc_id in ioc_ids:
            ioc = IOC.find_by_id(ioc_id)
            if ioc:
                if action == 'add':
                    ioc.add_tag(tag)
                else:
                    ioc.remove_tag(tag)
                ioc.save()
                updated_count += 1
        
        return {
            'message': f'Updated {updated_count} IOCs',
            'action': action,
            'tag': tag,
            'updated_count': updated_count
        }
