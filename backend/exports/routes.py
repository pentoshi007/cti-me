"""
Export API routes for IOC data
"""
import csv
import json
import io
from datetime import datetime
from flask import request, make_response
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import jwt_required

from iocs.models import IOC
from utils.decorators import require_permission

exports_ns = Namespace('exports', description='Data export operations')

# API Models
export_request_model = exports_ns.model('ExportRequest', {
    'format': fields.String(required=True, description='Export format (csv, json)', enum=['csv', 'json']),
    'filters': fields.Raw(description='Export filters')
})

export_response_model = exports_ns.model('ExportResponse', {
    'export_id': fields.String(description='Export job ID'),
    'status': fields.String(description='Export status'),
    'download_url': fields.String(description='Download URL when ready')
})


@exports_ns.route('')
class IOCExport(Resource):
    
    @exports_ns.expect(export_request_model)
    @jwt_required()
    @require_permission('export')
    def post(self):
        """Export IOC data directly"""
        data = request.get_json()
        export_format = data.get('format', 'csv').lower()
        filters = data.get('filters', {})
        
        # Build query from filters
        query = {}
        if filters.get('q'):
            query['value'] = {'$regex': filters['q'], '$options': 'i'}
        if filters.get('type'):
            query['type'] = filters['type']
        if filters.get('severity'):
            query['severity'] = filters['severity']
        if filters.get('tags'):
            tag_list = [tag.strip() for tag in filters['tags'].split(',') if tag.strip()]
            if tag_list:
                query['tags'] = {'$in': tag_list}
        
        # Get IOCs
        iocs, total = IOC.search(query=query, limit=10000)  # Reasonable export limit
        
        if export_format == 'csv':
            return self._export_csv(iocs)
        elif export_format == 'json':
            return self._export_json(iocs)
        else:
            exports_ns.abort(400, 'Unsupported export format')
    
    def _export_csv(self, iocs):
        """Export IOCs as CSV"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        headers = [
            'ID', 'Type', 'Value', 'Severity', 'Score', 'Tags',
            'First Seen', 'Last Seen', 'Created At', 'Sources'
        ]
        writer.writerow(headers)
        
        # Write IOC data
        for ioc in iocs:
            try:
                # Safely get datetime values
                first_seen = ''
                if hasattr(ioc, 'first_seen') and ioc.first_seen:
                    if hasattr(ioc.first_seen, 'isoformat'):
                        first_seen = ioc.first_seen.isoformat()
                    else:
                        first_seen = str(ioc.first_seen)
                
                last_seen = ''
                if hasattr(ioc, 'last_seen') and ioc.last_seen:
                    if hasattr(ioc.last_seen, 'isoformat'):
                        last_seen = ioc.last_seen.isoformat()
                    else:
                        last_seen = str(ioc.last_seen)
                
                created_at = ''
                if hasattr(ioc, 'created_at') and ioc.created_at:
                    if hasattr(ioc.created_at, 'isoformat'):
                        created_at = ioc.created_at.isoformat()
                    else:
                        created_at = str(ioc.created_at)
                
                # Safely get sources
                sources_str = ''
                if hasattr(ioc, 'sources') and ioc.sources:
                    try:
                        source_names = []
                        for source in ioc.sources:
                            if isinstance(source, dict):
                                source_names.append(source.get('name', ''))
                            else:
                                source_names.append(str(source))
                        sources_str = ', '.join(filter(None, source_names))
                    except Exception:
                        sources_str = str(ioc.sources)
                
                # Safely get tags
                tags_str = ''
                if hasattr(ioc, 'tags') and ioc.tags:
                    try:
                        if isinstance(ioc.tags, list):
                            tags_str = ', '.join(ioc.tags)
                        else:
                            tags_str = str(ioc.tags)
                    except Exception:
                        tags_str = str(ioc.tags)
                
                writer.writerow([
                    str(ioc._id) if hasattr(ioc, '_id') and ioc._id else '',
                    getattr(ioc, 'type', '') or '',
                    getattr(ioc, 'value', '') or '',
                    getattr(ioc, 'severity', '') or '',
                    getattr(ioc, 'score', 0) or 0,
                    tags_str,
                    first_seen,
                    last_seen,
                    created_at,
                    sources_str
                ])
            except Exception as e:
                # Log error but continue with other IOCs
                print(f"Error processing IOC {getattr(ioc, 'value', 'unknown')}: {e}")
                continue
        
        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=iocs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        return response
    
    def _export_json(self, iocs):
        """Export IOCs as JSON"""
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'total_records': len(iocs),
                'format': 'json'
            },
            'iocs': [ioc.to_dict() for ioc in iocs]
        }
        
        response = make_response(json.dumps(export_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=iocs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return response


@exports_ns.route('/<string:export_id>')
class ExportStatus(Resource):
    
    @exports_ns.marshal_with(export_response_model)
    @jwt_required()
    def get(self, export_id):
        """Get export job status"""
        # For now, return a placeholder response
        return {
            'export_id': export_id,
            'status': 'completed',
            'download_url': f'/api/exports/{export_id}/download'
        }
