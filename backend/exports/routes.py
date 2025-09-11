"""
Exports API routes - Full Flask blueprint implementation
"""
import logging
import json
import csv
import io
from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required
from utils.decorators import get_current_user
from bson import ObjectId
from datetime import datetime
import uuid

from database import MongoDB

logger = logging.getLogger(__name__)

exports_bp = Blueprint('exports', __name__)


@exports_bp.route('/', methods=['GET'])
@jwt_required()
def list_exports():
    """List user's export history"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        from database import MongoDB
        exports_collection = MongoDB.get_collection('exports')

        # Query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 20)), 100)  # Max 100 per page
        skip = (page - 1) * limit

        # Filters
        status = request.args.get('status')
        format_type = request.args.get('format')

        # Build query
        query = {'user_id': str(user._id)}

        if status:
            query['status'] = status

        if format_type:
            query['format'] = format_type

        # Get total count
        total = exports_collection.count_documents(query)

        # Get exports with pagination and sorting
        cursor = exports_collection.find(query).sort('created_at', -1).skip(skip).limit(limit)
        exports_data = []

        for doc in cursor:
            export_dict = {
                'id': str(doc['_id']),
                'filename': doc.get('filename'),
                'format': doc.get('format'),
                'status': doc.get('status'),
                'record_count': doc.get('record_count', 0),
                'file_size': doc.get('file_size'),
                'created_at': doc.get('created_at'),
                'completed_at': doc.get('completed_at'),
                'error': doc.get('error')
            }
            exports_data.append(export_dict)

        return jsonify({
            'exports': exports_data,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        })

    except Exception as e:
        logger.error(f"Error listing exports: {e}")
        return jsonify({'error': 'Failed to retrieve exports'}), 500


@exports_bp.route('/', methods=['POST'])
@jwt_required()
def create_export():
    """Create a new export"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        export_format = data.get('format', 'json').lower()
        if export_format not in ['json', 'csv']:
            return jsonify({'error': 'Format must be json or csv'}), 400

        # Build query for IOCs to export
        query = {}

        # Apply filters if provided
        if 'filters' in data:
            filters = data['filters']

            if 'type' in filters:
                query['type'] = filters['type']

            if 'severity' in filters:
                query['severity'] = filters['severity']

            if 'tags' in filters and filters['tags']:
                query['tags'] = {'$in': filters['tags']}

            if 'score_min' in filters:
                query['score'] = {'$gte': filters['score_min']}

            if 'score_max' in filters:
                if 'score' not in query:
                    query['score'] = {}
                query['score']['$lte'] = filters['score_max']

            if 'date_from' in filters:
                query['created_at'] = {'$gte': filters['date_from']}

            if 'date_to' in filters:
                if 'created_at' not in query:
                    query['created_at'] = {}
                query['created_at']['$lte'] = filters['date_to']

        # Generate unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        export_id = str(uuid.uuid4())[:8]
        filename = f"cti_export_{timestamp}_{export_id}.{export_format}"

        # Create export record
        from database import MongoDB
        exports_collection = MongoDB.get_collection('exports')

        export_record = {
            'filename': filename,
            'format': export_format,
            'status': 'processing',
            'user_id': str(user._id),
            'query': query,
            'record_count': 0,
            'created_at': datetime.utcnow()
        }

        result = exports_collection.insert_one(export_record)
        export_id = str(result.inserted_id)

        # Start export process asynchronously
        try:
            success = _process_export(export_id, export_format, query, filename)
            if success:
                return jsonify({
                    'id': export_id,
                    'filename': filename,
                    'status': 'completed',
                    'message': 'Export completed successfully'
                }), 201
            else:
                return jsonify({'error': 'Export failed'}), 500

        except Exception as e:
            logger.error(f"Export processing failed: {e}")
            # Update export status to failed
            exports_collection.update_one(
                {'_id': result.inserted_id},
                {'$set': {'status': 'failed', 'error': str(e)}}
            )
            return jsonify({'error': 'Export processing failed'}), 500

    except Exception as e:
        logger.error(f"Error creating export: {e}")
        return jsonify({'error': 'Failed to create export'}), 500


@exports_bp.route('/<export_id>', methods=['GET'])
@jwt_required()
def get_export(export_id):
    """Get export details"""
    try:
        if not ObjectId.is_valid(export_id):
            return jsonify({'error': 'Invalid export ID format'}), 400

        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        from database import MongoDB
        exports_collection = MongoDB.get_collection('exports')
        export_doc = exports_collection.find_one({'_id': ObjectId(export_id)})

        if not export_doc:
            return jsonify({'error': 'Export not found'}), 404

        # Check if user owns this export
        if export_doc.get('user_id') != str(user._id):
            return jsonify({'error': 'Access denied'}), 403

        # Convert to response format
        export_dict = {
            'id': str(export_doc['_id']),
            'filename': export_doc.get('filename'),
            'format': export_doc.get('format'),
            'status': export_doc.get('status'),
            'record_count': export_doc.get('record_count', 0),
            'file_size': export_doc.get('file_size'),
            'created_at': export_doc.get('created_at'),
            'completed_at': export_doc.get('completed_at'),
            'error': export_doc.get('error'),
            'query': export_doc.get('query')
        }

        return jsonify(export_dict)

    except Exception as e:
        logger.error(f"Error retrieving export {export_id}: {e}")
        return jsonify({'error': 'Failed to retrieve export'}), 500


@exports_bp.route('/<export_id>/download', methods=['GET'])
@jwt_required()
def download_export(export_id):
    """Download export file"""
    try:
        if not ObjectId.is_valid(export_id):
            return jsonify({'error': 'Invalid export ID format'}), 400

        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        from database import MongoDB
        exports_collection = MongoDB.get_collection('exports')
        export_doc = exports_collection.find_one({'_id': ObjectId(export_id)})

        if not export_doc:
            return jsonify({'error': 'Export not found'}), 404

        # Check if user owns this export
        if export_doc.get('user_id') != str(user._id):
            return jsonify({'error': 'Access denied'}), 403

        # Check if export is completed
        if export_doc.get('status') != 'completed':
            return jsonify({'error': 'Export is not ready for download'}), 400

        # Get the file data
        file_data = export_doc.get('file_data')
        if not file_data:
            return jsonify({'error': 'Export file data not found'}), 500

        # Create file-like object from binary data
        file_obj = io.BytesIO(file_data)

        # Determine MIME type
        format_type = export_doc.get('format', 'json')
        mime_type = 'application/json' if format_type == 'json' else 'text/csv'

        # Return file
        return send_file(
            file_obj,
            mimetype=mime_type,
            as_attachment=True,
            download_name=export_doc.get('filename')
        )

    except Exception as e:
        logger.error(f"Error downloading export {export_id}: {e}")
        return jsonify({'error': 'Failed to download export'}), 500


@exports_bp.route('/<export_id>', methods=['DELETE'])
@jwt_required()
def delete_export(export_id):
    """Delete an export record"""
    try:
        if not ObjectId.is_valid(export_id):
            return jsonify({'error': 'Invalid export ID format'}), 400

        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        from database import MongoDB
        exports_collection = MongoDB.get_collection('exports')
        export_doc = exports_collection.find_one({'_id': ObjectId(export_id)})

        if not export_doc:
            return jsonify({'error': 'Export not found'}), 404

        # Check if user owns this export
        if export_doc.get('user_id') != str(user._id):
            return jsonify({'error': 'Access denied'}), 403

        # Delete export
        result = exports_collection.delete_one({'_id': ObjectId(export_id)})

        if result.deleted_count > 0:
            logger.info(f"Deleted export {export_id} by user {user.username if user else 'unknown'}")
            return jsonify({'message': 'Export deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete export'}), 500

    except Exception as e:
        logger.error(f"Error deleting export {export_id}: {e}")
        return jsonify({'error': 'Failed to delete export'}), 500


def _process_export(export_id, format_type, query, filename):
    """Process export in background"""
    try:
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        exports_collection = MongoDB.get_collection('exports')

        # Get IOCs matching the query
        cursor = indicators.find(query)
        iocs = list(cursor)

        if not iocs:
            # Update export as completed with 0 records
            exports_collection.update_one(
                {'_id': ObjectId(export_id)},
                {'$set': {
                    'status': 'completed',
                    'record_count': 0,
                    'completed_at': datetime.utcnow()
                }}
            )
            return True

        # Convert IOCs to export format
        export_data = []
        for ioc in iocs:
            # Convert ObjectId to string and handle datetime serialization
            ioc_dict = {}
            for key, value in ioc.items():
                if isinstance(value, ObjectId):
                    ioc_dict[key] = str(value)
                elif isinstance(value, datetime):
                    ioc_dict[key] = value.isoformat()
                elif isinstance(value, dict):
                    # Recursively handle nested dicts
                    ioc_dict[key] = _serialize_dict(value)
                elif isinstance(value, list):
                    # Handle lists
                    ioc_dict[key] = _serialize_list(value)
                else:
                    ioc_dict[key] = value
            export_data.append(ioc_dict)

        # Generate file content
        if format_type == 'json':
            file_content = json.dumps(export_data, indent=2, ensure_ascii=False)
            file_data = file_content.encode('utf-8')
        elif format_type == 'csv':
            if export_data:
                # Get all unique keys for CSV headers
                all_keys = set()
                for item in export_data:
                    all_keys.update(item.keys())

                # Create CSV content
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=sorted(all_keys))
                writer.writeheader()
                writer.writerows(export_data)
                file_content = output.getvalue()
                file_data = file_content.encode('utf-8')
            else:
                file_data = b''
        else:
            raise ValueError(f"Unsupported format: {format_type}")

        # Update export record with file data
        exports_collection.update_one(
            {'_id': ObjectId(export_id)},
            {'$set': {
                'status': 'completed',
                'record_count': len(export_data),
                'file_size': len(file_data),
                'file_data': file_data,
                'completed_at': datetime.utcnow()
            }}
        )

        logger.info(f"Export {export_id} completed: {len(export_data)} records, {len(file_data)} bytes")
        return True

    except Exception as e:
        logger.error(f"Export processing failed for {export_id}: {e}")

        # Update export status to failed
        exports_collection.update_one(
            {'_id': ObjectId(export_id)},
            {'$set': {
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.utcnow()
            }}
        )

        return False


def _serialize_dict(obj):
    """Recursively serialize dictionary values"""
    result = {}
    for key, value in obj.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = _serialize_dict(value)
        elif isinstance(value, list):
            result[key] = _serialize_list(value)
        else:
            result[key] = value
    return result


def _serialize_list(obj):
    """Recursively serialize list values"""
    result = []
    for item in obj:
        if isinstance(item, ObjectId):
            result.append(str(item))
        elif isinstance(item, datetime):
            result.append(item.isoformat())
        elif isinstance(item, dict):
            result.append(_serialize_dict(item))
        elif isinstance(item, list):
            result.append(_serialize_list(item))
        else:
            result.append(item)
    return result
