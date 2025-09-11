"""
IOC API routes - Full Flask blueprint implementation
"""
import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from utils.decorators import get_current_user
from bson import ObjectId
from datetime import datetime
from typing import Optional, Dict, Any
import re

from iocs.models import IOC
from tags.models import Tag
from auth.models import User

logger = logging.getLogger(__name__)

iocs_bp = Blueprint('iocs', __name__)


def require_permission(permission: str):
    """Decorator to check user permissions"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user or not user.has_permission(permission):
                return jsonify({'error': 'Permission denied'}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def validate_ioc_data(data: Dict) -> tuple[Optional[str], Optional[str]]:
    """Validate IOC data and return (ioc_type, value) or (None, error_message)"""
    if not data:
        return None, "No data provided"

    value = data.get('value', '').strip()
    ioc_type = data.get('type', '').lower()

    if not value:
        return None, "IOC value is required"

    if not ioc_type:
        # Auto-detect type
        ioc_type = IOC.detect_type(value)

    if ioc_type not in IOC.IOC_TYPES:
        return None, f"Invalid IOC type. Must be one of: {', '.join(IOC.IOC_TYPES)}"

    if ioc_type == 'unknown':
        return None, "Could not determine IOC type from value"

    return ioc_type, value


@iocs_bp.route('/', methods=['GET'])
@jwt_required()
def list_iocs():
    """List IOCs with pagination and filtering"""
    try:
        # Query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 200)  # Max 200 per page
        skip = (page - 1) * limit

        # Filters
        ioc_type = request.args.get('type')
        severity = request.args.get('severity')
        tag = request.args.get('tag')
        search = request.args.get('search')

        # Build query
        query = {}
        if ioc_type and ioc_type in IOC.IOC_TYPES:
            query['type'] = ioc_type
        if severity and severity in IOC.SEVERITIES:
            query['severity'] = severity
        if tag:
            query['tags'] = {'$in': [tag]}
        if search:
            # Search in value field
            query['value'] = {'$regex': search, '$options': 'i'}

        # Sort options
        sort_by = request.args.get('sort_by', 'last_seen')
        sort_order = -1 if request.args.get('sort_order', 'desc') == 'desc' else 1

        # Validate sort field
        valid_sort_fields = ['last_seen', 'first_seen', 'created_at', 'score', 'value']
        if sort_by not in valid_sort_fields:
            sort_by = 'last_seen'

        sort = [(sort_by, sort_order)]

        # Execute search
        iocs, total = IOC.search(query, sort, skip, limit)

        # Convert to dicts
        ioc_data = [ioc.to_dict() for ioc in iocs]

        return jsonify({
            'iocs': ioc_data,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        })

    except Exception as e:
        logger.error(f"Error listing IOCs: {e}")
        return jsonify({'error': 'Failed to retrieve IOCs'}), 500


@iocs_bp.route('/<ioc_id>', methods=['GET'])
@jwt_required()
def get_ioc(ioc_id):
    """Get specific IOC by ID"""
    try:
        if not ObjectId.is_valid(ioc_id):
            return jsonify({'error': 'Invalid IOC ID format'}), 400

        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            return jsonify({'error': 'IOC not found'}), 404

        return jsonify(ioc.to_dict())

    except Exception as e:
        logger.error(f"Error retrieving IOC {ioc_id}: {e}")
        return jsonify({'error': 'Failed to retrieve IOC'}), 500


@iocs_bp.route('/', methods=['POST'])
@jwt_required()
@require_permission('edit')
def create_ioc():
    """Create a new IOC"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate IOC data
        ioc_type, value = validate_ioc_data(data)
        if not ioc_type:
            return jsonify({'error': value}), 400

        # Check if IOC already exists
        existing_ioc = IOC.find_by_value(ioc_type, value)
        if existing_ioc:
            return jsonify({
                'error': 'IOC already exists',
                'existing_ioc': existing_ioc.to_dict()
            }), 409

        # Create new IOC
        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            score=data.get('score', 0),
            severity=data.get('severity', 'info'),
            sources=data.get('sources', []),
            tags=data.get('tags', [])
        )

        # Add source indicating who created it
        user = get_current_user()
        ioc.add_source('manual_entry', f'Created by user {user.username}')

        # Save to database
        ioc_id = ioc.save()

        logger.info(f"Created new IOC: {ioc_type}:{value} by user {user.username}")
        return jsonify(ioc.to_dict()), 201

    except Exception as e:
        logger.error(f"Error creating IOC: {e}")
        return jsonify({'error': 'Failed to create IOC'}), 500


@iocs_bp.route('/<ioc_id>', methods=['PUT'])
@jwt_required()
@require_permission('edit')
def update_ioc(ioc_id):
    """Update an existing IOC"""
    try:
        if not ObjectId.is_valid(ioc_id):
            return jsonify({'error': 'Invalid IOC ID format'}), 400

        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            return jsonify({'error': 'IOC not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Update allowed fields
        if 'score' in data:
            ioc.score = max(0, min(100, int(data['score'])))
            ioc.update_severity()

        if 'severity' in data and data['severity'] in IOC.SEVERITIES:
            ioc.severity = data['severity']

        if 'tags' in data:
            ioc.tags = data['tags']

        # Add/update sources if provided
        if 'sources' in data:
            ioc.sources = data['sources']

        # Save changes
        ioc.save()

        user = get_current_user()
        logger.info(f"Updated IOC {ioc_id} by user {user.username}")

        return jsonify(ioc.to_dict())

    except Exception as e:
        logger.error(f"Error updating IOC {ioc_id}: {e}")
        return jsonify({'error': 'Failed to update IOC'}), 500


@iocs_bp.route('/<ioc_id>', methods=['DELETE'])
@jwt_required()
@require_permission('delete')
def delete_ioc(ioc_id):
    """Delete an IOC"""
    try:
        if not ObjectId.is_valid(ioc_id):
            return jsonify({'error': 'Invalid IOC ID format'}), 400

        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            return jsonify({'error': 'IOC not found'}), 404

        # Delete from database by setting _id and calling delete method
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        result = indicators.delete_one({'_id': ObjectId(ioc_id)})

        if result.deleted_count > 0:
            user = get_current_user()
            logger.info(f"Deleted IOC {ioc_id} by user {user.username}")
            return jsonify({'message': 'IOC deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete IOC'}), 500

    except Exception as e:
        logger.error(f"Error deleting IOC {ioc_id}: {e}")
        return jsonify({'error': 'Failed to delete IOC'}), 500


@iocs_bp.route('/<ioc_id>/tags', methods=['POST'])
@jwt_required()
@require_permission('tag')
def add_ioc_tag(ioc_id):
    """Add a tag to an IOC"""
    try:
        if not ObjectId.is_valid(ioc_id):
            return jsonify({'error': 'Invalid IOC ID format'}), 400

        data = request.get_json()
        if not data or 'tag_name' not in data:
            return jsonify({'error': 'tag_name is required'}), 400

        tag_name = data['tag_name'].strip()
        if not tag_name:
            return jsonify({'error': 'Tag name cannot be empty'}), 400

        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            return jsonify({'error': 'IOC not found'}), 404

        # Check if tag exists
        tag = Tag.find_by_name(tag_name)
        if not tag:
            return jsonify({'error': 'Tag does not exist'}), 404

        # Add tag to IOC
        ioc.add_tag(tag_name)
        ioc.save()

        user = get_current_user()
        logger.info(f"Added tag '{tag_name}' to IOC {ioc_id} by user {user.username}")

        return jsonify(ioc.to_dict())

    except Exception as e:
        logger.error(f"Error adding tag to IOC {ioc_id}: {e}")
        return jsonify({'error': 'Failed to add tag'}), 500


@iocs_bp.route('/<ioc_id>/tags/<tag_name>', methods=['DELETE'])
@jwt_required()
@require_permission('tag')
def remove_ioc_tag(ioc_id, tag_name):
    """Remove a tag from an IOC"""
    try:
        if not ObjectId.is_valid(ioc_id):
            return jsonify({'error': 'Invalid IOC ID format'}), 400

        ioc = IOC.find_by_id(ioc_id)
        if not ioc:
            return jsonify({'error': 'IOC not found'}), 404

        # Remove tag from IOC
        ioc.remove_tag(tag_name)
        ioc.save()

        user = get_current_user()
        logger.info(f"Removed tag '{tag_name}' from IOC {ioc_id} by user {user.username}")

        return jsonify(ioc.to_dict())

    except Exception as e:
        logger.error(f"Error removing tag from IOC {ioc_id}: {e}")
        return jsonify({'error': 'Failed to remove tag'}), 500


@iocs_bp.route('/bulk-tag', methods=['POST'])
@jwt_required()
@require_permission('tag')
def bulk_tag_iocs():
    """Add tags to multiple IOCs"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        ioc_ids = data.get('ioc_ids', [])
        tag_names = data.get('tag_names', [])

        if not ioc_ids:
            return jsonify({'error': 'ioc_ids list is required'}), 400

        if not tag_names:
            return jsonify({'error': 'tag_names list is required'}), 400

        # Validate tag existence
        for tag_name in tag_names:
            tag = Tag.find_by_name(tag_name)
            if not tag:
                return jsonify({'error': f'Tag "{tag_name}" does not exist'}), 404

        updated_iocs = []
        errors = []

        for ioc_id in ioc_ids:
            try:
                if not ObjectId.is_valid(ioc_id):
                    errors.append(f'Invalid IOC ID format: {ioc_id}')
                    continue

                ioc = IOC.find_by_id(ioc_id)
                if not ioc:
                    errors.append(f'IOC not found: {ioc_id}')
                    continue

                # Add all tags
                for tag_name in tag_names:
                    ioc.add_tag(tag_name)

                ioc.save()
                updated_iocs.append(ioc.to_dict())

            except Exception as e:
                errors.append(f'Error updating IOC {ioc_id}: {str(e)}')

        user = get_current_user()
        logger.info(f"Bulk tagged {len(updated_iocs)} IOCs with tags {tag_names} by user {user.username}")

        return jsonify({
            'updated_iocs': updated_iocs,
            'errors': errors,
            'success_count': len(updated_iocs),
            'error_count': len(errors)
        })

    except Exception as e:
        logger.error(f"Error in bulk tagging: {e}")
        return jsonify({'error': 'Failed to bulk tag IOCs'}), 500
