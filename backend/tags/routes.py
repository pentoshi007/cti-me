"""
Tags API routes - Full Flask blueprint implementation
"""
import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from utils.decorators import get_current_user
from bson import ObjectId
from datetime import datetime

from tags.models import Tag
from auth.models import User

logger = logging.getLogger(__name__)

tags_bp = Blueprint('tags', __name__)


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


@tags_bp.route('/', methods=['GET'])
@jwt_required()
def list_tags():
    """List all tags with optional filtering"""
    try:
        # Query parameters
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'name')
        sort_order = request.args.get('sort_order', 'asc')

        # Validate sort field
        valid_sort_fields = ['name', 'created_at']
        if sort_by not in valid_sort_fields:
            sort_by = 'name'

        # Get tags
        if search:
            tags = Tag.search(search)
        else:
            tags = Tag.list_all(sort_by)

        # Sort by created_at if requested
        if sort_by == 'created_at':
            reverse = sort_order == 'desc'
            tags.sort(key=lambda x: x.created_at or datetime.min, reverse=reverse)
        elif sort_by == 'name':
            reverse = sort_order == 'desc'
            tags.sort(key=lambda x: x.name, reverse=reverse)

        # Convert to dicts
        tags_data = [tag.to_dict() for tag in tags]

        return jsonify({
            'tags': tags_data,
            'total': len(tags_data)
        })

    except Exception as e:
        logger.error(f"Error listing tags: {e}")
        return jsonify({'error': 'Failed to retrieve tags'}), 500


@tags_bp.route('/', methods=['POST'])
@jwt_required()
@require_permission('tag')
def create_tag():
    """Create a new tag"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        name = data.get('name', '').strip()
        color = data.get('color', '#6B7280').strip()
        description = data.get('description', '').strip()

        # Validate name
        if not name:
            return jsonify({'error': 'Tag name is required'}), 400

        if len(name) < 2 or len(name) > 50:
            return jsonify({'error': 'Tag name must be 2-50 characters long'}), 400

        # Check if tag already exists
        existing_tag = Tag.find_by_name(name)
        if existing_tag:
            return jsonify({
                'error': 'Tag already exists',
                'existing_tag': existing_tag.to_dict()
            }), 409

        # Validate color format (hex color)
        if color and not color.startswith('#'):
            color = f'#{color}'
        if not color or len(color) != 7 or not color[1:].replace('0','').replace('1','').replace('2','').replace('3','').replace('4','').replace('5','').replace('6','').replace('7','').replace('8','').replace('9','').replace('a','').replace('b','').replace('c','').replace('d','').replace('e','').replace('f','').replace('A','').replace('B','').replace('C','').replace('D','').replace('E','').replace('F','').isalnum():
            return jsonify({'error': 'Invalid color format. Use hex format like #FF5733'}), 400

        # Create tag
        user = get_current_user()
        tag = Tag(
            name=name,
            color=color,
            description=description,
            created_by=str(user._id) if user else None
        )

        tag_id = tag.save()

        logger.info(f"Created tag '{name}' by user {user.username if user else 'unknown'}")
        return jsonify(tag.to_dict()), 201

    except Exception as e:
        logger.error(f"Error creating tag: {e}")
        return jsonify({'error': 'Failed to create tag'}), 500


@tags_bp.route('/<tag_id>', methods=['GET'])
@jwt_required()
def get_tag(tag_id):
    """Get specific tag by ID"""
    try:
        if not ObjectId.is_valid(tag_id):
            return jsonify({'error': 'Invalid tag ID format'}), 400

        tag = Tag.find_by_id(tag_id)
        if not tag:
            return jsonify({'error': 'Tag not found'}), 404

        return jsonify(tag.to_dict())

    except Exception as e:
        logger.error(f"Error retrieving tag {tag_id}: {e}")
        return jsonify({'error': 'Failed to retrieve tag'}), 500


@tags_bp.route('/<tag_id>', methods=['PUT'])
@jwt_required()
@require_permission('tag')
def update_tag(tag_id):
    """Update an existing tag"""
    try:
        if not ObjectId.is_valid(tag_id):
            return jsonify({'error': 'Invalid tag ID format'}), 400

        tag = Tag.find_by_id(tag_id)
        if not tag:
            return jsonify({'error': 'Tag not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Update allowed fields
        if 'name' in data:
            new_name = data['name'].strip()
            if not new_name:
                return jsonify({'error': 'Tag name cannot be empty'}), 400

            # Check if another tag with this name exists
            existing_tag = Tag.find_by_name(new_name)
            if existing_tag and str(existing_tag._id) != tag_id:
                return jsonify({
                    'error': 'Tag name already exists',
                    'existing_tag': existing_tag.to_dict()
                }), 409

            tag.name = new_name

        if 'color' in data:
            color = data['color'].strip()
            if color and not color.startswith('#'):
                color = f'#{color}'
            if not color or len(color) != 7 or not color[1:].replace('0','').replace('1','').replace('2','').replace('3','').replace('4','').replace('5','').replace('6','').replace('7','').replace('8','').replace('9','').replace('a','').replace('b','').replace('c','').replace('d','').replace('e','').replace('f','').replace('A','').replace('B','').replace('C','').replace('D','').replace('E','').replace('F','').isalnum():
                return jsonify({'error': 'Invalid color format. Use hex format like #FF5733'}), 400
            tag.color = color

        if 'description' in data:
            tag.description = data['description'].strip()

        # Save changes
        tag.save()

        user = get_current_user()
        logger.info(f"Updated tag {tag_id} by user {user.username if user else 'unknown'}")

        return jsonify(tag.to_dict())

    except Exception as e:
        logger.error(f"Error updating tag {tag_id}: {e}")
        return jsonify({'error': 'Failed to update tag'}), 500


@tags_bp.route('/<tag_id>', methods=['DELETE'])
@jwt_required()
@require_permission('tag')
def delete_tag(tag_id):
    """Delete a tag"""
    try:
        if not ObjectId.is_valid(tag_id):
            return jsonify({'error': 'Invalid tag ID format'}), 400

        tag = Tag.find_by_id(tag_id)
        if not tag:
            return jsonify({'error': 'Tag not found'}), 404

        # Check if tag is in use
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        usage_count = indicators.count_documents({'tags': tag.name})

        if usage_count > 0:
            return jsonify({
                'error': 'Cannot delete tag that is in use',
                'usage_count': usage_count,
                'message': f'This tag is used by {usage_count} IOC(s). Remove it from all IOCs before deleting.'
            }), 409

        # Delete tag
        if tag.delete():
            user = get_current_user()
            logger.info(f"Deleted tag '{tag.name}' by user {user.username if user else 'unknown'}")
            return jsonify({'message': 'Tag deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete tag'}), 500

    except Exception as e:
        logger.error(f"Error deleting tag {tag_id}: {e}")
        return jsonify({'error': 'Failed to delete tag'}), 500


@tags_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_tag_stats():
    """Get tag usage statistics"""
    try:
        tag_usage = Tag.get_tag_usage_stats()

        # Get total tags count
        total_tags = len(Tag.list_all())

        # Get tags with their usage
        tags = Tag.list_all()
        tags_with_usage = []
        for tag in tags:
            usage_count = tag_usage.get(tag.name, 0)
            tag_dict = tag.to_dict()
            tag_dict['usage_count'] = usage_count
            tags_with_usage.append(tag_dict)

        # Sort by usage count descending
        tags_with_usage.sort(key=lambda x: x['usage_count'], reverse=True)

        return jsonify({
            'total_tags': total_tags,
            'total_usage': sum(tag_usage.values()),
            'tags': tags_with_usage,
            'usage_breakdown': tag_usage
        })

    except Exception as e:
        logger.error(f"Error retrieving tag stats: {e}")
        return jsonify({'error': 'Failed to retrieve tag statistics'}), 500


@tags_bp.route('/validate', methods=['POST'])
@jwt_required()
def validate_tag_name():
    """Validate a tag name for uniqueness"""
    try:
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Tag name is required'}), 400

        name = data['name'].strip()
        if not name:
            return jsonify({'error': 'Tag name cannot be empty'}), 400

        # Check if tag exists
        existing_tag = Tag.find_by_name(name)
        if existing_tag:
            return jsonify({
                'valid': False,
                'message': 'Tag name already exists',
                'existing_tag': existing_tag.to_dict()
            })
        else:
            return jsonify({
                'valid': True,
                'message': 'Tag name is available'
            })

    except Exception as e:
        logger.error(f"Error validating tag name: {e}")
        return jsonify({'error': 'Failed to validate tag name'}), 500
